open Batteries

(** Range set is a set of ranges.
    The rangeset requires that elements are either subsets or distinct. I.e. No elements overlap partly
    inter a b = a | inter a b = b | inter a b = ø
*)
module type Ip = sig
  type t
  val to_bytes: t -> string
  val of_bytes_exn: string -> t
  module Prefix : sig
    type addr = t
    type t
    val compare: t -> t -> int
    val subset: subnet:t -> network:t -> bool
    val bits: t -> int
    val network : t -> addr
    val mem: addr -> t -> bool
    val make: int -> addr -> t
  end

end

module Make(Ip : Ip) = struct
  type elt = Ip.Prefix.t
  type tree = Node of tree * elt * tree
            | Nil
  type t = tree

  let rec to_list = function
    | Nil -> []
    | Node (l, t, r) ->
        (to_list l) @ [t] @ (to_list r)

  let empty = Nil

  let rec add t elt = match t with
    | Nil -> Node (Nil, elt, Nil)
    | Node (_, e, _) when Ip.Prefix.subset ~subnet:elt ~network:e -> t
    | Node (l, e, r) when Ip.Prefix.subset ~subnet:e ~network:elt ->
        (to_list l) @ (to_list r) |> List.enum |> Random.shuffle
        |> Array.fold_left add (add Nil elt)
    | Node (l, e, r) when Ip.Prefix.compare elt e < 0 ->
        Node ( add l elt, e, r)
    | Node (l, e, r) when Ip.Prefix.compare elt e > 0 ->
        Node ( l, e, add r elt)
    | Node (l, e, r) (* when Ip.Prefix.compare elt e = 0 *) ->
        Node (l, e, r)

  let of_list l =
    List.enum l |> Random.shuffle
    |> Array.fold_left add empty

  let is_empty = function
    | Nil -> true
    | Node _ -> false

  (* Call reduce as long as there are changes *)
  let reduce t =
    let reduce_pair x y =
      match Ip.Prefix.bits x = Ip.Prefix.bits y  with
      | true -> begin
          let e = Ip.Prefix.make (Ip.Prefix.bits x - 1) (Ip.Prefix.network x) in
          match Ip.Prefix.subset ~network:e ~subnet:y with
          | true -> Some e
          | false -> None
        end
      | false -> None
    in

    let rec reduce = function
      | x :: y :: xs -> begin
          match reduce_pair x y with
          | Some e -> e :: reduce xs
          | None -> x :: reduce (y :: xs)
        end
      | [ x ] -> [ x ]
      | [ ] -> []
    in
    let rec loop lst =
      let lst' = reduce lst in
      match List.length lst = List.length lst' with
      | true -> lst'
      | false -> loop lst'

    in
    loop t

  let equal a b =
    (to_list a |> reduce) = (to_list b |> reduce)

  let split ip =
    let bits = Ip.Prefix.bits ip + 1 in
    let addr = Ip.Prefix.network ip in
    let offset = bits / 8 in
    let rem = bits mod 8 in
    let addr2 =
      let s = Ip.to_bytes addr in
      let v = String.get s offset |> Char.code |> (lor) (1 lsl (8-rem)) |> Char.chr in
      String.set s offset v;
      Ip.of_bytes_exn s;
    in
    (Ip.Prefix.make bits addr, Ip.Prefix.make bits addr2)


  (* Intersection, Union, Diff *)
  let diff a b =
    let rec inner = function
      | xs, [] -> xs
      | [], _ -> []
      | x :: xs, y :: ys when Ip.Prefix.subset ~subnet:x ~network:y ->
          inner (xs, y :: ys)
      | x :: xs, y :: ys when Ip.Prefix.subset ~subnet:y ~network:x ->
          (* Need to create x in two pieces *)
          let a, b = split x in
          inner (a :: b :: xs, y :: ys)
      | x :: xs, y :: ys when Ip.Prefix.compare x y < 0 ->
          x :: inner (xs, y :: ys)
      | x :: xs, y :: ys when Ip.Prefix.compare x y > 0 ->
          inner (x :: xs, ys)
      | _ :: xs, _ :: ys (* when Ip.Prefix.compare x y = 0 *) ->
          inner (xs, ys)
    in
    inner (to_list a, to_list b) |> of_list

  let intersect a b =
    let rec inner = function
      | _, [] -> []
      | [], _ -> []
      | x :: xs, y :: ys when Ip.Prefix.subset ~subnet:x ~network:y ->
          x :: inner (xs, y :: ys)
      | x :: xs, y :: ys when Ip.Prefix.subset ~subnet:y ~network:x ->
          y :: inner (x :: xs, ys)
      | x :: xs, y :: ys when Ip.Prefix.compare x y < 0 ->
          inner (xs, y :: ys)
      | x :: xs, y :: ys when Ip.Prefix.compare x y > 0 ->
          inner (x :: xs, ys)
      | x :: xs, _ :: ys (* when Ip.Prefix.compare x y = 0 *) ->
          x :: inner (xs, ys)
    in
    inner (to_list a, to_list b) |> of_list

  let union a b =
    let rec inner = function
      | xs, [] -> xs
      | [], ys -> ys
      | x :: xs, y :: ys when Ip.Prefix.subset ~subnet:x ~network:y ->
          y :: inner (xs, ys)
      | x :: xs, y :: ys when Ip.Prefix.subset ~subnet:y ~network:x ->
          x :: inner (xs, ys)
      | x :: xs, y :: ys when Ip.Prefix.compare x y < 0 ->
          x :: inner (xs, y :: ys)
      | x :: xs, y :: ys when Ip.Prefix.compare x y > 0 ->
          y :: inner (x :: xs, ys)
      | x :: xs, _ :: ys (* when Ip.Prefix.compare x y = 0 *) ->
          x :: inner (xs, ys)
    in
    inner (to_list a, to_list b) |> of_list

end

module Ip4 = Make(Ipaddr.V4)
module Ip6 = Make(Ipaddr.V6)

module Test = struct
  open OUnit2

  module Ip4List = OUnitDiff.ListSimpleMake(struct
      let pp_printer f t = BatFormat.pp_print_string f (Ipaddr.V4.Prefix.to_string t)
      let pp_print_sep f () = BatFormat.pp_print_string f "; "
      type t = Ipaddr.V4.Prefix.t
      let compare = Ipaddr.V4.Prefix.compare
    end)


  let unittest = "Ip set" >::: [
      "Split" >:: begin fun _ ->
        let ip = Ipaddr.V4.Prefix.of_string_exn "127.0.0.0/24" in
        let expect = [ "127.0.0.0/25"; "127.0.0.128/25" ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        let observ = Ip4.split ip |> fun x -> [ fst x; snd x] in
        Ip4List.assert_equal expect observ
      end;
      "Reduce" >:: begin fun _ ->
        let ips = [ "127.0.0.0/32"; "127.0.0.1/32"; "127.0.0.2/32" ]
                  |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        let expect = [ "127.0.0.0/31"; "127.0.0.2/32" ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect (ips |> Ip4.reduce)
      end;
      "Set" >:: begin fun _ ->
        let ips = [ "127.0.0.1/32"; "127.0.0.0/24"; "127.0.0.2/32";  ]
                  |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        let expect = [ "127.0.0.0/24"; ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect (ips |> Ip4.of_list |> Ip4.to_list)
      end;
      "Union" >:: begin fun _ ->
        let observ = [ "127.0.0.1/32"; "127.0.0.0/24"; "127.0.0.2/32";  ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
                     |> List.map (Ip4.add Ip4.empty)
                     |> List.fold_left Ip4.union Ip4.empty
                     |> Ip4.to_list
        in
        let expect = [ "127.0.0.0/24"; ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect observ
      end;
      "Diff" >:: begin fun _ ->
        let ip_a = [ "127.0.0.1/32"; "128.0.0.0/24"; "127.0.0.3/32";  ]
                   |> List.map Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let ip_b = [ "128.0.0.0/27"; "127.0.0.3/32"; ]
                   |> List.map Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let observ = Ip4.diff ip_a ip_b |> Ip4.to_list in
        let expect = ["127.0.0.1/32"; "128.0.0.32/27"; "128.0.0.64/26"; "128.0.0.128/25"; ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect observ
      end;
      "Intersect" >:: begin fun _ ->
        let ip_a = [ "127.0.0.1/32"; "128.0.0.0/24"; "127.0.0.3/32";  ]
                   |> List.map Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let ip_b = [ "128.0.0.0/27"; "127.0.0.3/32"; "128.1.0.0/24"]
                   |> List.map Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let observ = Ip4.intersect ip_a ip_b |> Ip4.to_list in
        let expect = ["127.0.0.3/32"; "128.0.0.0/27"; ]
                     |> List.map Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect observ
      end;
    ]



end
