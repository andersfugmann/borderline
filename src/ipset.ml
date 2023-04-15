open Base

(** Range set is a set of ranges.
    The rangeset requires that elements are either subsets or distinct. I.e. No elements overlap partly
    inter a b = a | inter a b = b | inter a b = ø
*)
module type Ip = sig
  type t
  val to_string: t -> string
  val of_string_exn: string -> t
  val upper: t
  module Prefix : sig
    type addr = t
    type t
    val compare: t -> t -> int
    val subset: subnet:t -> network:t -> bool
    val bits: t -> int
    val network : t -> addr
    val network_address : t -> addr -> addr
    val mem: addr -> t -> bool
    val make: int -> addr -> t
  end
end

module Make(Ip : Ip) = struct

  module IpSet = Set
  type elt = Ip.Prefix.t
  module C = struct
    type t = Ip.Prefix.t
    include Comparator.Make( struct
      type t = Ip.Prefix.t
      let compare = Ip.Prefix.compare
      let sexp_of_t _ = failwith "Not implemented for ip sets"
    end)
  end
  type t = (elt, C.comparator_witness) IpSet.t

  let canonical t =
    let network = Ip.Prefix.network t in
    let bits = Ip.Prefix.bits t in
    Ip.Prefix.make bits network

  let to_list t = IpSet.to_list t
  let empty = IpSet.empty (module C)
  let singleton elt = IpSet.singleton (module C) elt
  let add t elt = IpSet.add t elt
  let of_list l = IpSet.of_list (module C) (List.map ~f:canonical l)
  let is_empty t = IpSet.is_empty t

  (* Call reduce as long as there are changes *)
  let reduce t =
    let rec reduce = function
      | x :: y :: xs when Ip.Prefix.bits x = Ip.Prefix.bits y -> begin
          let e = Ip.Prefix.make (Ip.Prefix.bits x - 1) (Ip.Prefix.network x) in
          match Ip.Prefix.subset ~network:e ~subnet:y with
          | true -> e :: reduce xs
          | false -> x :: reduce (y :: xs)
        end
      | x :: y :: xs when Ip.Prefix.subset ~network:y ~subnet:x ->
          reduce (y :: xs)
      | x :: y :: xs when Ip.Prefix.subset ~network:x ~subnet:y ->
          reduce (x :: xs)
      | x :: xs -> x :: reduce xs
      | [ ] -> []
    in
    let rec loop lst =
      let lst' = reduce lst in
      (* Hmm. No need for that I guess *)
      match List.length lst = List.length lst' with
      | true -> lst'
      | false -> loop lst'
    in
    loop t

  (* x/23 -> y/24, y'/24) *)
  let split ip =
    (* Return two prefixes *)
    let bits = Ip.Prefix.bits ip in
    let broadcast = Ip.Prefix.network_address ip Ip.upper in
    let network = Ip.Prefix.network ip in
    (Ip.Prefix.make (bits+1) network |> canonical,
     Ip.Prefix.make (bits+1) broadcast |> canonical)

  let equal a b =
    let rec inner = function
      | x :: xs, y :: ys when Ip.Prefix.compare x y = 0 ->
          inner (xs, ys)
      | x :: xs, y :: ys when Ip.Prefix.subset ~network:y ~subnet:x ->
          let (y1, y2) = split y in
          inner (x :: xs, y1 :: y2 :: ys)
      | x :: xs, y :: ys when Ip.Prefix.subset ~network:x ~subnet:y ->
          let (x1, x2) = split x in
          inner (x1 :: x2 :: xs, y :: ys)
      | [], [] -> true
      | _ -> false
    in
    inner (to_list a, to_list b)

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

module Ip4 = Make(struct
    include Ipaddr.V4
    let upper = make 0xff 0xff 0xff 0xff
  end)
module Ip6 = Make(struct
    include Ipaddr.V6
    let upper = make 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff
  end)

module Test = struct
  open OUnit2

  module Ip4List = OUnitDiff.ListSimpleMake(struct
      let pp_printer f t = Stdlib.Format.pp_print_string f (Ipaddr.V4.Prefix.to_string t)
      let pp_print_sep f () = Stdlib.Format.pp_print_string f "; "
      type t = Ipaddr.V4.Prefix.t
      let compare = Ipaddr.V4.Prefix.compare
    end)


  let unittest = "Ip set" >::: [
      "Split" >:: begin fun _ ->
        let ip = Ipaddr.V4.Prefix.of_string_exn "127.0.0.0/23" in
        let expect = [ "127.0.0.0/24"; "127.0.1.0/24" ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        let observ = Ip4.split ip |> fun x -> [ fst x; snd x] in
        Ip4List.assert_equal expect observ
      end;
      "Reduce" >:: begin fun _ ->
        let ips = [ "127.0.0.0/32"; "127.0.0.1/32"; "127.0.0.2/32" ]
                  |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        let expect = [ "127.0.0.0/31"; "127.0.0.2/32" ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect (ips |> Ip4.reduce)
      end;
      "Set" >:: begin fun _ ->
        let ips = [ "127.0.0.1/32"; "127.0.0.0/24"; "127.0.0.2/32";  ]
                  |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        let expect = [ "127.0.0.0/24"; ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect (ips |> Ip4.of_list |> Ip4.to_list |> Ip4.reduce)
      end;
      "Union" >:: begin fun _ ->
        let observ = [ "127.0.0.1/32"; "127.0.0.0/24"; "127.0.0.2/32";  ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                     |> List.map ~f:(Ip4.singleton)
                     |> List.fold_left ~f:Ip4.union ~init:Ip4.empty
                     |> Ip4.to_list
        in
        let expect = [ "127.0.0.0/24"; ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect observ
      end;
      "Diff" >:: begin fun _ ->
        let ip_a = [ "127.0.0.1/32"; "128.0.0.0/24"; "127.0.0.3/32";  ]
                   |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let ip_b = [ "128.0.0.0/27"; "127.0.0.3/32"; ]
                   |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let observ = Ip4.diff ip_a ip_b
                     |> Ip4.to_list
        in
        let expect = ["127.0.0.1/32"; "128.0.0.32/27"; "128.0.0.64/26"; "128.0.0.128/25"; ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect observ
      end;
      "Intersect" >:: begin fun _ ->
        let ip_a = [ "127.0.0.1/32"; "128.0.0.0/24"; "127.0.0.3/32";  ]
                   |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let ip_b = [ "128.0.0.0/27"; "127.0.0.3/32"; "128.1.0.0/24"]
                   |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let observ = Ip4.intersect ip_a ip_b |> Ip4.to_list in
        let expect = ["127.0.0.3/32"; "128.0.0.0/27"; ]
                     |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
        in
        Ip4List.assert_equal expect observ
      end;
      "Equal" >:: begin fun _ ->
        let ip_a = [ "127.0.0.0/24"; "128.0.0.0/23" ]
                   |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        let ip_b = [ "127.0.0.128/25"; "127.0.0.0/25"; "128.0.0.0/24"]
                   |> List.map ~f:Ipaddr.V4.Prefix.of_string_exn
                   |> Ip4.of_list
        in
        assert_bool "Should not be equal" (not (Ip4.equal ip_a ip_b));
        assert_bool "Should not be equal" (not (Ip4.equal ip_b ip_a));
        let ip_b =
          "128.0.1.0/24"
          |> Ipaddr.V4.Prefix.of_string_exn
          |> Ip4.add ip_b
        in
        assert_bool "Should be equal" (Ip4.equal ip_a ip_b);
        assert_bool "Should be equal" (Ip4.equal ip_b ip_a);
      end;
    ]



end
