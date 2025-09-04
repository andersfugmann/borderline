(* Ip ranges *)
open Base
let sprintf = Printf.sprintf
let printf = Stdio.printf

module T = Ipaddr.V4.Prefix

module type Prefix = sig
  type t
  type addr
  val compare: t -> t -> int
  val subset: subnet:t -> network:t -> bool
  val of_string_exn: string -> t
  val to_string: t -> string
  val subnets : int -> t -> t Stdlib.Seq.t
  val bits: t -> int
  val prefix: t -> t
end

module Make(Ip : Prefix) = struct
  (* Why the exclusions as a subset of ip.t. If we want that, we can very easily generate that *)
  type elt = Ip.t * Ip.t list
  type t = elt list

  (* Intersection between to lists of ips (sorted) *)
  let rec ip_intersection l1 l2 =
    match l1, l2 with
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l' ~network:l ->
        l' :: ip_intersection (l :: ls) ls'
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l ~network:l' ->
        l :: ip_intersection ls (l' :: ls')
      | l :: ls, l' :: ls' when Ip.compare l l' < 0 ->
        ip_intersection ls (l' :: ls')
      | l :: ls, _ :: ls' (* when Ip.compare l l' > 0 *) ->
        ip_intersection (l :: ls) ls'
      | [], _
      | _, [] -> []

  (* Union between to lists of ips (sorted) *)
  let rec ip_union l1 l2 =
    match l1, l2 with
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l' ~network:l ->
        ip_union (l :: ls) ls'
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l ~network:l' ->
        ip_union ls (l' :: ls')
      | l :: ls, l' :: ls' when Ip.compare l l' < 0 ->
        l :: ip_union ls (l' :: ls')
      | l :: ls, l' :: ls' (* when Ip.compare l l' > 0 *) ->
        l' :: ip_union (l :: ls) ls'
      | [], ls
      | ls, [] -> ls

  (*
  let ip_join_adjecent = function
    | n1 :: n2 :: ns ->
      (* So we want to make sure we are not holding the largest subset. *)
      (* But we cannot if we reduce correctly *)
      (* Where would 255.255.255.255/0 be? *)
      (* Do we even have  a regular ordering here, so that all subsets are close? *)
  *)

  let ip_subset ~of_:networks subnets =
    List.for_all ~f:(fun subnet ->
      List.exists ~f:(fun network -> Ip.subset ~subnet ~network) networks
    ) subnets

  let rec ip_reduce = function
    | n1 :: n2 :: ns when Ip.subset ~network:n1 ~subnet:n2 ->
      ip_reduce (n1 :: ns)
    | n1 :: n2 :: ns when Ip.subset ~network:n2 ~subnet:n1 ->
      ip_reduce (n2 :: ns)
    | n :: ns -> n :: ip_reduce ns
    | [] -> []

  let empty = [ ]
  let singleton ip = [ (Ip.prefix ip, []) ]
  let is_empty = List.is_empty

  let split_elt (incl, excls) =
    let bits = Ip.bits incl + 1 in
    Ip.subnets bits incl
    |> Stdlib.List.of_seq
    |> List.map ~f:(fun network -> network, List.filter ~f:(fun subnet -> Ip.subset ~network ~subnet) excls)

  let rec reduce t =
    t
    |> List.map ~f:(fun (incl, excls) ->
      let excls = ip_intersection [incl] excls in
      incl, excls)
    |> List.filter ~f:(fun (incl, excls) ->
      not (ip_subset ~of_:excls [incl]))
    |> List.map ~f:(function
      | incl, [ excl ] when Ip.bits incl + 1 = Ip.bits excl ->
        (* So excl could also be large *)
        begin match reduce (split_elt (incl, [ excl ])) with
        | [elt] -> elt
        | _ -> failwith "Precisely one element should be returned"
        end
      | elt -> elt)


  let rec union t t' =
    match t, t' with
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl ->
      union ((incl, ip_intersection excls excls') :: ts) ts'
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
       union ts ((incl', ip_intersection excls excls') :: ts')
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      (incl, excls) :: union ts ((incl', excls') :: ts')
    | ts, (incl', excls') :: ts' (* when Ip.compare incl incl' > 0 *) ->
      (incl', excls') :: union ts ts'
    | ts, [] -> ts

  let rec intersection t t' =
    match t, t' with
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl ->
      (incl', ip_intersection [incl'] (ip_union excls excls')) :: intersection ts ts'
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      (incl, ip_intersection [incl] (ip_union excls excls')) :: intersection ts ts'
    | (incl, _) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      union ts ((incl', excls') :: ts')
    | ts, _ :: ts' (* when Ip.compare incl incl' > 0 *) ->
      union ts ts'
    | _, [] -> []

  let rec diff t t' =
    match t, t' with
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      (* All are excluded.
         Its what-ever is not excluded - excls.
      *)
      let incls =
        ip_intersection [incl] excls'
        |> List.map ~f:(fun incl -> (incl, ip_intersection [incl] excls))
      in
      incls @ diff ts ((incl', excls') :: ts')
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl -> begin
        match ip_subset ~of_:excls excls' with
        | true ->
          (* If excl is smaller, we would just add incl' to the exclude list, but only if excl' is a subset of excl. *)
          let excls = ip_union excls [incl'] in
          diff ((incl, excls) :: ts) ts'
        | false ->
          let ts' = split_elt (incl, excls) @ ts' in
          diff ((incl, excls) :: ts) ts'
      end
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      (incl, excls) :: diff ts ((incl', excls') :: ts')
    | (incl, excls) :: ts, _ :: ts' (* when Ip.compare incl incl' > 0 *) ->
      diff ((incl, excls) :: ts) ts'
    | [], _ -> []
    | ts, [] -> ts

  let diff t t' =
    diff t t'
    |> reduce

  let show t =
    let show_elt (incl, excls) =
      let excls = match excls with
        | [] -> ""
        | excls -> List.map ~f:Ip.to_string excls |> String.concat ~sep:"; " |> sprintf "/[ %s ]"
      in
      sprintf "%s%s" (Ip.to_string incl) excls
    in
    sprintf "[ %s ]" (List.map ~f:show_elt t |> String.concat ~sep:"; ")
end

module Ip4Set = Make(Ipaddr.V4.Prefix)
module Ip6Set = Make(Ipaddr.V6.Prefix)

let%expect_test "compare" =
  let open Ipaddr.V4.Prefix in
  let test_compare xs ys =
    let x = of_string_exn xs |> prefix in
    let y = of_string_exn ys |> prefix in
    let res = Ipaddr.V4.Prefix.compare x y in
    printf "compare %s %s = %d\n" (to_string x) (to_string y) res
  in
  test_compare "10.0.0.10/32" "10.0.0.11/32";
  test_compare "10.0.0.11/32" "10.0.0.10/32";
  test_compare "10.0.0.10/8" "10.0.0.11/8";
  test_compare "10.0.0.11/8" "10.0.0.10/8";
  test_compare "10.0.0.0/8" "10.0.0.0/8";
  test_compare "10.0.0.0/8" "10.0.0.0/16";
  test_compare "10.0.0.0/16" "10.0.0.0/8";
  test_compare "10.0.0.1/8" "10.0.0.0/16";
  test_compare "10.0.0.1/16" "10.0.0.0/8";
  test_compare "20.0.0.0/8" "10.0.0.0/8";
  test_compare "10.0.0.0/25" "10.0.2.0/24";
  test_compare "0.0.0.0/0" "10.0.0.0/8";
  test_compare "255.255.255.255/0" "10.0.0.0/8";
  ();
  [%expect {|
    compare 10.0.0.10/32 10.0.0.11/32 = -1
    compare 10.0.0.11/32 10.0.0.10/32 = 1
    compare 10.0.0.0/8 10.0.0.0/8 = 0
    compare 10.0.0.0/8 10.0.0.0/8 = 0
    compare 10.0.0.0/8 10.0.0.0/8 = 0
    compare 10.0.0.0/8 10.0.0.0/16 = -1
    compare 10.0.0.0/16 10.0.0.0/8 = 1
    compare 10.0.0.0/8 10.0.0.0/16 = -1
    compare 10.0.0.0/16 10.0.0.0/8 = 1
    compare 20.0.0.0/8 10.0.0.0/8 = 1
    compare 10.0.0.0/25 10.0.2.0/24 = -1
    compare 0.0.0.0/0 10.0.0.0/8 = -1
    compare 0.0.0.0/0 10.0.0.0/8 = -1
    |}]

let%expect_test "ip subnet" =
  let test ~subnet:subnet_s ~network:network_s =
    let subnet = Ipaddr.V4.Prefix.of_string_exn subnet_s in
    let network = Ipaddr.V4.Prefix.of_string_exn network_s in
    printf "subnet %s is subset of network %s == %b\n" subnet_s network_s (Ipaddr.V4.Prefix.subset ~subnet ~network)
  in
  test ~subnet:"10.0.0.10/32" ~network:"10.0.0.0/8";
  test ~subnet:"10.0.0.8/8" ~network:"10.0.0.9/8";
  test ~subnet:"10.0.0.8/8" ~network:"10.0.0.8/9";
  test ~subnet:"10.0.0.0/8" ~network:"10.0.0.0/8";
  test ~subnet:"10.0.0.10/32" ~network:"10.0.0.10/32";
  test ~subnet:"10.0.0.10/16" ~network:"10.0.0.12/16";
  [%expect {|
    subnet 10.0.0.10/32 is subset of network 10.0.0.0/8 == true
    subnet 10.0.0.8/8 is subset of network 10.0.0.9/8 == true
    subnet 10.0.0.8/8 is subset of network 10.0.0.8/9 == false
    subnet 10.0.0.0/8 is subset of network 10.0.0.0/8 == true
    subnet 10.0.0.10/32 is subset of network 10.0.0.10/32 == true
    subnet 10.0.0.10/16 is subset of network 10.0.0.12/16 == true
    |}]


let%expect_test "ip set operations" =
  let test ~msg ~f a b =
    let a' = List.map ~f:Ipaddr.V4.Prefix.of_string_exn a in
    let b' = List.map ~f:Ipaddr.V4.Prefix.of_string_exn b in
    let res = f a' b' in
    printf "[%s] %s [%s] = [%s]\n"
      (String.concat ~sep:"; " a)
      msg
      (String.concat ~sep:"; " b)
      (List.map ~f:Ipaddr.V4.Prefix.to_string res |> String.concat ~sep:"; ")
  in
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.1/32"] ["10.0.0.2/32"];
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.9/32"] ["10.0.0.10/32"; "10.0.0.11/32"];
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.9/32";"10.0.0.10/32"; "10.0.0.11/32"] ["10.0.0.0/16"];
  test ~msg:"intersection" ~f:Ip4Set.ip_intersection ["10.0.0.11/32"] ["10.0.0.11/32"; "10.0.0.12/32"];
  test ~msg:"intersection" ~f:Ip4Set.ip_intersection ["10.0.0.0/24"; "10.0.0.0/8"] ["10.0.1.0/24"; "10.0.4.0/24"];

  [%expect {|
    [10.0.0.1/32] union [10.0.0.2/32] = [10.0.0.1/32; 10.0.0.2/32]
    [10.0.0.9/32] union [10.0.0.10/32; 10.0.0.11/32] = [10.0.0.9/32; 10.0.0.10/32; 10.0.0.11/32]
    [10.0.0.9/32; 10.0.0.10/32; 10.0.0.11/32] union [10.0.0.0/16] = [10.0.0.0/16]
    [10.0.0.11/32] intersection [10.0.0.11/32; 10.0.0.12/32] = [10.0.0.11/32]
    [10.0.0.0/24; 10.0.0.0/8] intersection [10.0.1.0/24; 10.0.4.0/24] = [10.0.1.0/24; 10.0.4.0/24]
    |}]

let%expect_test "Set operations" =
  let of_string = Ipaddr.V4.Prefix.of_string_exn in
  let singleton  s = Ip4Set.singleton (of_string s) in
  let _union t elt = Ip4Set.union t (singleton elt) in
  let ( ?@ ) a = singleton a in
  let ( + ) a b = Ip4Set.union a b in
  let ( - ) a b = Ip4Set.diff a b in
  let test ~msg ~f ts =
    let f ts = List.fold ~init:Ip4Set.empty ~f:(fun acc elt -> f acc (singleton elt)) ts in
    printf "%s: %s = %s\n" msg (String.concat ~sep:" x " ts)
      (Ip4Set.show (f ts))
  in
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.12/32"; "10.0.0.11/32"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/32"; "10.0.0.11/32"; "10.0.0.0/24"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/24"; "10.0.0.11/8"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/8"; "10.0.0.11/8"];
  test ~msg:"diff" ~f:Ip4Set.diff ["10.0.0.0/8"; "10.0.0.11/24"];
  test ~msg:"diff" ~f:Ip4Set.diff ["10.0.0.11/24"; "10.0.0.0/8"];
  let a = (?@"10.0.0.12/32" + ?@"10.0.0.13/32") - ?@"10.0.0.0/8" in
  printf "diff: -> %s\n" (Ip4Set.show a);
  let a = (?@"10.0.0.0/24" + ?@"10.0.10.0/24") - ?@"10.0.0.0/8" in
  printf "diff: -> %s\n" (Ip4Set.show a);
  let a = (?@"10.0.0.0/24" + ?@"10.0.1.0/24") - ?@"10.0.0.0/23" in
  printf "diff: -> %s\n" (Ip4Set.show a);
  let a = (?@"10.0.0.0/24" + ?@"10.0.1.0/24") - (?@"10.0.0.0/23" - ?@"10.0.0.0/25") in
  printf "diff: -> %s\n" (Ip4Set.show a);
  let a = (?@"10.0.0.0/24" + ?@"10.0.2.0/24") - (?@"10.0.0.0/23" - ?@"10.0.0.0/25") in
  printf "diff: -> %s\n" (Ip4Set.show a);
  ();

  [%expect {|
    union: 10.0.0.12/32 x 10.0.0.11/32 = [ 10.0.0.11/32; 10.0.0.12/32 ]
    union: 10.0.0.10/32 x 10.0.0.11/32 x 10.0.0.0/24 = [ 10.0.0.0/24 ]
    union: 10.0.0.10/24 x 10.0.0.11/8 = [ 10.0.0.0/8 ]
    union: 10.0.0.10/8 x 10.0.0.11/8 = [ 10.0.0.0/8 ]
    diff: 10.0.0.0/8 x 10.0.0.11/24 = [  ]
    diff: 10.0.0.11/24 x 10.0.0.0/8 = [  ]
    diff: -> [  ]
    diff: -> [  ]
    diff: -> [  ]
    diff: -> [ 10.0.0.0/25 ]
    diff: -> [ 10.0.0.0/25; 10.0.2.0/24 ]
    |}]

  (* Need to test exclusions. We can do that with diffing *)
