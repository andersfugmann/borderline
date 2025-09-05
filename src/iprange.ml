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
  val address: t -> addr
  val make: int -> addr -> t
end

module Make(Ip : Prefix) = struct
  type ip = Ip.t
  type elt = ip * ip list
  type t = elt list

  let ip_split ip =
    let bits = Ip.bits ip + 1 in
    Ip.subnets bits ip
    |> Stdlib.List.of_seq

  let ip_join_adjecent ip ip' =
    let bits = Ip.bits ip in
    match bits = Ip.bits ip' with
    | false -> None
    | true ->
      let ip = Ip.make (bits-1) (Ip.address ip) in
      match Ip.subset ~network:ip ~subnet:ip' with
      | true -> Some ip
      | false -> None

  let rec ip_reduce = function
    | i1 :: i2 :: is ->
      begin
        match ip_join_adjecent i1 i2 with
        | Some ip -> ip :: ip_reduce is
        | None -> i1 :: ip_reduce (i2 :: is)
      end
    | is -> is

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

  let ip_union l1 l2 = ip_union l1 l2 |> ip_reduce

  let rec ip_diff l1 l2 =
    match l1, l2 with
    | l :: ls, l' :: ls' when Ip.subset ~subnet:l ~network:l' ->
      ip_diff ls (l' :: ls')
    | l :: ls, l' :: ls' when Ip.subset ~subnet:l' ~network:l ->
      ip_diff ((ip_split l) @ ls) (l' :: ls')
    | l :: ls, l' :: ls' when Ip.compare l l' < 0 ->
      ip_diff ls (l' :: ls')
    | ls, _ :: ls' (* when Ip.compare l l' > 0 *) ->
      ip_diff ls ls'
    | ts, [] -> ts

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
    ip_split incl
    |> List.map ~f:(fun network -> network, List.filter ~f:(fun subnet -> Ip.subset ~network ~subnet) excls)

  let rec reduce t =
    let rec inner = function
      | (incl, excls) :: (incl', excls') :: ts ->
        begin
          match ip_join_adjecent incl incl' with
          | Some incl -> (incl, (ip_union excls excls')) :: inner ts
          | None -> (incl, excls) :: inner ((incl', excls') :: ts)
        end
      | ts -> ts
    in
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
    |> inner

  let rec union t t' =
    match t, t' with
    | ts, [] | [], ts -> ts
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl ->
      let excls = ip_union (ip_intersection excls excls') (ip_diff excls [incl']) in
      union ((incl, excls) :: ts) ts'
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      let excls' = ip_union (ip_intersection excls excls') (ip_diff excls' [incl]) in
      union ts ((incl', excls') :: ts')
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      (incl, excls) :: union ts ((incl', excls') :: ts')
    | ts, (incl', excls') :: ts' (* when Ip.compare incl incl' > 0 *) ->
      (incl', excls') :: union ts ts'
  let union t t' = union t t' |> reduce

  let rec intersection t t' =
    match t, t' with
    | [], _ | _, [] -> []
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl ->
      (incl', ip_intersection [incl'] (ip_union excls excls')) :: intersection ((incl, excls) :: ts) ts'
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      (incl, ip_intersection [incl] (ip_union excls excls')) :: intersection ts ((incl', excls') :: ts')
    | (incl, _) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      intersection ts ((incl', excls') :: ts')
    | ts, _ :: ts' (* when Ip.compare incl incl' > 0 *) ->
      intersection ts ts'

  let rec diff t t' =
    match t, t' with
    | [], _ -> []
    | ts, [] -> ts
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      (* All are excluded. Its what-ever is not excluded - excls. *)
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

  let diff t t' = diff t t' |> reduce


  let of_list l =
    List.map ~f:singleton l
    |> List.fold ~init:empty ~f:union


  let to_networks l =
    let incls, excls = List.unzip l in
    let excls = List.concat excls in
    incls, excls

  let show t =
    let show_elt (incl, excls) =
      let excls = match excls with
        | [] -> ""
        | excls -> List.map ~f:Ip.to_string excls |> String.concat ~sep:"; " |> sprintf " \\ [ %s ]"
      in
      sprintf "%s%s" (Ip.to_string incl) excls
    in
    sprintf "[ %s ]" (List.map ~f:show_elt t |> String.concat ~sep:"; ")
end


module Ip4Set = Make(Ipaddr.V4.Prefix)
module Ip6Set = Make(Ipaddr.V6.Prefix)

module type IpSet = sig
  type ip
  type elt
  type t
  val empty : t
  val singleton : Ipaddr.V6.Prefix.t -> (Ipaddr.V6.Prefix.t * 'a list) list
  val is_empty : t -> bool
  val union : t -> t -> t
  val intersection : t -> t -> t
  val diff : t -> t -> t
  val of_list : ip list -> t
  val to_networks : t -> ip list * ip list
  val show : t -> string
end

module X : (IpSet with type ip = Ipaddr.V6.Prefix.t) = Make(Ipaddr.V6.Prefix)

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

let%expect_test "decrease bits" =
  let module P = Ipaddr.V4.Prefix in
  let a = P.of_string_exn "10.0.0.0/8" in
  let bits = P.bits a in
  printf "Subnets of %s: " (P.to_string a);
  P.subnets (bits - 1) a
  |> Stdlib.Seq.iter (fun x -> printf "%s " (P.to_string x));
  printf "\n";
  ();
  [%expect {| Subnets of 10.0.0.0/8: |}]

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
  let of_list l =
    List.map ~f:(fun net -> Ipaddr.V4.Prefix.of_string_exn net |> Ipaddr.V4.Prefix.prefix) l
  in
  let test ~msg ~f a b =
    let a' = of_list a in
    let b' = of_list b in
    let res = f a' b' in
    printf "[%s] %s [%s] = [%s]\n"
      (String.concat ~sep:"; " a)
      msg
      (String.concat ~sep:"; " b)
      (List.map ~f:Ipaddr.V4.Prefix.to_string res |> String.concat ~sep:"; ")
  in
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.0/32"] ["10.0.0.1/32"];
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.1/32"] ["10.0.0.2/32"];
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.9/32"] ["10.0.0.10/32"; "10.0.0.11/32"];
  test ~msg:"union" ~f:Ip4Set.ip_union ["10.0.0.9/32";"10.0.0.10/32"; "10.0.0.11/32"] ["10.0.0.0/16"];
  test ~msg:"intersection" ~f:Ip4Set.ip_intersection ["10.0.0.11/32"] ["10.0.0.11/32"; "10.0.0.12/32"];
  test ~msg:"intersection" ~f:Ip4Set.ip_intersection ["10.0.0.0/24"; "10.0.0.0/8"] ["10.0.1.0/24"; "10.0.4.0/24"];

  [%expect {|
    [10.0.0.0/32] union [10.0.0.1/32] = [10.0.0.0/31]
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
    printf "%s: %s = %s\n" msg (String.concat ~sep:" o " ts)
      (Ip4Set.show (f ts))
  in
  let print_set ~msg t =
    printf "%s: -> %s\n" msg (Ip4Set.show t)
  in
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.12/32"; "10.0.0.11/32"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/32"; "10.0.0.11/32"; "10.0.0.0/24"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/24"; "10.0.0.11/8"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/8"; "10.0.0.11/8"];
  test ~msg:"diff" ~f:Ip4Set.diff ["10.0.0.0/8"; "10.0.0.11/24"];
  test ~msg:"diff" ~f:Ip4Set.diff ["10.0.0.11/24"; "10.0.0.0/8"];
  print_set ~msg:"empty1" @@ (?@"10.0.0.12/32" + ?@"10.0.0.13/32") - ?@"10.0.0.0/8";
  print_set ~msg:"empty2" @@ (?@"10.0.0.0/24" + ?@"10.0.10.0/24") - ?@"10.0.0.0/8";
  print_set ~msg:"empty3" @@ (?@"10.0.0.0/24" + ?@"10.0.1.0/24") - ?@"10.0.0.0/23";
  print_set ~msg:"diff with excl1" @@ (?@"10.0.0.0/24" + ?@"10.0.1.0/24") - (?@"10.0.0.0/23" - ?@"10.0.0.0/25");
  print_set ~msg:"diff with excl2" @@ (?@"10.0.0.0/24" + ?@"10.0.2.0/24") - (?@"10.0.0.0/23" - ?@"10.0.0.0/25");
  print_set ~msg:"diff with excl4" @@ (?@"10.0.0.0/24" - ?@"10.0.0.1/32") - (?@"10.0.0.0/25");
  print_set ~msg:"diff with excl5" @@ (?@"10.0.0.0/24" - ?@"10.0.0.1/32") - (?@"10.0.0.0/25" - ?@"10.0.0.2/32");
  print_set ~msg:"diff with excl6" @@ (?@"10.0.0.0/24" - ?@"10.0.0.1/32") - (?@"10.0.0.0/25" - ?@"10.0.0.0/31");
  print_set ~msg:"diff with excl7" @@ (?@"10.0.0.0/24" - ?@"10.0.0.1/32") - (?@"10.0.0.0/25" - ?@"10.0.0.255/31");
  print_set ~msg:"union" @@ (?@"10.0.0.0/8" - ?@"10.1.0.0/24" - ?@"10.0.0.1/32") + (?@"10.0.0.0/24");
  print_set ~msg:"union" @@ (?@"10.0.0.0/8" - ?@"10.1.0.0/24" - ?@"10.0.0.1/32") + (?@"10.0.0.0/24" - ?@"10.0.0.1/32");
  print_set ~msg:"union" @@ (?@"10.0.0.0/8" - ?@"10.1.0.0/24" - ?@"10.0.0.1/32") + (?@"10.0.0.0/24" - ?@"10.0.0.1/32" - ?@"10.0.0.2/32");
  print_set ~msg:"union" @@ (?@"10.0.0.0/24") + (?@"10.0.0.0/8" - ?@"10.1.0.0/24" - ?@"10.0.0.1/32");
  print_set ~msg:"union" @@ (?@"10.0.0.0/24" - ?@"10.0.0.1/32") + (?@"10.0.0.0/8" - ?@"10.1.0.0/24" - ?@"10.0.0.1/32");
  print_set ~msg:"union" @@ (?@"10.0.0.0/24" - ?@"10.0.0.1/32" - ?@"10.0.0.2/32") + (?@"10.0.0.0/8" - ?@"10.1.0.0/24" - ?@"10.0.0.1/32");
  ();

  [%expect {|
    union: 10.0.0.12/32 o 10.0.0.11/32 = [ 10.0.0.11/32; 10.0.0.12/32 ]
    union: 10.0.0.10/32 o 10.0.0.11/32 o 10.0.0.0/24 = [ 10.0.0.0/24 ]
    union: 10.0.0.10/24 o 10.0.0.11/8 = [ 10.0.0.0/8 ]
    union: 10.0.0.10/8 o 10.0.0.11/8 = [ 10.0.0.0/8 ]
    diff: 10.0.0.0/8 o 10.0.0.11/24 = [  ]
    diff: 10.0.0.11/24 o 10.0.0.0/8 = [  ]
    empty1: -> [  ]
    empty2: -> [  ]
    empty3: -> [  ]
    diff with excl1: -> [ 10.0.0.0/25 ]
    diff with excl2: -> [ 10.0.0.0/25; 10.0.2.0/24 ]
    diff with excl4: -> [ 10.0.0.128/25 ]
    diff with excl5: -> [ 10.0.0.0/24 \ [ 10.0.0.0/25; 10.0.0.128/25 ] ]
    diff with excl6: -> [ 10.0.0.0/24 \ [ 10.0.0.0/25; 10.0.0.128/25 ] ]
    diff with excl7: -> [ 10.0.0.128/25 ]
    union: -> [ 10.0.0.0/8 \ [ 10.1.0.0/24 ] ]
    union: -> [ 10.0.0.0/8 \ [ 10.0.0.1/32; 10.1.0.0/24 ] ]
    union: -> [ 10.0.0.0/8 \ [ 10.0.0.1/32; 10.1.0.0/24 ] ]
    union: -> [ 10.0.0.0/8 \ [ 10.1.0.0/24 ] ]
    union: -> [ 10.0.0.0/8 \ [ 10.0.0.1/32; 10.1.0.0/24 ] ]
    union: -> [ 10.0.0.0/8 \ [ 10.0.0.1/32; 10.1.0.0/24 ] ]
    |}]



let%expect_test "Set operations - ipv6 " =
  let of_string = Ipaddr.V6.Prefix.of_string_exn in
  let test ~msg ~f ts =
    let ts =
      List.map ~f:(fun l ->
        List.fold ~init:Ip6Set.empty ~f:(fun acc e ->
          Ip6Set.union acc (Ip6Set.singleton (of_string e))
        ) l
      ) ts
    in
    let res = List.reduce_exn ~f ts in
    printf "*****************\n%s\n    %s\n =  %s\n" msg
      (List.map ~f:Ip6Set.show ts |> String.concat ~sep:"\n o  ")
      (Ip6Set.show res)
  in



   let all =
     [ "::1/128"; "::/128"; "::ffff:0:0/96"; "64:ff9b::/96"; "64:ff9b:1::/48";
       "100::/64"; "100:0:0:1::/64";
       "2001::/23"; "2001::/32"; "2001:1::1/128"; "2001:1::2/128"; "2001:1::3/128"; "2001:2::/48";
       "2001:3::/32"; "2001:4:112::/48"; "2001:10::/28"; "2001:20::/28"; "2001:30::/28"; "2001:db8::/32";
       "2002::/16"; "2620:4f:8000::/48";
       "3fff::/20"; "5f00::/16"; "fc00::/7"; "fe80::/10" ]
  in

  let all' =
    [ "::/127"; "::ffff:0.0.0.0/96"; "64:ff9b::/96"; "64:ff9b:1::/48"; "100::/63";
      "2001::/23"; "2001:db8::/32";
      "2002::/16"; "2620:4f:8000::/48"; "3fff::/20"; "5f00::/16"; "fc00::/7"; "fe80::/10" ]
   in
   let sources =
     [ "::/128"; "64:ff9b::/96"; "64:ff9b:1::/48"; "100::/63";
       "2001::/32"; "2001:1::1/128"; "2001:1::2/127"; "2001:2::/48"; "2001:3::/32"; "2001:4:112::/48"; "2001:20::/27";
       "2002::/16"; "2620:4f:8000::/48"; "5f00::/16"; "fc00::/7"; "fe80::/10" ]
   in

   test ~msg:"all'" ~f:Ip6Set.diff [all'];
   test ~msg:"all" ~f:Ip6Set.diff [all];
   test ~msg:"sources" ~f:Ip6Set.diff [sources];
   test ~msg:"all \\ sources" ~f:Ip6Set.diff [all; sources];
   test ~msg:"all >< sources" ~f:Ip6Set.intersection [all; sources];
   test ~msg:"all >< sources (verify)" ~f:Ip6Set.intersection [["2001::/23"; "2001:db8::/32"]; ["2001::/32"; "2001:1::1/128"; "2001:1::2/127"; "2001:2::/48"; "2001:3::/32"; "2001:4:112::/48"; "2001:20::/27"]];
   ();
  [%expect {|
    *****************
    all'
        [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
    *****************
    all
        [ ::/128; ::1/128; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/64; 100:0:0:1::/64; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::/128; ::1/128; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/64; 100:0:0:1::/64; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
    *****************
    sources
        [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
    *****************
    all \ sources
        [ ::/128; ::1/128; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/64; 100:0:0:1::/64; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::1/128; ::ffff:0.0.0.0/96; 2001::/23 \ [ 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27 ]; 2001:db8::/32; 3fff::/20 ]
    *****************
    all >< sources
        [ ::/128; ::1/128; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/64; 100:0:0:1::/64; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/64; 100:0:0:1::/64; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
    *****************
    all >< sources (verify)
        [ 2001::/23; 2001:db8::/32 ]
     o  [ 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27 ]
     =  [ 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27 ]
    |}]
