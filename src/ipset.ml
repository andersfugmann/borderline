(** Ip Sets *)
open Base
let sprintf = Printf.sprintf
let printf = Stdio.printf
let eprintf = Stdio.printf

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
  val mask: int -> addr
end

let enable_reduce = true

(* For larger sets, we should see if we can reduce by excluding some ranges *)
(* Try increasing the bits by two and partition all networks. O(n^2) algorithm, and its not complete *)

module Make(Ip : Prefix) = struct
  module IpSet = struct
    (* This can be done smarter! *)
    let subset ~of_:networks subnets =
      List.for_all ~f:(fun subnet ->
        List.exists ~f:(fun network -> Ip.subset ~subnet ~network) networks
      ) subnets

    let split ip =
      let bits = Ip.bits ip + 1 in
      Ip.subnets bits ip
      |> Stdlib.List.of_seq

    let rec reduce = function
      | ns when not enable_reduce -> ns
      | n1 :: n2 :: ns when Ip.subset ~network:n1 ~subnet:n2 ->
        reduce (n1 :: ns)
      | n1 :: n2 :: ns when Ip.subset ~network:n2 ~subnet:n1 ->
        reduce (n2 :: ns)
      | n1 :: n2 :: ns when Ip.bits n1 = Ip.bits n2 && Ip.bits n1 > 0 ->
        begin
          let network = Ip.make (Ip.bits n1 - 1) (Ip.prefix n1 |> Ip.address) in
          match Ip.subset ~subnet:n2 ~network with
          | true ->
            reduce (network :: ns)
          | false -> n1 :: reduce (n2 :: ns)
        end
      | n :: ns -> n :: reduce ns
      | [] -> []
    let reduce l =
      let rec inner l =
        let l' = reduce l in
        match List.length l' = List.length l with
        | true -> l
        | false -> inner l'
      in
      inner l

    (* Intersection between to lists of ips (sorted) *)
    let rec intersection l1 l2 =
      match l1, l2 with
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l' ~network:l ->
        l' :: intersection (l :: ls) ls'
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l ~network:l' ->
        l :: intersection ls (l' :: ls')
      | l :: ls, l' :: ls' when Ip.compare l l' < 0 ->
        intersection ls (l' :: ls')
      | l :: ls, _ :: ls' (* when Ip.compare l l' > 0 *) ->
        intersection (l :: ls) ls'
      | [], _
      | _, [] -> []
    let intersection l1 l2 = intersection l1 l2 |> reduce

    (* Union between to lists of ips (sorted) *)
    let rec union l1 l2 =
      match l1, l2 with
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l' ~network:l ->
        union (l :: ls) ls'
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l ~network:l' ->
        union ls (l' :: ls')
      | l :: ls, l' :: ls' when Ip.compare l l' < 0 ->
        l :: union ls (l' :: ls')
      | l :: ls, l' :: ls' (* when Ip.compare l l' > 0 *) ->
        l' :: union (l :: ls) ls'
      | [], ls
      | ls, [] -> ls
    let union l1 l2 = union l1 l2 |> reduce

    let rec diff l1 l2 =
      match l1, l2 with
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l ~network:l' ->
        diff ls (l' :: ls')
      | l :: ls, l' :: ls' when Ip.subset ~subnet:l' ~network:l ->
        diff ((split l) @ ls) (l' :: ls')
      | l :: ls, l' :: ls' when Ip.compare l l' < 0 ->
        diff ls (l' :: ls')
      | ls, _ :: ls' (* when Ip.compare l l' > 0 *) ->
        diff ls ls'
      | ts, [] -> ts
    let diff l1 l2 = diff l1 l2 |> reduce
  end

  type ip = Ip.t
  type elt = ip * ip list
  type t = elt list

  let any = [ Ip.(make 0 (mask 0)), [] ]
  let empty = [ ]
  let singleton ip = [ (Ip.prefix ip, []) ]
  let is_empty = List.is_empty

  let is_any addr = Ip.bits addr = 0
  let ip_to_string = Ip.to_string

  let split_elt (incl, excls) =
    IpSet.split incl
    |> List.map ~f:(fun network -> network, List.filter ~f:(fun subnet -> Ip.subset ~network ~subnet) excls)

  let rec reduce l =
    let rec merge = function
      | (incl, excls) :: (incl', excls') :: ts when Ip.bits incl = Ip.bits incl' && Ip.bits incl > 0 ->
        begin
          let network = Ip.make (Ip.bits incl - 1) (Ip.prefix incl |> Ip.address) in
          match Ip.subset ~subnet:incl' ~network with
          | true ->
            merge ((network, IpSet.union excls excls') :: ts)
          | false ->
            (incl, excls) :: merge ((incl', excls') :: ts)
        end
      | t :: ts -> t :: merge ts
      | [] -> []
    in

    let rec inner = function
      | (incl, excls) :: ts when List.exists ~f:(fun excl -> Ip.subset ~network:excl ~subnet:incl) excls ->
        inner ts
      | (incl, excls) :: ts when List.exists ~f:(fun excl -> Ip.bits excl - 1 = Ip.bits incl) excls ->
        let ts' = List.map (IpSet.split incl) ~f:(fun incl -> (incl, IpSet.intersection [incl] excls)) in
        inner (ts' @ ts)
      | t :: ts -> t :: inner ts
      | [] -> []
    in
    let l = inner l in
    let l' = merge l in
    match List.length l' = List.length l with
    | true -> l'
    | false -> reduce l'

  let rec union t t' =
    match t, t' with
    | ts, [] | [], ts -> ts
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl ->
      let excls = IpSet.union (IpSet.intersection excls excls') (IpSet.diff excls [incl']) in
      union ((incl, excls) :: ts) ts'
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      let excls' = IpSet.union (IpSet.intersection excls excls') (IpSet.diff excls' [incl]) in
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
      (incl', IpSet.intersection [incl'] (IpSet.union excls excls')) :: intersection ((incl, excls) :: ts) ts'
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      (incl, IpSet.intersection [incl] (IpSet.union excls excls')) :: intersection ts ((incl', excls') :: ts')
    | (incl, _) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      intersection ts ((incl', excls') :: ts')
    | ts, _ :: ts' (* when Ip.compare incl incl' > 0 *) ->
      intersection ts ts'

  let rec diff t t' =
    match t, t' with
    | [], _ -> []
    | ts, [] -> ts
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl ~network:incl' ->
      (* Complete range excluded. Its what-ever is not excluded within incl, and keep excls *)
      let incls =
        IpSet.intersection [incl] excls'
        |> List.map ~f:(fun incl -> (incl, IpSet.intersection [incl] excls))
      in
      incls @ diff ts ((incl', excls') :: ts')
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.subset ~subnet:incl' ~network:incl -> begin
        (* Parts of incl is excluded.
           If we should not exclude what is already excluded, then we can ignore excls, and just add incl' to the list of exclusions
           Reduce will break it up into smaller bits if needed
        *)
        match IpSet.subset ~of_:excls excls' with
        | true ->
          let excls = IpSet.union excls [incl'] in
          diff ((incl, excls) :: ts) ts'
        | false -> (* Split into two smaller elements and repeat *)
          diff (split_elt (incl, excls) @ ts) ((incl', excls') :: ts')
      end
    | (incl, excls) :: ts, (incl', excls') :: ts' when Ip.compare incl incl' < 0 ->
      (incl, excls) :: diff ts ((incl', excls') :: ts')
    | ts, _ :: ts' (* when Ip.compare incl incl' > 0 *) ->
      diff ts ts'
  let diff t t' = diff t t' |> reduce

  let equal t t' =
    diff t t' |> is_empty && diff t' t |> is_empty

  let of_list l =
    List.concat_map ~f:singleton l
    |> List.sort ~compare:(fun (a, _) (b, _) -> Ip.compare a b)
    |> reduce

  let to_networks l =
    let incls, excls = List.unzip l in
    let excls = List.concat excls in
    incls, excls

  let cardinal l =
    List.fold ~init:0 ~f:(fun acc (_, excl) -> acc + 1 + List.length excl) l

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


module type IpSet = sig
  type ip
  type t
  val empty : t
  val singleton : ip -> t
  val is_empty : t -> bool
  val union : t -> t -> t
  val intersection : t -> t -> t
  val diff : t -> t -> t
  val equal : t -> t -> bool
  val of_list : ip list -> t
  val to_networks : t -> ip list * ip list
  val show : t -> string
  val cardinal : t -> int
  val any : t
  val is_any : ip -> bool
  val ip_to_string : ip -> string
end

module Ip4Set : (IpSet with type ip = Ipaddr.V4.Prefix.t) = Make(Ipaddr.V4.Prefix)
module Ip6Set : (IpSet with type ip = Ipaddr.V6.Prefix.t) = Make(Ipaddr.V6.Prefix)


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
  let module Ip4Set = Make(Ipaddr.V4.Prefix) in
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
  test ~msg:"union" ~f:Ip4Set.IpSet.union ["10.0.0.0/32"] ["10.0.0.1/32"];
  test ~msg:"union" ~f:Ip4Set.IpSet.union ["10.0.0.1/32"] ["10.0.0.2/32"];
  test ~msg:"union" ~f:Ip4Set.IpSet.union ["10.0.0.9/32"] ["10.0.0.10/32"; "10.0.0.11/32"];
  test ~msg:"union" ~f:Ip4Set.IpSet.union ["10.0.0.9/32";"10.0.0.10/32"; "10.0.0.11/32"] ["10.0.0.0/16"];
  test ~msg:"intersection" ~f:Ip4Set.IpSet.intersection ["10.0.0.11/32"] ["10.0.0.11/32"; "10.0.0.12/32"];
  test ~msg:"intersection" ~f:Ip4Set.IpSet.intersection ["10.0.0.0/24"; "10.0.0.0/8"] ["10.0.1.0/24"; "10.0.4.0/24"];

  [%expect {|
    [10.0.0.0/32] union [10.0.0.1/32] = [10.0.0.0/31]
    [10.0.0.1/32] union [10.0.0.2/32] = [10.0.0.1/32; 10.0.0.2/32]
    [10.0.0.9/32] union [10.0.0.10/32; 10.0.0.11/32] = [10.0.0.9/32; 10.0.0.10/31]
    [10.0.0.9/32; 10.0.0.10/32; 10.0.0.11/32] union [10.0.0.0/16] = [10.0.0.0/16]
    [10.0.0.11/32] intersection [10.0.0.11/32; 10.0.0.12/32] = [10.0.0.11/32]
    [10.0.0.0/24; 10.0.0.0/8] intersection [10.0.1.0/24; 10.0.4.0/24] = [10.0.1.0/24; 10.0.4.0/24]
    |}]

let%expect_test "Set operations" =
  let of_string = Ipaddr.V4.Prefix.of_string_exn in
  let singleton  s = Ip4Set.singleton (of_string s) in
  let _union t elt = Ip4Set.union t (singleton elt) in
  let ( ?@ ) a = singleton a in
  let ( ! ) a =  Ipaddr.V4.Prefix.of_string_exn a in
  let ( + ) a b = Ip4Set.union a b in
  let ( - ) a b = Ip4Set.diff a b in
  let test ~msg ~f ts =
    let ts' = List.map ~f:singleton ts in
    let f ts = List.reduce ~f ts |> Option.value ~default:Ip4Set.empty in
    printf "%s: %s = %s\n" msg (String.concat ~sep:" o " ts)
      (Ip4Set.show (f ts'))
  in
  let print_set ~msg t =
    printf "%s: -> %s\n" msg (Ip4Set.show t)
  in
  test ~msg:"diff" ~f:Ip4Set.diff ["0.0.0.0/0"; "0.0.0.0/0"];
  test ~msg:"diff" ~f:Ip4Set.diff ["10.0.0.0/8"; "10.0.0.11/24"];
  test ~msg:"diff" ~f:Ip4Set.diff ["10.0.0.11/24"; "10.0.0.0/8"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.12/32"; "10.0.0.11/32"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/32"; "10.0.0.11/32"; "10.0.0.0/24"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/24"; "10.0.0.11/8"];
  test ~msg:"union" ~f:Ip4Set.union ["10.0.0.10/8"; "10.0.0.11/8"];
  print_set ~msg:"of_list" (Ip4Set.of_list [ !"10.0.0.0/32"; !"10.0.0.1/32"; !"10.0.0.2/32"]);
  print_set ~msg:"of_list" (Ip4Set.of_list [ !"10.0.0.0/32"; !"10.0.0.2/32"; !"10.0.0.1/32"]);
  print_set ~msg:"of_list" (Ip4Set.of_list [ !"10.0.0.0/32"; !"10.0.0.1/32"; !"10.0.0.2/32"; !"10.0.0.3/32"]);
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
    diff: 0.0.0.0/0 o 0.0.0.0/0 = [  ]
    diff: 10.0.0.0/8 o 10.0.0.11/24 = [ 10.0.0.0/8 \ [ 10.0.0.0/24 ] ]
    diff: 10.0.0.11/24 o 10.0.0.0/8 = [  ]
    union: 10.0.0.12/32 o 10.0.0.11/32 = [ 10.0.0.11/32; 10.0.0.12/32 ]
    union: 10.0.0.10/32 o 10.0.0.11/32 o 10.0.0.0/24 = [ 10.0.0.0/24 ]
    union: 10.0.0.10/24 o 10.0.0.11/8 = [ 10.0.0.0/8 ]
    union: 10.0.0.10/8 o 10.0.0.11/8 = [ 10.0.0.0/8 ]
    of_list: -> [ 10.0.0.0/31; 10.0.0.2/32 ]
    of_list: -> [ 10.0.0.0/31; 10.0.0.2/32 ]
    of_list: -> [ 10.0.0.0/30 ]
    empty1: -> [  ]
    empty2: -> [  ]
    empty3: -> [  ]
    diff with excl1: -> [ 10.0.0.0/25 ]
    diff with excl2: -> [ 10.0.0.0/25; 10.0.2.0/24 ]
    diff with excl4: -> [ 10.0.0.128/25 ]
    diff with excl5: -> [ 10.0.0.2/32; 10.0.0.128/25 ]
    diff with excl6: -> [ 10.0.0.0/32; 10.0.0.128/25 ]
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
   test ~msg:"all' \\ all" ~f:Ip6Set.diff [all'; all];
   test ~msg:"all \\ all'" ~f:Ip6Set.diff [all; all'];
   test ~msg:"sources \\ all" ~f:Ip6Set.diff [sources; all];
   test ~msg:"all \\ sources" ~f:Ip6Set.diff [all; sources];
   test ~msg:"all ∩ sources" ~f:Ip6Set.intersection [all; sources];
   ();
  [%expect {|
    *****************
    all' \ all
        [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [  ]
    *****************
    all \ all'
        [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [  ]
    *****************
    sources \ all
        [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [  ]
    *****************
    all \ sources
        [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::1/128; ::ffff:0.0.0.0/96; 2001::/23 \ [ 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27 ]; 2001:db8::/32; 3fff::/20 ]
    *****************
    all ∩ sources
        [ ::/127; ::ffff:0.0.0.0/96; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/23; 2001:db8::/32; 2002::/16; 2620:4f:8000::/48; 3fff::/20; 5f00::/16; fc00::/7; fe80::/10 ]
     o  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
     =  [ ::/128; 64:ff9b::/96; 64:ff9b:1::/48; 100::/63; 2001::/32; 2001:1::1/128; 2001:1::2/127; 2001:2::/48; 2001:3::/32; 2001:4:112::/48; 2001:20::/27; 2002::/16; 2620:4f:8000::/48; 5f00::/16; fc00::/7; fe80::/10 ]
    |}]
