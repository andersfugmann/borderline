open Base
module Set = Set.Poly
open Ir
open Poly
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

type t = Ir.predicate * bool

let to_string (p, n) =
  Printf.sprintf "%s, %b" (Ir.predicate_to_string p) n

let string_of_predicates preds =
  List.map ~f:(to_string) preds
  |> String.concat ~sep:"; "
  |> Printf.sprintf "[ %s ]"


let cost pred =
  let h, l =
    match fst pred with
    | State s -> (10, Set.length s)
    | Zone (_, s) -> (5, Set.length s)
    | Ports (_, _, s) -> (20, Set.length s)
    | Protocol s -> (6, Set.length s)
    | TcpFlags _ -> (15, 0)
    | Ip6Set (_, _) -> (30, 0)
    | Ip4Set (_, _) -> (29, 0)
    | Interface (_, s) -> 12, Set.length s
    | If_group  (_, s) -> 11, Set.length s
    | Icmp6 s -> 25, Set.length s
    | Icmp4 s -> 24, Set.length s
    | Hoplimit s -> 26, Set.length s
    | True -> 0, 0
    | Mark _ -> 1, 0
    | Address_family _ -> 2, 0
  in
  h * 65535 + l

(** List of predicates that always results in true *)
let true_predicates =
  let true_predicates direction =
    [
      (*
         input/output will not have an interface name. I dont know how nft matches it, but should make no difference here. Maybe it will match the empty string (which is an element)

         Interface (direction, Set.empty), true;
         If_group (direction, Set.empty), true;
      *)
      Zone (direction, Set.empty), true;
      Ports (direction, Port_type.Tcp, Set.empty), true;
      Ports (direction, Port_type.Udp, Set.empty), true;
      Ip6Set (direction, Ip6.empty), true;
      Ip4Set (direction, Ip4.empty), true;
    ]
  in

  [
    State Set.empty, true;
    Protocol Set.empty, true;
    Icmp6 Set.empty, true;
    Icmp4 Set.empty, true;
    Mark (0, 0), false;
    TcpFlags (Set.empty, Set.empty), false;
    Hoplimit Set.empty, true;
    Address_family Set.empty, true;
    True, false;
  ] @ true_predicates Direction.Destination @ true_predicates Direction.Source

let false_predicates = List.map ~f:(fun (pred, neg) -> pred, not neg) true_predicates

(** Test if expr always evaluates to value *)
let is_always value =
  let open Poly in
  function
  | State states, neg when State.equal states State.all -> (neg <> value)
  | State states, neg -> State.is_empty states && (neg = value)
  | Zone (_, zs), neg -> Set.is_empty zs && (neg = value)
  | Ports (_, _, ps), neg -> Set.is_empty ps && (neg = value)
  | Protocol s, neg -> Set.is_empty s && (neg = value)
  | TcpFlags (flags, mask), neg when Set.is_empty flags && Set.is_empty mask -> neg <> value
  | TcpFlags (flags, mask), neg when not (Set.is_subset ~of_:mask flags) -> neg = value
  | TcpFlags _, _ -> false
  | Ip6Set (_, s), neg when Ip6.equal s (Ip6.singleton (Ipaddr.V6.Prefix.of_string_exn "::/0")) -> neg <> value
  | Ip6Set (_, s), neg -> Ip6.is_empty s && (neg = value)
  | Ip4Set (_, s), neg when Ip4.equal s (Ip4.singleton (Ipaddr.V4.Prefix.of_string_exn "0.0.0.0/0")) -> neg <> value
  | Ip4Set (_, s), neg -> Ip4.is_empty s && (neg = value)
  | Interface (_, ifs), neg -> Set.is_empty ifs && (neg = value)
  | If_group  (_, ifs), neg -> Set.is_empty ifs && (neg = value)
  | Icmp6 is, neg -> Set.is_empty is && (neg = value)
  | Icmp4 is, neg -> Set.is_empty is && (neg = value)
  | Hoplimit cnts, neg -> Set.is_empty cnts && (neg = value)
  | True, neg -> neg <> value
  | Mark (value_, mask), neg when value_ = 0 && mask = 0 -> neg <> value
  | Mark (_, mask), neg when mask = 0 -> neg = value
  | Mark _, _ -> false
  | Address_family a, neg ->
    (* Make sure to generate a compiler warning if address_family is extended *)
    match Set.to_list a with
    | [] -> neg = value
    | [(Ipv4|Ipv6)] -> false
    | _ :: _ :: _ -> neg <> value


let merge_pred ?(tpe=`Inter) a b =
  (* !A => !B => X   =>  !(A | B) => X

     A => B => X     => A U B => X

     A => !B => X    => (A / B) => X
     !A => B => X    => (B / A) => X

  *)
  let merge_inter inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (inter a b, false)
    | (a, true),  (b, true)  -> (union a b, true)
    | (a, false), (b, true)  -> (diff  a b, false)
    | (a, true),  (b, false) -> (diff  b a, false)
  in

  let merge_union inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (union a b, false)
    | (a, true),  (b, true)  -> (inter a b, true)
    | (a, false), (b, true)  -> (diff  b a, true)
    | (a, true),  (b, false) -> (diff  a b, true)
  in
  (* What a matches but not what b matches *)
  let merge_diff inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (diff  a b, false) (* OK *)
    | (a, true),  (b, true)  -> (diff  b a, false) (* OK *)
    | (a, false), (b, true)  -> (inter a b, false) (* OK *)
    | (a, true),  (b, false) -> (union a b, true)  (* OK *)
  in

  let merge = match tpe with
    | `Inter -> merge_inter
    | `Union -> merge_union
    | `Diff -> merge_diff
  in
  let merge_states = merge State.intersect State.union State.diff in
  let merge_ip6sets = merge Ip6.intersect Ip6.union Ip6.diff in
  let merge_ip4sets = merge Ip4.intersect Ip4.union Ip4.diff in
  let merge_sets a b = merge Set.inter Set.union Set.diff a b in

  let all_address_families = Set.of_list [Ipv4; Ipv6] in

  let invert = function
    | State s, true -> (State (Set.diff State.all s), false)
    | State s, false -> (State s, false)
    | Address_family s, true ->
      Address_family (Set.diff all_address_families s), false
    | v -> v
  in
  let a = invert a in
  let b = invert b in

  match a, b with
  | (State s, neg), (State s', neg') ->
    let (s'', neg'') = merge_states (s, neg) (s', neg') in
    (State s'', neg'') |> Option.some
  | (State _, _), _ -> None
  | (Ports (dir, pt, ports), neg), (Ports (dir', pt', ports'), neg') when dir = dir' && pt = pt' ->
    let (ports'', neg'') = merge_sets (ports, neg) (ports', neg') in
    (Ports (dir, pt, ports''), neg'') |> Option.some
  | (Ports _, _), _ -> None
  | (Protocol p, neg), (Protocol p', neg') ->
    let (p'', neg'') = merge_sets (p, neg) (p', neg') in
    (Protocol (p''), neg'') |> Option.some
  | (Protocol _, _), _ -> None
  | (Icmp6 types, neg), (Icmp6 types', neg') ->
    let (types'', neg'') = merge_sets (types, neg) (types', neg') in
    (Icmp6 types'', neg'') |> Option.some
  | (Icmp6 _, _), _ -> None
  | (Icmp4 types, neg), (Icmp4 types', neg') ->
    let (types'', neg'') = merge_sets (types, neg) (types', neg') in
    (Icmp4 types'', neg'') |> Option.some
  | (Icmp4 _, _), _ -> None
  | (Ip6Set (dir, set), neg), (Ip6Set (dir', set'), neg') when dir = dir' ->
    let (set'', neg'') = merge_ip6sets (set, neg) (set', neg') in
    (Ip6Set (dir, set''), neg'') |> Option.some
  | (Ip6Set _, _), _ -> None
  | (Ip4Set (dir, set), neg), (Ip4Set (dir', set'), neg') when dir = dir' ->
    let (set'', neg'') = merge_ip4sets (set, neg) (set', neg') in
    Some (Ip4Set (dir, set''), neg'')
  | (Ip4Set _, _), _ -> None
  | (Zone (dir, zones), neg), (Zone (dir', zones'), neg') when dir = dir' ->
    let (zones'', neg'') = merge_sets (zones, neg) (zones', neg') in
    Some (Zone (dir, zones''), neg'')
  | (Zone _, _), _ -> None
  (* Wonder if I could do better here. Well. Could reverse the flags at least *)
  | (TcpFlags (f, m), false), (TcpFlags (f', m'), false) ->
    begin
      let set_flags = Set.union f f' in
      let unset_flags = Set.union (Set.diff m f) (Set.diff m' f') in
      match Set.inter set_flags unset_flags |> Set.is_empty with
      | true ->
        Some (TcpFlags (set_flags, Set.union m m'), false)
      | false -> Some (True, true)
    end
  | (TcpFlags _, _), _ -> None (* These can be merged - potentially *)
  | (True, neg), (True, neg') -> Some (True, neg || neg')
  | (True, _), _  -> None
  | (If_group (dir, ifs), neg), (If_group (dir', ifs'), neg') when dir = dir' ->
    let (ifs'', neg'') = merge_sets (ifs, neg) (ifs', neg') in
    (If_group (dir, ifs''), neg'') |> Option.some
  | (If_group _, _), _  -> None
  | (Interface (dir, is), neg), (Interface (dir', is'), neg') when dir = dir' ->
    let (is'', neg'') = merge_sets (is, neg) (is', neg') in
    (Interface (dir, is''), neg'') |> Option.some
  | (Interface _, _), _ -> None
  | (Mark _, _), _ -> None
  | (Hoplimit limits, neg), (Hoplimit limits', neg') ->
    let (limits, neg) = merge_sets (limits, neg) (limits', neg') in
    (Hoplimit limits, neg) |> Option.some
  | (Hoplimit _, _), _ -> None
  | (Address_family af, neg), (Address_family af', neg') ->
    let (af'', neg'') = merge_sets (af, neg) (af', neg') in
    (Address_family af'', neg'') |> Option.some
  | (Address_family _, _), _ -> None

let cardinal_of_pred = function
  | Interface (_, is), _ -> Set.length is
  | If_group (_, set), _ -> Set.length set
  | State s, _ -> Set.length s
  | Ports (_, _, ports), _ -> Set.length ports
  | Protocol p, _ -> Set.length p
  | Icmp6 types, _ -> Set.length types
  | Icmp4 types, _ -> Set.length types
  | Ip6Set (_, set), _ -> Ip6.IpSet.length set
  | Ip4Set (_, set), _ -> Ip4.IpSet.length set
  | Zone (_, zones), _ -> Set.length zones
  | TcpFlags (f, _), _ -> Set.length f
  | True, _ -> 1
  | Mark (_, _), _ -> 1
  | Hoplimit limits, _ -> Set.length limits
  | Address_family af, _ -> Set.length af


(** Return a derived predicate from the given predicate.
 * ipv6 => !icmp4
 * icmp4 => ipv4
 * !icmp4 => Ø
*)
let get_implied_predicate pred =
  let icmp = 1 in
  let igmp  = 2 in
  let tcp = 6 in
  let udp = 17 in
  let icmp6 = 58 in

  let ipv4_protocols = [icmp; igmp] |> Set.of_list in
  let ipv6_protocols = [icmp6] |> Set.of_list in

  let make_address_family tpe neg = (Address_family (Set.singleton tpe), neg) |> Option.some in
  let make_protocol lst neg = (Ir.Protocol (Set.of_list lst), neg) |> Option.some in

  match pred with
  | Ir.Protocol s, false when Set.is_subset ~of_:ipv4_protocols s && not (Set.is_empty s) ->
    make_address_family Ipv4 false
  | Ir.Protocol s, false when Set.is_subset ~of_:ipv6_protocols s && not (Set.is_empty s) ->
    make_address_family Ipv6 false
  | Ir.Protocol _, _ -> None

  | Ir.True, _
  | Ir.Interface _, _
  | Ir.If_group _, _
  | Ir.Zone _, _
  | Ir.State _, _
  | Ir.Mark _, _ -> None

  | Ir.Ports (_, Tcp, _), _ -> make_protocol [tcp] false
  | Ir.Ports (_, Udp, _), _ -> make_protocol [udp] false
  | Ir.TcpFlags _, _ -> make_protocol [tcp] false

  | Ir.Hoplimit _, _ -> make_address_family Ipv6 false
  | Ir.Icmp6 _, _ -> make_protocol [icmp6] false
  | Ir.Ip6Set _, _ -> make_address_family Ipv6 false

  (* Ipv4 *)
  | Ir.Icmp4 _, _ -> make_protocol [icmp] false
  | Ir.Ip4Set _, _ -> make_address_family Ipv4 false

  (* Flip also *)
  | Ir.Address_family af, neg when Set.length af = 1 && false -> begin
      match Set.choose_exn af, neg with
      | Ir.Ipv4, false
      | Ir.Ipv6, true -> (Protocol ipv6_protocols, true) |> Option.some
      | Ir.Ipv4, true
      | Ir.Ipv6, false -> (Protocol ipv4_protocols, true) |> Option.some
    end
  | Ir.Address_family _, _ -> None


(** Only return implied predicates *)
let rec get_implied_predicates = function
  | [] -> []
  | p :: ps ->
    match get_implied_predicate p with
    | None -> get_implied_predicates ps
    | Some p -> p :: get_implied_predicates (p :: ps)

(* O(N^2) - I know. But N < 30 (constant) so its ok *)
(* Bug: Merge preds ~tpe:`Union have very different semantics *)
(* Create different functions for each type *)
let inter_preds preds =
  let rec inner acc pred = function
    | [] -> pred, acc
    | p :: ps ->
      match merge_pred ~tpe:`Inter pred p with
      | None -> inner (p :: acc) pred ps
      | Some pred -> inner acc pred ps
  in
  let rec merge =
    function
    | [] -> []
    | p :: ps ->
      let pred, rest = inner [] p ps in
      pred :: merge rest
  in
  get_implied_predicates preds
  |> List.rev_append preds
  |> merge

let union_preds preds_list =
  let preds_list =
    List.map ~f:inter_preds preds_list
  in
  match preds_list with
  | [] -> []
  | preds :: [] -> preds
  | preds :: rest ->
    List.filter_map ~f:(fun pred ->
      List.fold_until ~finish:Option.some ~init:pred ~f:(fun pred preds ->
        match List.find_map ~f:(merge_pred ~tpe:`Union pred) preds with
        | None -> Continue_or_stop.Stop None
        | Some pred -> Continue_or_stop.Continue pred
      ) rest
    ) preds

let is_subset b ~of_:a =
  merge_pred ~tpe:`Union a b |> Option.value_map ~f:(eq_pred a) ~default:false

let is_satisfiable preds =
  inter_preds preds
  |> List.exists ~f:(is_always false)
  |> not

let disjoint preds preds' =
  inter_preds (preds @ preds')
  |> List.exists ~f:(is_always false)

let%test "Disjoint Address_family" =
  let ipv4 = Address_family (Set.singleton Ipv4) in
  let ipv6 = Address_family (Set.singleton Ipv6) in
  disjoint [ipv4, false] [ipv6, false]


let preds_all_true preds =
  inter_preds preds
  |> List.for_all ~f:(is_always true)

let equal_predicate a b =
  let res = is_subset a ~of_:b && is_subset b ~of_:a in
  match res, eq_pred a b with
  | true, _ -> true
  | false, true -> failwith "Equal check"
  | false, false -> false

module Test = struct
  open OUnit2
  let eq_pred_opt = function
    | Some m -> begin
        function Some n -> Ir.eq_pred m n
               | None -> false
      end
    | None -> begin
        function None -> true
               | Some _ -> false
      end

  let unittest = "Optimize" >::: [
      "merge_diff" >:: begin fun _ ->
        let expect = Ir.Zone (Ir.Direction.Source, ["int"] |> Set.of_list), false in
        let a = Ir.Zone (Ir.Direction.Source, ["int"; "ext"] |> Set.of_list), false in
        let b = Ir.Zone (Ir.Direction.Source, ["ext"; "other"] |> Set.of_list), false in
        let res = merge_pred ~tpe:`Diff a b
        in
        assert_equal ~cmp:eq_pred_opt ~msg:"Wrong result" res (Some expect);
      end;

      "merge_inter" >:: begin fun _ ->
        let expect = Ir.Zone (Ir.Direction.Source, ["ext"] |> Set.of_list), false in
        let a = Ir.Zone (Ir.Direction.Source, ["int"; "ext"] |> Set.of_list), false in
        let b = Ir.Zone (Ir.Direction.Source, ["ext"; "other"] |> Set.of_list), false in
        let res = merge_pred ~tpe:`Inter a b
        in
        assert_equal ~cmp:eq_pred_opt ~msg:"Wrong result" res (Some expect);
      end;

      "subset|equal" >:: begin fun _ ->
        let a = (Ir.State State.([New] |> of_list), false) in
        let b = (Ir.State State.([New; Established] |> of_list), false) in
        let c = (Ir.State State.([Established] |> of_list), false) in

        assert_bool "'a' is equal to 'a'" (equal_predicate a a);
        assert_bool "'a' is not equal to 'b'" (equal_predicate a b |> not);
        assert_bool "'a' is not equal to 'c'" (equal_predicate a c |> not);

        assert_bool "'a' is a subset of 'b'" (is_subset ~of_:b a);
        assert_bool "'b' is not a subset of 'a'" (not (is_subset ~of_:a b));
        assert_bool "'a' is not a subset of 'c'" (not (is_subset ~of_:c a));
        assert_bool "'c' is not a subset of 'a'" (not (is_subset ~of_:a c));
        assert_bool "'c' is a subset of 'b'" (is_subset ~of_:b c);
        assert_bool "'b' is a subset of 'b'" (is_subset ~of_:b b);

        ()
      end;

      "address family" >:: begin fun _ ->
        let make lst neg = Ir.Address_family (Set.of_list lst), neg in
        let ipv4 = make [Ir.Ipv4] false in
        let ipv6 = make [Ir.Ipv6] false in
        let ipv4' = make [Ir.Ipv6] true in
        let ipv6' = make [Ir.Ipv4] true in
        let none = make [] false in
        let none' = make [Ir.Ipv4; Ir.Ipv6] true in
        let all = make [] true in
        let all' = make [Ir.Ipv4; Ir.Ipv6] false in

        let _ = ipv4, ipv4', ipv6, ipv6', all, all', none, none' in

        let res = merge_pred ipv4 ipv4 |> Option.value_exn in
        assert_bool "ipv4 * ipv4" (eq_pred res ipv4);

        let res = merge_pred ipv6 ipv6 |> Option.value_exn in
        assert_bool "ipv6 * ipv6" (eq_pred res ipv6);

        let res = merge_pred ipv4 ipv6 |> Option.value_exn in
        assert_bool "ipv4 * ipv6" (is_always false res);

        let res = merge_pred ipv6 ipv4 |> Option.value_exn in
        assert_bool "ipv6 * ipv4" (is_always false res);

        assert_bool "all" (is_always true all);
        assert_bool "all'" (is_always true all');
        assert_bool "none" (is_always false none);
        assert_bool "none'" (is_always false none');

        let res = merge_pred ipv4 all |> Option.value_exn in
        assert_bool "ipv4 * all" (eq_pred res ipv4);
        let res = merge_pred ipv4 all' |> Option.value_exn in
        assert_bool "ipv4 * all'" (eq_pred res ipv4);

        let res = merge_pred ipv4 none |> Option.value_exn in
        assert_bool "ipv4 * none" (is_always false res);
        let res = merge_pred ipv4 none' |> Option.value_exn in
        assert_bool "ipv4 * none'" (is_always false res);

        let res = merge_pred ipv6 all |> Option.value_exn in
        assert_bool "ipv6 * all" (eq_pred res ipv6);
        let res = merge_pred ipv6 all' |> Option.value_exn in
        assert_bool "ipv6 * all'" (eq_pred res ipv6);
        let res = merge_pred ipv6 none |> Option.value_exn in
        assert_bool "ipv6 * none" (is_always false res);
        let res = merge_pred ipv6 none' |> Option.value_exn in
        assert_bool "ipv6 * none'" (is_always false res);

        let res = merge_pred ~tpe:`Diff all ipv4 |> Option.value_exn in
        assert_bool "all / ipv4" (eq_pred res ipv6');
        let res = merge_pred ~tpe:`Diff all ipv4' |> Option.value_exn in
        assert_bool "all / ipv4'" (eq_pred res ipv6);

        let res = merge_pred ~tpe:`Diff all ipv6 |> Option.value_exn in
        assert_bool "all / ipv6" (eq_pred res ipv4');
        let res = merge_pred ~tpe:`Diff all ipv6' |> Option.value_exn in
        assert_bool "all / ipv6'" (eq_pred res ipv4);

        let res = merge_pred ~tpe:`Union ipv4 ipv4 |> Option.value_exn in
        assert_bool "ipv4 + ipv4" (eq_pred res ipv4);
        let res = merge_pred ~tpe:`Union ipv4 ipv4' |> Option.value_exn in
        assert_bool "ipv4 + ipv4'" (eq_pred res ipv4');
        let res = merge_pred ~tpe:`Union ipv4' ipv4 |> Option.value_exn in
        assert_bool "ipv4' + ipv4" (eq_pred res ipv4');
        let res = merge_pred ~tpe:`Union ipv4 all |> Option.value_exn in
        assert_bool "ipv4 + all" (eq_pred res all);
        let res = merge_pred ~tpe:`Union ipv4' all |> Option.value_exn in
        assert_bool "ipv4' + all" (eq_pred res all);
        let res = merge_pred ~tpe:`Union ipv4' all' |> Option.value_exn in
        assert_bool "ipv4' + all'" (eq_pred res all);
        let res = merge_pred ~tpe:`Union ipv4 none |> Option.value_exn in
        assert_bool "ipv4 + none" (eq_pred res ipv4);
        let res = merge_pred ~tpe:`Union ipv4 none' |> Option.value_exn in
        assert_bool "ipv4 + none'" (eq_pred res ipv4');
        let res = merge_pred ~tpe:`Union ipv4' none |> Option.value_exn in
        assert_bool "ipv4' + none" (eq_pred res ipv4');
        let res = merge_pred ~tpe:`Union ipv4' none' |> Option.value_exn in
        assert_bool "ipv4' + none'" (eq_pred res ipv4');

      end;

      "is_true" >:: begin fun _ ->
        List.iteri ~f:(fun i pred ->
          let msg =
            Printf.sprintf "Predicate %s (index %d) should always be true" (to_string pred) i
          in
          assert_bool msg (is_always true pred)
        ) true_predicates
      end;

      "is_false" >:: begin fun _ ->
        List.iteri ~f:(fun i pred ->
          let msg =
            Printf.sprintf "Predicate %s (index %d) should always be false" (to_string pred) i
          in
          assert_bool msg (is_always false pred)
        ) false_predicates
      end;

    ]
end
