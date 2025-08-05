open Base
module Set = Set.Poly
open Stdio
open Ir
open Poly
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

type string = id [@@ocaml.warning "-34"]

(** Bugs:
    Reducing indegree does not work as intended
    - It ought not to introduce bugs though. But we need to verify that though
*)


(* Percentage for predicates are pushed down to called chains *)
let min_push = 80

(* Make sure that no chains have an indegree more than N,
   so that 'for all chains | chain_reference_count <= N' holds
*)
let max_chain_indegree = 1

(** Define the saving in predicates when inlining. *)
let max_inline_cost = 0

(** Minimum length of sequence to of predicates to merge into a new chain *)
let min_merge = 2

(* List of predicates that always results in true *)
let true_predicates =
  let true_predicates direction =
    [
      Interface (direction, Set.empty), true;
      If_group (direction, Set.empty), true;
      Zone (direction, Set.empty), true;
      Ports (direction, Port_type.Tcp, Set.empty), true;
      Ports (direction, Port_type.Udp, Set.empty), true;
      Ip6Set (direction, Ip6.empty), true;
      Ip4Set (direction, Ip4.empty), true;
    ]
  in

  [
    (* State of State.t - Singular state? Not a set of states? Impossible to create a catch all *)
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

let string_of_predicate (p, n) =
  Printf.sprintf "(%s,%b)" (string_of_predicate p) n

let is_satisfiable preds =
  not (List.exists ~f:(is_always false) preds)

let is_subset_eq a b =
  List.for_all ~f:(fun a -> List.exists b ~f:((=) a)) a

let is_eq a b =
  is_subset_eq a b && is_subset_eq b a

let chain_reference_count id chains =
  let count_references acc rules =
    List.fold_left ~init:acc ~f:(fun acc -> function (_, _, Jump id') when Chain_id.equal id id' -> acc + 1 | _ -> acc)  rules
  in
  Map.fold ~init:0 ~f:(fun ~key:_ ~data:chn acc -> (count_references acc chn.rules)) chains

let get_referring_rules chain chains =
  let test (_preds, _effects, target) = target = Jump (chain.id) in
  let referring_chains = Chain.filter (fun chn -> List.exists ~f:test chn.rules) chains in
  List.fold_left ~f:(fun acc chn -> (List.filter ~f:test chn.rules) @ acc) ~init:[] referring_chains

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules ~f chains =
  Map.map ~f:(fun chn -> { chn with rules = f chn.rules }) chains

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

  match a, b with
  | (Interface (dir, is), neg), (Interface (dir', is'), neg') when dir = dir' ->
    let (is'', neg'') = merge_sets (is, neg) (is', neg') in
    (Interface (dir, is''), neg'') |> Option.some
  | (Interface _, _), _ -> None
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
  | (TcpFlags _, _), _ -> None
  | (True, neg), (True, neg') -> Some (True, neg || neg')
  | (True, _), _  -> None
  | (If_group _, _), _  -> None
  | (Mark _, _), _ -> None
  | (Hoplimit limits, neg), (Hoplimit limits', neg') ->
    let (limits, neg) = merge_sets (limits, neg) (limits', neg') in
    (Hoplimit limits, neg) |> Option.some
  | (Hoplimit _, _), _ -> None
  | (Address_family af, neg), (Address_family af', neg') ->
    let (af'', neg'') = merge_sets (af, neg) (af', neg') in
    (* printf "merged: %d,%b + %d,%b -> %d,%b\n" (Set.length af) neg (Set.length af') neg' (Set.length af'') neg''; *)
    (Address_family af'', neg'') |> Option.some
  | (Address_family _, _), _ -> None

let cardinal_of_pred = function
  | Interface (_, is), _ -> Set.length is
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
  | If_group (_, set), _ -> Set.length set
  | Mark (_, _), _ -> 1
  | Hoplimit limits, _ -> Set.length limits
  | Address_family af, _ -> Set.length af

let sort_predicates predicates =
  List.stable_sort ~compare:Ir.compare_predicate predicates

let merge_predicates predicates =
  let reduce predicates =
    let rec inner = function
      | [] -> failwith "Cannot merge empty groups"
      | p1 :: [] -> [p1]
      | p1 :: p2 :: xs ->
        match merge_pred p1 p2 with
        | Some p -> inner (p :: xs)
        | None -> predicates
    in
    inner predicates
  in
  predicates
  |> sort_predicates
  |> List.group ~break:(fun (p1, _) (p2, _) -> Ir.enumerate_pred p1 <> Ir.enumerate_pred p2)
  |> List.concat_map ~f:reduce

let is_subset b ~of_:a =
  let is_satisfiable a b =
    merge_pred ~tpe:`Diff a b
    |> Option.map ~f:(fun p -> is_always false p |> not)
  in
  match is_satisfiable b a with
  | Some false -> true
  | _ -> false

let equal_predicate a b =
  is_subset a ~of_:b && is_subset b ~of_:a

let is_terminal = function
  | Pass | Jump _ -> false
  | Accept | Drop | Return | Reject _ -> true

(* Return a list of chains with leaves first *)
let get_ordered_chains chains =
  let rec traverse_chains seen chains acc chain_id =
    let seen = match Set.mem seen chain_id with
      | false -> Set.add seen chain_id
      | true -> failwith "Cycle detected!"
    in
    match Map.find chains chain_id with
    | Some { rules; _ } ->
      let acc = chain_id :: acc in
      List.fold_left ~init:acc ~f:(fun acc -> function
        | (_pred, _effect, Jump chain_id) -> traverse_chains seen chains acc chain_id
        | _ -> acc
      ) rules
    | None -> failwith "Chain id not found"
  in
  (* Traverse all builtin chains *)
  Map.fold chains ~init:[] ~f:(fun ~key ~data:_ acc ->
    match key with
    | (Ir.Chain_id.Builtin _) as chain_id ->
      traverse_chains (Set.empty) chains acc chain_id
    | _ -> acc
  )
  |> List.stable_dedup ~compare:Ir.Chain_id.compare

let join chains =
  let has_pred pred = function
    | (preds, _effects, _target) ->
      List.exists ~f:(Ir.eq_pred pred) preds
  in
  let filter_pred pred (preds, effects, target) =
    (List.filter ~f:(fun c -> not (Ir.eq_pred pred c)) preds, effects, target)
  in

  (* Count consecutive predicates *)
  let rec count_cont_preds pred = function
    | x :: xs when has_pred pred x ->
      1 + count_cont_preds pred xs
    | _ -> 0
  in

  let partition pred rules =
    List.partition_tf ~f:(has_pred pred) rules
  in
  let new_chains = ref [] in

  let rec inner acc = function
    | (preds, _effects, _target) as rule :: xs -> begin
        let x = List.map ~f:(fun pred -> (pred, count_cont_preds pred acc, count_cont_preds pred xs)) preds in
        let choose =
          List.reduce x ~f:(fun (c, p, n) (c', p', n') -> if p+n>=p'+n' then (c, p, n) else (c', p', n'))
        in
        match choose with
        | Some (pred, prev, next) when next = 0 && prev >= 3 ->
          printf "J";
          let (to_inline, rest) = partition pred (rule :: acc) in
          let chain_rules = List.map ~f:(filter_pred pred) to_inline in
          let chain = Chain.create chain_rules "Predicate moved" in
          new_chains := chain :: !new_chains;
          (* Replace with a jump to the chain *)
          let acc = ([pred], [], Ir.Jump chain.id) :: rest in
          (List.rev acc) @ inner [] xs
        | _ -> inner (rule :: acc) xs
      end
    | [] -> List.rev acc
  in
  let chains = Map.map ~f:(fun chn -> { chn with rules = inner [] chn.rules }) chains in
  List.fold_left ~init:chains ~f:(fun chains chain -> Map.add_exn ~key:chain.id ~data:chain chains) !new_chains

(** Remove all return statements, by creating new chains for each
    return statement. Add an empty rule to the new chain to do the effects *)
let fold_return_statements chains =
  let neg tg preds = List.map ~f:(fun (x, a) -> [(x, not a)], [], tg) preds in
  let rec fold_return acc = function
    | (cl, _ef, Return) :: xs ->
      printf "F";
      let rls, chns = fold_return [] xs in
      let chn = Chain.create rls "Return stm inlined" in
      let jumps = neg (Jump (chn.id)) cl in
      (acc @ jumps, chn :: chns)
    | rle :: xs -> fold_return (acc @ [rle]) xs
    | [] -> (acc, [])
  in

  let fold_func ~key:_ ~data:chn acc =
    let rls, chns = fold_return [] chn.rules in
    List.fold_left ~f:(fun acc chn -> Map.add_exn ~key:chn.id ~data:chn acc) ~init:acc ( { id = chn.id; rules = rls; comment = chn.comment } :: chns )
  in
  Map.fold chains ~f:fold_func ~init:(Map.empty (module Ir.Chain_id))

let remove_unreferenced_chains chains =
  let get_referenced_chains chain =
    List.fold_left ~f:(fun acc -> function (_, _, Jump id) -> (Map.find_exn chains id) :: acc | _ -> acc) ~init:[] chain.rules
  in
  let rec descend acc chain =
    match Map.mem acc chain.id with
    | true -> acc
    | false ->
      List.fold_left
        ~init:(Map.add_exn ~key:chain.id ~data:chain acc)
        ~f:(fun acc chn -> descend acc chn)
        (get_referenced_chains chain)
  in
  Map.fold
    ~init:(Map.empty (module Ir.Chain_id))
    ~f:(fun ~key:id ~data:chn acc -> match id with Builtin _ -> descend acc chn | _ -> acc) chains

(** Remove duplicate chains *)
let remove_duplicate_chains chains =
  let replace_chain_ids (id, ids) chns =
    map_chain_rules ~f:(List.map ~f:(function (c, e, Jump id') when List.mem ~equal:(=) ids id' -> (c, e, Jump id) | x -> x)) chns
  in
  let is_sibling a b = (Ir.eq_rules a.rules b.rules) && not (a.id = b.id) && Chain.is_temp a.id && Chain.is_temp b.id in
  let identical_chains chain chains =
    Map.fold ~f:(fun ~key:id ~data:chn acc ->
      if is_sibling chain chn then id :: acc else acc) chains ~init:[] in
  let remap_list = Map.fold ~f:(fun ~key:id ~data:chn acc -> (id, identical_chains chn chains) :: acc) chains ~init:[] in
  List.fold_left ~f:(fun acc (id, ids) -> if List.length ids > 0 then printf "D"; replace_chain_ids (id, ids) acc) ~init:chains remap_list

(** Move drops to the bottom. This allows improvement to dead code
    elimination, and helps reduce.
*)

let reorder rules =
  let can_reorder (cl1, ef1, act1) (cl2, ef2, act2) =
    (is_eq ef1 ef2 && act1 = act2) || not (is_satisfiable (merge_predicates (cl1 @ cl2)))
  in

  let order = function
    | Accept     -> 0
    | Reject _   -> 1
    | Drop       -> 2
    | Return     -> 3
    | Jump _     -> 4
    | Pass       -> 5
  in
  let should_reorder_rules (cl1, ef1, act1) (cl2, ef2, act2) =
    match can_reorder (cl1, ef1, act1) (cl2, ef2, act2) with
    | false -> false
    | true ->
      match order act1 - order act2 with
      | n when n > 0 -> true
      | 0 when List.length cl1 + List.length ef1 < List.length cl2 + List.length ef2 -> true
      | _ -> false
  in
  let reorder_rules _acc rules =
    List.stable_sort ~compare:(fun r1 r2 -> match should_reorder_rules r1 r2 with
      | true -> printf "~"; 1
      | false -> -1
    ) rules
  in
  reorder_rules [] rules

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

  let make_address_family tpe neg = Address_family (Set.singleton tpe), neg in
  let make_protocol lst neg = Ir.Protocol (Set.of_list lst), neg in

  match pred with
  | Ir.Protocol s, false when Set.is_subset ~of_:ipv4_protocols s && not (Set.is_empty s) ->
    make_address_family Ipv4 false |> Option.some
  | Ir.Protocol s, false when Set.is_subset ~of_:ipv6_protocols s && not (Set.is_empty s) ->
    make_address_family Ipv6 false |> Option.some
  | Ir.Protocol _, _ -> None

  | Ir.True, _
  | Ir.Interface _, _
  | Ir.If_group _, _
  | Ir.Zone _, _
  | Ir.State _, _
  | Ir.Mark _, _ -> None

  | Ir.Ports (_, Tcp, _), _ -> make_protocol [tcp] false |> Option.some
  | Ir.Ports (_, Udp, _), _ -> make_protocol [udp] false |> Option.some
  | Ir.TcpFlags _, _ -> make_protocol [tcp] false |> Option.some

  | Ir.Hoplimit _, _ -> make_address_family Ipv6 false |> Option.some
  | Ir.Icmp6 _, _ -> make_protocol [icmp] false |> Option.some
  | Ir.Ip6Set _, _ -> make_address_family Ipv6 false |> Option.some

  (* Ipv4 *)
  | Ir.Icmp4 _, _ -> make_protocol [icmp] false |> Option.some
  | Ir.Ip4Set _, _ -> make_address_family Ipv4 false |> Option.some

  (* Flip also *)
  | Ir.Address_family af, neg when Set.length af = 1 -> begin
      match Set.choose_exn af, neg with
      | Ir.Ipv4, false
      | Ir.Ipv6, true -> (Protocol ipv6_protocols, true) |> Option.some
      | Ir.Ipv4, true
      | Ir.Ipv6, false -> (Protocol ipv4_protocols, true) |> Option.some
    end
  | Ir.Address_family _, _ -> None

let (>::) elt elts =
  Option.value_map ~f:(fun elt -> elt :: elts) ~default:elts elt

let preds_all_true preds =
  List.fold ~init:[] ~f:(fun acc pred -> get_implied_predicate pred >:: pred :: acc) preds
  |> List.for_all ~f:(is_always true)

let inline_chains ~max_rules chains =
  let chain_rule_length chains id =
    match Map.find chains id with
    | Some { rules; _ } -> List.length rules
    | None -> 0
  in
  get_ordered_chains chains
  |> List.fold ~init:chains ~f:(fun chains chain_id ->
    match Map.find chains chain_id with
    | Some ({ rules; _ } as chain) ->
      let rules =
        List.concat_map ~f:(function
          | (preds, effects, Ir.Jump id) when chain_rule_length chains id <= max_rules ->
            (* Inline *)
            let { rules; _ } = Map.find_exn chains id in
            List.map ~f:(fun (preds', effects', target) ->
              (preds' @ preds), effects' @ effects, target
            ) rules
          | rule -> [rule]
        ) rules
      in
      Map.set chains ~key:chain_id ~data:{ chain with rules }
    | None ->
      chains
  )


(** Inline chains that satifies p *)
let rec inline cost_f chains =
  let rec inline_chain chain = function
    | (preds, effects, target) :: xs when equal_target target (Jump chain.id) -> begin
        let rec inline_rules (preds, effects) = function
          | (c, e, t) :: xs -> ( preds @ c, effects @ e, t ) :: inline_rules (preds, effects) xs
          | [] -> []
        in
        (inline_rules (preds, effects) chain.rules) @ (inline_chain chain xs)
      end
    | x :: xs -> x :: inline_chain chain xs
    | [] -> []
  in

  (* Select the chain with the least cost *)
  let chain_to_inline =
    Map.fold ~init:None
      ~f:(fun ~key:_ ~data:chain acc ->
        match Chain.is_temp chain.id && chain_reference_count chain.id chains > 0 with
        | false -> acc
        | true ->
            let cost = cost_f chains chain in
            match cost, acc with
            | c, _ when c > max_inline_cost -> acc
            | _, Some (_, c) when c < cost -> acc
            | _ -> Some (chain, cost)
      ) chains
    |> Option.map ~f:fst
  in
  (* Inline the chain *)
  match chain_to_inline with
  | Some chain ->
    printf "I";
    let chains = map_chain_rules ~f:(inline_chain chain) chains in
    inline cost_f chains
  | None -> chains

(* AFU: First map all rules with equivalent protocol or address family *)
let rec eliminate_unreachable_rules = function
  | (preds, _effects, target) as rule :: xs when
      is_terminal target && preds_all_true preds ->
    List.iter ~f:(fun _ -> printf "X") xs;
    [ rule ]
  | rle :: xs -> rle :: eliminate_unreachable_rules xs
  | [] -> []

(* Why not just merge the rules? *)
let rec eliminate_duplicate_rules = function
  | rle1 :: rle2 :: xs when Ir.eq_rule rle1 rle2 ->
    printf "D";
    eliminate_duplicate_rules (rle1 :: xs)
  | rle :: xs -> rle :: eliminate_duplicate_rules xs
  | [] -> []

(** For each rule in a chain, tests is the predicates are satisfiable.
    All rules which contains an unsatisfiable rule are removed
    (including its target)
*)
let remove_unsatisfiable_rules rules =
  (* Removing complete rules due to unsatifiability is ok *)
  List.filter ~f:(fun (preds, _, _) -> match is_satisfiable preds with
    | true -> true
    | false ->
      printf "U"; false
  )rules

let remove_empty_rules rules =
  List.filter ~f:(function
    | (_, [], Ir.Pass) -> printf "E"; false
    | _ -> true
  ) rules

let union_preds ps ps' =
  let ps = sort_predicates ps in
  let ps' = sort_predicates ps' in
  match List.map2 ~f:(merge_pred ~tpe:`Union) ps ps' with
  | Ok l when List.for_all ~f:Option.is_some l ->
    (* Lets print everything to see whats going on *)
    let r = List.filter_opt l in
    Some r
  | _ -> None
[@@warning "-32"]

(** Depth first traversal of chains *)
let traverse_chains_depth_first ~f chains =
  let rec inner chains chain_id =
    match Map.find chains chain_id with
    | None -> chains
    | Some ({ rules; _ } as chain) ->
      let chains = f chains chain in
      List.fold_left ~init:chains ~f:(fun chains -> function
        | (_, _, Ir.Jump chain_id) -> inner chains chain_id
        | _ -> chains
      ) rules
  in
  (* Find all buildin chains *)
  Map.fold ~init:[] ~f:(fun ~key:chain_id ~data:_ acc ->
    match chain_id with
    | Builtin _ -> chain_id :: acc
    | _ -> acc
  ) chains
  |> List.fold ~init:chains ~f:inner
[@@warning "-32"]

let process_chains_breath_first ~f chains =
  let rec traverse ~init chains chain_id =
    match Map.find chains chain_id with
    | Some { rules; _ } ->
      List.fold_left ~init:(chain_id :: init) ~f:(fun acc -> function
        | (_, _, Jump id) ->
          traverse ~init:acc chains id
        | _ -> acc
      ) rules
    | None -> init
  in
  Map.fold ~init:[] ~f:(fun ~key:chain_id ~data:_ acc ->
    match chain_id with
    | Chain_id.Builtin _ as chain_id -> traverse ~init:acc chains chain_id
    | _ -> acc
  ) chains
  |> List.stable_dedup ~compare:(Chain_id.compare)
  |> List.rev
  |> List.fold ~init:chains ~f

let preds_equal ps ps' =
  let ps = sort_predicates ps in
  let ps' = sort_predicates ps' in
  List.equal equal_predicate ps ps'

let merge_adjecent_rules chains =
  let is_subset ps' ~of_:ps =
    let rec inner = function
      | p :: ps, p' :: ps' when is_subset p' ~of_:p ->
        inner (ps, ps')
      | [], _ -> true
      | _, _ -> false
    in
    let ps = sort_predicates ps in
    let ps' = sort_predicates ps' in
    inner (ps, ps')
  in

  let new_chains = ref [] in
  let rec merge = function
    | ([pred], effects, target) :: ([pred'], effects', target') :: xs
      when Ir.eq_pred pred pred' ->
      printf "s";
      let chain = Chain.create [ ([], effects, target); ([], effects', target') ] "rule merged" in
      new_chains := chain :: !new_chains;
      merge (([pred], [], Jump chain.id) :: xs)
    | (preds, effects, target) :: (preds', effects', target') :: xs
      when preds_equal preds preds'
        && List.length preds = 1 ->
      printf "S";
      let chain = Chain.create [ ([], effects, target); ([], effects', target') ] "rule merged" in
      new_chains := chain :: !new_chains;
      merge ((preds, [], Jump chain.id) :: xs)
    | ([pred], effects, target) :: ([pred'], effects', target') :: xs
      when Ir.eq_effects effects effects'
        && Ir.equal_target target target'
        && merge_pred ~tpe:`Union pred pred' |> Option.is_some ->
      printf "j";
      let pred =
        merge_pred ~tpe:`Union pred pred' |> Option.value_exn
      in
      merge (([pred], effects, target) :: xs)
    | (preds, effects, target) :: (preds', _, _) :: xs
      when is_terminal target
        && is_subset ~of_:preds preds' ->
      printf "t";
      merge ((preds, effects, target) :: xs)
    | (preds, effects, target) :: (preds', effects', target') :: xs
      when Ir.equal_target target target'
        && Ir.equal_effects effects effects'
        && is_subset ~of_:preds' preds ->
      printf "m";
      merge ((preds', effects, target) :: xs)
    | (preds, effects, target) :: (preds', effects', target') :: xs
      when Ir.equal_target target target'
        && Ir.equal_effects effects effects'
        && is_subset ~of_:preds preds' ->
      printf "m";
      merge ((preds, effects, target) :: xs)

    | x :: xs -> x :: merge xs
    | [] -> []
  in
  let chains = Map.map ~f:(fun c -> { c with rules = merge c.rules }) chains in
  List.fold_left ~init:chains ~f:(fun acc chain -> Map.add_exn acc ~key:chain.id ~data:chain) !new_chains

(** All predicates which is always true are removed *)
let remove_true_predicates rules =
  (* AFU: First map all rules with equivalent protocol or address family *)
  List.map ~f:(fun (preds, effects, target) ->
    (List.filter_map ~f:(fun pred -> match is_always true pred with
       | true -> printf "E"; get_implied_predicate pred
       | false -> Some pred
    ) preds, effects,target)) rules

(** Determine the cost of inlining. *)
let inline_cost cs c =
  (* Number of predicates in the chain to be inlined *)
  let chain_preds = List.fold_left ~f:(fun acc (cl, _ef, _t) -> acc + List.length cl) ~init:0 c.rules in
  (* Number of predicates for each reference to the chain to be inlined. *)
  let rule_preds = List.map ~f:(fun (cl, _ef, _t) -> List.length cl) (get_referring_rules c cs) in
  (* Current count of predicates + targets *)
  let old_preds = (List.fold_left ~f:(+) ~init:0 rule_preds) + chain_preds + List.length rule_preds + List.length c.rules in
  (* Inlined count of predicates + targets *)
  let new_preds = List.fold_left ~f:(fun acc n -> acc + n * List.length c.rules + chain_preds) ~init:0 rule_preds + (List.length rule_preds * List.length c.rules) in
  new_preds - old_preds

(** Recursive reduction
    Traversing all chains, reduce all rules that match the initial rule.
    All redundant rules are removed
*)
let reduce_recursive ~(f:'acc list -> 'predicates -> 'acc * 'predicates) chains =
  let map_chain chains inputs chain =
    let input = Map.find_multi inputs chain.id in
    (* Verify that we have as many inputs as references to the chain *)
    let () =
      match chain_reference_count chain.id chains, List.length input with
      | references, inputs when references <> inputs ->
        eprintf "Error: %s has %d inputs, but %d references\n" (Chain_id.show chain.id) inputs references;
        assert false
      | _ -> ()
    in
    let inputs, rules =
      List.fold_left ~init:(inputs, []) ~f:(fun (inputs, acc) (predicates, effects, target) ->
        let output, predicates = f input predicates in
        let inputs =
          match target with
          | Ir.Jump chain_id -> Map.add_multi inputs ~key:chain_id ~data:output
          | _ -> inputs
        in
        (* I don't think this is needed at all *)
        let acc =
          match is_always false output with
          | true ->
            printf "P";
            ((Ir.True, true) :: predicates, effects, target) :: acc
          | false -> (predicates, effects, target) :: acc
        in
        (inputs, acc)
      ) chain.rules
    in
    inputs, { chain with rules = List.rev rules }
  in
  let input_chains = chains in

  let ordered_chains = get_ordered_chains chains |> List.rev in


  ordered_chains
  |> List.filter_map ~f:(Map.find chains)
  |> List.fold ~init:(Map.empty (module Ir.Chain_id), []) ~f:(fun (inputs, chains) chain ->
    let inputs, chain = map_chain input_chains inputs chain in
    inputs, chain :: chains
  )
  |> snd
  |> List.fold_left ~init:chains ~f:(fun chains chain -> Map.set chains ~key:chain.id ~data:chain)

(** Recursive reduction
    Traversing all chains, reduce all rules that match the initial rule.
    All redundant rules are removed
*)

let filter_predicates ~init inputs predicates =
  let input =
    List.reduce ~f:(fun acc pred -> merge_pred ~tpe:`Union acc pred |> Option.value ~default:init) inputs
    |> Option.value ~default:init
  in
  (* Augment input with derived predicates *)
  let input =
    List.fold ~init:input ~f:(fun acc pred ->
      match get_implied_predicate pred with
      | Some pred' when equal_predicate pred pred' ->
        acc
      | Some pred' ->
        merge_pred acc pred'
        |> Option.value ~default:acc
      | None -> acc
    ) predicates
  in
  let merge input pred =
    match merge_pred ~tpe:`Inter input pred with
    | None -> None
    | Some pred' ->
      match merge_pred ~tpe:`Diff input pred' with
      | None ->
        Some pred'
      | Some (p, n) ->
        match merge_pred input (p, not n) with
        | None ->
          printf "§";
          Some pred'
        | Some pred'' when equal_predicate pred' pred'' && cardinal_of_pred (p, not n) < cardinal_of_pred pred' ->
          printf "€";
          Some (p, not n)
        | Some _ ->
          printf "$";
          Some pred'
  in

  let output, predicates =
    List.fold_left ~init:(input, []) ~f:(fun (input, preds) pred ->
      match merge input pred with
      | Some pred' when eq_pred pred' input ->
        (* Predicate had no effect. *)
        printf "R";
        input, preds
      | Some pred' ->
        if (eq_pred pred pred' |> not) then printf "r";
        pred', (pred' :: preds)
      | None ->
        input, (pred :: preds)

    ) predicates
  in
  output, predicates

let reduce_all_predicates chains =
  List.fold_left ~init:chains ~f:(fun chains init ->
    reduce_recursive ~f:(filter_predicates ~init) chains
  ) true_predicates

let map_predicates ~f rules =
  List.map ~f:(fun (predicates, effects, target) ->
    (f predicates, effects, target)
  ) rules

let map_predicate ~f predicates =
  List.map ~f predicates

let merge_adjecent_rules2 ~min_merge ~typ chains =
  let merge acc preds =
    List.find_map ~f:(fun pred ->
      merge_pred ~tpe:`Union pred acc
      |> Option.bind ~f:(function
        | pred when is_always true pred -> None
        | pred -> Some pred
      )
    ) preds
  in
  let rec inner chains mergeable common_pred rules =
    let common_pred' =
      List.hd rules |> Option.bind ~f:(fun (preds, _, _) -> merge common_pred preds)
    in
    match common_pred', rules with
    (* Consider moving rules *)
    | Some common_pred, r :: rs ->
      printf "^%!";
      inner chains (r :: mergeable) common_pred rs
    | None, rs when List.length mergeable >= min_merge ->
      let new_chain = Chain.create (List.rev mergeable) "Reduce2" in
      let chains = Map.add_exn ~key:new_chain.id ~data:new_chain chains in
      let rule = ([common_pred], [], Ir.Jump new_chain.id) in
      let chains, rules = inner chains [] typ rs in
      chains, rule :: rules
    | None, r :: rs ->
      let (chain, rules) = inner chains [] typ rs in
      let rules = (List.rev mergeable) @ (r :: rules) in
      chain, rules
    | _, [] ->
      chains, List.rev mergeable
  in
  (* Map every chain *)
  Map.data chains
  |> List.fold ~init:(Map.empty (module Ir.Chain_id)) ~f:(fun acc ({ id; rules; _ } as chain) ->
    let acc, rules = inner acc [] typ rules in
    Map.add_exn acc ~key:id ~data:{ chain with rules }
  )

let merge_all_rules chains =
  List.fold_left ~init:chains ~f:(fun chains typ ->
    merge_adjecent_rules2 ~min_merge ~typ chains
  ) false_predicates



(** Push predicates to sub-chains if the predicate are already present on the subchains
    This only works for chains that has only one reference.
*)
let push_predicates ~min_push chains =
  (* Replace the chain with a chain where all rules have been extended with pred *)
  let merge pred preds = pred :: preds in

  let push rules pred =
    List.map ~f:(fun (preds, effects, target) ->
      (merge pred preds, effects, target)
    ) rules
  in

  let can_merge pred pred' =
    merge_pred pred pred' |> Option.is_some
  in

  let has_conflict pred pred' =
    match pred_type_identical (fst pred) (fst pred') with
    | true -> can_merge pred pred' |> not
    | false -> false
  in

  let can_merge_rules rules pred =
    List.exists ~f:(fun (preds, _, _) ->
      List.exists ~f:(fun pred' -> has_conflict pred pred') preds
    ) rules
    |> not
  in

  let count_merges rules pred =
    let count =
      List.count ~f:(fun (preds, _, _) ->
        List.exists ~f:(can_merge pred) preds
      ) rules
    in
    count * 100 / List.length rules
  in

  let process_chain_rules chains rules =
    let chains, rules =
      List.fold ~init:(chains, []) ~f:(fun (chains, acc) -> function
        | (preds, effects, (Ir.Jump target_id as target)) as rule when chain_reference_count target_id chains = 1 -> begin
            match Map.find chains target_id with
            | None -> chains, rule :: acc
            | Some ({ rules = target_rules; _ } as target_chain) ->
              let chains, preds =
                List.fold ~init:(chains, []) ~f:(fun (chains, acc) pred ->
                  match can_merge_rules rules pred && count_merges target_rules pred >= min_push with
                  | false -> (chains, pred :: acc)
                  | true ->
                    printf ">";
                    let target_rules = push target_rules pred in
                    let chains = Map.set chains ~key:target_id ~data:{ target_chain with rules = target_rules } in
                    chains, acc
                ) preds
              in
              chains, (List.rev preds, effects, target) :: acc
          end
        | rule -> chains, rule :: acc
      ) rules
    in
    chains, List.rev rules
  in

  (* Take all chains in order and start replacing. *)
  process_chains_breath_first ~f:(fun chains chain_id ->
    match Map.find chains chain_id with
    | Some ({ rules; _ } as chain) ->
      let chains, rules = process_chain_rules chains rules in
      Map.set chains ~key:chain_id ~data:{chain with rules}
    | _ -> chains
  ) chains

let reduce_chain_indegree ~max_indegree chains =
  let folding_map_chain_rules chains ~(init:'acc) ~(f: 'acc -> 'rule -> 'acc * 'rule) =
    let keys = Map.keys chains in
    keys
    |> List.fold ~init:(chains, init) ~f:(fun (chains, acc) chain_id ->
      match Map.find chains chain_id with
      | None -> (chains, acc)
      | Some ({ rules; _ } as chain) ->
        (* Replace the chain *)
        let rules, acc =
          List.fold ~init:([], acc) ~f:(fun (rules_acc, acc) rule ->
            let acc, rule = f acc rule in
            (rule :: rules_acc, acc)
          ) rules
        in
        let chains =
          Map.set chains ~key:chain_id ~data:{ chain with rules = List.rev rules }
        in
        chains, acc
    )
  in
  let replace_chain chain acc = function
    | (preds, effects, Jump id) when Chain_id.equal id chain.id ->
      let new_chain = Chain.create chain.rules "Duplicate" in
      new_chain :: acc, (preds, effects, Jump new_chain.id)
    | rule -> acc, rule
  in

  let chain_reference_count id chains =
    let count_references acc rules =
      List.fold_left ~init:acc ~f:(fun acc -> function
        | (_, _, Jump id') when Chain_id.equal id id' -> acc + 1
        | _ -> acc)  rules
    in
    Map.fold ~init:0 ~f:(fun ~key:id ~data:chn acc -> match id with
      | Chain_id.Temporary _ -> (count_references acc chn.rules)
      | _ -> acc
    ) chains
  in


  process_chains_breath_first ~f:(fun chains chain_id ->
    match Map.find chains chain_id, chain_reference_count chain_id chains > max_indegree with
    | Some chain, true ->
      let chains, new_chains = folding_map_chain_rules chains ~init:[] ~f:(replace_chain chain) in
      List.fold ~init:chains ~f:(fun chains chain -> Map.add_exn chains ~key:chain.id ~data:chain) new_chains
    | _, _ -> chains
  ) chains

let replace_with_address_family =
  let ipv4 = Address_family (Set.singleton Ir.Ipv4), false in
  let ipv6 = Address_family (Set.singleton Ir.Ipv6), false in

  function
  | Ip4Set (_, s), false when Ip6.is_empty s -> ipv4
  | Ip6Set (_, s), false when Ip6.is_empty s -> ipv6
  | Icmp4 is, false when Set.is_empty is -> ipv6
  | Icmp6 is, false when Set.is_empty is -> ipv6
  | Hoplimit cnts, false when Set.is_empty cnts -> ipv6
  | pred -> pred

let remove_transient_chains chains =
  (* Make a map of transient chains *)
  let transient_chains =
    Map.fold ~init:(Map.empty (module Chain_id)) ~f:(fun ~key ~data acc ->
      match data with
      | { rules = [([], [], Ir.Jump id)]; _ } -> Map.set acc ~key ~data:id
      | _ -> acc
    ) chains
  in
  map_chain_rules ~f:(fun rules ->
    List.map ~f:(function
      | (preds, effects, Ir.Jump id) when Map.mem transient_chains id ->
        (preds, effects, Ir.Jump (Map.find_exn transient_chains id))
      | rule -> rule
    ) rules
  ) chains




let optimize_pass ~stage chains =
  let chains = fold_return_statements chains in
  let optimize_functions =
    let (@@) a b = a ~f:b in
    [
      [  2  ], reduce_chain_indegree ~max_indegree:max_chain_indegree;
      [1;2;3], remove_unreferenced_chains;
      [1;2  ], push_predicates ~min_push;
      [1;2;3], map_chain_rules @@ eliminate_unreachable_rules;
      [1;2;3], map_chain_rules @@ map_predicates @@ merge_predicates;
      [1;2;3], map_chain_rules @@ map_predicates @@ map_predicate @@ replace_with_address_family;
      [1;2;3], map_chain_rules @@ remove_unsatisfiable_rules;
      [1;2;3], map_chain_rules @@ remove_true_predicates;
      [1;2;3], map_chain_rules @@ remove_empty_rules;
      [1;2;3], map_chain_rules @@ eliminate_duplicate_rules;
      [1;2;3], map_chain_rules @@ reorder;
      [1;2  ], join;
      [1;2;3], merge_adjecent_rules;
      [1;2  ], inline inline_cost;
      [1;2;3], remove_unreferenced_chains;
      [1;2;3], map_chain_rules ~f:(fun rls -> List.map ~f:(fun (preds, effect_, tg) -> (merge_predicates preds, effect_, tg)) rls);
      [1;2;3], reduce_all_predicates;
      [1;2;3], remove_duplicate_chains;
      [1;2  ], merge_all_rules;
      [     ], remove_transient_chains;
      [1;  3], inline_chains ~max_rules:1
    ]
  in
  let chains' = List.fold_left ~init:chains ~f:(fun chains' (stages, optim_func) ->
    match List.exists ~f:(Int.equal stage) stages with
    | true -> printf "%!"; optim_func chains'
    | false -> chains')  optimize_functions
  in
  chains'
  |> map_chain_rules ~f:(map_predicates ~f:sort_predicates)

let rec optimize ?(stage=1) ?(iter=1) chains =
  printf "\n#Stage: %d,%d: (%d, %d, %d): " stage iter (Chain.count_rules chains) (Chain.count_predicates chains) (Chain.count_chains chains);
  let chains' = optimize_pass ~stage chains in

  match (Chain.count_rules chains = Chain.count_rules chains'
         && Chain.count_predicates chains = Chain.count_predicates chains'
         && Chain.count_chains chains = Chain.count_chains chains') with
  | true when iter > 2  && stage >= 3 -> printf "\n#Optimization done\n";
    (* Print chain order *)
    printf "\n# Chains: [";
    let _ = process_chains_breath_first ~f:(fun chains' chain_id -> printf "%s; " (Chain_id.show chain_id); chains') chains in
    printf "]\n";
    chains'
    (*|> merge_all_rules
    |> reduce_all_predicates
    *)
  | true when iter > 2 ->
    optimize ~stage:(stage + 1) chains'
  | true ->
    optimize ~stage ~iter:(iter + 1) chains'
  | false ->
    printf "%!";
    optimize ~stage chains'

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

      "ip6set diff" >:: begin fun _ ->
        let make lst n =
          lst
          |> List.map ~f:Ipaddr.V6.Prefix.of_string_exn
          |> Ip6.of_list
          |> fun v -> Ir.Ip6Set (Ir.Direction.Source, v), n
        in
        let a = make ["2000::/3"; "fe80::/10"; "ff02::1:2/128"] false in
        let x = make ["2000::/3"; "fe80::/10"] false in
        let y = make ["fe80::/10"; "ff02::1:2/128"] false in
        let z = make ["2000::/3"] false in

        [ "a", a;
          "x", x;
          "y", y;
          "z", z;
          "a / x", merge_pred ~tpe:`Diff a x |> Option.value_exn;
          "a / x", merge_pred ~tpe:`Diff a x |> Option.value_exn
        ]
        |> List.map ~f:(fun (s, v) -> Printf.sprintf "%s: %s" s (string_of_predicate v))
        |> String.concat ~sep:"\n"
        |> Stdio.eprintf "%s %s\n" (Ipaddr.V6.Prefix.of_string_exn "::/0" |> Ipaddr.V6.Prefix.to_string)

      end;

      "is_true" >:: begin fun _ ->
        List.iteri ~f:(fun i pred ->
          let msg =
            Printf.sprintf "Predicate %s (index %d) should always be true" (string_of_predicate pred) i
          in
          assert_bool msg (is_always true pred)
        ) true_predicates
      end;
    ]
end
