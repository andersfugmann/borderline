open Base
module Set = Set.Poly
open Stdio
open Ir
open Poly
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

(** Bugs:
    Reducing indegree does not work as intended
    - It ought not to introduce bugs though. But we need to verify that though

    ipv4/ipv4 are exlusive. This means that they cannot render true easily.
    This also means that nft generation does not need to emit address families
*)


(* Percentage for predicates are pushed down to called chains *)
let min_push = 60

(* Make sure that no chains have an indegree more than N,
   so that 'for all chains | chain_reference_count <= N' holds
*)
let max_chain_indegree = 1


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


(** Define the saving in predicates when inlining. *)
let max_inline_cost = 1

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
  let merge_diff inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (diff  a b, false)
    | (a, true),  (b, true)  -> (diff  b a, false)
    | (a, false), (b, true)  -> (inter a b, false)
    | (a, true),  (b, false) -> (union a b, true)
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
    elimination, and helps reduce *)
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
    if can_reorder (cl1, ef1, act1) (cl2, ef2, act2) then
      match order act1 - order act2 with
      | n when n > 0 -> true
      | 0 when List.length cl1 + List.length ef1 < List.length cl2 + List.length ef2 -> true
      | _ -> false
    else
      false
  in
  let reorder_rules _acc rules =
    List.stable_sort ~compare:(fun r1 r2 -> match should_reorder_rules r1 r2 with
      | true -> 1
      | false -> -1
    ) rules
  in
  reorder_rules [] rules

let icmp = 1
let igmp  = 2
let tcp = 6
let udp = 17
let icmp6 = 58

let protocol_of_pred pred =
  let s, n =
    match pred with
    | Ir.Protocol p, neg -> p, neg
    | Ir.True, _
    | Ir.Interface (_,_), _
    | Ir.If_group (_,_), _
    | Ir.Zone (_,_), _
    | Ir.State _, _
    | Ir.Mark (_,_), _ ->
      Set.empty, true
    | Ir.Hoplimit _, _ ->
      Set.of_list [ icmp; igmp ], true
    | Ir.Ip6Set (_,_), _ ->
      Set.of_list [ icmp; igmp ], true
    | Ir.Ip4Set (_,_), _ ->
      Set.of_list [ icmp6 ], true
    | Ir.Ports (_, Ir.Port_type.Tcp, _), _ ->
      Set.singleton tcp , false
    | Ir.Ports (_, Ir.Port_type.Udp, _), _ ->
      Set.singleton udp, false
    | Ir.Icmp4 _, _ ->
      Set.singleton icmp, false
    | Ir.Icmp6 _, _ ->
      Set.singleton icmp6, false
    | Ir.TcpFlags (_,_), _ ->
      Set.singleton tcp, false
    | Ir.Address_family fs, neg ->
      match Set.to_list fs, neg with
      | [ Ir.Ipv4 ], false
      | [ Ir.Ipv6 ], true ->
        Set.of_list [ icmp6 ], true
      | [ Ir.Ipv4 ], true
      | [ Ir.Ipv6 ], false ->
        Set.of_list [ icmp; igmp ], true
      | [Ir.Ipv4; Ir.Ipv6], false
      | [Ir.Ipv6; Ir.Ipv4], false
      | [], true ->
        Set.empty, true
      | [Ir.Ipv4; Ir.Ipv6], true
      | [Ir.Ipv6; Ir.Ipv4], true
      | [ ], false ->
        Set.empty, false
      | _ :: _ :: _ , _ -> failwith "This cannot be reached and will cause a compilation error"
  in
  Ir.Protocol s, n

let address_family_of_pred pred =
  let ipv4_protocols = Set.of_list [ icmp; igmp ] in
  let ipv6_protocols = Set.of_list [ icmp6 ] in
  let s, n =
    match pred with
    | Ir.Hoplimit _, _
    | Ir.Icmp6 _, _
    | Ir.Ip6Set (_,_), _ ->
      Set.singleton Ir.Ipv6, false
    | Ir.Icmp4 _, _
    | Ir.Ip4Set (_,_), _ ->
      Set.singleton Ir.Ipv4, false

    | Ir.Protocol p, false when Set.is_subset p ~of_:ipv6_protocols ->
      Set.singleton Ir.Ipv6, false
    | Ir.Protocol p, false when Set.is_subset p ~of_:ipv4_protocols ->
      Set.singleton Ir.Ipv4, false

    | Ir.Protocol p, true when Set.is_subset ipv6_protocols ~of_:p ->
      Set.singleton Ir.Ipv4, false
    | Ir.Protocol p, false when Set.is_subset ipv4_protocols ~of_:p ->
      Set.singleton Ir.Ipv6, false
    | Ir.Protocol _, _
    | Ir.True, _
    | Ir.Interface (_,_), _
    | Ir.If_group (_,_), _
    | Ir.Zone (_,_), _
    | Ir.State _, _
    | Ir.Mark (_,_), _
    | Ir.Ports _, _
    | Ir.TcpFlags (_,_), _ ->
      Set.empty, true
    | Ir.Address_family af, neg -> af, neg
  in
  Ir.Address_family s, n

let preds_all_true preds =
  List.for_all ~f:(is_always true) preds

(** Inline chains that satifies p *)
let rec inline cost_f chains =
  let rec inline_chain chain = function
    | (preds, effects, target) :: xs when target = Jump(chain.id) && (Chain.is_temp chain.id)-> begin
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
        match Chain.is_temp chain.id &&
              chain_reference_count chain.id chains > 0 with
        | true -> begin
            let cost = cost_f chains chain in
            match cost, acc with
            | c, _ when c > max_inline_cost -> acc
            | _, Some (_, c) when c < cost -> acc
            | _ -> Some (chain, cost)
          end
        | false -> acc
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

let rec eliminate_dead_rules = function
  | (preds, _effects, target) as rule :: xs when
      is_terminal target && preds_all_true preds->
    List.iter ~f:(fun _ -> printf "D") xs;
    [ rule ]
  | rle :: xs -> rle :: eliminate_dead_rules xs
  | [] -> []

(* Why not just merge the rules? *)
let rec eliminate_duplicate_rules = function
  | rle1 :: rle2 :: xs when Ir.eq_rule rle1 rle2 ->
    printf "d";
    rle1 :: eliminate_duplicate_rules xs
  | rle :: xs -> rle :: eliminate_duplicate_rules xs
  | [] -> []

(** For each rule in a chain, tests is the predicates are satisfiable.
    All rules which contains an unsatisfiable rule are removed
    (including its target)
*)
let remove_unsatisfiable_rules rules =
  List.filter ~f:(fun (preds, _, _) -> is_satisfiable preds) rules

let remove_empty_rules rules =
  List.filter ~f:(function (_, [], Ir.Pass) -> false | _ -> true) rules

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
  List.map ~f:(fun (preds, effects, target) ->
    (List.filter ~f:(fun pred -> not (is_always true pred)) preds, effects,target)) rules

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
  let create_ordered_chains chains =
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
    |> List.rev
  in

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
        let acc =
          match is_always false output with
          | true ->
            printf "P";
            acc
          | false -> (predicates, effects, target) :: acc
        in
        (inputs, acc)
      ) chain.rules
    in
    inputs, { chain with rules = List.rev rules }
  in
  let input_chains = chains in

  let ordered_chains = create_ordered_chains chains in


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
  let output, predicates =
    List.fold_left ~init:(input, []) ~f:(fun (input, preds) pred ->
      match merge_pred input pred with
      | Some pred when eq_pred pred input ->
        (* Predicate had no effect *)
        printf "R";
        input, preds
      | Some pred' ->
        if (equal_predicate pred pred' |> not) then printf "U";
        pred', (pred' :: preds)
      | None -> input, (pred :: preds)
    ) predicates
  in
  output, predicates

(** Filter based on derived predicates *)
let filter_predicates_derived ~init ~of_pred inputs predicates =
  let input =
    List.reduce ~f:(fun acc pred -> merge_pred ~tpe:`Union acc pred |> Option.value_exn) inputs
    |> Option.value ~default:init
  in
  (* Map all predicates *)
  let predicates' =
    List.map ~f:(fun pred -> pred, of_pred pred) predicates
  in
  let input =
    List.fold ~init:input ~f:(fun acc (pred, derived) ->
      match pred_type_identical (fst pred) (fst derived) with
      | true -> acc
      | false -> merge_pred derived acc |> Option.value_exn
    ) predicates'
  in
  let output, predicates =
    List.fold_left ~init:(input, []) ~f:(fun (input, preds) (pred, _derived) ->
      match merge_pred input pred with
      | Some pred when eq_pred pred input ->
        printf "R";
        input, preds
      | Some pred ->
        printf "U";
        pred, (pred :: preds)
      | None -> input, (pred :: preds)
    ) predicates'
  in
  output, List.rev predicates

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

(** Push predicates to sub-chains if the predicate are already present on the subchains
    This only works for chains that has only one reference.
*)
let push_predicates ~min_push chains =
  (* Replace the chain with a chain where all rules have been extended with pred *)
  (* We should not merge!!! *)
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

  let proccess_chain_rules chains rules =
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
                    printf "F";
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
      let chains, rules = proccess_chain_rules chains rules in
      Map.set chains ~key:chain_id ~data:{chain with rules}
    | _ -> chains
  ) chains

(* This function essentially does not work as intended. *)
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

let optimize_pass chains =
  printf "#Optim: (%d, %d, %d) %!" (Map.length chains) (Chain.count_rules chains) (Chain.count_predicates chains);
  let chains = fold_return_statements chains in
  let optimize_functions =
    let (@@) a b = a ~f:b in
    [
      reduce_chain_indegree ~max_indegree:max_chain_indegree;
      remove_unreferenced_chains;
      push_predicates ~min_push;
      map_chain_rules @@ eliminate_dead_rules;
      map_chain_rules @@ map_predicates @@ merge_predicates;
      map_chain_rules @@ map_predicates @@ map_predicate @@ replace_with_address_family;
      map_chain_rules @@ remove_unsatisfiable_rules;
      map_chain_rules @@ remove_true_predicates;
      map_chain_rules @@ remove_empty_rules;
      map_chain_rules @@ eliminate_duplicate_rules;
      map_chain_rules @@ reorder;
      join;
      merge_adjecent_rules;
      inline inline_cost;
      remove_unreferenced_chains;
      map_chain_rules ~f:(fun rls -> List.map ~f:(fun (preds, effect_, tg) -> (merge_predicates preds, effect_, tg)) rls);
      reduce_all_predicates;
      reduce_recursive ~f:(filter_predicates_derived ~init:(Ir.Protocol Set.empty, true) ~of_pred:protocol_of_pred);
      reduce_recursive ~f:(filter_predicates_derived ~init:(Ir.Address_family Set.empty, true) ~of_pred:address_family_of_pred);
      remove_duplicate_chains;
    ]
  in
  let chains' = List.fold_left ~f:(fun chains' optim_func -> printf "%!"; optim_func chains') ~init:chains optimize_functions in
  printf " (%d, %d)\n" (Chain.count_rules chains') (Chain.count_predicates chains');
  chains'
  |> map_chain_rules ~f:(map_predicates ~f:sort_predicates)

let rec optimize ?(iter=3) chains =
  let chains' = optimize_pass chains in
  match (Chain.count_rules chains = Chain.count_rules chains'
         && Chain.count_predicates chains = Chain.count_predicates chains'
         && Chain.count_chains chains = Chain.count_chains chains') with
  | true when iter = 0 -> printf "#Optimization done\n";
    (* Print chain order *)
    printf "\n# Chains: [";
    let _ = process_chains_breath_first ~f:(fun chains' chain_id -> printf "%s; " (Chain_id.show chain_id); chains') chains in
    printf "]\n";
    chains'
  | true ->
    optimize ~iter:(iter - 1) chains'
  | false ->
    printf "%!";
    optimize chains'

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

      "is_true" >:: begin fun _ ->
        List.iteri ~f:(fun i pred ->
          let msg =
            Printf.sprintf "Predicate %s (index %d) should always be true" (Ir.string_of_predicate (fst pred)) i
          in
          assert_bool msg (is_always true pred)
        ) true_predicates
      end;
    ]
end
