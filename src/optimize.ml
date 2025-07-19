open Base
module Set = Set.Poly
open Stdio
open Ir
open Poly
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

(*
   1. Extend all predicates with their protocol counterpart.
   2. Recurcive Filter all counterparts that has no effect.
      - We have a merge optimization that merged all identical rules into one
      - So at this point, we only have one rule
      - But we want to scan to the end of the rule to see if the rule is redundant.
      - This optimization pass is actually generic (as we may not have merging)
      - So we scan all rules first (But would like to exclude the ones we are looking for.
      - Maybe we need a specific pass that has an

   - An accumulator.
      - a merge function acc -> oper -> acc, oper option (None means delete the op)
      - The function should map over all rules in two passes.
      - An implicit map would never change non-matching rules, but maintain an 'non' matched?
      - Only for the mapped ones? Would that work? No.

*)


(** Define the saving in predicates when inlining. *)
let max_inline_cost = 1

let is_satisfiable preds =
  not (List.exists ~f:(is_always false) preds)

let is_subset_eq a b =
  List.for_all ~f:(fun a -> List.exists b ~f:((=) a)) a

let is_eq a b =
  is_subset_eq a b && is_subset_eq b a

let chain_reference_count id chains =
  let count_references rules =
    List.fold_left ~f:(fun acc -> function (_, _, Jump id') when id = id' -> acc + 1 | _ -> acc) ~init:0 rules
  in
  Map.fold ~f:(fun ~key:_ ~data:chn acc -> acc + (count_references chn.rules)) chains ~init:0

let get_referring_rules chain chains =
  let test (_preds, _effects, target) = target = Jump (chain.id) in
  let referring_chains = Chain.filter (fun chn -> List.exists ~f:test chn.rules) chains in
  List.fold_left ~f:(fun acc chn -> (List.filter ~f:test chn.rules) @ acc) ~init:[] referring_chains

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules ~f chains =
  Map.map ~f:(fun chn -> { chn with rules = f chn.rules }) chains

let merge_oper ?(tpe=`Inter) a b =
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


  (* This is a problem. We should match on everything here! *)
  let merge = match a with
    | (Interface (dir, is), neg) -> begin
        function
        | (Interface (dir', is'), neg') when dir = dir' ->
          let (is'', neg'') = merge_sets (is, neg) (is', neg') in
          (Interface (dir, is''), neg'') |> Option.some
        | _ -> None
      end
    | (State s, neg) -> begin
        function
        | (State s', neg') ->
          let (s'', neg'') = merge_states (s, neg) (s', neg') in
          (State s'', neg'') |> Option.some
        | _ -> None
      end
    | (Ports (dir, pt, ports), neg) -> begin
        function
        | (Ports (dir', pt', ports'), neg') when dir = dir' && pt = pt' ->
          let (ports'', neg'') = merge_sets (ports, neg) (ports', neg') in
          (Ports (dir, pt, ports''), neg'') |> Option.some
        | _ -> None
      end
    | (Protocol (p), neg) -> begin
        function (Protocol (p'), neg') ->
          let (p'', neg'') = merge_sets (p, neg) (p', neg') in
          (Protocol (p''), neg'') |> Option.some
               | _ -> None
      end
    | (Icmp6 types, neg) -> begin
        function
        | (Icmp6 types', neg') ->
          let (types'', neg'') = merge_sets (types, neg) (types', neg') in
          (Icmp6 types'', neg'') |> Option.some
        | _ -> None
      end
    | (Icmp4 types, neg) -> begin
        function
        | (Icmp4 types', neg') ->
          let (types'', neg'') = merge_sets (types, neg) (types', neg') in
          (Icmp4 types'', neg'') |> Option.some
        | _ -> None
      end
    | (Ip6Set (dir, set), neg) -> begin
        function
        | (Ip6Set (dir', set'), neg') when dir = dir' ->
          let (set'', neg'') = merge_ip6sets (set, neg) (set', neg') in
          (Ip6Set (dir, set''), neg'') |> Option.some
        | _ -> None
      end
    | (Ip4Set (dir, set), neg) -> begin
        function
        | (Ip4Set (dir', set'), neg') when dir = dir' ->
          let (set'', neg'') = merge_ip4sets (set, neg) (set', neg') in
          Some (Ip4Set (dir, set''), neg'')
        | _ -> None
      end
    | (Zone (dir, zones), neg) -> begin
        function
        | (Zone (dir', zones'), neg') when dir = dir' ->
          let (zones'', neg'') = merge_sets (zones, neg) (zones', neg') in
          Some (Zone (dir, zones''), neg'')
        | _ -> None
      end
    | (TcpFlags (f, m), neg) -> begin
        function
        | (TcpFlags (f', m'), false) when not neg ->
          begin
            let set_flags = Set.union f f' in
            let unset_flags = Set.union (Set.diff m f) (Set.diff m' f') in
            match Set.inter set_flags unset_flags |> Set.is_empty with
            | true ->
              Some (TcpFlags (set_flags, Set.union m m'), false)
            | false -> Some (True, true)
          end
        | _ -> None
      end
    | (True, neg) -> begin
        function
        | (True, neg') -> Some (True, neg || neg')
        | _ -> None
      end
    | If_group (_, _), _neg -> fun _ -> None
    | Mark (_, _), _neg -> fun _ -> None
    | Hoplimit limits, neg -> begin
        function
        | Hoplimit limits', neg' ->
          let (limits, neg) = merge_sets (limits, neg) (limits', neg') in
          (Hoplimit limits, neg) |> Option.some
        | _ -> None
      end
    | Address_family af, neg -> begin
        function
        | Address_family af', neg' ->
          let (af'', neg'') = merge_sets (af, neg) (af', neg') in
          (* printf "merged: %d,%b + %d,%b -> %d,%b\n" (Set.length af) neg (Set.length af') neg' (Set.length af'') neg''; *)
          (Address_family af'', neg'') |> Option.some
        | _ -> None
      end
  in
  merge b

let merge_opers rle =
  let rec merge_siblings acc = function
    | x :: xs ->
      let (x', xs') = List.fold_left ~f:(
        fun (m, rest) op -> match merge_oper m op with
          | Some m' -> (m', rest)
          | None -> (m, op :: rest)
      ) ~init:(x, []) xs in
      merge_siblings (x' :: acc) xs'
    | [] -> acc
  in
  merge_siblings [] rle

let is_subset a b =
  match merge_oper ~tpe:`Diff a b with
  | Some r ->
    (* if b - a is still satisfiable, then b covers more that a. *)
    is_always false r
  | None -> false

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
  let rec count_preds pred = function
    | x :: xs when has_pred pred x ->
      1 + count_preds pred xs
    | _ -> 0
  in
  let partition pred rules =
    List.partition_tf ~f:(has_pred pred) rules
  in
  let new_chains = ref [] in
  let rec inner acc = function
    | (preds, _effects, _target) as rule :: xs -> begin
        let x = List.map ~f:(fun pred -> (pred, count_preds pred acc, count_preds pred xs)) preds in
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
    (is_eq ef1 ef2 && act1 = act2) || not (is_satisfiable (merge_opers (cl1 @ cl2)))
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
    | Ir.Ip6Set (_,_), _
    | Ir.Icmp6 _, _ ->
      Set.singleton Ir.Ipv6, false
    | Ir.Ip4Set (_,_), _
    | Ir.Icmp4 _, _ ->
      Set.singleton Ir.Ipv4, false
    | Ir.Protocol p, false when Set.is_subset p ~of_:ipv6_protocols ->
      Set.singleton Ir.Ipv6, false
    | Ir.Protocol p, false when Set.is_subset p ~of_:ipv4_protocols ->
      Set.singleton Ir.Ipv4, false
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

(* Lets see if we can generalize this *)
let filter_derived ~init ~of_pred chain =
  let calculate ~total inferred =
    let merged = merge_oper total inferred in
    match Ir.eq_pred (merged |> Option.value_exn) inferred with
    | true -> None
    | false -> merged
  in

  let merge f preds =
    List.fold ~init ~f:(fun acc p ->
      merge_oper acc (f p) |> Option.value_exn
    ) preds
  in

  let filter (preds, effects, target) =
    (* We may have an empty rule set. That not the same as possible to match *)
    (* So we need to understand if the *)
    let preds = List.map ~f:(fun pred -> of_pred pred, pred) preds in
    let total = merge fst preds in

    match is_always false total with
    | true ->
      (* Unsatisfiable *)
      printf "P";
      None
    | false ->
      let filtered_preds =
        List.filter ~f:(function
          | pred, pred' when eq_pred pred pred' -> false
          | _ -> true
        ) preds
      in
      let inferred = merge fst filtered_preds in
      let filtered_preds = List.map ~f:snd filtered_preds in
      let preds =
        match calculate ~total inferred with
        | None ->
          filtered_preds
        | Some pred ->
          pred :: filtered_preds
      in
      Some (preds, effects, target)
  in
  List.filter_map ~f:filter chain


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
  | ([], effects, target) :: xs when is_terminal target ->
    if List.length xs > 0 then printf "D";
    [ ([], effects, target) ]
  | rle :: xs -> rle :: eliminate_dead_rules xs
  | [] -> []

let rec eliminate_duplicate_rules = function
  | rle1 :: rle2 :: xs when Ir.eq_oper rle1 rle2 ->
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

let merge_adjecent_rules chains =
  let new_chains = ref [] in
  let rec merge = function
    | ([rule], effects, target) :: ([rule'], effects', target') :: xs when Ir.eq_pred rule rule' -> begin
        let chain = Chain.create [ ([], effects, target); ([], effects', target') ] "rule merged" in
        new_chains := chain :: !new_chains;
        merge (([rule], [], Jump chain.id) :: xs)
      end
    | ([rule], effects, target) :: ([rule'], effects', target') :: xs
      when Ir.eq_effects effects effects'
        && target = target'
        && merge_oper ~tpe:`Union rule rule' <> None ->
      let r = merge_oper ~tpe:`Union rule rule' in
      merge (([Option.value_exn r], effects, target) :: xs)
    | ([rule], effects, target) :: ([rule'], _, _) :: xs
      when is_terminal target && is_subset rule' rule ->
      merge (([rule], effects, target) :: xs)
    | x :: xs -> x :: merge xs
    | [] -> []
  in
  let chains = Map.map ~f:(fun c -> { c with rules = merge c.rules }) chains in
  List.fold_left ~init:chains ~f:(fun acc chain -> Map.add_exn acc ~key:chain.id ~data:chain) !new_chains

(** All predicates which is always true are removed *)
let remove_true_rules rules =
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

(** Remove unsatisfiable rules recursively. Loop over all chains, and follow the chains. *)
let filter_exclusive_rules acc pred =
  let is_unsatisfiable preds pred =
    List.exists preds ~f:(fun pred' ->
      match merge_oper pred pred' with
      | Some oper when is_always false oper ->
        true
      | Some _
      | None -> false
    )
  in
  match acc with
  | None -> `Satisfiable (Some [pred])
  | Some preds ->
    match is_unsatisfiable preds pred with
    | true -> `Unsatisfiable
    | false -> `Satisfiable (Some (pred :: preds))

let filter_unsatisfiable f acc pred =
  (* Acc is a protocol *)
  let pred = f pred in
  match acc with
  | None -> `Satisfiable (Some pred)
  | Some acc ->
    let acc = merge_oper acc pred in
    match is_always false (acc |> Option.value_exn) with
    | true -> `Unsatisfiable
    | false -> `Satisfiable acc

(** Recursive reduction
    Traversing all chains, reduce all rules that match the initial rule.
    All redundant rules are removed
*)
let reduce_recursive ~init chains =
  let rec process_chain chains chain_id acc =
    match Map.find chains chain_id with
    | None -> failwith "Chain could not be found"
    | Some ({ rules ; _ } as chain) ->
      let chains, rules =
        (* Iterate over rules *)
        List.fold_left ~init:(chains, []) ~f:(fun (chains, rules) (preds, effects, target) ->
          let acc, preds =
            (* Iterate over predicates. *)
            List.fold_left ~init:(acc, []) ~f:(fun (acc, preds) pred ->
              match merge_oper acc pred with
              | None -> (acc, pred :: preds)
              | Some pred when eq_pred pred acc ->
                (* Predicate had no effect *)
                printf "R";
                (acc, preds)
              | Some pred' ->
                (pred', pred' :: preds)
            ) preds
          in
          let rule = (List.rev preds, effects, target) in
          let chains =
            match target with
            | Jump chain_id ->
              process_chain chains chain_id acc
            | _ -> chains
          in
          chains, rule :: rules
        ) rules
      in
      Map.set chains ~key:chain_id ~data:{ chain with rules = List.rev rules }
  in
  Map.keys chains
  |> List.fold ~init:chains ~f:(fun chains -> function
    | Ir.Chain_id.Builtin _ as chain_id -> process_chain chains chain_id init
    | _ -> chains
  )

let remove_unsatisfiable_rules_recursive filter chains =
  let rec preds_satisfiable acc = function
    | [] -> `Satisfiable acc
    | pred :: preds ->
      match filter acc pred with
      | `Satisfiable acc -> preds_satisfiable acc preds
      | `Unsatisfiable -> `Unsatisfiable
  in
  (* Do we have a list of top_level chains? I guess we do! *)
  (* Its a map. Not an imperative structure. Which means that we need to replace before we descend! *)

  let rec process_chain chains chain_id acc =
    match Map.find chains chain_id with
    | None -> failwith "Chain could not be found"
    | Some ({ rules ; _ } as chain) ->
      let chains, rules =
        List.fold_left ~init:(chains, []) ~f:(fun (chains, rules) (preds, effects, target) ->
          (* If we encounter a filtered rule, then stop *)
          match preds_satisfiable acc preds with
          | `Unsatisfiable ->
            printf "U";
            chains, rules
          | `Satisfiable acc ->
            let chains =
              match target with
              | Jump chain_id -> process_chain chains chain_id acc
              | _ -> chains
            in
            let rule = (preds, effects, target) in
            chains, rule :: rules
        ) rules
      in
      Map.set chains ~key:chain_id ~data:{ chain with rules = List.rev rules }
  in
  (* Loop over all built_in rules *)
  Map.keys chains
  |> List.fold ~init:chains ~f:(fun chains -> function
    | Ir.Chain_id.Builtin _ as chain_id -> process_chain chains chain_id None
    | _ -> chains
  )

let filter_protocol = filter_derived ~init:(Ir.Protocol Set.empty, true) ~of_pred:protocol_of_pred
let filter_address_family = filter_derived ~init:(Ir.Address_family Set.empty, true) ~of_pred:address_family_of_pred

let optimize_pass chains =
  printf "#Optim: (%d, %d) %!" (Chain.count_rules chains) (Chain.count_predicates chains);
  let chains = fold_return_statements chains in
  let optimize_functions = [
    map_chain_rules ~f:eliminate_dead_rules;
    remove_duplicate_chains;
    map_chain_rules ~f:filter_protocol;
    map_chain_rules ~f:filter_address_family;
    map_chain_rules ~f:remove_unsatisfiable_rules;
    map_chain_rules ~f:remove_true_rules;
    map_chain_rules ~f:remove_empty_rules;
    map_chain_rules ~f:eliminate_duplicate_rules;
    map_chain_rules ~f:reorder;
    join;
    merge_adjecent_rules;
    inline inline_cost;
    map_chain_rules ~f:(fun rls -> Common.map_filter_exceptions (fun (opers, effect_, tg) -> (merge_opers opers, effect_, tg)) rls);
    reduce_recursive ~init:(Ir.Protocol Set.empty, true);
    remove_unsatisfiable_rules_recursive filter_exclusive_rules;
    remove_unsatisfiable_rules_recursive (filter_unsatisfiable protocol_of_pred);
    remove_unsatisfiable_rules_recursive (filter_unsatisfiable address_family_of_pred);
    remove_unreferenced_chains;
  ] in
  let chains' = List.fold_left ~f:(fun chains' optim_func -> optim_func chains') ~init:chains optimize_functions in
  printf " (%d, %d)\n" (Chain.count_rules chains') (Chain.count_predicates chains');
  chains'

let rec optimize chains =
  let chains' = optimize_pass chains in
  match (Chain.count_rules chains = Chain.count_rules chains' && Chain.count_predicates chains = Chain.count_predicates chains') with
  | true -> printf "#Optimization done\n";
    chains'
  | false -> optimize chains'



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
        let res = merge_oper ~tpe:`Diff a b
        in
        assert_equal ~cmp:eq_pred_opt ~msg:"Wrong result" res (Some expect);
      end;

      "merge_inter" >:: begin fun _ ->
        let expect = Ir.Zone (Ir.Direction.Source, ["ext"] |> Set.of_list), false in
        let a = Ir.Zone (Ir.Direction.Source, ["int"; "ext"] |> Set.of_list), false in
        let b = Ir.Zone (Ir.Direction.Source, ["ext"; "other"] |> Set.of_list), false in
        let res = merge_oper ~tpe:`Inter a b
        in
        assert_equal ~cmp:eq_pred_opt ~msg:"Wrong result" res (Some expect);
      end;

      "subset" >:: begin fun _ ->
        let a = (Ir.State ([State.New] |> State.of_list), false) in
        let b = (Ir.State ([State.New; State.Established] |> State.of_list), false) in
        let c = (Ir.State ([State.Established] |> State.of_list), false) in

        assert_bool "a b must be a subset" (is_subset a b);
        assert_bool "b a must not be a subset" (not (is_subset b a));
        assert_bool "a c must not be a subset" (not (is_subset a c));
        assert_bool "c a must not be a subset" (not (is_subset c a));
        assert_bool "c b must be a subset" (is_subset c b);
        ()
      end;
    ]
end
