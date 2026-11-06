open Base
module Set = Set.Poly
open Ir
open Poly
module Ip6Set = Ipset.Ip6Set
module Ip4Set = Ipset.Ip4Set
module P = Predicate

let printf = Stdio.printf
let sprintf = Printf.sprintf [@@ocaml.warning "-32"]

(** Minimum sequence of predicates to push *)
let min_push_seq = 3

type string = id [@@ocaml.warning "-34"]

(**
  Further improvements
  * Sort predicates based on rank
*)

let (>::) elt elts =
  Option.value_map ~f:(fun elt -> elt :: elts) ~default:elts elt
[@@ocaml.warning "-32"]

let equal_rule (preds, effects, target) (preds', effects', target') =
  P.equal_predicates preds preds' && Ir.equal_effects effects effects' && Ir.equal_target target target'

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_rules ~f chains =
  Map.map ~f:(fun chn -> { chn with rules = f chn.rules }) chains

let map_predicates ~f rules =
  List.map ~f:(fun (preds, effects, target) -> (f preds, effects, target)) rules

let is_terminal = function
  | Pass | Jump _ -> false
  | Accept | Drop | Return | Reject _ -> true

module Dependencies = struct
  type field =
    | Source_zone | Destination_zone | Packet_mark | Connection_state
    | Source_address | Destination_address | Other_packet_fields

  type writes = field Set.t option

  let none : writes = Some Set.empty
  let union a b = Option.map2 a b ~f:Set.union

  let zone = function
    | Direction.Source -> Source_zone
    | Direction.Destination -> Destination_zone

  let address = function
    | Direction.Source -> Source_address
    | Direction.Destination -> Destination_address

  let reads = function
    | Zone (dir, _), _ -> Set.singleton (zone dir)
    | Mark _, _ -> Set.singleton Packet_mark
    | State _, _ -> Set.singleton Connection_state
    | (Ip4Set (dir, _) | Ip6Set (dir, _)), _ -> Set.singleton (address dir)
    | True, _ -> Set.empty
    | _ -> Set.singleton Other_packet_fields

  let effects effects =
    List.concat_map effects ~f:(function
      | MarkZone (dir, _) -> [zone dir; Packet_mark]
      | Notrack -> [Connection_state]
      | Snat _ -> [Source_address]
      | Counter | Log _ | Comment _ -> [])
    |> Set.of_list
    |> Option.some

  let affects writes pred =
    let reads = reads pred in
    match writes with
    | None -> not (Set.is_empty reads)
    | Some writes -> not (Set.is_empty (Set.inter writes reads))

  let invalidate writes preds =
    List.filter preds ~f:(fun pred -> not (affects writes pred))

  let is_read_only = function
    | Some writes -> Set.is_empty writes
    | None -> false

  let rule summaries (_, effects_, target) =
    let writes = effects effects_ in
    match target with
    | Jump id -> union writes (Map.find_exn summaries id)
    | _ -> writes

  let independent (preds, effects_, target) (preds', effects', target') =
    let writes effects_ = function
      | Jump _ -> None
      | _ -> effects effects_
    in
    let a = writes effects_ target in
    let b = writes effects' target' in
    let has_log = List.exists ~f:(function Log _ -> true | _ -> false) in
    match a, b with
    | Some a', Some b' ->
      Set.is_empty (Set.inter a' b') &&
      not (List.exists preds' ~f:(affects a)) &&
      not (List.exists preds ~f:(affects b)) &&
      (not (has_log effects_) || is_read_only b) &&
      (not (has_log effects') || is_read_only a)
    | _ -> false
end

module Graph = struct
  type t = {
    leaves_first: Chain_id.t list;
    references: (Chain_id.t, int, Chain_id.comparator_witness) Map.t;
  }

  let analyze chains =
    let rec visit active (visited, order) id =
      if Set.mem active id then failwith ("Chain cycle: " ^ Chain_id.show id);
      if Set.mem visited id then visited, order
      else
        let chain = match Map.find chains id with
          | Some chain -> chain
          | None -> failwith ("Missing jump target: " ^ Chain_id.show id)
        in
        let active = Set.add active id in
        let visited, order =
          List.fold chain.rules ~init:(visited, order) ~f:(fun acc -> function
            | _, _, Jump child -> visit active acc child
            | _ -> acc)
        in
        Set.add visited id, id :: order
    in
    let _, order =
      Map.fold chains ~init:(Set.empty, []) ~f:(fun ~key:id ~data:_ acc ->
        if Chain.is_builtin id then visit Set.empty acc id else acc)
    in
    let leaves_first = List.rev order in
    let references =
      List.fold leaves_first ~init:(Map.empty (module Chain_id))
        ~f:(fun refs id ->
          List.fold (Map.find_exn chains id).rules ~init:refs ~f:(fun refs -> function
            | _, _, Jump child ->
              Map.update refs child ~f:(fun n -> Option.value n ~default:0 + 1)
            | _ -> refs))
    in
    { leaves_first; references }

  let reference_count graph id =
    Option.value (Map.find graph.references id) ~default:0
end

let get_ordered_chains chains = (Graph.analyze chains).leaves_first

let process_chains_parents_first ~order chains ~f =
  order
  |> List.rev
  |> List.fold_left ~init:chains ~f

let summarize_writes chains graph =
  graph.Graph.leaves_first
  |> List.fold ~init:(Map.empty (module Chain_id)) ~f:(fun summaries id ->
    let writes =
      if Chain.is_named id then None
      else
        List.fold (Map.find_exn chains id).rules ~init:Dependencies.none
          ~f:(fun writes rule -> Dependencies.union writes (Dependencies.rule summaries rule))
    in
    Map.set summaries ~key:id ~data:writes)

type context = {
  chains: (Chain_id.t, chain, Chain_id.comparator_witness) Map.t;
  graph: Graph.t;
  writes: (Chain_id.t, Dependencies.writes, Chain_id.comparator_witness) Map.t;
}

let analyze chains =
  let graph = Graph.analyze chains in
  { chains; graph; writes = summarize_writes chains graph }

let chain_writes chains = (analyze chains).writes

let input_after_rule summaries input (preds, _, target as rule) =
  match preds with
  | [(p, n)] when is_terminal target && Option.is_none (P.get_implied_predicate (p, n)) ->
    P.inter_preds ((p, not n) :: input)
  | _ when is_terminal target -> input
  | _ -> Dependencies.invalidate (Dependencies.rule summaries rule) input

let rule_inputs context input rules =
  List.fold_map rules ~init:input ~f:(fun input rule ->
    input_after_rule context.writes input rule, (input, rule))
  |> snd

(** Return an ordered list of chains extended inputs for each inputs *)
let map_chains_inputs context =
  let summaries = context.writes in
  (* Get the set of chains *)
  let chains =
    context.graph.leaves_first
    |> List.rev
    |> List.map ~f:(Map.find_exn context.chains)
  in
  (* Map the chains to have initial reduced input. *)
  (* Extend to also handle derived inputs *)
  let _inputs, chains =
    List.fold_map ~init:(Map.empty (module Chain_id)) ~f:(fun inputs chain ->
      let input =
        if Chain.is_named chain.id then []
        else Map.find_multi inputs chain.id |> P.union_preds
      in
      let (inputs, _input) =
        List.fold ~init:(inputs, input) ~f:(fun (inputs, input) -> function
          | (preds, effects, target) as rule ->
            let inputs = match target with
              | Jump id ->
                let input' =
                  P.inter_preds (preds @ input)
                  |> Dependencies.invalidate (Dependencies.effects effects)
                in
                Map.add_multi inputs ~key:id ~data:input'
              | _ -> inputs
            in
            inputs, input_after_rule summaries input rule
        ) chain.rules
      in
      inputs, (input, chain)
    ) chains
  in
  chains

let remap_chain_ids chains =
  let chain_ids =
    get_ordered_chains chains
    |> List.rev
  in
  let chain_map, _ =
    List.fold ~init:(Chain.empty, 1) ~f:(fun (acc, next_id) -> function
      | Chain_id.Temporary _ as chain_id -> Map.add_exn acc ~key:chain_id ~data:(Chain_id.Temporary next_id), next_id + 1
      | _ -> (acc, next_id)
    ) chain_ids
  in
  Map.data chains
  |> List.map ~f:(fun ({ id; rules; _ } as rule) ->
      let id = Map.find chain_map id |> Option.value ~default:id in
      let rules =
        List.map ~f:(function
            | (preds, effects, Ir.Jump target) ->
              let target = Map.find chain_map target |> Option.value ~default:target in
              (preds, effects, Ir.Jump target)
            | rule -> rule
          ) rules
      in
      { rule with id; rules }
  )
  |> List.map ~f:(fun chain -> chain.id, chain)
  |> Map.of_alist_exn (module Chain_id)

(** This should be used with a set of filters *)
let map_rules_input ~f chains =
  let context = analyze chains in
  map_chains_inputs context
  |> List.concat_map ~f:(function
    | (input, ({ id = Temporary _; rules; _ } as chain)) ->
      let rules, new_chains = f context input rules in
      { chain with rules } :: new_chains
    | _, chain -> [chain]
  )
  |> List.map ~f:(fun chain -> chain.id, chain)
  |> Map.of_alist_exn (module Chain_id)


let remove_unsatisfiable_rules context input rules =
  (* Removing complete rules due to unsatifiability is ok *)
  let rules =
    rule_inputs context input rules
    |> List.filter_map ~f:(fun (input, ((preds, _, _) as rule)) ->
      match P.is_satisfiable (input @ preds) with
      | false ->
        printf "U";
        None
      | true -> Some rule
    )
  in
  rules, []

let remove_empty_rules rules =
  List.filter ~f:(function
    | (_, [], Ir.Pass) -> printf "E"; false
    | _ -> true
  ) rules

let union_rule_predicates preds preds' =
  let contains pred = List.exists ~f:(P.equal_predicate pred) in
  let common = List.filter preds ~f:(fun pred -> contains pred preds') in
  let unique preds = List.filter preds ~f:(fun pred -> not (contains pred common)) in
  match unique preds, unique preds' with
  | [], _ | _, [] -> Some common
  (* Predicate.merge_pred does not implement unions for TCP flags. *)
  | [((TcpFlags _ | True), _)], _
  | _, [((TcpFlags _ | True), _)] -> None
  | [a], [b] ->
    P.merge_pred ~tpe:`Union a b
    |> Option.map ~f:(fun union -> P.inter_preds (union :: common))
  | _ -> None

let merge_rules (preds, effects, target) (preds', effects', target') =
  if is_terminal target && equal_target target target' &&
     List.equal equal_effect_ effects effects'
  then
    union_rule_predicates preds preds'
    |> Option.map ~f:(fun preds -> preds, effects, target)
  else None

let rec join_rules_with_same_target = function
  | rule :: ((next_preds, _, _) as next) :: rest ->
    begin match merge_rules rule next with
    | Some merged -> join_rules_with_same_target (merged :: rest)
    | None ->
      let across_next = match rest with
        | ((preds, _, _) as later) :: tail
          when Dependencies.independent next later &&
               P.disjoint next_preds preds ->
          Option.map (merge_rules rule later) ~f:(fun merged ->
            join_rules_with_same_target (merged :: next :: tail))
        | _ -> None
      in
      Option.value_or_thunk across_next ~default:(fun () ->
        rule :: join_rules_with_same_target (next :: rest))
    end
  | rules -> rules

let remove_unreferenced_chains chains =
  let referenced_chains =
    get_ordered_chains chains
    |> Set.of_list
  in
  Map.filter_keys ~f:(Set.mem referenced_chains) chains

let can_inline_call chains summaries ~max_rules (preds, effects, id) =
  let child = Map.find_exn chains id in
  Chain.is_temp id &&
  List.is_empty effects &&
  List.length child.rules <= max_rules &&
  not (List.exists child.rules ~f:(fun (_, _, target) -> equal_target target Return)) &&
  not (List.exists preds ~f:(Dependencies.affects (Map.find_exn summaries id)))

let inline_chains ~max_rules chains =
  let context = analyze chains in
  let summaries = context.writes in
  context.graph.leaves_first
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | (preds, effects, Ir.Jump id) when
                  can_inline_call chains summaries ~max_rules (preds, effects, id) ->
                printf "I";
                let { rules; _ } = Map.find_exn chains id in
                List.map ~f:(fun (preds', effects', target) ->
                  P.inter_preds (preds @ preds'), effects @ effects', target
                ) rules
              | rule -> [rule]
            ) rules
          in
        Some { chain with rules }
        | None ->
          None
      )
    | _ -> chains
  )

let remove_implied_predicates context input rules =
  let rules =
    rule_inputs context input rules
    |> List.map ~f:(fun (input, (preds, effects, target)) ->
      let implied_predicates = P.get_implied_predicates (preds @ input) in
      let preds = List.filter ~f:(fun pred -> List.mem implied_predicates pred ~equal:P.equal_predicate |> not) preds in
      (preds, effects, target)
    )
  in
  rules, []

let rec push_common_predicates ~find_pred context input (rules : Rule.t list) =
  let chains = context.chains in
  (* Create a set of merge sequences based in the input predicate *)
  let rec get_seqeuences ~input head rules =
    (* Find a pred where the the type matches *)
    let get_pred_by_type pred preds  =
      List.find ~f:(fun pred' ->
          P.merge_pred ~tpe:`Union pred pred' |> Option.is_some
        ) preds
    in

    (* Determine if the target and predicates are the same if its a jump target *)
    let match_effect_and_target (_, effects, target) rule' =
      let rec inner = function
        | [] -> true
        | (_, effects', target') :: rules
          when Ir.equal_effects effects effects' &&
               Ir.equal_target target target' ->
          inner rules
        | (_, effects', Jump id) :: rules
          when Chain.is_temp id && Ir.equal_effects effects effects' ->
          Map.find chains id
          |> Option.value_map ~default:false ~f:(fun { rules; _ } ->
            inner rules) &&
          inner rules
        | _ -> false
      in
      inner [rule']
    in

    let can_reorder (preds, effects, target) rules =
      List.for_all ~f:(fun (preds', effects', target') ->
          Dependencies.independent (preds, effects, target) (preds', effects', target') &&
          (match_effect_and_target (preds, effects, target) (preds', effects', target') ||
           P.disjoint preds preds')) rules
    in

    let rec reorder_disjoint pred (acc : Rule.t list) = function
      | [] -> None
      | ((preds, _, _) as rule) :: rules ->
        match find_pred pred preds with
        (* Found a match. See if we can reorder and return if true *)
        | Some pred when can_reorder rule acc ->
          Some (pred, rule, List.rev_append acc rules)
        (* Acc could not be reordered *)
        | Some _ -> None
        | None ->
          (* No match for this rule - continue *)
          reorder_disjoint pred (rule :: acc) rules
    in

    let rec create_seq (acc, seq) = function
      | [] -> (acc, List.rev seq, [])
      | rule :: rules ->
        match reorder_disjoint acc [] (rule :: rules) with
        | None -> (acc, List.rev seq, (rule :: rules))
        | Some (pred, rule, tail) ->
          create_seq (pred, rule :: seq) tail
    in
    match rules with
    | [] -> []
    | ((preds, _, _) as rule) :: rules ->
      match get_pred_by_type input preds with
      | Some pred ->
        let (pred, seq, tail) = create_seq (pred, []) (rule :: rules) in
        let head', tail' = List.split_n (rule :: rules) (List.length seq) in
        (pred, List.rev head, seq, tail) :: get_seqeuences ~input (List.rev_append head' head) tail'
      | None ->
        get_seqeuences ~input (rule :: head) rules
  in
  let input_predicates =
    let rec reduce = function
      | [] -> []
      | pred :: preds when List.exists ~f:(fun pred' -> P.merge_pred pred pred' |> Option.is_some) preds ->
        reduce preds
      | pred :: preds -> pred :: reduce preds
    in
    List.concat_map ~f:(fun (preds, _, _) -> preds) rules
    |> (fun preds -> preds @ P.get_implied_predicates preds)
    |> reduce
  in

  let rank (pred, _, seq, _) = Predicate.cardinal_of_pred pred * List.length seq in
  let sequence =
    List.concat_map ~f:(fun input ->
      get_seqeuences ~input [] rules
    ) input_predicates
    |> List.filter ~f:(fun (_, _, seq, _) -> List.length seq >= min_push_seq)
    (* Remove predicates that have already been matched as part of input *)
    |> List.filter ~f:(fun (pred, _, _, _) -> List.exists ~f:(fun input -> P.equal_predicate pred input) input |> not)
    |> List.filter ~f:(fun (pred, _, _, _) -> not (P.is_always true pred))
    |> List.max_elt ~compare:(fun a b  -> Int.compare (rank a) (rank b))
  in
  match sequence with
  | Some (pred, head, seq, tail) ->
    printf "V";
    (* Map the new chain *)
    let input' = pred :: input in
    let seq', new_chains' = push_common_predicates ~find_pred context input' seq in
    let new_chain = Chain.create seq' (Printf.sprintf "Push common pred: %d: %s" (List.length seq) (P.to_string pred)) in
    let rules = head @ ([pred], [], Ir.Jump new_chain.id) :: tail in
    rules, new_chain :: new_chains'
  | _ -> rules, []

let push_common_predicates_equal =
  let find_pred pred preds =
    List.find ~f:(Predicate.equal_predicate pred) preds
  in
  push_common_predicates ~find_pred

let push_common_predicates_union =
  let find_pred pred preds =
    List.find_map ~f:(fun pred' ->
      P.merge_pred ~tpe:`Union pred pred'
    ) preds
  in
  push_common_predicates ~find_pred


let reduce_predicates context input rules =
  let merge pred input =
    match P.merge_pred ~tpe:`Inter input pred with
    | None -> None (* Cannot reduce *)
    | Some result when P.equal_predicate result input ->
      printf "£";
      Some (True, false);
    | Some result ->
      (* We may have that the input is a,b,c,d and pred id a,b,c. Then we want to
         have !d.
         If input is a,b,c,d and pred is a,b,c,e => !d
      *)
      match P.merge_pred ~tpe:`Diff input pred with
      | Some (p, n) when P.cardinal_of_pred (p, not n) <= P.cardinal_of_pred result &&
                         P.cardinal_of_pred (p, not n) <= P.cardinal_of_pred pred &&
                         P.merge_pred ~tpe:`Inter (p, not n) input |> Option.value_map ~default:false ~f:(P.equal_predicate result) ->
        printf "€";
        Some (p, not n)
      | _ when P.cardinal_of_pred result <= P.cardinal_of_pred pred ->
        printf "§";
        Some result
      | _ ->
        printf "$";
        Some pred
  in

  let rules =
    rule_inputs context input rules
    |> List.map ~f:(fun (input, (preds, effects, target)) ->
      let preds =
        List.map ~f:(fun p -> match List.find_map ~f:(merge p) input with
          | Some p' -> p'
          | None -> p
        ) preds
      in
      (preds, effects, target)
    )
  in
  rules, []

let rec eliminate_unreachable_rules = function
  | (preds, _effects, target) as rule :: rs when
      is_terminal target && P.preds_all_true preds ->
    List.iter ~f:(fun _ -> printf "X") rs;
    [ rule ]
  | r :: rs -> r :: eliminate_unreachable_rules rs
  | [] -> []

(** All predicates which is always true are removed *)
let remove_true_predicates rules =
  List.map ~f:(fun (preds, effects, target) ->
    (List.filter_map ~f:(fun pred -> match P.is_always true pred with
       | true -> printf "E"; P.get_implied_predicate pred
       | false -> Some pred
    ) preds, effects,target)) rules

(** Push predicates to sub-chains if the predicate are already present on the subchains
  * This only works for chains that has only one reference.
*)
let push_predicates ~min_push chains =
  let context = analyze chains in
  let summaries = context.writes in
  (* Replace the chain with a chain where all rules have been extended with pred *)
  let merge pred preds = pred :: preds in

  let push rules pred =
    List.map ~f:(fun (preds, effects, target) ->
      (merge pred preds, effects, target)
    ) rules
  in

  let can_merge pred pred' =
    P.merge_pred pred pred' |> Option.is_some
  in

  let has_conflict pred pred' =
    can_merge pred pred' |> not
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
    count * 100 / (List.length rules + 1)
  in

  let process_chain_rules chains rules =
    let chains, rules =
      List.fold ~init:(chains, []) ~f:(fun (chains, acc) -> function
        | (preds, effects, (Ir.Jump target_id as target)) as rule when
            Chain.is_temp target_id &&
            List.is_empty effects &&
            Graph.reference_count context.graph target_id = 1 -> begin
            match Map.find chains target_id with
            | None -> chains, rule :: acc
            | Some target_chain ->
              let target_rules, preds =
                List.fold ~init:(target_chain.rules, []) ~f:(fun (target_rules, acc) pred ->
                  match
                    not (Dependencies.affects (Map.find_exn summaries target_id) pred) &&
                    can_merge_rules rules pred && count_merges target_rules pred >= min_push
                  with
                  | false -> (target_rules, pred :: acc)
                  | true ->
                    printf ">";
                    push target_rules pred, acc
                ) preds
              in
              let chains = Map.set chains ~key:target_id ~data:{ target_chain with rules = target_rules } in
              chains, (List.rev preds, effects, target) :: acc
          end
        | rule -> chains, rule :: acc
      ) rules
    in
    chains, List.rev rules
  in

  (* Take all chains in order and start replacing. *)
  process_chains_parents_first ~order:context.graph.leaves_first ~f:(fun chains chain_id ->
    match Map.find chains chain_id with
    | Some ({ rules; _ } as chain) ->
      let chains, rules = process_chain_rules chains rules in
      Map.set chains ~key:chain_id ~data:{chain with rules}
    | _ -> chains
  ) chains

let inline_pure_jumps chains =
  let context = analyze chains in
  let summaries = context.writes in
  context.graph.leaves_first
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | None -> None
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | ([], [], Ir.Jump target) as rule when
                  can_inline_call chains summaries ~max_rules:Int.max_value ([], [], target) ->
                printf "P";
                Map.find chains target
                |> Option.value_map ~default:[rule] ~f:(fun { rules; _ } -> rules)
              | rule -> [rule]
            ) rules
          in
          Some { chain with rules }
      )
    | _ -> chains
  )

let reduce_chain_indegree ~max_indegree chains =
  let graph = Graph.analyze chains in
  let folding_map_chain_rules chains ~(init:'acc) ~(f: 'acc -> 'rule -> 'acc * 'rule) =
    Map.keys chains
    |> List.fold ~init:(chains, init) ~f:(fun (chains, acc) chain_id ->
      match Map.find chains chain_id with
      | Some ({ id = Temporary _; rules; _ } as chain) ->
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
      | _ -> (chains, acc)
    )
  in
  let replace_chain chain acc = function
    | (preds, effects, Jump id) when Chain_id.equal id chain.id ->
      let new_chain = Chain.create chain.rules "Duplicate" in
      new_chain :: acc, (preds, effects, Jump new_chain.id)
    | rule -> acc, rule
  in

  process_chains_parents_first ~order:graph.leaves_first ~f:(fun chains chain_id ->
    match Map.find chains chain_id, Graph.reference_count graph chain_id > max_indegree with
    | Some chain, true when Chain.is_temp chain.id ->
      let chains, new_chains = folding_map_chain_rules chains ~init:[] ~f:(replace_chain chain) in
      List.fold ~init:chains ~f:(fun chains chain -> Map.add_exn chains ~key:chain.id ~data:chain) new_chains
    | _, _ -> chains
  ) chains


let merge_identical_chains chains =
  let rec inner acc = function
    | { id; rules; _ } :: chains ->
      let to_merge, rest = List.partition_tf ~f:(fun { rules = rules'; _ } -> List.equal equal_rule rules rules') chains in
      let acc = List.fold ~init:acc ~f:(fun acc { id = id'; _ } -> Map.add_exn ~key:id' ~data:id acc) to_merge in
      inner acc rest
    | [] -> acc
  in
  let replace_map =
    Map.data chains
    |> List.filter ~f:(fun chain -> Chain.is_temp chain.id)
    |> inner (Map.empty (module Chain_id))
  in
  (* Replace all jumps *)
  map_rules ~f:(fun rules ->
    List.map ~f:(function
      | (pred, effects, Jump id) when Map.mem replace_map id ->
        printf "M";
        let id = Map.find_exn replace_map id in
        (pred, effects, Jump id)
      | rule -> rule
    ) rules
  ) chains

let rec join_rules = function
  | first :: second :: rest ->
    begin match merge_rules first second with
    | Some merged -> join_rules (merged :: rest)
    | None -> first :: join_rules (second :: rest)
    end
  | rules -> rules

(** filter rules that a a subset of a later or previous rule.
    When doing a forward pass, we can safely remove any rule that is a subset.
    When doing a backward pass (rollup) both effects and target must be the same.
*)
let filter_covered_subset chains =
  let summaries = chain_writes chains in
  let rec get_rules = function
    (* User-defined chains can be populated outside the generated ruleset. *)
    | (_, _, Jump (Named _)) as rule -> [rule]
    | (preds, [], Jump chain_id) as rule ->
      let chain = Map.find_exn chains chain_id in
      if Dependencies.is_read_only (Map.find_exn summaries chain_id) &&
         List.for_all chain.rules ~f:(fun (_, _, target) -> is_terminal target)
      then
        List.concat_map ~f:get_rules chain.rules
        |> List.map ~f:(fun (preds', effects', target) -> (preds @ preds', effects', target))
      else [rule]
    | rule -> [rule]
  in

  let can_rollup (preds, effects, target) rules =
    List.for_all ~f:(fun (preds', effects', target') ->
      equal_effects effects effects' &&
      Ir.equal_target target target' &&
      P.subset_preds ~of_:preds preds'
    ) rules
  in
  let rec forward ((matched_preds, _, _) as rule) = function
    | (preds, _, _) :: rs
      when P.subset_preds ~of_:matched_preds preds ->
      printf "F";
      forward rule rs
    | r :: rs ->
      if List.exists matched_preds ~f:(Dependencies.affects (Dependencies.rule summaries r))
      then r :: rs
      else r :: forward rule rs
    | [] -> []
  in
  (* If a jump only has the same targets, and all are subsets we can drop the jump *)
  let rec rollup ((preds, _effects, _target) as rule) =
    function
    | [] -> []
    | r :: rs ->
      let rules = get_rules r in
      match can_rollup rule rules with
      | true ->
        printf "R";
        rollup rule rs
      | false when
          not (List.exists preds ~f:(Dependencies.affects (Dependencies.rule summaries r))) &&
          List.for_all ~f:(fun (preds', _, _) -> Predicate.disjoint preds preds') rules ->
        r :: rollup rule rs
      | false -> r :: rs
  in

  let rec loop ~f = function
    | (_, _, target) as rule :: rules when is_terminal target ->
      let rest = f rule rules in
      rule :: loop ~f rest
    | rule :: rules -> rule :: loop ~f rules
    | [] -> []
  in
  let map_rules rules =
    loop ~f:forward rules
    |> List.rev
    |> loop ~f:rollup
    |> List.rev
  in
  Map.map ~f:(fun chn -> { chn with rules = map_rules chn.rules }) chains

let reorder_rules rules =
  let order_target = function
    | Ir.Accept -> 1
    | Drop -> 2
    | Reject _ -> 3
    | Return -> 4
    | Pass -> 5
    | Jump _ -> 6
  in
  let rec inner acc = function
    | [] -> List.rev acc
    | ((preds, effects, target) as rule1) :: ((preds', effects', target') as rule2) :: rules
      when
        Dependencies.independent rule1 rule2 &&
        (
        (Ir.equal_target target target' && equal_effects effects effects' &&
         P.costs preds' < P.costs preds) ||
        (order_target target' < order_target target && P.disjoint preds preds')
        )
      ->
      printf "^";
      inner [] (List.rev_append acc (rule2 :: rule1 :: rules))
    | rule :: rules ->
      inner (rule :: acc) rules
  in
  inner [] rules


let reorder_preds preds =
  List.stable_sort ~compare:(fun a b -> Int.compare (P.cost a) (P.cost b)) preds

let same_chains =
  Map.equal (fun a b ->
    List.equal (fun (preds, effects, target) (preds', effects', target') ->
      P.equal_predicates preds preds' &&
      List.equal equal_effect_ effects effects' &&
      equal_target target target') a.rules b.rules)

let run_pass name f chains =
  let started = Stdlib.Sys.time () in
  let before = Chain.count_rules chains, Chain.count_predicates chains in
  printf "\n# Optimize %s: %!" name;
  let result = f chains in
  let rules, predicates = before in
  printf " rules %d -> %d, predicates %d -> %d, cpu %.3f ms\n"
    rules (Chain.count_rules result) predicates (Chain.count_predicates result)
    ((Stdlib.Sys.time () -. started) *. 1000.);
  result

let until_stable ~name ~max_rounds f chains =
  let rec loop remaining chains =
    let result = f chains in
    if same_chains chains result then result
    else if remaining = 1 then begin
      printf "\n# Optimize %s: reached %d-round budget\n" name max_rounds;
      result
    end
    else loop (remaining - 1) result
  in
  loop max_rounds chains

let simplify chains =
  let once chains =
    chains
    |> run_pass "normalize" (map_rules ~f:(map_predicates ~f:P.inter_preds))
    |> run_pass "merge adjacent rules" (map_rules ~f:join_rules)
    |> run_pass "reduce predicates" (map_rules_input ~f:reduce_predicates)
    |> run_pass "remove empty rules" (map_rules ~f:remove_empty_rules)
    |> run_pass "remove impossible rules" (map_rules_input ~f:remove_unsatisfiable_rules)
    |> run_pass "remove true predicates" (map_rules ~f:remove_true_predicates)
    |> run_pass "remove unreachable rules" (map_rules ~f:eliminate_unreachable_rules)
    |> run_pass "remove covered rules" filter_covered_subset
    |> run_pass "merge matching targets" (map_rules ~f:join_rules_with_same_target)
    |> run_pass "remove unused chains" remove_unreferenced_chains
  in
  until_stable ~name:"simplification" ~max_rounds:8 once chains

let dump_chains chains =
  let graph = Graph.analyze chains in
  graph.leaves_first
  |> List.rev
  |> List.filter_map ~f:(fun chain -> Map.find chains chain)
  |> List.iter ~f:(fun {id; rules; _ } ->
    printf "# Chain %s. Rules %3d. Ref: %2d\n" (Chain_id.show id) (List.length rules) (Graph.reference_count graph id)
  )

let optimize chains =
  let factor chains =
    chains
    |> run_pass "push call guards" (push_predicates ~min_push:2)
    |> run_pass "factor predicate unions" (map_rules_input ~f:push_common_predicates_union)
    |> run_pass "factor equal predicates" (map_rules_input ~f:push_common_predicates_equal)
    |> simplify
  in
  chains
  |> simplify
  |> run_pass "specialize callers" (reduce_chain_indegree ~max_indegree:1)
  |> run_pass "inline expanded calls" (inline_chains ~max_rules:10000)
  |> simplify
  |> until_stable ~name:"factoring" ~max_rounds:4 factor
  |> run_pass "inline small calls" (inline_chains ~max_rules:2)
  |> run_pass "inline pure jumps" inline_pure_jumps
  |> run_pass "merge identical chains" merge_identical_chains
  |> run_pass "order independent rules" (map_rules ~f:reorder_rules)
  |> simplify
  |> run_pass "remove implied predicates" (map_rules_input ~f:remove_implied_predicates)
  |> run_pass "order predicates" (map_rules ~f:(map_predicates ~f:reorder_preds))
  |> run_pass "renumber temporary chains" remap_chain_ids
  |> (fun chains -> dump_chains chains; chains)

module Test = struct
  open OUnit2
  open Chain_id

  type observation = {
    accepted: bool;
    source_zone: string option;
    counters: int;
    logs: string list;
  } [@@deriving show]

  let tcp = 6
  let udp = 17
  let icmpv6 = 58

  let protocol_name = function
    | 6 -> "TCP"
    | 17 -> "UDP"
    | 58 -> "ICMPv6"
    | value -> Int.to_string value

  let protocols values = Protocol (Set.of_list values), false
  let except_protocols values = Protocol (Set.of_list values), true
  let source_zones values = Zone (Direction.Source, Set.of_list values), false

  let rule ?(when_=[]) ?(effects=[]) target = when_, effects, target

  let chain id rules = { id; rules; comment = "Optimizer regression" }
  let input rules = chain (Builtin Chain_type.Input) rules

  let chain_map chains =
    List.map chains ~f:(fun chain -> chain.id, chain)
    |> Map.of_alist_exn (module Chain_id)

  let denied = {
    accepted = false;
    source_zone = None;
    counters = 0;
    logs = [];
  }

  let allowed = { denied with accepted = true }

  let observe ~context chains protocol =
    let source_zone = ref None in
    let counters = ref 0 in
    let logs = ref [] in
    let matches = function
      | Protocol values, neg -> Set.mem values protocol <> neg
      | Zone (Direction.Source, values), neg ->
        Set.mem values (Option.value !source_zone ~default:"unclassified") <> neg
      | True, neg -> not neg
      | pred -> failwith ("Unsupported test predicate: " ^ P.to_string pred)
    in
    let apply_effect = function
      | MarkZone (Direction.Source, zone) -> source_zone := Some zone
      | Counter -> Int.incr counters
      | Log prefix -> logs := prefix :: !logs
      | Comment _ -> ()
      | _ -> failwith "Unsupported test effect"
    in
    let rec run_chain id =
      match Map.find chains id with
      | Some chain -> run_rules chain.rules
      | None ->
        assert_failure (context ^ ": missing jump target")
    and run_rules = function
      | [] -> None
      | (preds, effects, target) :: rest ->
        if not (List.for_all preds ~f:matches) then run_rules rest
        else begin
          List.iter effects ~f:apply_effect;
          match target with
          | Accept -> Some true
          | Drop | Reject _ -> Some false
          | Return -> None
          | Pass -> run_rules rest
          | Jump id ->
            match run_chain id with
            | Some _ as result -> result
            | None -> run_rules rest
        end
    in
    let accepted =
      Option.value (run_chain (Builtin Chain_type.Input)) ~default:false
    in
    {
      accepted;
      source_zone = !source_zone;
      counters = !counters;
      logs = List.rev !logs;
    }

  let check_optimization ~optimize ~chains ~cases =
    let check phase chains =
      List.iter cases ~f:(fun (protocol, expected) ->
        let context = phase ^ ": " ^ protocol_name protocol in
        assert_equal ~printer:show_observation
          ~msg:context expected (observe ~context chains protocol))
    in
    check "Original rules" chains;
    check "Optimized rules" (optimize chains)

  let expect_rule_count expected chains =
    assert_equal ~msg:"Generated rule count" ~printer:Int.to_string
      expected (Chain.count_rules chains);
    chains

  let%test_unit "terminal unions retain a shared conjunction" =
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "lan")] Pass;
        rule ~when_:[source_zones ["lan"]; protocols [tcp]]
          ~effects:[Counter; Log "allowed"] Accept;
        rule ~when_:[source_zones ["lan"]; protocols [udp]]
          ~effects:[Counter; Log "allowed"] Accept;
        rule Drop;
      ];
    ] in
    let optimize chains = map_rules ~f:join_rules chains |> expect_rule_count 3 in
    check_optimization ~optimize ~chains
      ~cases:[
        tcp, { allowed with source_zone = Some "lan"; counters = 1; logs = ["allowed"] };
        udp, { allowed with source_zone = Some "lan"; counters = 1; logs = ["allowed"] };
        icmpv6, { denied with source_zone = Some "lan" };
      ]

  let%test_unit "terminal unions preserve correlations between dimensions" =
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "one")] Pass;
        rule ~when_:[source_zones ["one"]; protocols [tcp]] Accept;
        rule ~when_:[source_zones ["two"]; protocols [udp]] Accept;
        rule Drop;
      ];
    ] in
    let optimize chains =
      map_rules ~f:join_rules_with_same_target chains |> expect_rule_count 4
    in
    check_optimization ~optimize ~chains
      ~cases:[
        tcp, { allowed with source_zone = Some "one" };
        udp, { denied with source_zone = Some "one" };
      ]

  let%test_unit "push_predicates preserves every moved guard" =
    let child = Temporary 1 in
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp; udp]; protocols [udp; icmpv6]]
          (Jump child);
        rule Drop;
      ];
      chain child [rule ~when_:[protocols [tcp; udp; icmpv6]] Accept];
    ] in
    (* Keep both guards to exercise this pass before predicate normalization. *)
    check_optimization ~optimize:(push_predicates ~min_push:2) ~chains
      ~cases:[
        udp, allowed;
        icmpv6, denied;
        tcp, denied;
      ]

  let%test_unit "non-terminal effects do not exclude subsequent jump inputs" =
    let child = Temporary 1 in
    let chains = chain_map [
      input [
        rule ~when_:[protocols [udp]] ~effects:[Counter] Pass;
        rule ~when_:[protocols [udp]] (Jump child);
        rule Drop;
      ];
      chain child [rule Accept];
    ] in
    check_optimization
      ~optimize:(map_rules_input ~f:remove_unsatisfiable_rules) ~chains
      ~cases:[
        udp, { allowed with counters = 1 };
        tcp, denied;
      ]

  let%test_unit "reorder_rules preserves overlapping zone-mark effects" =
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp; udp]]
          ~effects:[MarkZone (Direction.Source, "int")] Pass;
        rule ~when_:[protocols [tcp]]
          ~effects:[MarkZone (Direction.Source, "guest")] Pass;
        rule Accept;
      ];
    ] in
    check_optimization ~optimize:(map_rules ~f:reorder_rules) ~chains
      ~cases:[
        tcp, { allowed with source_zone = Some "guest" };
        udp, { allowed with source_zone = Some "int" };
        icmpv6, allowed;
      ]

  let%test_unit "reorder_rules preserves first matching terminal effects" =
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp; udp]] ~effects:[Log "first"] Accept;
        rule ~when_:[protocols [tcp]] ~effects:[Log "second"] Accept;
        rule Drop;
      ];
    ] in
    check_optimization ~optimize:(map_rules ~f:reorder_rules) ~chains
      ~cases:[
        tcp, { allowed with logs = ["first"] };
        udp, { allowed with logs = ["first"] };
        icmpv6, denied;
      ]

  let%test_unit "referenced named chains remain reachable" =
    let named = Named "local_policy" in
    let chains = chain_map [
      input [rule (Jump named)];
      chain named [rule Accept];
    ] in
    check_optimization ~optimize:remove_unreferenced_chains ~chains
      ~cases:[udp, allowed]

  let%test_unit "reordering cannot move a zone test before its writer" =
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "before")] Pass;
        rule ~when_:[source_zones ["before"]]
          ~effects:[MarkZone (Direction.Source, "after")] Pass;
        rule ~when_:[source_zones ["after"]] Accept;
        rule Drop;
      ];
    ] in
    check_optimization ~optimize:(map_rules ~f:reorder_rules) ~chains
      ~cases:[udp, { allowed with source_zone = Some "after" }]

  let%test_unit "input-sensitive passes forget overwritten zone facts" =
    let parent = Temporary 1 in
    let child = Temporary 2 in
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "before")] Pass;
        rule ~when_:[source_zones ["before"]] (Jump parent);
      ];
      chain parent [
        rule ~effects:[MarkZone (Direction.Source, "after")] Pass;
        rule ~when_:[source_zones ["after"]] (Jump child);
      ];
      chain child [rule ~when_:[source_zones ["after"]] Accept];
    ] in
    let optimize chains =
      chains
      |> map_rules_input ~f:remove_unsatisfiable_rules
      |> map_rules_input ~f:reduce_predicates
      |> map_rules_input ~f:remove_implied_predicates
    in
    check_optimization ~optimize ~chains
      ~cases:[udp, { allowed with source_zone = Some "after" }]

  let%test_unit "user-chain calls invalidate facts used by later jumps" =
    let parent = Temporary 1 in
    let child = Temporary 2 in
    let hook = Named "change_zone" in
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "before")] Pass;
        rule ~when_:[source_zones ["before"]] (Jump parent);
      ];
      chain parent [
        rule (Jump hook);
        rule ~when_:[source_zones ["after"]] (Jump child);
      ];
      chain hook [rule ~effects:[MarkZone (Direction.Source, "after")] Return];
      chain child [rule Accept];
    ] in
    check_optimization
      ~optimize:(map_rules_input ~f:remove_unsatisfiable_rules) ~chains
      ~cases:[udp, { allowed with source_zone = Some "after" }]

  let%test_unit "covered-rule removal stops at writes to the covering predicate" =
    let chains = chain_map [
      input [
        rule ~when_:[source_zones ["after"]] Drop;
        rule ~effects:[MarkZone (Direction.Source, "after")] Pass;
        rule ~when_:[source_zones ["after"]] Accept;
      ];
    ] in
    check_optimization ~optimize:filter_covered_subset ~chains
      ~cases:[udp, { allowed with source_zone = Some "after" }]

  let%test_unit "inlining preserves caller effects when the child does not match" =
    let parent = Temporary 1 in
    let child = Temporary 2 in
    let chains = chain_map [
      input [rule (Jump parent)];
      chain parent [
        rule ~when_:[protocols [udp]] ~effects:[Counter] (Jump child);
        rule Accept;
      ];
      chain child [rule ~when_:[protocols [tcp]] Accept];
    ] in
    check_optimization ~optimize:(inline_chains ~max_rules:3) ~chains
      ~cases:[
        udp, { allowed with counters = 1 };
        tcp, allowed;
      ]

  let%test_unit "shared descendants receive inputs from every caller path" =
    let left = Temporary 1 in
    let right = Temporary 2 in
    let shared = Temporary 3 in
    let chains = chain_map [
      input [
        rule ~when_:[protocols [udp]] (Jump left);
        rule ~when_:[protocols [tcp]] (Jump right);
        rule Drop;
      ];
      chain left [rule (Jump shared)];
      chain right [rule (Jump left)];
      chain shared [rule ~when_:[protocols [tcp; udp]] Accept];
    ] in
    check_optimization
      ~optimize:(map_rules_input ~f:remove_unsatisfiable_rules) ~chains
      ~cases:[tcp, allowed; udp, allowed; icmpv6, denied]

  let%test_unit "both inliners preserve the frame of an explicit return" =
    let parent = Temporary 1 in
    let child = Temporary 2 in
    let chains = chain_map [
      input [rule (Jump parent); rule Drop];
      chain parent [rule (Jump child); rule Accept];
      chain child [rule Return];
    ] in
    let optimize chains =
      chains |> inline_chains ~max_rules:3 |> inline_pure_jumps
    in
    check_optimization ~optimize ~chains ~cases:[udp, allowed]

  let%test_unit "inlining does not repeat a guard changed by the child" =
    let parent = Temporary 1 in
    let child = Temporary 2 in
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "before")] Pass;
        rule (Jump parent);
      ];
      chain parent [rule ~when_:[source_zones ["before"]] (Jump child)];
      chain child [
        rule ~effects:[MarkZone (Direction.Source, "after")] Pass;
        rule ~effects:[Counter] Accept;
      ];
    ] in
    check_optimization ~optimize:(inline_chains ~max_rules:3) ~chains
      ~cases:[udp, { allowed with source_zone = Some "after"; counters = 1 }]

  let overlapping_nonterminal_effects = chain_map [
    input [
      rule ~when_:[except_protocols [tcp]]
        ~effects:[Counter; Log "matched"] Pass;
      rule ~when_:[except_protocols [udp]]
        ~effects:[Counter; Log "matched"] Pass;
      rule Accept;
    ];
  ]

  let%test_unit "join_rules preserves counter and log multiplicity" =
    check_optimization ~optimize:(map_rules ~f:join_rules)
      ~chains:overlapping_nonterminal_effects
      ~cases:[
        tcp, { allowed with counters = 1; logs = ["matched"] };
        udp, { allowed with counters = 1; logs = ["matched"] };
        icmpv6, { allowed with counters = 2; logs = ["matched"; "matched"] };
      ]

  let%test_unit "join_rules_with_same_target preserves effect multiplicity" =
    check_optimization ~optimize:(map_rules ~f:join_rules_with_same_target)
      ~chains:overlapping_nonterminal_effects
      ~cases:[
        tcp, { allowed with counters = 1; logs = ["matched"] };
        udp, { allowed with counters = 1; logs = ["matched"] };
        icmpv6, { allowed with counters = 2; logs = ["matched"; "matched"] };
      ]

  let overlapping_returning_jumps =
    let child = Temporary 1 in
    chain_map [
      input [
        rule ~when_:[except_protocols [tcp]] (Jump child);
        rule ~when_:[except_protocols [udp]] (Jump child);
        rule Accept;
      ];
      chain child [rule ~effects:[Counter; Log "visited"] Return];
    ]

  let%test_unit "join_rules preserves repeated returning jumps" =
    check_optimization ~optimize:(map_rules ~f:join_rules)
      ~chains:overlapping_returning_jumps
      ~cases:[
        tcp, { allowed with counters = 1; logs = ["visited"] };
        udp, { allowed with counters = 1; logs = ["visited"] };
        icmpv6, { allowed with counters = 2; logs = ["visited"; "visited"] };
      ]

  let%test_unit "join_rules_with_same_target preserves repeated returning jumps" =
    check_optimization ~optimize:(map_rules ~f:join_rules_with_same_target)
      ~chains:overlapping_returning_jumps
      ~cases:[
        tcp, { allowed with counters = 1; logs = ["visited"] };
        udp, { allowed with counters = 1; logs = ["visited"] };
        icmpv6, { allowed with counters = 2; logs = ["visited"; "visited"] };
      ]
end
