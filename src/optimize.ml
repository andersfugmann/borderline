open Base
module Set = Set.Poly
open Ir
open Poly
module Ip6Set = Ipset.Ip6Set
module Ip4Set = Ipset.Ip4Set
module P = Predicate

let printf = Stdio.printf
let sprintf = Printf.sprintf [@@ocaml.warning "-32"]


type string = id [@@ocaml.warning "-34"]

(**
  Further improvements
  * Sort predicates based on rank
*)

let (>::) elt elts =
  Option.value_map ~f:(fun elt -> elt :: elts) ~default:elts elt
[@@ocaml.warning "-32"]

let chain_reference_count id chains =
  let count_references acc rules =
    List.fold_left ~init:acc ~f:(fun acc -> function (_, _, Jump id') when Chain_id.equal id id' -> acc + 1 | _ -> acc)  rules
  in
  Map.fold ~init:0 ~f:(fun ~key:_ ~data:chn acc -> (count_references acc chn.rules)) chains

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

(** Return a list of chains with leaves first *)
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
        | (_pred, _effect, Jump ((Temporary _) as chain_id)) -> traverse_chains seen chains acc chain_id
        | _ -> acc
      ) rules
    | None -> acc
  in
  (* Traverse all builtin chains *)
  Map.fold chains ~init:[] ~f:(fun ~key ~data:_ acc ->
    match key with
    | (Ir.Chain_id.Builtin _) as chain_id ->
      traverse_chains (Set.empty) chains acc chain_id
    | _ -> acc
  )
  |> List.stable_dedup ~compare:Ir.Chain_id.compare

let process_chains_breath_first chains ~f =
  get_ordered_chains chains
  |> List.rev
  |> List.fold_left ~init:chains ~f

(** Return an ordered list of chains extended inputs for each inputs *)
let map_chains_inputs chains =
  (* Get the set of chains *)
  let chains =
    get_ordered_chains chains
    |> List.rev
    |> List.filter_map ~f:(Map.find chains)
  in
  (* Map the chains to have initial reduced input. *)
  (* Extend to also handle derived inputs *)
  let _inputs, chains =
    List.fold_map ~init:(Map.empty (module Chain_id)) ~f:(fun inputs chain ->
      let input =
        Map.find_multi inputs chain.id
        |> P.union_preds
      in
      let (inputs, _input) =
        List.fold ~init:(inputs, input) ~f:(fun (inputs, input) -> function
          | (preds, _, Jump id) ->
            let input' = P.inter_preds (preds @ input) in
            let inputs = Map.add_multi inputs ~key:id ~data:input' in
            (inputs, input)
            (* Only use the single predicate as filter if it has no implied predicate, i.e. its not ipv4 filter *)
          | ([(p, n)], _, _) when P.get_implied_predicate (p,n) |> Option.is_none ->
            inputs, P.inter_preds ((p, not n) :: input)
          | _ ->
            inputs, input
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
  map_chains_inputs chains
  |> List.concat_map ~f:(function
    | (input, ({ id = Temporary _; rules; _ } as chain)) ->
      let rules, new_chains = f chains input rules in
      { chain with rules } :: new_chains
    | _, chain -> [chain]
  )
  |> List.map ~f:(fun chain -> chain.id, chain)
  |> Map.of_alist_exn (module Chain_id)


let remove_unsatisfiable_rules _chains input rules =
  (* Removing complete rules due to unsatifiability is ok *)
  let rules =
    List.filter ~f:(fun (preds, _, _) ->
      match P.is_satisfiable (input @ preds) with
      | false ->
        printf "U";
        false
      | true -> true
    ) rules
  in
  rules, []

let remove_empty_rules rules =
  List.filter ~f:(function
    | (_, [], Ir.Pass) -> printf "E"; false
    | _ -> true
  ) rules

let rec join_rules_with_same_target =
  let is_union_true pred pred' =
    P.merge_pred ~tpe:`Union pred pred'
    |> Option.value_map ~f:(P.is_always true) ~default:false
  in

  let common preds preds' =
    List.filter ~f:(fun pred ->
      List.exists ~f:(P.equal_predicate pred) preds'
    ) preds
  in
  (* Return common, uniq_a, uniq_b *)
  let mutual_differences preds1 preds2 =
    let exclusive p p' =
      List.filter ~f:(fun pred ->
        List.exists ~f:(P.equal_predicate pred) p' |> not)
        p
    in
    let common = common preds1 preds2 in
    let preds1' = exclusive preds1 common in
    let preds2' = exclusive preds2 common in
    common, preds1', preds2'
  in

  let can_merge (preds, effects, target) = function
    | (preds', effects', target') when
        equal_target target target' &&
        equal_effects effects effects' ->
      begin
        match mutual_differences preds preds' with
        | (_common, [pred], [pred']) -> is_union_true pred pred'
        | (_common, [], _)
        | (_common, _, []) -> true
        | _ -> false
      end
    | _ -> false
  in

  function
  | ((preds1, effects, target) as rule1) :: ((preds2, _, _) as rule2) :: rules when can_merge rule1 rule2 ->
    let common = common preds1 preds2 in
    join_rules_with_same_target ((common, effects, target) :: rules)
  | ((preds1, effects, target) as rule1) :: ((preds3, _, _) as rule3) :: ((preds2, _, _) as rule2) :: rules
    when can_merge rule1 rule2 && P.disjoint preds3 preds2 ->
    let common = common preds1 preds2 in
    join_rules_with_same_target ((common, effects, target) :: rule3 :: rules)
  | rule :: rules ->
    rule :: join_rules_with_same_target rules
  | [] -> []

let remove_unreferenced_chains chains =
  let referenced_chains =
    get_ordered_chains chains
    |> Set.of_list
  in
  Map.filter_keys ~f:(Set.mem referenced_chains) chains

let inline_chains ~max_rules chains =
  let should_inline chains id =
    match Map.find chains id with
    | Some { rules; _ } -> Chain.is_temp id && List.length rules <= max_rules
    | None -> false
  in
  get_ordered_chains chains
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | (preds, effects, Ir.Jump id) when should_inline chains id->
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

let remove_implied_predicates _chains input rules =
  let rules =
    List.map ~f:(fun (preds, effects, target) ->
      let implied_predicates = P.get_implied_predicates (preds @ input) in
      let preds = List.filter ~f:(fun pred -> List.mem implied_predicates pred ~equal:P.equal_predicate |> not) preds in
      (preds, effects, target)
    ) rules
  in
  rules, []

let rec push_common_predicates ~find_pred chains input (rules : Rule.t list) =
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
          when Ir.equal_effects effects effects' ->
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
          match_effect_and_target (preds, effects, target) (preds', effects', target') ||
          P.disjoint preds preds') rules
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

  let rank (_, _, seq, _) = List.length seq in
  let sequence =
    List.concat_map ~f:(fun input ->
      get_seqeuences ~input [] rules
    ) input_predicates
    |> List.filter ~f:(fun (_, _, seq, _) -> List.length seq >= 2)
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
    let seq', new_chains' = push_common_predicates ~find_pred chains input' seq in
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


let reduce_predicates _chains input rules =
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

  let rules, _input =
    List.fold ~init:([], input) ~f:(fun (acc, input) (preds, effects, target) ->
      let preds =
        List.map ~f:(fun p -> match List.find_map ~f:(merge p) input with
          | Some p' -> p'
          | None -> p
        ) preds
      in
      let input = match preds with
        | [(p,n)] when
            is_terminal target &&
            P.get_implied_predicate (p,n) |> Option.is_none ->
          P.inter_preds ((p, not n) :: input)
        | _ -> input
      in
      (preds, effects, target) :: acc, input
    ) rules
  in
  List.rev rules, []

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
    count * 100 / (List.length rules + 1)
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

let inline_pure_jumps chains =
  get_ordered_chains chains
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | None -> None
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | ([], [], Ir.Jump target) as rule ->
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

  process_chains_breath_first ~f:(fun chains chain_id ->
    match Map.find chains chain_id, chain_reference_count chain_id chains > max_indegree with
    | Some chain, true ->
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
  let replace_map = inner (Map.empty (module Chain_id)) (Map.data chains) in
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
  | (([pred], effects, target) as r1) :: (([pred'], effects', target') as r2) :: rules
    when equal_effects effects effects' && equal_target target target' ->
    begin
      match P.merge_pred ~tpe:`Union pred pred' with
      | Some pred -> join_rules (([pred], effects, target) :: rules)
      | None -> r1 :: join_rules (r2 :: rules)
    end
  | r1 :: rules -> r1 :: join_rules rules
  | [] -> []

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
    | ((preds, _effects, target) as rule1) :: ((preds', _effects', target') as rule2) :: rules
      when
        (Ir.equal_target target target' && P.costs preds' < P.costs preds) ||
        (order_target target' < order_target target && P.disjoint preds preds')
      ->
      printf "^";
      inner [] (List.rev_append acc (rule2 :: rule1 :: rules))
    | rule :: rules ->
      inner (rule :: acc) rules
  in
  inner [] rules


let reorder_preds preds =
  List.stable_sort ~compare:(fun a b -> Int.compare (P.cost a) (P.cost b)) preds

let optimize_pass ~stage chains =
  let (@@) a b = a ~f:b in
  let optimize_functions =
    [
      [1;       ], reduce_chain_indegree ~max_indegree:1;
      [1;       ], inline_chains ~max_rules:10000;
      [  2      ], inline_chains ~max_rules:3;
      [    3;4;5], inline_chains ~max_rules:1;
      [1;2;3;4;5], map_rules @@ map_predicates @@ P.inter_preds;
      [1;2;3;4;5], map_rules @@ join_rules;
      [1;2;3;4;5], map_rules_input @@ reduce_predicates;
      [        5], map_rules_input @@ remove_implied_predicates;
      [1;2;3;4;5], map_rules @@ remove_empty_rules;
      [1;2;3;4;5], map_rules_input @@ remove_unsatisfiable_rules;
      [1;2;3;4;5], map_rules @@ remove_true_predicates;
      [1;2;3;4;5], map_rules @@ eliminate_unreachable_rules;
      [         ], push_predicates ~min_push:10;
      [1;2;3;4  ], map_rules_input @@ push_common_predicates_equal;
      [1;2;3;4  ], map_rules_input @@ push_common_predicates_equal;
      [1;2;3;4  ], map_rules_input @@ push_common_predicates_equal;
      [         ], map_rules_input @@ push_common_predicates_union;
      [  2;3;4  ], remove_unreferenced_chains;
      [1;2;3;4  ], inline_pure_jumps;
      [1;  3;4  ], merge_identical_chains;
      [1;  3;4  ], map_rules @@ join_rules_with_same_target;
      [1;      5], remove_unreferenced_chains;
      [1;      5], remap_chain_ids;
      [        5], map_rules @@ map_predicates @@ reorder_preds;
      [    3;4;5], map_rules @@ reorder_rules
    ]
  in

  List.fold_left ~init:chains ~f:(fun chains' (stages, optim_func) ->
    match List.exists ~f:(Int.equal stage) stages with
    | true -> printf "%!"; optim_func chains'
    | false -> chains'
  ) optimize_functions

let dump_chains chains =
  chains
  |> get_ordered_chains
  |> List.rev
  |> List.filter_map ~f:(fun chain -> Map.find chains chain)
  |> List.iter ~f:(fun {id; rules; _ } ->
    printf "# Chain %s. Rules %3d. Ref: %2d\n" (Chain_id.show id) (List.length rules) (chain_reference_count id chains)
  )

let max_stages = 5
let rec optimize ~stage chains =
  printf "\n#Stage: %d: (%d, %d, %d): " stage (Chain.count_rules chains) (Chain.count_predicates chains) (Chain.count_chains chains);
  let chains' = optimize_pass ~stage chains in
  match (stage >= max_stages) with
  | false ->
    optimize ~stage:(stage+1) chains'
  | true ->
    printf "\n#Optimization done\n";
    chains'


let optimize chains =
  chains
  |> optimize ~stage:1
  |> (fun chains -> dump_chains chains; chains)
