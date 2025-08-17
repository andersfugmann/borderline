open Base
module Set = Set.Poly
open Stdio
open Ir
open Poly
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4
module P = Predicate

type string = id [@@ocaml.warning "-34"]

(**
   - Marking of zones is an effect. Verify that effects are not ignored when inlining.
   - Ideas: Define upper bound for zones

   - duplicate negates predicates to remaining chains when the target is terminal.
     - a -> drop
     - b & c -> X => ^a & b & c -> X

   in general:
    - a & b -> drop
    - c & d -> X  =>

    ^(a & b) & c & d -> X
    => (^a | ^b) & c & d -> X
    => c & d => { ^a -> X | ^b -> X }(* No optimization needed *)

    - a & b -> drop
    - b & d -> X  =>

    ^(a & b) & b & d -> X
    => ^a & b & d -> X
*)

(* Percentage for predicates are pushed down to called chains *)
let min_push = 50

(* Make sure that no chains have an indegree more than N,
   so that 'for all chains | chain_reference_count <= N' holds
*)
let max_chain_indegree = 1

(** Define the saving in predicates when inlining. *)
let _max_inline_cost = 5

(** Minimum length of sequence to of predicates to merge into a new chain *)
let _min_merge = 3

let (>::) elt elts =
  Option.value_map ~f:(fun elt -> elt :: elts) ~default:elts elt

let _ = ( >:: )

let chain_reference_count id chains =
  let count_references acc rules =
    List.fold_left ~init:acc ~f:(fun acc -> function (_, _, Jump id') when Chain_id.equal id id' -> acc + 1 | _ -> acc)  rules
  in
  Map.fold ~init:0 ~f:(fun ~key:_ ~data:chn acc -> (count_references acc chn.rules)) chains

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules ~f chains =
  Map.map ~f:(fun chn -> { chn with rules = f chn.rules }) chains

let map_predicates ~f rules =
  List.map ~f:(fun (preds, effects, target) -> (f preds, effects, target)) rules

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

let process_chains_breath_first chains ~f =
  get_ordered_chains chains
  |> List.rev
  |> List.fold_left ~init:chains ~f

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
        List.map ~f:(fun (preds, effects, target) ->
          let target =
            match target with
            | Ir.Jump target ->
              Ir.Jump (Map.find chain_map target |> Option.value ~default:id)
            | _ -> target
          in
          (preds, effects, target)
        ) rules
      in
      { rule with id; rules }
  )
  |> List.map ~f:(fun chain -> chain.id, chain)
  |> Map.of_alist_exn (module Chain_id)


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
      let inputs =
        List.fold ~init:inputs ~f:(fun inputs -> function
          | (preds, _, Jump id) ->
            let input = P.inter_preds (input @ preds) in
            Map.add_multi inputs ~key:id ~data:input
          | _ -> inputs
        ) chain.rules
      in
      inputs, (input, chain)
    ) chains
  in
  chains

(** This should be used with a set of filters *)
let map_rules_input ~f chains =
  map_chains_inputs chains
  |> List.concat_map ~f:(fun (input, chain) ->
    let rules, new_chains = f input chain.rules in
    { chain with rules } :: new_chains
  )
  |> List.map ~f:(fun chain -> chain.id, chain)
  |> Map.of_alist_exn (module Chain_id)


let remove_unsatisfiable_rules input rules =
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
  let mutual_differences preds1 preds2 =
    let exclusive p p' =
      List.filter ~f:(fun pred ->
        List.exists ~f:(P.equal_predicate pred) p' |> not)
        p
    in
    let common preds preds' =
      List.filter ~f:(fun pred ->
        List.exists ~f:(P.equal_predicate pred) preds'
      ) preds
    in

    let common = common preds1 preds2 in
    let preds1' = exclusive preds1 common in
    let preds2' = exclusive preds2 common in
    common, preds1', preds2'
  in

  function
  | ((preds, effects, target) as rule1) :: ((preds', effects', target') as rule2) :: rules when
      equal_target target target' &&
      eq_effects effects effects' ->
    begin match mutual_differences preds preds' with
    | (common, [pred], [pred']) when is_union_true pred pred' ->
      (common, effects, target) :: join_rules_with_same_target rules
    | _ -> rule1 :: join_rules_with_same_target (rule2 :: rules)
    end
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

let remove_implied_predicates input rules =
  let rules =
    List.map ~f:(fun (preds, effects, target) ->
      let implied_predicates = P.get_implied_predicates (preds @ input) in
      let preds = List.filter ~f:(fun pred -> List.mem implied_predicates pred ~equal:P.equal_predicate |> not) preds in
      (preds, effects, target)
    ) rules
  in
  rules, []

let reduce_predicates input rules =
  let map_predicates predicates =
    let input = P.inter_preds input in
    (* As input now contains all implied predicates, we can filter
       implied.  Its a bit dangerous, as we want to remove implied
       also, so we need to replace with the implied, but not filter on
       the implied results again *)

    let merge pred input =
      match P.merge_pred ~tpe:`Inter input pred with
      | None -> None (* Cannot reduce *)
      | Some pred' ->
        match P.merge_pred ~tpe:`Diff input pred' with
        | Some (p, n) when P.cardinal_of_pred (p, not n) < P.cardinal_of_pred pred' ->
          printf "$";
          Some (p, not n)
        | _ ->
          printf "€";
          Some pred'
    in

    let rec inner = function
      [] -> []
      | p :: ps ->
        match List.find_map input ~f:(merge p) with
        | None -> p :: inner ps
        | Some p ->
          printf "r";
          p :: inner ps
    in
    inner predicates
  in
  let rules =
    List.map ~f:(fun (preds, effects, target) ->
      map_predicates preds, effects, target
    ) rules
  in
  rules, []

let push_common_pred input rules =
  let is_mem input pred =
    (* If the predicate already exists in the input, dont use the result *)
    List.exists ~f:(fun input -> P.is_subset pred ~of_:input) input
  in

  let common_pred pred preds =
    match List.find_map ~f:(P.merge_pred ~tpe:`Union pred) preds with
    | Some pred when not (P.is_always true pred) ->
      Some pred
    | _ ->
      None
  in

  let rec find_pred_seq pred seq = function
    | [] ->
      pred, (List.rev seq), []
    | ((preds, _, _) as rule) :: rules ->
      match common_pred pred preds with
      | Some pred ->
        find_pred_seq pred (rule :: seq) rules
      | None ->
        pred, (List.rev seq), rules
  in

  let rec inner (pred, seq, head, tail) prev = function
    | (preds, _, _) as rule :: rules ->
      let (pred, seq, head, tail) =
        List.fold ~init:(pred, seq, head, tail) ~f:(fun (pred, seq, head, tail) p ->
          let (pred', seq', tail') = find_pred_seq p [] (rule :: rules) in
          match List.length seq' > List.length seq with
          | true when not (is_mem input pred') ->
            printf "!";
            (pred', seq', List.rev prev, tail') (* This is not the spot, I think *)
          | true ->
            printf "%%";
            (pred, seq, head, tail)
          | false ->
            (pred, seq, head, tail)
        ) preds
      in
      inner (pred, seq, head, tail) (rule :: prev) rules
    | [] -> (pred, seq, head, tail)
  in

  let init = ((Ir.True, true), [], rules, []) in
  let (pred, seq, head, tail) = inner init [] rules in
  match List.length seq with
  | n when n < 3 -> rules, []
  | n ->
    printf "C";
    (* Create a new chain *)
    let new_chain = Chain.create seq (Printf.sprintf "Push common pred: %d: %s" n (P.to_string pred)) in
    let rules = head @ ([pred], [], Ir.Jump new_chain.id) :: tail in
    rules, [new_chain]

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
    *This only works for chains that has only one reference.
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

(** Always inline chains when a chain ends with a jump *)
let tail_inline chains =
  Map.keys chains
  |> List.fold ~init:chains ~f:(fun chains chain_id ->
    let chain = Map.find_exn chains chain_id in
    let rules =
      match List.rev chain.rules with
      | ([], [], Ir.Jump target) :: rules_rev ->
        let target = Map.find_exn chains target in
        List.rev_append rules_rev target.rules
      | rules -> List.rev rules
    in
    Map.set chains ~key:chain_id ~data:{ chain with rules }
  )


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

  process_chains_breath_first ~f:(fun chains chain_id ->
    match Map.find chains chain_id, chain_reference_count chain_id chains > max_indegree with
    | Some chain, true ->
      let chains, new_chains = folding_map_chain_rules chains ~init:[] ~f:(replace_chain chain) in
      List.fold ~init:chains ~f:(fun chains chain -> Map.add_exn chains ~key:chain.id ~data:chain) new_chains
    | _, _ -> chains
  ) chains

(* If a chain ends in a jump, inline that chain *)

let optimize_pass ~stage chains =
  let (@@) a b = a ~f:b in
  let optimize_functions =
    [
      [  0;   ], reduce_chain_indegree ~max_indegree:max_chain_indegree;
      [  0;   ], push_predicates ~min_push;
      [  2;   ], map_chain_rules @@ map_predicates @@ P.inter_preds;
      [  2;   ], map_rules_input @@ remove_unsatisfiable_rules;
      [  2;   ], map_rules_input @@ reduce_predicates;
      [  2;   ], map_rules_input @@ remove_implied_predicates;
      [  2;   ], map_chain_rules @@ eliminate_unreachable_rules;
      [  2;   ], map_chain_rules @@ remove_true_predicates;
      [  2;   ], map_chain_rules @@ remove_empty_rules;
      [  2;   ], map_chain_rules @@ join_rules_with_same_target;
      [  2;   ], remove_unreferenced_chains;
      [  2;   ], tail_inline;
      [  2;   ], map_rules_input @@ push_common_pred;
      [  1;   ], inline_chains ~max_rules:5;
      [  2;   ], inline_chains ~max_rules:2;
    ]
  in

  List.fold_left ~init:chains ~f:(fun chains' (stages, optim_func) ->
    match List.exists ~f:(Int.equal stage) stages with
    | true -> printf "%!"; optim_func chains'
    | false -> chains'
  ) optimize_functions

let max_stages = 4
let rec optimize ?(stage=1) ?(iter=1) chains =
  printf "\n#Stage: %d,%d: (%d, %d, %d): " stage iter (Chain.count_rules chains) (Chain.count_predicates chains) (Chain.count_chains chains);
  let chains' = optimize_pass ~stage chains in

  match (Chain.count_rules chains = Chain.count_rules chains'
         && Chain.count_predicates chains = Chain.count_predicates chains'
         && Chain.count_chains chains = Chain.count_chains chains') with
  | true when iter > 2  && stage >= max_stages -> printf "\n#Optimization done\n";
    (* Print chain order *)
    printf "\n# Chains: [";
    let _ = process_chains_breath_first ~f:(fun chains' chain_id -> printf "%s; " (Chain_id.show chain_id); chains') chains in
    printf "]\n";
    chains'
    |> remap_chain_ids

  | true when iter > 2 ->
    optimize ~stage:(stage + 1) chains'
  | true ->
    optimize ~stage ~iter:(iter + 1) chains'
  | false ->
    printf "%!";
    optimize ~stage chains'
