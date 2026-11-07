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
  next_temporary: int ref;
}

let analyze chains =
  let graph = Graph.analyze chains in
  let next_temporary =
    Map.fold chains ~init:0 ~f:(fun ~key ~data:_ next ->
      match key with Temporary id -> Int.max next (id + 1) | _ -> next)
    |> ref
  in
  { chains; graph; writes = summarize_writes chains graph; next_temporary }

let chain_writes chains = (analyze chains).writes

let create_chain context rules comment =
  let id = Chain_id.Temporary !(context.next_temporary) in
  Int.incr context.next_temporary;
  { id; rules; comment }

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
  let f = f context in
  map_chains_inputs context
  |> List.concat_map ~f:(function
    | (input, ({ id = Temporary _; rules; _ } as chain)) ->
      let rules, new_chains = f input rules in
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
  let preserves_multiplicity =
    is_terminal target ||
    (equal_target target Pass &&
     Dependencies.is_read_only (Dependencies.effects effects) &&
     P.disjoint preds preds')
  in
  if preserves_multiplicity && equal_target target target' &&
     equal_effects effects effects'
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

let can_inline_call context chains ~max_rules (preds, effects, id) =
  let child = Map.find_exn chains id in
  Chain.is_temp id &&
  List.is_empty effects &&
  List.length child.rules <= max_rules &&
  (Graph.reference_count context.graph id = 1 || List.length child.rules <= 1) &&
  not (List.exists child.rules ~f:(fun (_, _, target) -> equal_target target Return)) &&
  not (List.exists preds ~f:(Dependencies.affects (Map.find_exn context.writes id)))

let inline_chains ~max_rules chains =
  let context = analyze chains in
  context.graph.leaves_first
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | (preds, effects, Ir.Jump id) when
                  can_inline_call context chains ~max_rules (preds, effects, id) ->
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

module Cost = struct
  let jump = 65535

  let rules rules =
    List.sum (module Int) rules ~f:(fun (preds, _, target) ->
      P.costs preds + (match target with Jump _ -> jump | _ -> 0))

  let factoring_gain guard rules =
    let saved =
      List.sum (module Int) rules ~f:(fun (preds, _, _) ->
        List.sum (module Int) preds ~f:(fun pred ->
          if P.is_subset guard ~of_:pred then P.cost pred else 0))
    in
    saved - P.cost guard - jump
end

let rec push_common_predicates ~find_pred context input rules =
  let factorable = function (TcpFlags _ | True | Mark _), _ -> false | _ -> true in
  let rec extend guard seq = function
    | ((preds, _, target) as rule) :: rest when not (equal_target target Return) ->
      begin match find_pred guard (preds @ P.get_implied_predicates preds) with
      | Some next when
          not (P.is_always true next) &&
          not (Dependencies.affects (Dependencies.rule context.writes rule) next) ->
        if not (P.equal_predicate guard next) &&
           List.length seq >= min_push_seq && Cost.factoring_gain guard seq > 0
        then guard, List.rev seq, rule :: rest
        else extend next (rule :: seq) rest
      | _ -> guard, List.rev seq, rule :: rest
      end
    | rest -> guard, List.rev seq, rest
  in
  let rec candidates head = function
    | [] -> []
    | ((preds, _, _) as rule) :: rest ->
      let here =
        preds @ P.get_implied_predicates preds
        |> List.filter ~f:factorable
        |> List.filter_map ~f:(fun guard ->
          let guard, seq, tail = extend guard [] (rule :: rest) in
          let gain = Cost.factoring_gain guard seq in
          if List.length seq >= min_push_seq && gain > 0 &&
             not (List.exists input ~f:(P.equal_predicate guard))
          then Some (gain, guard, List.rev head, seq, tail)
          else None)
      in
      here @ candidates (rule :: head) rest
  in
  match List.max_elt (candidates [] rules)
          ~compare:(fun (a, _, _, _, _) (b, _, _, _, _) -> Int.compare a b) with
  | None -> rules, []
  | Some (_, guard, head, seq, tail) ->
    printf "V";
    let seq, nested = push_common_predicates ~find_pred context (guard :: input) seq in
    let child = create_chain context seq ("Common predicate: " ^ P.to_string guard) in
    head @ ([guard], [], Jump child.id) :: tail, child :: nested

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


let reduce_predicates ~zones context =
  let writes =
    Map.fold context.writes ~init:Dependencies.none
      ~f:(fun ~key:_ ~data writes -> Dependencies.union writes data)
  in
  let assigned_zones =
    Map.data context.chains
    |> List.concat_map ~f:(fun chain ->
      match chain.id with Builtin _ -> chain.rules | _ -> [])
    |> List.concat_map ~f:(function [], effects, _ -> effects | _ -> [])
    |> List.filter_map ~f:(function MarkZone (dir, id) -> Some (dir, id) | _ -> None)
    |> Set.of_list
  in
  let zone_addresses make pred dir ids =
    Set.fold ids ~init:(make (Ip4Set.empty, Ip6Set.empty)) ~f:(fun allowed id ->
      let unrestricted =
        Dependencies.affects writes pred || Set.mem assigned_zones (dir, id)
      in
      let ips =
        match unrestricted with
        | true -> Ip4Set.any, Ip6Set.any
        | false ->
          List.Assoc.find zones id ~equal:String.equal
          |> Option.value ~default:(Ip4Set.any, Ip6Set.any)
      in
      P.merge_pred ~tpe:`Union allowed (make ips) |> Option.value_exn)
  in
  let address_input pred input =
    match input, pred with
    | (Zone (dir, ids), false), (Ip4Set (dir', _), _) when dir = dir' ->
      zone_addresses (fun (ip4, _) ->
        match Ip4Set.equal ip4 Ip4Set.any with
        | true -> Ip4Set (dir, Ip4Set.empty), true
        | false -> Ip4Set (dir, ip4), false) pred dir ids
    | (Zone (dir, ids), false), (Ip6Set (dir', _), _) when dir = dir' ->
      zone_addresses (fun (_, ip6) ->
        match Ip6Set.equal ip6 Ip6Set.any with
        | true -> Ip6Set (dir, Ip6Set.empty), true
        | false -> Ip6Set (dir, ip6), false) pred dir ids
    | (Zone (dir, ids), false), (Address_family _, _) ->
      zone_addresses (fun (ip4, ip6) ->
        Address_family (match Ip4Set.is_empty ip4, Ip6Set.is_empty ip6 with
          | true, true -> Set.empty
          | true, false -> Set.singleton Ipv6
          | false, true -> Set.singleton Ipv4
          | false, false -> Set.of_list [Ipv4; Ipv6]), false) pred dir ids
    | _ -> input
  in
  let merge pred input =
    match P.merge_pred ~tpe:`Inter input pred with
    | None -> None (* Cannot reduce *)
    | Some result when P.is_always false result -> Some result
    | Some result when P.equal_predicate result input ->
      printf "£";
      Some (Option.value (P.get_implied_predicate pred) ~default:(True, false));
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

  fun input rules ->
  let rules =
    rule_inputs context input rules
    |> List.map ~f:(fun (input, (preds, effects, target)) ->
      let preds =
        List.map ~f:(fun p ->
          let input =
            match p with
            | (Ip4Set _ | Ip6Set _ | Address_family _), _ ->
              List.filter preds ~f:(function Zone _, _ -> true | _ -> false)
              |> List.rev_append input
              |> List.map ~f:(address_input p)
              |> P.inter_preds
            | _ -> input
          in
          match List.find_map ~f:(merge p) input with
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

(** Move stable guards into single-caller chains only when the merged predicates cost less. *)
let push_predicates chains =
  let context = analyze chains in
  let summaries = context.writes in
  let push rules pred =
    List.map ~f:(fun (preds, effects, target) ->
      (P.inter_preds (pred :: preds), effects, target)
    ) rules
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
                  let pushed = push target_rules pred in
                  match
                    not (Dependencies.affects (Map.find_exn summaries target_id) pred) &&
                    Cost.rules pushed < Cost.rules target_rules + P.cost pred
                  with
                  | false -> (target_rules, pred :: acc)
                  | true ->
                    printf ">";
                    pushed, acc
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
  context.graph.leaves_first
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | None -> None
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | ([], [], Ir.Jump target) as rule when
                  can_inline_call context chains ~max_rules:Int.max_value ([], [], target) ->
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

let specialize_callers ~zones ~max_growth chains =
  let context = analyze chains in
  let reduce = reduce_predicates ~zones context in
  let remaining = ref max_growth in
  let added = ref [] in
  let specialize input = function
    | (preds, effects, Jump id) as rule when
        Chain.is_temp id && Graph.reference_count context.graph id > 1 ->
      let child = Map.find_exn chains id in
      let input =
        P.inter_preds (preds @ input)
        |> Dependencies.invalidate (Dependencies.effects effects)
      in
      let rules, _ = remove_unsatisfiable_rules context input child.rules in
      let rules, _ = reduce input rules in
      let rules = remove_true_predicates rules in
      let size = List.length rules in
      if size < List.length child.rules &&
         Cost.rules rules < Cost.rules child.rules && size <= !remaining
      then begin
        remaining := !remaining - size;
        if size = 0 then preds, effects, Pass
        else begin
          let child = create_chain context rules "Specialized caller" in
          added := child :: !added;
          preds, effects, Jump child.id
        end
      end
      else rule
    | rule -> rule
  in
  let chains =
    map_chains_inputs context
    |> List.map ~f:(fun (input, chain) ->
      let rules =
        if Chain.is_named chain.id then chain.rules
        else rule_inputs context input chain.rules
          |> List.map ~f:(fun (input, rule) -> specialize input rule)
      in
      chain.id, { chain with rules })
    |> Map.of_alist_exn (module Chain_id)
  in
  List.fold !added ~init:chains ~f:(fun chains child ->
    Map.add_exn chains ~key:child.id ~data:child)


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

let rec share_terminal_tails chains =
  let context = analyze chains in
  let shareable = function
    | _, _, (Accept | Drop | Reject _) -> true
    | _ -> false
  in
  let rec add_suffixes groups id size cost tail =
    if size < 2 then groups
    else
      let rec add = function
        | [] -> [tail, [id]]
        | (other, ids) :: rest when List.equal equal_rule tail other ->
          (other, id :: ids) :: rest
        | entry :: rest -> entry :: add rest
      in
      let groups = Map.update groups (size, cost) ~f:(fun entries ->
        add (Option.value entries ~default:[]))
      in
      add_suffixes groups id (size - 1)
        (cost - Cost.rules [List.hd_exn tail]) (List.tl_exn tail)
  in
  let groups =
    List.fold context.graph.leaves_first ~init:Map.Poly.empty ~f:(fun groups id ->
      if not (Chain.is_temp id) then groups
      else
        let tail =
          List.rev (Map.find_exn chains id).rules
          |> List.take_while ~f:shareable
          |> List.rev
        in
        add_suffixes groups id (List.length tail) (Cost.rules tail) tail)
  in
  let best =
    Map.data groups
    |> List.concat
    |> List.fold ~init:None ~f:(fun best (tail, ids) ->
      let length = List.length tail in
      let saved = List.length ids * (length - 1) - length in
      let previous = Option.value_map best ~default:0 ~f:(fun (saved, _, _) -> saved) in
      if saved > previous then Some (saved, tail, ids) else best)
  in
  match best with
  | None -> chains
  | Some (_, tail, ids) ->
    let child = create_chain context tail "Shared terminal tail" in
    let chains = Map.add_exn chains ~key:child.id ~data:child in
    let chains =
      List.fold ids ~init:chains ~f:(fun chains id ->
        let chain = Map.find_exn chains id in
        let prefix = List.take chain.rules (List.length chain.rules - List.length tail) in
        Map.set chains ~key:id ~data:{ chain with rules = prefix @ [[], [], Jump child.id] })
    in
    share_terminal_tails chains

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

let reorder_rules ?(chains=Map.empty (module Chain_id)) rules =
  let rec pure_rule_outcome active (preds, effects, target) =
    if not (List.for_all effects ~f:(function Comment _ -> true | _ -> false)) then None
    else
      let outcome =
        match target with
        | Accept | Drop | Reject _ -> Some (Some target, 0)
        | Return -> Some (None, 0)
        | Pass -> None
        | Jump (Temporary _ as id) when not (Set.mem active id) ->
          Option.bind (Map.find chains id) ~f:(fun chain ->
            pure_chain_outcome (Set.add active id) chain.rules)
          |> Option.map ~f:(fun (target, cost) -> target, cost + Cost.jump)
        | Jump _ -> None
      in
      Option.map outcome ~f:(fun (target, cost) -> target, cost + P.costs preds)
  and pure_chain_outcome active rules =
    List.fold rules ~init:(Some (None, 0)) ~f:(fun outcome rule ->
      Option.bind outcome ~f:(fun (target, cost) ->
        Option.bind (pure_rule_outcome active rule) ~f:(fun (next, next_cost) ->
          match target, next with
          | None, target | target, None -> Some (target, cost + next_cost)
          | Some target, Some next when equal_target target next ->
            Some (Some target, cost + next_cost)
          | _ -> None)))
  in
  let order_target = function
    | Ir.Accept -> 1
    | Drop -> 2
    | Reject _ -> 3
    | Return -> 4
    | Pass -> 5
    | Jump _ -> 6
  in
  let should_swap ((preds, effects, target) as rule1) ((preds', effects', target') as rule2) =
    match pure_rule_outcome Set.empty rule1, pure_rule_outcome Set.empty rule2 with
    | Some (Some outcome, cost), Some (Some outcome', cost') when equal_target outcome outcome' ->
      cost' < cost
    | _ ->
      Dependencies.independent rule1 rule2 &&
      (
      (Ir.equal_target target target' && equal_effects effects effects' &&
       P.costs preds' < P.costs preds) ||
      (order_target target' < order_target target && P.disjoint preds preds')
      )
  in
  let rec inner acc = function
    | [] -> List.rev acc
    | rule1 :: rule2 :: rules when should_swap rule1 rule2 ->
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
      equal_effects effects effects' &&
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

let prefer_positive_predicates =
  map_predicates ~f:(List.map ~f:(function
    | (_, true) as pred ->
      begin match P.positive_predicate pred with
      | (_, false) as positive when P.cost positive = P.cost pred -> positive
      | _ -> pred
      end
    | pred -> pred))

let simplify ~zones chains =
  let once chains =
    chains
    |> run_pass "normalize" (map_rules ~f:(map_predicates ~f:P.inter_preds))
    |> run_pass "merge adjacent rules" (map_rules ~f:join_rules)
    |> run_pass "reduce predicates" (map_rules_input ~f:(reduce_predicates ~zones))
    |> run_pass "remove empty rules" (map_rules ~f:remove_empty_rules)
    |> run_pass "remove impossible rules" (map_rules_input ~f:remove_unsatisfiable_rules)
    |> run_pass "remove true predicates" (map_rules ~f:remove_true_predicates)
    |> run_pass "remove unreachable rules" (map_rules ~f:eliminate_unreachable_rules)
    |> run_pass "remove covered rules" filter_covered_subset
    |> run_pass "merge matching targets" (map_rules ~f:join_rules_with_same_target)
    |> run_pass "remove unused chains" remove_unreferenced_chains
    |> run_pass "prefer positive predicates" (map_rules ~f:prefer_positive_predicates)
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

let optimize ~zones chains =
  let zones =
    List.map zones ~f:(fun (id, statements) ->
      let zone = Zone.init statements in
      let ips =
        match Rule.list2ip zone.networks with
        | [], [] -> Ip4Set.any, Ip6Set.any
        | ip4, ip6 -> Ip4Set.of_list ip4, Ip6Set.of_list ip6
      in
      id, ips)
  in
  let factor chains =
    chains
    |> run_pass "push call guards" push_predicates
    |> run_pass "factor predicate unions" (map_rules_input ~f:push_common_predicates_union)
    |> run_pass "factor equal predicates" (map_rules_input ~f:push_common_predicates_equal)
    |> simplify ~zones
  in
  chains
  |> simplify ~zones
  |> run_pass "specialize callers" (fun chains ->
    specialize_callers ~zones ~max_growth:(Chain.count_rules chains / 4) chains)
  |> run_pass "inline small calls" (inline_chains ~max_rules:3)
  |> simplify ~zones
  |> until_stable ~name:"factoring" ~max_rounds:4 factor
  |> run_pass "inline small calls" (inline_chains ~max_rules:2)
  |> run_pass "inline pure jumps" inline_pure_jumps
  |> run_pass "merge identical chains" merge_identical_chains
  |> run_pass "order independent rules" (fun chains -> map_rules ~f:(reorder_rules ~chains) chains)
  |> simplify ~zones
  |> run_pass "share terminal tails" share_terminal_tails
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

  let%test_unit "simplification prefers positive predicates only at equal cost" =
    let family value neg = Address_family (Set.singleton value), neg in
    let small_states = State (State.of_list [State.New; State.Established]), true in
    let large_states = State (State.of_list [State.New; State.Established; State.Related]), true in
    let negative_zone = Zone (Direction.Source, Set.singleton "lan"), true in
    List.iter [
      family Ipv6 true, family Ipv4 false;
      family Ipv4 true, family Ipv6 false;
      family Ipv4 false, family Ipv4 false;
      small_states, small_states;
      large_states, large_states;
      negative_zone, negative_zone;
    ] ~f:(fun (pred, expected) ->
      let effects = [Counter; Log "matched"] in
      let chains = chain_map [input [rule ~when_:[pred] ~effects Accept]] in
      let result = Map.find_exn (simplify ~zones:[] chains) (Builtin Chain_type.Input) in
      match result.rules with
      | [([actual], actual_effects, Accept)] ->
        assert_equal ~printer:Fn.id ~msg:(P.to_string pred)
          (P.to_string expected) (P.to_string actual);
        assert_equal ~printer:Int.to_string (P.cost pred) (P.cost actual);
        assert_bool "effects retain their order" (Ir.equal_effects effects actual_effects);
        List.iter [Ipv4; Ipv6] ~f:(fun value ->
          let matches = function
            | Address_family families, neg -> Set.mem families value <> neg
            | _ -> true
          in
          assert_equal ~printer:Bool.to_string (matches pred) (matches actual))
      | _ -> assert_failure "Expected one unchanged rule with a canonical predicate")

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

  let%test_unit "disjoint read-only pass rules merge without losing effects" =
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp]] ~effects:[Counter; Log "matched"] Pass;
        rule ~when_:[protocols [udp]] ~effects:[Counter; Log "matched"] Pass;
        rule Accept;
      ];
    ] in
    List.iter [join_rules; join_rules_with_same_target] ~f:(fun merge ->
      let optimize chains = map_rules ~f:merge chains |> expect_rule_count 2 in
      check_optimization ~optimize ~chains
        ~cases:[
          tcp, { allowed with counters = 1; logs = ["matched"] };
          udp, { allowed with counters = 1; logs = ["matched"] };
          icmpv6, allowed;
        ])

  let%test_unit "pass merging cannot collapse writes that enable a later match" =
    let effects = [MarkZone (Direction.Source, "after"); Counter] in
    let chains = chain_map [
      input [
        rule ~effects:[MarkZone (Direction.Source, "before")] Pass;
        rule ~when_:[source_zones ["before"]] ~effects Pass;
        rule ~when_:[source_zones ["after"]] ~effects Pass;
        rule Accept;
      ];
    ] in
    List.iter [join_rules; join_rules_with_same_target] ~f:(fun merge ->
      let optimize chains = map_rules ~f:merge chains |> expect_rule_count 4 in
      check_optimization ~optimize ~chains
        ~cases:[udp, { allowed with source_zone = Some "after"; counters = 2 }])

  let%test_unit "factoring removes repeated predicates when the guard pays for its jump" =
    let parent = Temporary 1 in
    let chains = chain_map [
      input [rule (Jump parent)];
      chain parent [
        rule ~when_:[protocols [udp]] ~effects:[Counter] Pass;
        rule ~when_:[protocols [udp]] ~effects:[Log "matched"] Pass;
        rule ~when_:[protocols [udp]] Accept;
        rule ~when_:[protocols [tcp]] Drop;
        rule Drop;
      ];
    ] in
    let optimize chains =
      let result =
        chains
        |> map_rules_input ~f:push_common_predicates_union
        |> map_rules_input ~f:(reduce_predicates ~zones:[])
        |> map_rules ~f:remove_true_predicates
      in
      assert_equal ~msg:"The profitable UDP prefix shares one guard before the TCP rule"
        2 (Chain.count_predicates result);
      result
    in
    check_optimization ~optimize ~chains
      ~cases:[
        udp, { allowed with counters = 1; logs = ["matched"] };
        tcp, denied;
      ]

  let%test_unit "factoring skips a union that removes no repeated predicate work" =
    let parent = Temporary 1 in
    let chains = chain_map [
      input [rule (Jump parent)];
      chain parent [
        rule ~when_:[protocols [tcp]] ~effects:[Counter] Pass;
        rule ~when_:[protocols [udp]] ~effects:[Log "udp"] Pass;
        rule ~when_:[protocols [icmpv6]] Accept;
      ];
    ] in
    let optimize chains =
      map_rules_input ~f:push_common_predicates_union chains |> expect_rule_count 4
    in
    check_optimization ~optimize ~chains
      ~cases:[
        tcp, { denied with counters = 1 };
        udp, { denied with logs = ["udp"] };
        icmpv6, allowed;
      ]

  let%test_unit "factoring preserves explicit return boundaries" =
    let parent = Temporary 1 in
    let chains = chain_map [
      input [rule (Jump parent); rule Accept];
      chain parent [
        rule ~when_:[protocols [udp]] ~effects:[Counter] Pass;
        rule ~when_:[protocols [udp]] ~effects:[Log "returning"] Pass;
        rule ~when_:[protocols [udp]] Return;
        rule Drop;
      ];
    ] in
    check_optimization ~optimize:(map_rules_input ~f:push_common_predicates_union)
      ~chains
      ~cases:[
        udp, { allowed with counters = 1; logs = ["returning"] };
        tcp, denied;
      ]

  let%test_unit "caller specialization prunes branches within its growth budget" =
    let shared = Temporary 1 in
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp]] (Jump shared);
        rule ~when_:[protocols [udp]] (Jump shared);
        rule Drop;
      ];
      chain shared [
        rule ~when_:[protocols [tcp]] ~effects:[Log "tcp"] Accept;
        rule ~when_:[protocols [udp]] ~effects:[Log "udp"] Accept;
        rule ~when_:[protocols [icmpv6]] ~effects:[Log "icmpv6"] Accept;
        rule Drop;
      ];
    ] in
    List.iter [0, 7; 1, 8; 2, 5] ~f:(fun (max_growth, expected_rules) ->
      let optimize chains =
        specialize_callers ~zones:[] ~max_growth chains
        |> remove_unreferenced_chains
        |> expect_rule_count expected_rules
      in
      check_optimization ~optimize ~chains
        ~cases:[
          tcp, { allowed with logs = ["tcp"] };
          udp, { allowed with logs = ["udp"] };
          icmpv6, denied;
        ])

  let%test_unit "terminal tail sharing retains branch prefixes and effects" =
    let left = Temporary 1 in
    let right = Temporary 2 in
    let tail = [
      rule ~when_:[protocols [tcp]] ~effects:[Counter] Accept;
      rule ~when_:[protocols [udp]] ~effects:[Log "udp"] Accept;
      rule Drop;
    ] in
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp; icmpv6]] (Jump left);
        rule ~when_:[protocols [udp]] (Jump right);
        rule Drop;
      ];
      chain left (rule ~when_:[protocols [icmpv6]] ~effects:[Log "left"] Drop :: tail);
      chain right (rule ~when_:[protocols [icmpv6]] ~effects:[Log "right"] Drop :: tail);
    ] in
    let optimize chains = share_terminal_tails chains |> expect_rule_count 10 in
    check_optimization ~optimize ~chains
      ~cases:[
        tcp, { allowed with counters = 1 };
        udp, { allowed with logs = ["udp"] };
        icmpv6, { denied with logs = ["left"] };
      ]

  let%test_unit "terminal tails are not shared when jumps erase the size saving" =
    let left = Temporary 1 in
    let right = Temporary 2 in
    let tail = [
      rule ~when_:[protocols [tcp]] ~effects:[Counter] Accept;
      rule Drop;
    ] in
    let chains = chain_map [
      input [
        rule ~when_:[protocols [tcp; icmpv6]] (Jump left);
        rule ~when_:[protocols [udp]] (Jump right);
        rule Drop;
      ];
      chain left (rule ~when_:[protocols [icmpv6]] ~effects:[Log "left"] Drop :: tail);
      chain right (rule ~when_:[protocols [icmpv6]] ~effects:[Log "right"] Drop :: tail);
    ] in
    let optimize chains = share_terminal_tails chains |> expect_rule_count 9 in
    check_optimization ~optimize ~chains
      ~cases:[
        tcp, { allowed with counters = 1 };
        udp, denied;
        icmpv6, { denied with logs = ["left"] };
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
    check_optimization ~optimize:push_predicates ~chains
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
      |> map_rules_input ~f:(reduce_predicates ~zones:[])
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
