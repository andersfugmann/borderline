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
let min_push_seq = 2

type string = id [@@ocaml.warning "-34"]

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

let rec remove_duplicate_counters = function
  | [] -> []
  | Counter :: effects ->
    Counter :: List.filter effects ~f:(fun effect_ -> not (equal_effect_ Counter effect_))
  | effect_ :: effects -> effect_ :: remove_duplicate_counters effects

let normalize_rules rules =
  List.map rules ~f:(fun (preds, effects, target) ->
    P.inter_preds preds, remove_duplicate_counters effects, target)

let is_terminal = function
  | Pass | Jump _ -> false
  | Accept | Drop | Return | Reject _ -> true

let effect_modifies_packet = function
  | MarkZone _ | Notrack | Snat _ -> true
  | Log _ | Counter | Comment _ -> false

let rec exists_effect ~chains ~f = function
  | (_, effects, _) when List.exists effects ~f -> true
  | (_, _, Jump (Named _)) -> true
  | (_, _, Jump id) ->
    List.exists (Map.find_exn chains id).rules ~f:(exists_effect ~chains ~f)
  | _ -> false

let modifies_packet ~chains =
  exists_effect ~chains ~f:effect_modifies_packet

let has_sideeffects ~chains =
  exists_effect ~chains ~f:(function
    | Log _ -> true
    | effect_ -> effect_modifies_packet effect_)

let effect_preserves_predicate (pred, _) = function
  | MarkZone (dir, _) ->
    begin match pred with
    | Zone (dir', _) -> dir <> dir'
    | Mark _ -> false
    | _ -> true
    end
  | Notrack ->
    begin match pred with State _ -> false | _ -> true end
  | Snat _ ->
    begin match pred with
    | Ip4Set (Direction.Source, _) | Ip6Set (Direction.Source, _) -> false
    | _ -> true
    end
  | Log _ | Counter | Comment _ -> true

let preserves_predicate ~chains rule pred =
  not (exists_effect ~chains ~f:(fun effect_ ->
    not (effect_preserves_predicate pred effect_)) rule)

let input_for_call input (preds, effects, _) =
  P.inter_preds (preds @ input)
  |> List.filter ~f:(fun pred ->
    List.for_all effects ~f:(effect_preserves_predicate pred))

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

type context = {
  chains: (Chain_id.t, chain, Chain_id.comparator_witness) Map.t;
  graph: Graph.t;
  next_temporary: int ref;
}

let analyze chains =
  let graph = Graph.analyze chains in
  let next_temporary =
    Map.fold chains ~init:0 ~f:(fun ~key ~data:_ next ->
      match key with Temporary id -> Int.max next (id + 1) | _ -> next)
    |> ref
  in
  { chains; graph; next_temporary }

let create_chain context rules comment =
  let id = Chain_id.Temporary !(context.next_temporary) in
  Int.incr context.next_temporary;
  { id; rules; comment }

let input_after_rule ~chains input (preds, _, target as rule) =
  (* Only unmatched packets continue after a terminal rule. *)
  match preds with
  | [(p, n)] when is_terminal target && Option.is_none (P.get_implied_predicate (p, n)) ->
    P.inter_preds ((p, not n) :: input)
  | _ when is_terminal target -> input
  | _ -> List.filter input ~f:(preserves_predicate ~chains rule)

let rule_inputs context input rules =
  List.fold_map rules ~init:input ~f:(fun input rule ->
    input_after_rule ~chains:context.chains input rule, (input, rule))
  |> snd

(** Return an ordered list of chains extended inputs for each inputs *)
let map_chains_inputs context =
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
      let input = match chain.id with
        | Named _ -> []
        | _ -> Map.find_multi inputs chain.id |> P.union_preds
      in
      let (inputs, _input) =
        List.fold ~init:(inputs, input) ~f:(fun (inputs, input) -> function
          | (_, _, target) as rule ->
            let inputs = match target with
              | Jump id ->
                Map.add_multi inputs ~key:id ~data:(input_for_call input rule)
              | _ -> inputs
            in
            inputs, input_after_rule ~chains:context.chains input rule
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

let remove_unreferenced_chains chains =
  let referenced_chains =
    get_ordered_chains chains
    |> Set.of_list
  in
  Map.filter_keys ~f:(Set.mem referenced_chains) chains

let can_inline_call context chains ~max_rules = function
  | (preds, [], Jump (Temporary _ as id)) as rule ->
    let child = Map.find_exn chains id in
    List.length child.rules <= max_rules &&
    (Graph.reference_count context.graph id = 1 || List.length child.rules <= 1) &&
    not (List.exists child.rules ~f:(fun (_, _, target) -> equal_target target Return)) &&
    (* Guard stability matters only when inlining repeats it. *)
    (List.is_empty preds || List.length child.rules <= 1 ||
     List.for_all preds ~f:(preserves_predicate ~chains rule))
  | _ -> false

let inline_chains ~max_rules chains =
  let context = analyze chains in
  context.graph.leaves_first
  |> List.fold ~init:chains ~f:(fun chains -> function
    | (Ir.Chain_id.Temporary _) as chain_id ->
      Map.change chains chain_id ~f:(function
        | Some ({ rules; _ } as chain) ->
          let rules =
            List.concat_map ~f:(function
              | (preds, effects, Ir.Jump id) as rule when
                  can_inline_call context chains ~max_rules rule ->
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
      | Some next when not (P.is_always true next) &&
                       preserves_predicate ~chains:context.chains rule next ->
        begin match not (P.equal_predicate guard next) &&
                    List.length seq >= min_push_seq && Cost.factoring_gain guard seq > 0 with
        | true -> guard, List.rev seq, rule :: rest
        | false -> extend next (rule :: seq) rest
        end
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
          match List.length seq >= min_push_seq && gain > 0 &&
                not (List.exists input ~f:(P.equal_predicate guard)) with
          | true -> Some (gain, guard, List.rev head, seq, tail)
          | false -> None)
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
  let assigned_zones =
    Map.data context.chains
    |> List.concat_map ~f:(fun chain ->
      match chain.id with Builtin _ -> chain.rules | _ -> [])
    |> List.concat_map ~f:(function [], effects, _ -> effects | _ -> [])
    |> List.filter_map ~f:(function MarkZone (dir, id) -> Some (dir, id) | _ -> None)
    |> Set.of_list
  in
  let zone_addresses make pred dir ids =
    let stable =
      List.for_all context.graph.leaves_first ~f:(fun id ->
        List.for_all (Map.find_exn context.chains id).rules
          ~f:(fun rule -> preserves_predicate ~chains:context.chains rule pred))
    in
    Set.fold ids ~init:(make (Ip4Set.empty, Ip6Set.empty)) ~f:(fun allowed id ->
      let ips =
        match not stable || Set.mem assigned_zones (dir, id) with
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
                    preserves_predicate ~chains rule pred &&
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
                  can_inline_call context chains ~max_rules:Int.max_value rule ->
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
      let input = input_for_call input rule in
      let rules, _ = remove_unsatisfiable_rules context input child.rules in
      let rules, _ = reduce input rules in
      let rules = remove_true_predicates rules in
      let size = List.length rules in
      begin match size < List.length child.rules &&
                  Cost.rules rules < Cost.rules child.rules && size <= !remaining with
      | true ->
        remaining := !remaining - size;
        begin match rules with
        | [] -> preds, effects, Pass
        | _ ->
          let child = create_chain context rules "Specialized caller" in
          added := child :: !added;
          preds, effects, Jump child.id
        end
      | false -> rule
      end
    | rule -> rule
  in
  let chains =
    map_chains_inputs context
    |> List.map ~f:(fun (input, chain) ->
      let rules = match chain.id with
        | Named _ -> chain.rules
        | _ -> rule_inputs context input chain.rules
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

(* Remove earlier covered actions, descending only into uniquely referenced chains. *)
let rollup_rules chains =
  let is_return = function Ir.Return -> true | _ -> false in
  let graph = Graph.analyze chains in
  (* Input and output are reversed; acc holds the visited, retained rules forwards. *)
  let rec filter_rev ~acc ~chains ((preds, effects, target) as covering) = function
    | (preds', effects', target') :: rules when
        equal_target target target' && equal_effects effects effects' &&
        P.subset_preds ~of_:preds preds' ->
      printf "f";
      filter_rev ~acc ~chains covering rules
    | ((preds', _, _) as rule) :: rules when
        P.disjoint preds preds' ->
      filter_rev ~acc:(rule :: acc) ~chains covering rules
    | ((_, _, Jump (Temporary _ as id)) as rule) :: rules when
        not (is_return target) && Graph.reference_count graph id = 1 ->
      let chain = Map.find_exn chains id in
      let chains, reversed = filter_rev ~acc:[] ~chains covering (List.rev chain.rules) in
      let chains = Map.set chains ~key:id ~data:{ chain with rules = List.rev reversed } in
      chains, List.rev_append acc (rule :: rules)
    | rules -> chains, List.rev_append acc rules
  in

  let rec traverse_rev ~acc ~chains = function
    | (_, _, target) as rule :: rules when is_terminal target ->
      let chains, rules = filter_rev ~acc:[] ~chains rule rules in
      traverse_rev ~acc:(rule :: acc) ~chains rules
    | rule :: rules -> traverse_rev ~acc:(rule::acc) ~chains rules
    | [] -> chains, acc
  in

  graph.leaves_first
  |> List.fold ~init:chains ~f:(fun chains chain_id ->
      let chain = Map.find_exn chains chain_id in
      let chains, rules = traverse_rev ~acc:[] ~chains (List.rev chain.rules) in
      let chain = { chain with rules } in
      Map.set chains ~key:chain_id ~data:chain
    )


(** filter rules that a a subset of a later or previous rule.
    When doing a forward pass, we can safely remove any rule that is a subset.
    When doing a backward pass (rollup) both effects and target must be the same.
*)
let filter_covered_subset chains =
  let rec get_rules = function
    | (preds, [], Jump chain_id) as rule when not (modifies_packet ~chains rule) ->
      let chain = Map.find_exn chains chain_id in
      begin match List.for_all chain.rules ~f:(fun (_, _, target) -> is_terminal target) with
      | true ->
        List.concat_map ~f:get_rules chain.rules
        |> List.map ~f:(fun (preds', effects', target) -> (preds @ preds', effects', target))
      | false -> [rule]
      end
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
    | r :: _ as rules when
        not (List.for_all matched_preds ~f:(preserves_predicate ~chains r)) -> rules
    | r :: rs -> r :: forward rule rs
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
          List.for_all preds ~f:(preserves_predicate ~chains r) &&
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

let rec sort_rules ~chains = function
  | [] -> []
  | rule :: rules ->
    match rule, sort_rules ~chains rules with
    | rule, rules when has_sideeffects ~chains rule ->
      rule :: rules
    | rule1, rule2 :: rules when has_sideeffects ~chains rule2 ->
      rule1 :: rule2 :: rules
    | ((preds, _, target) as rule1), ((preds', _, target') as rule2) :: rules when
        P.disjoint preds preds' && Ir.order_target target' < Ir.order_target target ->
      rule2 :: sort_rules ~chains (rule1 :: rules)
    | rule, rules ->
      rule :: rules

let rec merge_rules ~chains rules =
  let rec merge ((preds, effects, target) as rule1) acc = function
    | [] -> None
    | rule :: _ when has_sideeffects ~chains rule ->
      None
    | ((preds', effects', target') as rule2) :: rules ->
      match Ir.equal_target target target', union_rule_predicates preds preds' with
      | true, Some merged_preds ->
        let merged_effects = effects @ effects' in
        Some ((List.rev ((merged_preds, merged_effects, target) :: acc)) @ rules)
      | _, _ when P.disjoint preds preds' ->
        merge rule1 (rule2 :: acc) rules
      | _ ->
        None
  in
  match rules with
  | [] -> []
  | rule :: rules when has_sideeffects ~chains rule ->
    rule :: merge_rules ~chains rules
  | rule :: rules ->
    match merge rule [] rules with
    | Some rules -> merge_rules ~chains rules
    | None -> rule :: merge_rules ~chains rules

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
  printf "# Optimize %s: %!" name;
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
    |> run_pass "normalize" (map_rules ~f:normalize_rules)
    |> run_pass "reduce predicates" (map_rules_input ~f:(reduce_predicates ~zones))
    |> run_pass "remove empty rules" (map_rules ~f:remove_empty_rules)
    |> run_pass "remove impossible rules" (map_rules_input ~f:remove_unsatisfiable_rules)
    |> run_pass "remove true predicates" (map_rules ~f:remove_true_predicates)
    |> run_pass "remove unreachable rules" (map_rules ~f:eliminate_unreachable_rules)
    |> run_pass "remove covered rules" filter_covered_subset
    |> run_pass "remove unused chains" remove_unreferenced_chains
    |> run_pass "prefer positive predicates" (map_rules ~f:prefer_positive_predicates)
    |> run_pass "rollup rules" rollup_rules
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
  |> run_pass "merge rules" (fun chains -> map_rules ~f:(merge_rules ~chains) chains)
  |> run_pass "sort rules" (fun chains -> map_rules ~f:(sort_rules ~chains) chains)
  |> simplify ~zones
  |> run_pass "share terminal tails" share_terminal_tails
  |> run_pass "remove implied predicates" (map_rules_input ~f:remove_implied_predicates)
  |> run_pass "order predicates" (map_rules ~f:(map_predicates ~f:reorder_preds))
  |> run_pass "renumber temporary chains" remap_chain_ids
  |> (fun chains -> dump_chains chains; chains)

module Test = struct
  open OUnit2
  open Chain_id

  let tcp = 6
  let udp = 17

  let protocols values = Protocol (Set.of_list values), false

  let rule ?(when_=[]) ?(effects=[]) target = when_, effects, target

  let chain id rules = { id; rules; comment = "Optimizer regression" }
  let input rules = chain (Builtin Chain_type.Input) rules

  let chain_map chains =
    List.map chains ~f:(fun chain -> chain.id, chain)
    |> Map.of_alist_exn (module Chain_id)

  type packet = {
    protocol: int;
    interfaces: string * string;
    groups: [`Int of int | `String of string] * [`Int of int | `String of string];
    zones: string option * string option;
    addresses: Ipaddr.t * Ipaddr.t;
    state: State.state;
  } [@@deriving show]

  type execution = {
    packet: packet;
    counters: int;
    logs: string list;
  } [@@deriving show]

  type verdict = Accepted | Dropped | Rejected of Reject.t [@@deriving show]
  type control = Continue | Stop of verdict

  let select dir (source, destination) =
    match dir with Direction.Source -> source | Direction.Destination -> destination

  let replace dir value (source, destination) =
    match dir with Direction.Source -> value, destination | Direction.Destination -> source, value

  let default_packet protocol = {
    protocol;
    interfaces = "if0", "if1";
    groups = `Int 0, `Int 1;
    zones = None, None;
    addresses = Ipaddr.of_string_exn "192.0.2.0", Ipaddr.of_string_exn "192.0.2.7";
    state = State.New;
  }

  let in_networks mem address (included, excluded) =
    List.exists included ~f:(mem address) && not (List.exists excluded ~f:(mem address))

  let packet_matches (pred, neg) =
    let matches value = value <> neg in
    match pred with
    | Protocol values -> fun packet -> matches (Set.mem values packet.protocol)
    | Interface (dir, values) -> fun packet -> matches (Set.mem values (select dir packet.interfaces))
    | If_group (dir, values) -> fun packet -> matches (Set.mem values (select dir packet.groups))
    | Zone (dir, values) ->
      fun packet -> matches (Set.mem values (Option.value (select dir packet.zones) ~default:"unclassified"))
    | State values -> fun packet -> matches (State.mem values packet.state)
    | Address_family values -> fun packet ->
      let family = match fst packet.addresses with Ipaddr.V4 _ -> Ipv4 | Ipaddr.V6 _ -> Ipv6 in
      matches (Set.mem values family)
    | Ip4Set (dir, ips) ->
      let networks = Ip4Set.to_networks ips in
      fun packet ->
      begin match select dir packet.addresses with
      | Ipaddr.V4 address -> matches (in_networks Ipaddr.V4.Prefix.mem address networks)
      | Ipaddr.V6 _ -> false
      end
    | Ip6Set (dir, ips) ->
      let networks = Ip6Set.to_networks ips in
      fun packet ->
      begin match select dir packet.addresses with
      | Ipaddr.V6 address -> matches (in_networks Ipaddr.V6.Prefix.mem address networks)
      | Ipaddr.V4 _ -> false
      end
    | True -> fun _ -> matches true
    | _ -> failwith ("Unsupported test predicate: " ^ P.to_string (pred, neg))

  let apply_packet_effect execution = function
    | MarkZone (dir, zone) ->
      { execution with packet = {
          execution.packet with zones = replace dir (Some zone) execution.packet.zones;
        } }
    | Notrack -> { execution with packet = { execution.packet with state = State.Untracked } }
    | Snat (Some address) ->
      { execution with packet = {
          execution.packet with addresses = Ipaddr.V4 address, snd execution.packet.addresses;
        } }
    | Counter -> { execution with counters = execution.counters + 1 }
    | Log prefix -> { execution with logs = prefix :: execution.logs }
    | Comment _ -> execution
    | Snat None -> failwith "A test SNAT effect must specify its translated address"

  let observe chains =
    let chains = Map.map chains ~f:(fun chain ->
      List.map chain.rules ~f:(fun (preds, effects, target) ->
        List.map preds ~f:packet_matches, effects, target))
    in
    let rec run_chain execution id =
      run_rules execution (Map.find_exn chains id)
    and run_rules execution = function
      | [] -> Continue, execution
      | (preds, effects, target) :: rest ->
        begin match List.for_all preds ~f:(fun matches -> matches execution.packet) with
        | false -> run_rules execution rest
        | true ->
          let execution = List.fold effects ~init:execution ~f:apply_packet_effect in
          match target with
          | Accept -> Stop Accepted, execution
          | Drop -> Stop Dropped, execution
          | Reject reason -> Stop (Rejected reason), execution
          | Return -> Continue, execution
          | Pass -> run_rules execution rest
          | Jump id ->
            match run_chain execution id with
            | Stop _, _ as result -> result
            | Continue, execution -> run_rules execution rest
        end
    in
    fun packet ->
    let initial = { packet; counters = 0; logs = [] } in
    match run_chain initial (Builtin Chain_type.Input) with
    | Continue, execution -> Dropped, execution
    | Stop verdict, execution -> verdict, execution

  module Properties = struct
    let directions = [Direction.Source; Direction.Destination]
    let labels = ["a"; "b"]
    let protocol_sets = [[tcp]; [udp]; [tcp; udp]]

    let rec words alphabet = function
      | 0 -> [[]]
      | length ->
        List.concat_map alphabet ~f:(fun value ->
          List.map (words alphabet (length - 1)) ~f:(fun rest -> value :: rest))

    let sequences alphabet bound =
      List.concat_map (List.range 0 (bound + 1)) ~f:(words alphabet)

    let address family offset =
      match family with
      | Ipv4 -> Ipaddr.of_string_exn (sprintf "192.0.2.%d" offset)
      | Ipv6 -> Ipaddr.of_string_exn (sprintf "2001:db8::%x" offset)

    let network family dir offset bits =
      match family with
      | Ipv4 ->
        let prefix = Ipaddr.V4.Prefix.of_string_exn (sprintf "192.0.2.%d/%d" offset bits) in
        (Ip4Set (dir, Ip4Set.of_list [prefix]), false),
        Frontend.Network [Frontend.Ip (Frontend.Ipv4 prefix, Lexing.dummy_pos)]
      | Ipv6 ->
        let prefix = Ipaddr.V6.Prefix.of_string_exn (sprintf "2001:db8::%x/%d" offset bits) in
        (Ip6Set (dir, Ip6Set.of_list [prefix]), false),
        Frontend.Network [Frontend.Ip (Frontend.Ipv6 prefix, Lexing.dummy_pos)]

    let packets =
      let zones = None :: List.map labels ~f:Option.some in
      let states = [State.New; State.Established; State.Untracked] in
      List.concat_map [Ipv4; Ipv6] ~f:(fun family ->
        List.concat_map [tcp; udp; 253] ~f:(fun protocol ->
          List.init 6 ~f:(fun index ->
            let group = index % 2 in
            {
              protocol;
              interfaces = sprintf "if%d" group, sprintf "if%d" (1 - group);
              groups = `Int group, `Int (1 - group);
              zones = List.nth_exn zones (index % List.length zones),
                      List.nth_exn zones ((index + 1) % List.length zones);
              addresses = address family (group * 7), address family ((1 - group) * 7);
              state = List.nth_exn states ((index / 2) % List.length states);
            })))

    let guards =
      List.map protocol_sets ~f:protocols @
      [State (State.of_list [State.New]), false; Address_family (Set.singleton Ipv4), false] @
      List.concat_map directions ~f:(fun dir -> [
        Interface (dir, Set.singleton "if0"), false;
        If_group (dir, Set.singleton (`Int 0)), false;
        Zone (dir, Set.singleton "a"), false;
        fst (network Ipv4 dir 0 31);
        fst (network Ipv6 dir 0 127);
      ])
      |> List.concat_map ~f:(fun (pred, _) -> [pred, false; pred, true])

    let marks =
      List.concat_map directions ~f:(fun dir ->
        List.map labels ~f:(fun label -> MarkZone (dir, label)))

    let effects = [Counter; Log "a"; Log "b"; Notrack] @ marks

    let check ?(packets=packets) name transform before =
      let after = transform before in
      let original = observe before and optimized = observe after in
      let printer (verdict, execution) = show_verdict verdict ^ "\n" ^ show_execution execution in
      List.iteri packets ~f:(fun index packet ->
        assert_equal ~printer ~msg:(sprintf "%s, packet %d" name index)
          (original packet) (optimized packet));
      after

    let graphs guard body =
      let parent = Temporary 1 and child = Temporary 2 and shared = Temporary 3 in
      let root = input [rule (Jump parent); rule Drop] in
      let frame effects id = [
        rule ~when_:[guard; protocols [udp; 253]] ~effects (Jump id);
        rule ~effects:[Log "return"] Accept;
      ] in
      [
        [root; chain parent body];
        [root; chain parent (frame [] child); chain child body];
        [root; chain parent (frame [Counter; Log "call"] child); chain child body];
        [root; chain parent (frame [] (Named "hook")); chain (Named "hook") body];
        [
          input [rule ~when_:[protocols [tcp]] (Jump parent); rule (Jump child)];
          chain parent [rule (Jump shared)];
          chain child [rule (Jump parent)];
          chain shared body;
        ];
        [
          input [rule ~when_:[guard] (Jump parent); rule (Jump child)];
          chain parent (rule ~effects:[Log "left"] Pass :: body);
          chain child (rule ~effects:[Log "right"] Pass :: body);
        ];
      ] |> List.map ~f:chain_map

    let programs f =
      let body guard effects target =
        let pred, neg = guard in
        let apply guard = List.map effects ~f:(fun effect_ ->
          rule ~when_:[guard] ~effects:[effect_] Pass)
        in
        apply guard @ [rule ~when_:[guard] ~effects:[Counter] target] @
        apply (pred, not neg) @ [
          rule ~when_:[guard] ~effects:[Log "enabled"] (Reject Reject.TcpReset);
          rule ~when_:[pred, not neg] ~effects:[Log "miss"] (Reject Reject.PortUnreachable);
          rule Drop;
        ]
      in
      let emit guard effects target =
        List.iter (graphs guard (body guard effects target)) ~f
      in
      List.iter guards ~f:(fun guard ->
        List.iter (sequences effects 1) ~f:(fun effects ->
          emit guard effects Accept);
        List.iter [Return; Reject Reject.TcpReset] ~f:(emit guard []));
      List.iter protocol_sets ~f:(fun values ->
        List.iter (words effects 2) ~f:(fun effects ->
          f (chain_map [
            input [rule (Jump (Temporary 1)); rule Drop];
            chain (Temporary 1) (body (protocols values) effects Return);
          ])));
      let assignments = List.concat_map protocol_sets ~f:(fun values ->
        List.map marks ~f:(fun mark -> rule ~when_:[protocols values] ~effects:[mark] Pass))
      in
      List.iter (words assignments 2) ~f:(fun rules ->
        f (chain_map [
          input [rule (Jump (Temporary 1)); rule Accept];
          chain (Temporary 1) rules;
        ]))

    let transformations = [
      "pipeline", optimize ~zones:[];
      "simplify", simplify ~zones:[];
      "inline", inline_chains ~max_rules:3;
      "inline jumps", inline_pure_jumps;
      "specialize", specialize_callers ~zones:[] ~max_growth:8;
      "push guards", push_predicates;
      "factor unions", map_rules_input ~f:push_common_predicates_union;
      "factor equal", map_rules_input ~f:push_common_predicates_equal;
      "reduce", map_rules_input ~f:(reduce_predicates ~zones:[]);
      "implied", map_rules_input ~f:remove_implied_predicates;
      "impossible", map_rules_input ~f:remove_unsatisfiable_rules;
      "covered", filter_covered_subset;
      "empty", map_rules ~f:remove_empty_rules;
      "true", map_rules ~f:remove_true_predicates;
      "unreachable", map_rules ~f:eliminate_unreachable_rules;
      "unused", remove_unreferenced_chains;
      "identical", merge_identical_chains;
      "tails", share_terminal_tails;
      "merge", (fun chains -> map_rules ~f:(merge_rules ~chains) chains);
      "sort", (fun chains -> map_rules ~f:(sort_rules ~chains) chains);
      "normalize", map_rules ~f:normalize_rules;
      "positive", map_rules ~f:prefer_positive_predicates;
      "order", map_rules ~f:(map_predicates ~f:reorder_preds);
      "renumber", remap_chain_ids;
    ]

    let%test_unit "passes and pipeline preserve execution" =
      let index = ref 0 in
      programs (fun before ->
        Int.incr index;
        List.iter transformations ~f:(fun (name, transform) ->
          ignore (check (sprintf "%s, program %d" name !index) transform before)))

    let%test_unit "counter normalization is canonical and preserves emitted effects" =
      let non_counters = List.filter ~f:(fun effect_ -> not (equal_effect_ Counter effect_)) in
      let alphabet = effects @ [Comment "test"; Snat None; Snat (Some (Ipaddr.V4.of_string_exn "192.0.2.1"))] in
      List.iter (sequences alphabet 3) ~f:(fun effects ->
        let normalized = remove_duplicate_counters effects in
        assert_bool "At most one counter per rule"
          (List.count normalized ~f:(equal_effect_ Counter) <= 1);
        assert_bool "Other effects keep their order and multiplicity"
          (equal_effects (non_counters effects) (non_counters normalized));
        assert_bool "Counter normalization is idempotent"
          (equal_effects normalized (remove_duplicate_counters normalized));
        assert_equal ~printer:(String.concat ~sep:"\n")
          (Nftables.emit_nat_rules [rule ~effects Accept])
          (Nftables.emit_nat_rules [rule ~effects:normalized Accept]))

    let improves measure before =
      let after = check "optimization progress" (optimize ~zones:[]) before in
      assert_bool "Redundancy must decrease" (measure after < measure before)

    let%test_unit "known guards remain useful across unrelated effects" =
      List.iter protocol_sets ~f:(fun values ->
        List.iter (sequences effects 2) ~f:(fun effects ->
          let guard = protocols values and child = Temporary 1 in
          chain_map [
            input [rule ~when_:[guard] (Jump child); rule Drop];
            chain child [
              rule ~effects Pass;
              rule ~when_:[guard] ~effects:[Counter] Accept;
              rule Drop;
            ];
          ] |> improves Chain.count_predicates))

    let%test_unit "repeated guards can be shared" =
      List.iter protocol_sets ~f:(fun values ->
        List.iter (sequences effects 1) ~f:(fun effects ->
          List.iter [3; 4; 5] ~f:(fun repeats ->
            let guard = protocols values and child = Temporary 1 in
            chain_map [
              input [rule (Jump child)];
              chain child (
                List.init repeats ~f:(fun _ -> rule ~when_:[guard] ~effects Pass) @
                [rule ~when_:[guard] Accept; rule Drop]);
            ] |> improves Chain.count_predicates)))

    let%test_unit "redundant call frames can be removed" =
      List.iter protocol_sets ~f:(fun values ->
        List.iter (sequences effects 2) ~f:(fun effects ->
          let child = Temporary 2 in
          chain_map [
            input [rule (Jump (Temporary 1))];
            chain (Temporary 1) [rule ~when_:[protocols values] (Jump child); rule Drop];
            chain child [rule ~effects Pass; rule Accept];
          ] |> improves Chain.count_chains))

    let%test_unit "specialization respects its growth budget" =
      programs (fun before ->
        List.iter [0; 1; 3] ~f:(fun max_growth ->
          let after = check "growth budget"
            (specialize_callers ~zones:[] ~max_growth) before in
          assert_bool "Specialization must stay within its budget"
            (Chain.count_rules after <= Chain.count_rules before + max_growth)))

    let%test_unit "zone-domain inference preserves execution" =
      List.iter [Ipv4, [30; 31]; Ipv6, [126; 127]] ~f:(fun (family, lengths) ->
        List.iter directions ~f:(fun dir ->
          let networks =
            List.concat_map [0; 4] ~f:(fun offset ->
              List.map lengths ~f:(fun bits -> network family dir offset bits))
          in
          List.iter networks ~f:(fun (domain, declaration) ->
            let packets =
              List.init 9 ~f:(fun offset ->
                { (default_packet tcp) with
                  addresses = address family offset, address family offset;
                })
            in
            let effects = match family with
              | Ipv4 -> effects @ [Snat (Some (Ipaddr.V4.of_string_exn "198.51.100.1"))]
              | Ipv6 -> effects
            in
            List.iter (sequences effects 1) ~f:(fun effects ->
              let queries =
                List.concat_map networks ~f:(fun ((pred, _), _) -> [pred, false; pred, true]) @
                [Address_family (Set.singleton family), false]
              in
              List.iter queries ~f:(fun query ->
                let parent = Temporary 1 in
                let before = chain_map [
                  input [
                    rule ~when_:[domain] ~effects:[MarkZone (dir, "a")] Pass;
                    rule ~effects Pass;
                    rule ~when_:[Zone (dir, Set.singleton "a"), false] (Jump parent);
                    rule Drop;
                  ];
                  chain parent [rule ~when_:[query] ~effects:[Counter] Accept; rule Drop];
                ] in
                let name = sprintf "zone domain %s, query %s"
                  (P.to_string domain) (P.to_string query) in
                ignore (check ~packets name
                  (optimize ~zones:["a", [declaration]]) before))))))
  end

end
