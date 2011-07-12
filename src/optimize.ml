open Common
open Ir
open Printf
open Chain

(** Define the saving in conditions when inlining. *)
let min_inline_saving = -2

let rec chain_reference_count id chains =
  let count_references rules =
    List.fold_left (fun acc -> function (_, Jump id') when id = id' -> acc + 1 | _ -> acc) 0 rules
  in
    Chain_map.fold (fun _ chn acc -> acc + (count_references chn.rules)) chains 0

let rec get_referring_rules chain chains =
  let test (conds, target) = target = Jump (chain.id) in
  let referring_chains = Chain.filter (fun chn -> List.exists test chn.rules) chains in
    List.fold_left (fun acc chn -> (List.filter test chn.rules) @ acc) [] referring_chains

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains =
  Chain_map.map (fun chn -> { id = chn.id; rules = func chn.rules; comment = chn.comment }) chains

let rec map_chain_rules_expand func chains : Ir.chain list =
  let rec map_rules = function
      (opers, target) :: xs ->
        (try
          (List.map (fun opers' -> (opers', target)) (func opers))
         with _ -> printf "E"; []
        ) @ map_rules xs
    | [] -> []
  in
    List.map (fun chn -> { id = chn.id; rules = map_rules chn.rules; comment = chn.comment } ) chains

let merge_opers rle =
  (** A bit dangerous, as the compiler wont warn when new types are added. *)
  let is_sibling a b =
    match (a, b) with
        (Interface (dir, _), _), (Interface (dir', _), _) when dir = dir' -> true
      | (State s, neg), (State s', neg') -> true
      | (Ports (dir, _), _), (Ports (dir', _), _) when dir = dir' -> true
      | (Protocol _, _), (Protocol _, _) -> true
      | (IcmpType _, _), (IcmpType _, _) -> true
      | (IpSet (dir, _), _), (IpSet (dir', _), _) when dir = dir' -> true
      | (Zone (dir, _), _), (Zone (dir', _), _) when dir = dir' -> true
      | (TcpFlags _, _), (TcpFlags _, _) -> false
      | _ -> false
  in
  let merge_list (s, neg) (s', neg') =
    match neg, neg' with
        (false, false) -> (intersection (=) s s', false)
      | (true, true) -> (union (=) s s', true)
      | (false, true) -> (difference (=) s s', false)
      | (true, false) -> (difference (=) s' s, false)
  in
  let rec merge_oper a b =
    match a, b with
        (Interface (dir, il), neg), (Interface (dir', il'), neg') when dir = dir' ->
          let (il'', neg'') = merge_list (il, neg) (il', neg') in (Interface (dir, il''), neg'')
      | (State s, neg), (State s', neg') ->
          let (s'', neg'') = merge_list (s, neg) (s', neg') in (State s'', neg'')
      | (Ports (dir, ports), neg), (Ports (dir', ports'), neg') when dir = dir' ->
          let (ports'', neg'') = merge_list (ports, neg) (ports', neg') in (Ports (dir, ports''), neg'')
      | (Protocol proto, neg), (Protocol proto', neg') ->
          let (proto'', neg'') = merge_list (proto, neg) (proto', neg') in (Protocol (proto''), neg'')
      | (IcmpType types, neg), (IcmpType types', neg') ->
          let (types'', neg'') = merge_list (types, neg) (types', neg') in (IcmpType types'', neg'')
      | ((IpSet (dir, ips), true) as a), ((IpSet (dir', ips'), false) as b) when dir = dir' ->
          merge_oper b a
      | (IpSet (dir, ips), false), (IpSet (dir', ips'), true) when dir = dir' ->
          (IpSet (dir, Ipset.diff ips ips'), false)
      | (IpSet (dir, ips), neg), (IpSet (dir', ips'), neg') when dir = dir' && neg = neg' ->
          (IpSet (dir, Ipset.inter ips ips'), neg)
      | (Zone (dir, zones), neg), (Zone (dir', zones'), neg') when dir = dir' ->
          let (zones'', neg'') = merge_list (zones, neg) (zones', neg') in (Zone (dir, zones''), neg'')
      | (cond, _), (cond', _) -> failwith ("is_sibling failed: " ^ string_of_int (enumerate_cond cond) ^ ", " ^ string_of_int (enumerate_cond cond'))

  in
  let rec merge_siblings acc = function
      x :: xs -> let siblings, rest = List.partition (is_sibling x) xs in
        merge_siblings ( (List.fold_left merge_oper x siblings) :: acc ) rest
    | [] -> acc
  in
    merge_siblings [] rle

let is_satisfiable conds =
  not (List.exists (is_always false) conds)

let is_subset a b =
  not (List.exists (fun (cond, neg) -> is_satisfiable (merge_opers ((cond, not neg) :: a))) b)

(** Reduce rules. Walk the tree (forward and backwards) and eliminate
    unreachable rules. *)
let reduce chains =
  let false_rule = ([State [], false], Notrack) in
  let is_terminal = function
    | Jump _ | MarkZone _ | Notrack | Log _ -> false
    | Accept | Drop | Reject _ | Return -> true
  in
  let chains = ref chains in
  let get_chain chain_id = Chain_map.find chain_id !chains in
  let rec reduce_chain func chain_id =
    let chn = get_chain chain_id in
    let rls = func chn.rules in
    chains := Chain_map.add chn.id { id = chn.id; rules = rls; comment = chn.comment } !chains;

  and reduce_jump conds rules chain_id =
    let rec filter_until pred = function
    x :: xs when pred x -> []
      | x :: xs -> x :: filter_until pred xs
      | [] -> []
    in
    let terminal_rules = List.filter (fun (_, tg) -> is_terminal tg) (get_chain chain_id).rules in
    let terminals = filter_until (fun (_, tg) -> tg = Return) terminal_rules in
    List.fold_left (fun rules (conds', target') -> reduce_rules ((merge_opers conds @ conds'), target') rules) rules terminals

  and reduce_forward_jump = function
    | (cond', Jump chain_id) as rle :: xs ->
      rle :: reduce_forward_jump (reduce_jump cond' xs chain_id)
    | rle :: xs -> rle :: reduce_forward_jump xs
    | [] -> []


  and reduce_rules (cond, target) = function
  (cond', _) :: xs when is_subset cond' cond ->
    print_string "E"; reduce_rules (cond, target) xs
    | (cond', Jump chain_id) as rle :: xs when chain_reference_count chain_id !chains = 1 ->
      reduce_chain (reduce_rules (cond, target)) chain_id;
      rle :: reduce_rules (cond, target) xs
    | (cond', target') as rle :: xs when is_terminal target' ->
      rle :: reduce_rules (cond', target') (reduce_rules (cond, target) xs)
    | rle :: xs -> rle :: reduce_rules (cond,target) xs
    | [] -> []

  and reduce_rules_rev (cond, target) = function
  (cond', Return) as rle :: xs -> rle :: reduce_rules_rev false_rule xs
    | (cond', target') :: xs when target = target' && is_subset cond' cond ->
      print_string "F"; reduce_rules_rev (cond, target) xs
    | (cond', target') as rle :: xs when target = target' ->
      let rls = reduce_rules_rev (cond, target) xs in rle :: reduce_rules_rev rle rls
    | (cond', Jump chain_id) as rle :: xs ->
      reduce_chain (reduce_rules_reverse (cond, target)) chain_id;
      rle :: reduce_rules_rev false_rule xs
    | (cond', target) as rle :: xs when is_terminal target -> rle :: reduce_rules_rev rle xs
    | rle :: xs -> rle :: reduce_rules_rev false_rule xs
    | [] -> []

  and reduce_rules_reverse (cond, target) rules =
    List.rev (reduce_rules_rev (cond, target) (List.rev rules))
  in

  let keys = Chain_map.fold (fun key _ acc -> key :: acc) !chains [] in
  List.iter (reduce_chain (reduce_rules false_rule)) keys;
  List.iter (reduce_chain (reduce_rules_reverse false_rule)) keys;
  List.iter (reduce_chain reduce_forward_jump) keys;
  !chains

(** Remove all return statements, by creating new chains for each
    return statement *)
let rec fold_return_statements chains =  
  let rec neg = List.map (fun (x, a) -> (x, not a)) in
  let rec fold_return acc = function
  (cl, Return) :: xs ->
    printf "F";
    let rls, chns = fold_return [] xs in
    let chn = Chain.create rls "Return stm inlined" in
    (acc @ [(neg cl, Jump(chn.id))], chn :: chns)
    | rle :: xs -> fold_return (acc @ [rle]) xs
    | [] -> (acc, [])
  in
  
  let fold_func _ chn acc =
    let rls, chns = fold_return [] chn.rules in
    List.fold_left (fun acc chn -> Chain_map.add chn.id chn acc) acc ( { id = chn.id; rules = rls; comment = chn.comment } :: chns )
  in
  Chain_map.fold fold_func chains Chain_map.empty

let remove_unreferenced_chains chains =
  let get_referenced_chains chain =
    List.fold_left (fun acc -> function (_, Jump id) -> (Chain_map.find id chains) :: acc | _ -> acc) [] chain.rules
  in
  let rec descend acc chain =
    List.fold_left (fun acc chn -> descend acc chn) (Chain_map.add chain.id chain acc) (get_referenced_chains chain)
  in
  Chain_map.fold (fun id chn acc -> match id with Builtin _ -> descend acc chn | _ -> acc) chains Chain_map.empty

(** Remove dublicate chains *)
let remove_dublicate_chains chains =
  let replace_chain_ids (id, ids) chns =
      map_chain_rules (List.map (function (c, Jump id') when List.mem id' ids -> (c, Jump id) | x -> x)) chns
  in
  let is_sibling a b = (Ir.eq_rules a.rules b.rules) && not (a.id = b.id) in
  let identical_chains chain chains = Chain_map.fold (fun id chn acc -> if is_sibling chain chn then id :: acc else acc) chains [] in
  let remap_list = Chain_map.fold (fun id chn acc -> (id, identical_chains chn chains) :: acc) chains [] in
    List.fold_left (fun acc (id, ids) -> if List.length ids > 0 then printf "D"; replace_chain_ids (id, ids) acc) chains remap_list

(** Move drops to the bottom. This allows improvement to dead code
    elimination, and helps reduce *)
let rec reorder rules =
  let can_reorder (cl1, act1) (cl2, act2) =
    act1 = act2 || not (is_satisfiable (merge_opers (cl1 @ cl2)))
  in

  let order = function
    | Log _ -> 0
    | Notrack -> 1
    | Accept -> 2
    | MarkZone _ -> 3
    | Jump _ -> 4
    | Return -> 5
    | Reject _ -> 6
    | Drop -> 7
  in
  let should_reorder_rules (cl1, act1) (cl2, act2) =
    if can_reorder (cl1, act1) (cl2, act2) then
      match order act1 - order act2 with
          n when n > 0 -> true
        | 0 -> if List.length cl1 < List.length cl2 then true
          else (* Weight the types, and add them. *) false
        | _ -> false
    else
      false
  in
  let rec reorder_rules acc = function
      rule1 :: rule2 :: xs when should_reorder_rules rule1 rule2 ->
        printf "R";
        reorder_rules [] (acc @ rule2 :: rule1 :: xs)
    | rule1 :: xs ->
        reorder_rules (acc @ [ rule1]) xs
    | [] -> acc

  in
    reorder_rules [] rules

(** Inline chains that satifies p *)
let rec inline p chains =
  let has_target target rules =
    List.exists (fun (_, t) -> t = target) rules
  in
  let rec inline_chain chain = function
      (conds, target) :: xs when target = Jump(chain.id) ->
        begin
          let rec inline_rules conds = function
              (c, t) :: xs when t = Return -> failwith "Inline of return target dosallowed."
            | (c, t) :: xs -> ( conds @ c, t ) :: inline_rules conds xs
            | [] -> []
          in
            (inline_rules conds chain.rules) @ (inline_chain chain xs)
        end
    | x :: xs -> x :: inline_chain chain xs
    | [] -> []
  in

  (** Find one chain that satifies p *)
  let p' chains chain = (not (has_target Return chain.rules || Chain.is_builtin chain.id) ) && chain_reference_count chain.id chains > 0 && p chains chain in
    try
      let chains_to_inline = List.hd (Chain.filter (p' chains) chains) in
        printf "I"; inline p (map_chain_rules (inline_chain chains_to_inline) chains)
    with Failure _ -> chains

let rec eliminate_dead_rules = function
    ([], Accept) | ([], Drop) | ([], Return) | ([], Reject _) as rle :: xs ->
      if List.length xs > 0 then printf "D";
      [ rle ]
  | rle :: xs -> rle :: eliminate_dead_rules xs
  | [] -> []

let rec eliminate_dublicate_rules = function
    rle1 :: rle2 :: xs when Ir.eq_oper rle1 rle2 ->
      printf "d";
      rle1 :: eliminate_dublicate_rules xs
  | rle :: xs -> rle :: eliminate_dublicate_rules xs
  | [] -> []

(** For each rule in a chain, tests is the conditions are satisfiable.
    All rules which contains an unsatisfiable rule are removed
    (including its target)
*)
let remove_unsatisfiable_rules rules =
  List.filter (fun (conds, _) -> is_satisfiable conds) rules

(** All conditions which a tautologically true are removed *)
let remove_true_rules rules =
  List.map (fun (conds, target) -> (List.filter (fun cond -> not (is_always true cond)) conds, target)) rules

let rec count_rules chains =
  Chain_map.fold (fun _ chn acc -> acc + List.length chn.rules) chains 0

(** Determine if a chain should be linined. The algorithm is based on
    number of conditions before and after the merge, with a slight
    tendency to inline *)
let should_inline cs c =
  (* Number of conditions in the chain to be inlined *)
  let chain_conds = List.fold_left (fun acc (cl, t) -> acc + List.length cl) 0 c.rules in
  (* Number of conditions for each reference to the chain to be inlined. *)
  let rule_conds = List.map (fun (cl, t) -> List.length cl) (get_referring_rules c cs) in
  (* Current count of conditions + targets *)
  let old_conds = (List.fold_left (+) 0 rule_conds) + chain_conds + List.length rule_conds + List.length c.rules in
  (* Inlined count of conditions + targets *)
  let new_conds = List.fold_left (fun acc n -> acc + n * List.length c.rules + chain_conds) 0 rule_conds + (List.length rule_conds * List.length c.rules) in
    old_conds - new_conds > min_inline_saving

let conds chains =
  Chain_map.fold (fun _ chn acc -> List.fold_left (fun acc (cl, _) -> List.length cl + acc) (acc + 1) chn.rules) chains 0

let optimize_pass chains =
  printf "Optim: (%d, %d) " (count_rules chains) (conds chains); flush stdout;
  let optimize_functions = [
    fold_return_statements;
    remove_dublicate_chains;
    map_chain_rules remove_unsatisfiable_rules;
    map_chain_rules remove_true_rules;
    map_chain_rules eliminate_dead_rules;
    map_chain_rules eliminate_dublicate_rules;
    map_chain_rules reorder;
    reduce;
    inline should_inline;
    map_chain_rules (fun rls -> Common.map_filter_exceptions (fun (opers, tg) -> (merge_opers opers, tg)) rls);
    remove_unreferenced_chains ] in
  let chains' = List.fold_left (fun chains' optim_func -> optim_func chains') chains optimize_functions in
    printf " (%d, %d)\n" (count_rules chains') (conds chains');
    chains'

let rec optimize chains =
  let chains' = optimize_pass chains in
    match (conds chains) = (conds chains') with
        true -> printf "Optimization done\n"; chains'
      | false -> optimize chains'

