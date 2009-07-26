open Common
open Ir
open Printf
open Chain

exception MergeImpossible

let max_inline_size = 1

module Chain_set = Set.Make (struct
                               type t = Ir.chain_id
                               let compare = Chain.compare
                             end)

let rec chain_reference_count id chains =
  let filter id = function (_, Jump chn_id) when chn_id = id -> true | _ -> false in
    match chains with
        chain :: xs ->
          List.length (List.filter (filter id) chain.rules) + chain_reference_count id xs
      | [] -> 0

let rec get_referring_rule c = function
    chn :: xs -> begin
      try List.find (fun (conds, target) -> target = Jump (c.id)) chn.rules with Not_found -> get_referring_rule c xs
    end
  | [] -> failwith "Chain not referenced"


(* Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains : Ir.chain list =
  List.map (fun chn -> { id = chn.id; rules = func chn.rules; comment = chn.comment } ) chains

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
  let is_sibling (a, _) (b, _) =
    (cond_type_identical a b) && (get_dir a = get_dir b)
  in
  let test = function
      (x :: xs, _) as res -> res
    | ([], _) -> raise MergeImpossible
  in
  let merge_list (s, neg) (s', neg') =
    match neg, neg' with
        (true, true) | (false, false) -> test (intersection (=) s s', neg)
      | (false, true) -> test (difference (=) s s', false)
      | (true, false) -> test (difference (=) s' s, false)
  in
  let merge_elem (i, neg) (i', neg') =
    let (i'', neg'') = merge_list ([i], neg) ([i'], neg') in
      (List.hd i'', neg'')
  in
  let rec merge_oper = function
      (Interface (dir, i), neg), (Interface (dir', i'), neg') when dir = dir' ->
        let (i'', neg'') = merge_elem (i, neg) (i', neg') in [(Interface (dir, i''), neg'')]
    | (State s, neg), (State s', neg') ->
        let (s'', neg'') = merge_list (s, neg) (s', neg') in [(State s'', neg'')]
    | (Ports (dir, ports), neg), (Ports (dir', ports'), neg') when dir = dir' ->
        let (ports'', neg'') = merge_list (ports, neg) (ports', neg') in [(Ports (dir, ports''), neg'')]
    | (Protocol proto, neg), (Protocol proto', neg') ->
        let (proto'', neg'') = merge_list (proto, neg) (proto', neg') in [(Protocol (proto''), neg'')]
    | ((IpRange (dir, ips), true) as a), ((IpRange (dir', ips'), false) as b) when dir = dir' ->
        printf "X\n"; flush stdout; merge_oper (b,a)
    | (IpRange (dir, ips), false), (IpRange (dir', ips'), true) when dir = dir' ->
        [ (IpRange (dir, Ipv6.list_difference ips ips'), false) ]
    | (IpRange (dir, ips), neg), (IpRange (dir', ips'), neg') when dir = dir' && neg = neg' ->
        [ (IpRange (dir, Ipv6.list_intersection ips ips'), neg) ]
    | (Zone (dir, zone), neg), (Zone (dir', zone'), neg') when dir = dir' ->
        let (zone'', neg'') = merge_elem (zone, neg) (zone', neg') in [(Zone (dir, zone''), neg'')]
    | _, _ -> raise MergeImpossible

  in
    (* Return a list of all needed rules *)
  let rec merge_siblings acc = function
      x :: xs -> let acc' = List.flatten ( List.map ( fun sib -> merge_oper (sib, x) ) acc ) in
                 merge_siblings acc' xs
    | [] -> acc
  in
    [ List.flatten (List.map (fun lst -> merge_siblings [List.hd lst] (List.tl lst)) (group is_sibling [] rle)) ]

(* Merge two rules that points to the same target when rule a is a subset of rule b. *)
let reduce rules =
  let rec reduce_rev = function
      (cl1, tg1) as r :: (cl2, tg2) :: xs when tg1 = tg2 && is_subset eq_cond cl1 cl2 ->
        printf "*"; r :: reduce_rev xs
    | r :: xs -> r :: reduce_rev xs
    | [] -> []
  in
  let rec reduce_inner rules =
    let rules' = reduce_rev rules in
      if Ir.eq_rules rules rules' then rules
      else reduce_inner rules'
  in
    List.rev (reduce_inner (List.rev rules))

(* Remove all return statements, by creating new chains for each return statement *)
let rec fold_return_statements chains =
  let rec neg = function
      (x,b) :: xs -> (x, not b) :: neg xs
    | [] -> []
  in
  let rec fold_return rules = function
      (cl, Return) :: xs ->
        printf "F";
        let chn = Chain.create xs "Return stm inlined" in
          (rules @ [(neg cl, Jump(chn.id))], [chn])
    | rle :: xs -> fold_return (rules @ [rle]) xs
    | [] -> (rules, [])
  in match chains with
      chn :: xs ->
        let (rules, chn') = fold_return [] chn.rules in
          { id = chn.id; rules = rules; comment = chn.comment } :: fold_return_statements (chn' @ xs)
    | [] -> []

let remove_unreferenced_chains chains =
(* This function visits all reachable chains, and removed all unvisited chains. *)

  let rec get_chain_references = function
      (_, Jump chn_id) :: xs -> chn_id :: get_chain_references xs
    | x :: xs -> get_chain_references xs
    | [] -> []
  in
  let find_chain_opers id =
    try
      let chn = List.find (fun chn -> chn.id = id) chains in
        chn.rules
    with Not_found -> []
  in
  let rec visit visited = function
      chn_id :: xs when not (Chain_set.mem chn_id visited) ->
        let visited = visit (Chain_set.add chn_id visited) (get_chain_references (find_chain_opers chn_id)) in
          visit visited xs
    | x :: xs -> visit visited xs
    | [] -> visited
  in
  let build_in_chains = List.map (fun chn -> chn.id) (List.filter (fun chn -> Chain.is_builtin chn.id) chains) in
  let referenced_chains = visit Chain_set.empty build_in_chains in

    List.filter (fun chn -> Chain_set.mem chn.id referenced_chains) chains

(* Remove dublicate chains *)
let remove_dublicate_chains chains =
  let replace_chain_ids ids id chains =
    let replace = function
        (conds, Jump id') when List.mem id' ids -> (conds, Jump id)
      | x -> x
    in
      map_chain_rules (List.map replace) chains
  in
  let is_sibling a b = (Ir.eq_rules a.rules b.rules) && not (a.id = b.id) in
    try
      let chain = List.find (fun chn -> List.exists (is_sibling chn) chains) chains in
      let (rem_chains, new_chains) = List.partition (is_sibling chain) chains in
      let ids = List.map (fun chn -> chn.id) rem_chains in
        printf "D";
        replace_chain_ids ids chain.id new_chains
    with Not_found -> chains

(* Move drops to the bottom. This allows improvement to dead code elimination, and helps reduce *)
let rec reorder rules =
  let can_reorder cl1 cl2 =
    try
      let _ = merge_opers (cl1 @ cl2) in
        false (* The rules did not conflict. *)
    with MergeImpossible -> true
  in

  let order = function
      Notrack -> 1
    | Accept -> 2
    | MarkZone _ -> 3
    | Jump _ -> 4
    | Return -> 5
    | Reject _ -> 6
    | Drop -> 7
  in
  let should_reorder_rules (cl1, act1) (cl2, act2) =
    if can_reorder cl1 cl2 then
      match order act1 - order act2 with
          n when n > 0 -> true
        | 0 -> List.length cl1 < List.length cl2
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

(* Inline chains for which expr evaluates true *)
let rec inline expr chains : Ir.chain list =
  let has_target target rules =
    List.exists (fun (c, t) -> t = target) rules
  in
  let rec inline_chain chain = function
      (conds, target) :: xs when target = Jump(chain.id) ->
        begin
          let rec inline_rules conds = function
              (c, t) :: xs when t = Return -> raise MergeImpossible
            | (c, t) :: xs -> ( conds @ c, t ) :: inline_rules conds xs
            | [] -> []
          in
            (inline_rules conds chain.rules) @ (inline_chain chain xs)
        end
    | x :: xs -> x :: inline_chain chain xs
    | [] -> []
  in
  let chain_to_inline expr chains chain  =
    (not (has_target Return chain.rules || Chain.is_builtin chain.id) ) && expr chains chain
  in

  let rec find_inlineable_chain expr chains =
    List.find (chain_to_inline expr chains) chains
  in

  try
    let chain = find_inlineable_chain expr chains in
    let filtered_chains = List.filter (fun chn -> chn.id != chain.id) chains in
      printf "I";
      inline expr (map_chain_rules (inline_chain chain) filtered_chains)
  with not_found -> chains

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

let rec count_rules = function
    chain :: xs -> List.length chain.rules + count_rules xs
  | [] -> 0

let optimize_pass chains: Ir.chain list =  printf "Optim: %d " (count_rules chains); flush stdout;
  let chains' = chains in
  let chains' = remove_dublicate_chains chains' in
  let chains' = fold_return_statements chains' in
  let chains' = map_chain_rules eliminate_dead_rules chains' in
  let chains' = map_chain_rules eliminate_dublicate_rules chains' in
  let chains' = inline (fun _ c -> List.length c.rules <= max_inline_size) chains' in
  let chains' = inline (fun cs c -> chain_reference_count c.id cs = 1 && List.length (fst (get_referring_rule c cs)) < 1) chains' in
  let chains' = inline (fun cs c -> chain_reference_count c.id cs < 2 && List.length c.rules < 3) chains' in
  let chains' = map_chain_rules reorder chains' in
  let chains' = map_chain_rules reduce chains' in
  let chains' = map_chain_rules_expand merge_opers chains' in
  let chains' = remove_unreferenced_chains chains' in
  let _ = printf " %d\n" (count_rules chains') in
    chains'

let rec optimize chains : Ir.chain list =
  let chains' = optimize_pass chains in
    if not (count_rules chains' = count_rules chains) then optimize chains'
    else (
      printf "\nOptimization done\n";
      chains')
