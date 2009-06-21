open Ir
open Printf
open Chain

exception MergeImpossible
exception ImpossibleState

(* Reorder rules. This is done if the system can see if two rules are independant of each other.
*)

let rec intersection xs = function 
    x :: xs' when List.mem x xs -> x :: intersection xs xs'
  | x :: xs' -> intersection xs xs'
  | [] -> []   

(* Determine if a is a true subset of b *)
let is_subset a b = 
  intersection a b = a
 
let has_intersection a b =
  not (intersection a b = [])

let cond_type_identical cond1 cond2 = 
  let enumerate_condition = function
      Interface _ -> 1
    | Zone _      -> 2
    | State _     -> 3
    | TcpPort _   -> 4
    | UdpPort _   -> 5
    | Address _   -> 6
    | Protocol _  -> 7
  in 
    enumerate_condition cond1 = enumerate_condition cond2

let rec chain_reference_count id chains = 
  let filter id = function (_, Jump chn_id) when chn_id = id -> true | _ -> false in
    match chains with
        chain :: xs ->
          List.length (List.filter (filter id) chain.rules) + chain_reference_count id xs
      | [] -> 0

(* Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains : Ir.chain list =
  List.map (fun chn -> { id = chn.id; rules = func chn.rules; comment = chn.comment } ) chains

(* Merge two rules that points to the same target is rule a is a subset of rule b. *)
let reduce rules = 
  let rec reduce_rev = function
      (cl1, tg1) as r :: (cl2, tg2) :: xs when tg1 = tg2 && is_subset cl1 cl2 -> 
        printf "*"; r :: reduce_rev xs              
    | r :: xs -> r :: reduce_rev xs
    | [] -> []
  in
  let rec reduce_inner rules = 
    let rules' = reduce_rev rules in
      if rules = rules' then rules else reduce_inner rules'
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

module Chain_set = Set.Make (struct
                               type t = Ir.chain_id
                               let compare = Chain.compare
                             end)

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


(* Move drops to the bottom. This allows improvement to dead code elimination, and helps reduce *)
let rec reorder rules =
  (* From two lists, create pairs that of the same id *)
  let rec find_intersection cond_list = function
      (cond, neg) :: xs -> 
        begin
          try 
            let (cond', neg') = List.find (fun (cond', _) -> cond_type_identical cond cond') cond_list in
              ((cond, neg), (cond', neg')) :: find_intersection cond_list xs
          with not_found -> find_intersection cond_list xs
        end
    | [] -> []

  in
  let exclusive = function
      (cond, neg), (cond', neg') when not (neg = neg') -> cond = cond' 
    | (Interface (dir, i), _), (Interface (dir', i'), _) when dir = dir' -> not (i = i')
    | (State s1, _), (State s2, _) -> not (has_intersection s1 s2)
    | (TcpPort (dir, ports), _), (TcpPort (dir', ports'), _) when dir = dir' -> not (has_intersection ports ports')
    | (UdpPort (dir, ports), _), (UdpPort (dir', ports'), _) when dir = dir' -> not (has_intersection ports ports')
    | (Address (dir, addr), _), (Address (dir', addr'), _) when dir = dir' -> false (* We dont has ip intersection yet *)
    | (Protocol proto, _), (Protocol proto', _) -> not (proto = proto')
    | _ -> false
  in
  let can_reorder cl1 cl2 = 
    let intersection = find_intersection cl1 cl2 in
      List.exists exclusive intersection
  in
    
  let order = function
      Notrack -> 1
    | Return -> 2
    | Jump _ -> 3
    | MarkZone _ -> 4
    | Accept -> 5
    | Reject _ -> 6
    | Drop -> 7
  in
  let should_reorder_rules (cl1, act1) (cl2, act2) = 
    order act1 > order act2 && can_reorder cl1 cl2
  in
  let rec reorder_rules = function
      rule1 :: rule2 :: xs when should_reorder_rules rule1 rule2 -> 
        printf "R";
        rule2 :: reorder_rules (rule1 :: xs)
    | rule1 :: xs -> 
        rule1 :: reorder_rules xs
    | [] -> []
  
  in
  let rules' = reorder_rules rules in
    if rules = rules' then rules'
    else reorder rules'
      
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
    rle1 :: rle2 :: xs when rle1 = rle2 ->
      printf "d";
      rle1 :: eliminate_dublicate_rules xs
  | rle :: xs -> rle :: eliminate_dublicate_rules xs
  | [] -> []

let rec count_rules = function
    chain :: xs -> List.length chain.rules + count_rules xs
  | [] -> 0

let optimize_pass chains: Ir.chain list =   let _ = printf "Rules: %d " (count_rules chains) in
  let chains' = chains in
  let chains' = fold_return_statements chains' in
  let chains' = map_chain_rules eliminate_dead_rules chains' in
  let chains' = map_chain_rules eliminate_dublicate_rules chains' in
  let chains' = inline (fun _ c -> List.length c.rules <= 2) chains' in
  let chains' = inline (fun cs c -> chain_reference_count c.id cs = 1 && List.length c.rules < 3) chains' in
  let chains' = map_chain_rules reorder chains' in
  let chains' = map_chain_rules reduce chains' in
  let chains' = remove_unreferenced_chains chains' in 
  let _ = printf " %d\n" (count_rules chains') in
    chains'
  
let rec optimize chains : Ir.chain list =
  let chains' = optimize_pass chains in
    if not (count_rules chains' = count_rules chains) then optimize chains'
    else (
      printf "\nOptimization done\n"; 
      chains')
