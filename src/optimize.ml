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
  intersection a b != []

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
let map_chain_rules func chains : Chain.chain list =
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

(* Move drops to the bottom. This allows improvement to dead code elimination, and helps reduce *)
type oper = (condition * bool) list * action

let has_common_rule rule1 rule2 =
  let has_common_match a b = 
    if cond_type_identical a b then 
      match (a, b) with
          Interface (d1, i1), Interface (d2, i2) -> d1 = d2 && i1 = i2 
        | Zone (d1, z1), Zone (d2, z2) -> d1 = d2 && z1 = z2 
        | State s1, State s2 -> has_intersection s1 s2
        | TcpPort (d1, p1), TcpPort (d2, p2) when d1 = d2 -> has_intersection p1 p2
        | UdpPort (d1, p1), UdpPort (d2, p2) when d1 = d2 -> has_intersection p1 p2
        | Address (d1, a1), Address (d2, a2) -> false (* We dont has ip intersection yet *)
        | Protocol p1, Protocol p2 -> p1 = p2
        | _ -> raise ImpossibleState
    else 
      false
  in    
    match (rule1, rule2) with
        ((cond1, neg1), (cond2, neg2)) when neg1 = neg2 -> has_common_match cond1 cond2
      | _ -> false

let rec reorder rules = 
  let has_intersection cl1 cl2 = 
    let exists cond cond_list = List.exists (fun cond' -> has_common_rule cond cond') cond_list in
      List.exists (fun cond -> exists cond cl2) cl1
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
    order act1 > order act2 && not (has_intersection cl1 cl2)
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
let rec inline expr chains : Chain.chain list =
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

(*
      ( 
        (List.length chain.rules <= 2) || (chain_reference_count chain.id chains = 1)
      )
*)
        
let optimize_pass chains: Chain.chain list = 
  let _ = printf "Rules: %d -" (count_rules chains) in
  let chains' = chains in
  let chains' = fold_return_statements chains' in
  let chains' = inline (fun _ c -> List.length c.rules <= 2) chains' in
  let chains' = map_chain_rules reduce chains' in
  let chains' = map_chain_rules reorder chains' in
  (* let chains' = map_chain_rules merge_rules chains' in *)
  let chains' = map_chain_rules eliminate_dead_rules chains' in
  let chains' = map_chain_rules eliminate_dublicate_rules chains' in
  let chains' = inline (fun cs c -> chain_reference_count c.id cs = 1 && List.length c.rules < 3) chains' in
  let _ = printf "- %d\n" (count_rules chains') in
    chains'
  
let rec optimize chains : Chain.chain list =
  let chains' = optimize_pass chains in
    if count_rules chains' != count_rules chains then optimize chains'
    else (
      printf "\nOptimization done\n"; 
      chains')
