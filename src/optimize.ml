open Ir
open Printf
open Chain

exception MergeImpossible

(* Reorder rules. This is done if the system can see if two rules are independant of each other.
*)


let list_has_intersection a b =
  List.exists (fun x -> List.mem x b) a

let has_common_match a b = match (a, b) with
    Interface (d1, i1), Interface (d2, i2) -> d1 = d2 && i1 = i2 
  | Zone (d1, z1), Zone (d2, z2) -> d1 = d2 && z1 = z2 
  | State s1, State s2 -> list_has_intersection s1 s2
  | TcpPort (d1, p1), TcpPort (d2, p2) when d1 = d2 -> list_has_intersection p1 p2
  | UdpPort (d1, p1), UdpPort (d2, p2) when d1 = d2 -> list_has_intersection p1 p2
  | Address (d1, a1), Address (d2, a2) -> false (* We dont has ip intersection yet *)
  | Protocol p1, Protocol p2 -> p1 = p2
  | _ -> false

let rec chain_reference_count id chains = 
  let filter id = function (_, Jump chn_id) when chn_id = id -> true | _ -> false in
    match chains with
        chain :: xs ->
          List.length (List.filter (filter id) chain.rules) + chain_reference_count id xs
      | [] -> 0

(* Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains : Chain.chain list =
  List.map (fun chn -> { id = chn.id; rules = func chn.rules; comment = chn.comment } ) chains

let rec neg = function
    (x,b) :: xs -> (x, not b) :: neg xs
  | [] -> []

let rec back_merge = function
    (ra, target) :: (rb, Return) :: xs ->
      printf "M";
      back_merge ( (ra @ (neg rb), target) :: xs )
  | x :: xs -> x :: back_merge xs
  | [] -> []

let reduce rules =
  let rules = back_merge (List.rev rules) in
    List.rev rules

let has_target target rules =
  List.exists (fun (c, t) -> t = target) rules

(* Move drops to the bottom. This allows improvement to dead code ellimination *)
type oper = (condition * bool) list * action

let has_common_rule rule1 rule2 =
  match (rule1, rule2) with
      ((cond1, neg1), (cond2, neg2)) when neg1 = neg2 -> has_common_match cond1 cond2
    | _ -> false

let has_intersection cl1 cl2 = 
  let exists cond cond_list = List.exists (fun cond' -> has_common_rule cond cond') cond_list in
    List.exists (fun cond -> exists cond cl2) cl1
    
let order = function
    Notrack -> 1
  | Return -> 2
  | Jump _ -> 3
  | MarkZone _ -> 4
  | Accept -> 5
  | Reject _ -> 6
  | Drop -> 7
      
let reorder_rules (cl1, act1) (cl2, act2) = 
  order act1 > order act2 && not (has_intersection cl1 cl2)
  
let rec reorder = function
    rule1 :: rule2 :: xs when reorder_rules rule1 rule2 -> 
      printf "R";
      rule2 :: reorder (rule1 :: xs)
  | rule1 :: xs -> 
      rule1 :: reorder xs
  | [] -> []

let rec inline chains : Chain.chain list =
  (* inline a list of rules in the given chain *)
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
  let chain_to_inline chains chain = 
    (not (has_target Return chain.rules || Chain.is_builtin chain.id) ) &&
      ( 
        (List.length chain.rules <= 2) ||
          (chain_reference_count chain.id chains = 1)
      )
  in
    
  let rec find_inlineable_chain chains = 
    List.find (chain_to_inline chains) chains
  in

  try
    let chain = find_inlineable_chain chains in
    let filtered_chains = List.filter (fun chn -> chn.id != chain.id) chains in
      printf "I";
      inline (map_chain_rules (inline_chain chain) filtered_chains)
  with not_found -> chains

let rec merge_rules opers = 
  let rec merge = function
      ([], Accept)   as rle :: (_, Accept)    :: xs -> printf "m"; rle :: merge xs
    | ([], Drop)     as rle :: (_, Drop)      :: xs -> printf "m"; rle :: merge xs
    | ([], Return)   as rle :: (_, Return)    :: xs -> printf "m"; rle :: merge xs
    | ([], Reject i) as rle :: (_, Reject i') :: xs when i = i' -> printf "m"; rle :: merge xs
    | rle :: xs -> rle :: merge xs
    | [] -> []
  in
    List.rev (merge (List.rev opers))

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
        
let optimize_pass chains: Chain.chain list = 
  let _ = printf "Rules: %d -" (count_rules chains) in
  let chains = map_chain_rules reduce chains in
  let chains = inline chains in
  let chains = map_chain_rules reorder chains in
  let chains = map_chain_rules merge_rules chains in
  let chains = map_chain_rules eliminate_dead_rules chains in
  let chains = map_chain_rules eliminate_dublicate_rules chains in
  let _ = printf "- %d\n" (count_rules chains) in
    chains
  
let optimize chains : Chain.chain list =
  let chains = optimize_pass chains in
  let chains = optimize_pass chains in
    printf "\nOptimization done\n"; chains
