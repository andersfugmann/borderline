open Ir
open Printf
open Chain

exception MergeImpossible

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
      printf "R";
      back_merge ( (ra @ (neg rb), target) :: xs )
  | x :: xs -> x :: back_merge xs
  | [] -> []

let reduce rules =
  let rules = back_merge (List.rev rules) in
    List.rev rules

let has_target target rules =
  List.exists (fun (c, t) -> t = target) rules

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
  let chains = map_chain_rules eliminate_dead_rules chains in
  let chains = map_chain_rules eliminate_dublicate_rules chains in
  let _ = printf "- %d\n" (count_rules chains) in
    chains
  
let optimize chains : Chain.chain list =
  let chains = optimize_pass chains in
  let chains = optimize_pass chains in
    printf "\nOptimization done\n"; chains
