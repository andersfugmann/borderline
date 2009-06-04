open Ir
open Printf
open Chain

exception MergeImpossible
  
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
      
let rec inline chains = 
  let rec chain_to_inline = function
      (* Inline until no works is to be done. *)
      chain :: xs when List.length chain.rules <= 2 -> 
        begin
          match List.filter (fun (c, t) -> t = Return) chain.rules with
              [] -> Some(chain) (* No return statements present *)
            | _ -> chain_to_inline xs
        end
          (* Other inline candidates are single referenced chains, that
             does NOT contain a return. We must be very carefull not to
             emit returns, or we must find a way to unfold return
             statements:
             a -> return; b -> target; c -> target ==> !a ^ b -> target; !a ^ c -> target 
           *)
    | x :: xs -> chain_to_inline xs
    | [] -> None
  in
    match chain_to_inline chains with
        Some(chain) ->
          printf "I";
          let filtered_chains = List.filter (fun chn -> chn.id != chain.id) chains in
          let mapped = map_chain_rules (inline_chain chain) filtered_chains in
            inline mapped
              
      | None -> chains (* No chains to inline -> Done *)
          
          
let optimize chains =
  let chains = map_chain_rules reduce chains in
  let chains = inline chains in
  let chains = map_chain_rules reduce chains in
  let chains = inline chains in
    printf "\nOptimization done\n"; chains
      
      




