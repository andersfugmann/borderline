open Ir
open Printf
open Chain

exception MergeImpossible

let chain_reference_count id = function
    chain :: xs ->
      let filter = fun (rle, target) -> match target with Jump chn_id when chn_id = id -> true | _ -> false in
        List.length (List.filter filter rules) + chain_reference_count id xs
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

let rec find_inlineable_chain = function
    (* Inline until no works is to be done. *)
    chain :: xs when List.length chain.rules <= 2 ->
      begin
        match has_target Return chain.rules with
            false -> Some(chain) (* No return statements present *)
          | true -> find_inlineable_chain xs
      end
        (* Other inline candidates are single referenced chains, that
           does NOT contain a return. We must be very carefull not to
           emit returns, or we must find a way to unfold return
           statements:
           a -> return; b -> target; c -> target ==> !a ^ b -> target; !a ^ c -> target
        *)
  | x :: xs -> find_inlineable_chain xs
  | [] -> None

let rec inline chains : Chain.chain list =
  match find_inlineable_chain chains with
      Some(chain) ->
        printf "I";
        let filtered_chains = List.filter (fun chn -> chn.id != chain.id) chains in
          inline (map_chain_rules (inline_chain chain) filtered_chains)

    | None -> chains (* No chains to inline -> Done *)


let optimize chains : Chain.chain list =
  let chains = map_chain_rules reduce chains in
  let chains = inline chains in
    printf "\nOptimization done\n"; chains






