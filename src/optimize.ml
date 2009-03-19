open Ir
open Printf
open Chain

exception MergeImpossible

let rec neg = function
    (x,b) :: xs -> (x, not b) :: neg xs
  | [] -> []

let rec back_merge = function
    (ra, target) :: (rb, Return) :: xs -> printf "R"; back_merge ( (ra @ (neg rb), target) :: xs )
  | x :: xs -> x :: back_merge xs
  | [] -> []

let reduce rules =
  let rules = back_merge (List.rev rules) in
    List.rev rules

(* Inline calling inline does not work *)

(* Inline chains with only one rule *)
let rec inline_rule id (trls, target) = function
    (rls, Jump _id) :: xs when _id == id ->
      printf "I"; (rls @ trls, target) :: inline_rule id (rls, target) xs
  | x :: xs -> x :: inline_rule id (trls, target) xs
  | _ -> []


let inline acc chain =
  match chain.id with
      Builtin _ -> acc
    | _ ->
        begin
          match chain.rules with
              [(conds, target)] when target != Return ->
                Chain.optimize (inline_rule chain.id (conds, target));
                chain.id :: acc
            | _ -> acc
        end

let optimize () =
  let _ = Chain.optimize reduce in
  let inlined_chains = Chain.fold inline [] in
  let _ = List.iter (fun _ -> printf "D") inlined_chains in
  let _ = List.map Chain.delete inlined_chains in
    printf "\nOptimization done\n"





