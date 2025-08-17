open Base
(** Operations on chains *)

(** This module keeps global state of all chains. *)
open Ir

let next_id = ref 0

(** Test if a chain is builtin*)
let is_builtin = function
  | Chain_id.Builtin _ -> true
  | _ -> false

let is_named = function
  | Chain_id.Named _ -> true
  | _ -> false

let is_temp = function
  | Chain_id.Temporary _ -> true
  | _ -> false

let empty = Map.empty (module Ir.Chain_id)
let chains = ref empty

(** Select all chains that satisfies pred *)
let filter pred chains : Ir.chain list =
  Map.fold ~f:(fun ~key:_ ~data:chn acc -> if pred chn then chn :: acc else acc) chains ~init:[]

(** Place a chain in the map *)
let add chain =
  try
    chains := Map.add_exn ~key:chain.id ~data:chain !chains
  with
  | _ ->
    Printf.failwithf "Could not add chain: %s" ([%sexp_of: Ir.Chain_id.t] chain.id |> Sexp.to_string) ()

(** Delete a chain *)
let delete id =
  chains := Map.remove !chains id

(** Create a new unnamed chain *)
let create rules comment =
  let id = !next_id in
  next_id := !next_id + 1;
  let chain = { id = Temporary(id); rules = rules; comment = comment } in
  add chain; chain

(** Insert a chain with the given id, rules and comment, possibly replacing exising chain of the same name *)
let replace id rules comment =
  let chain = { id = id; rules = rules; comment = comment } in
  delete id;
  add chain; chain

(** Create a chain with the given name *)
let get_named_chain (id, _) = Ir.Chain_id.Named(id)

let create_named_chain id rules comment =
  let chain_id = get_named_chain id in
    add { id = chain_id; rules = rules; comment = comment }

(** Retrieve a chain id *)
let get chain_id =
  Map.find chain_id !chains

(** Pass all chains to an emitter *)
let emit emitter =
  emitter !chains

(** Pass all chains through an optimizing pass *)
let optimize opt =
  chains := opt !chains

let count_chains chains =
  Map.length (chains)

let count_rules chains =
  Map.fold ~init:0 ~f:(fun ~key:_ ~data:{ rules; _ } acc -> acc + (List.length rules)) chains

let count_predicates chains =
  Map.fold ~init:0 ~f:(fun ~key:_ ~data:{ rules; _ } acc ->
    List.fold_left ~init:acc ~f:(fun acc (preds, _effects, _targets) ->
      acc + List.length preds
    ) rules
  ) chains
