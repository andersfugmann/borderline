open Batteries
(** Operations on chains *)

(** This module keeps global state of all chains. *)

open Common
open Ir

let next_id = ref 0

(** Test if a chain is builtin*)
let is_builtin = function
  | Builtin(_) -> true
  | _ -> false

let chains = ref Map.empty

(** Select all chains that satisfies pred *)
let filter pred chains : Ir.chain list =
  Map.fold (fun chn acc -> if pred chn then chn :: acc else acc) chains []

(** Place a chain in the map *)
let add chain =
  chains := Map.add chain.id chain !chains

(** Delete a chain *)
let delete id =
  chains := Map.remove id !chains

(** Create a new unnamed chain *)
let create rules comment =
  let id = !next_id in
  incr next_id;
  let chain = { id = Temporary(id); rules = rules; comment = comment } in
  add chain; chain

(** Insert a chain with the given id, rules and comment, possibly replacing exising chain of the same name *)
let replace id rules comment =
  let chain = { id = id; rules = rules; comment = comment } in
  add chain; chain

(** Create a chain with the given name *)
let get_named_chain (id, _) = Named(id)

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
