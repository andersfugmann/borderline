open Core
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

let chains = ref (Map.empty (module Ir.Chain_id))

(** Select all chains that satisfies pred *)
let filter pred chains : Ir.chain list =
  Map.fold ~f:(fun ~key:_ ~data:chn acc -> if pred chn then chn :: acc else acc) chains ~init:[]

(** Place a chain in the map *)
let add chain =
  try
    chains := Map.add_exn ~key:chain.id ~data:chain !chains
  with
  | _ ->
    let chains =
      Map.fold ~init:[] ~f:(fun ~key ~data:_ acc -> key :: acc) !chains
      |> List.map ~f:(fun chain -> Ir.Chain_id.show chain)
      |> String.concat ~sep:"; "
    in
    failwithf "Could not add chain: %s [%s]" ([%show: Ir.Chain_id.t] chain.id) chains ()

(** Delete a chain *)
let delete id =
  chains := Map.remove !chains id

(** Create a new unnamed chain *)
let create rules comment =
  let id = !next_id in
  incr next_id;
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
