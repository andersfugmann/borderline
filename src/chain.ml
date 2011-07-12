(** Operations on chains *)

(** This module keeps global state of all chains. *)

open Common
open Ir

let next_id = ref 0

(** Equality between chain names *)
let cmp_chain_id = function
    Temporary(a), Temporary(b) -> a = b
  | Builtin(a), Builtin(b)     -> a = b
  | Named(a), Named(b)         -> a = b
  | _, _                       -> false

(** Retrieve the string name of a chain *)
let get_chain_name = function
    Temporary(id) -> Printf.sprintf "temp_%04d" id
  | Named(name) -> Printf.sprintf "%s" name
  | Builtin(tpe) -> match tpe with
        INPUT   -> "INPUT"
      | OUTPUT  -> "OUTPUT"
      | FORWARD -> "FORWARD"

(** Test if a chain isa builtin one *)
let is_builtin = function
    Builtin(_) -> true
  | _ -> false

let compare a b =
  String.compare (get_chain_name a) (get_chain_name b)

module Chain_map = Map.Make (struct
                               type t = Ir.chain_id
                               let compare = compare
                             end)

let chains = ref Chain_map.empty

(** Select all chains that satisfies pred *)
let filter pred chains : Ir.chain list =
  Chain_map.fold (fun _ chn acc -> if pred chn then chn :: acc else acc) chains []

(** Place a chain in the map *)
let set chain =
  chains := Chain_map.add chain.id chain !chains

(** Delete a chain *)
let delete id =
  chains := Chain_map.remove id !chains

(** Create a new unnamed chain *)
let create rules comment =
  let id = !next_id in
  incr next_id; 
  let chain = { id = Temporary(id); rules = rules; comment = comment } in
  set chain; chain

(** Insert a chain with the given id, rules and comment, possibly replacing exising change of the same name *)
let replace id rules comment =
  let chain = { id = id; rules = rules; comment = comment } in
  set chain; chain

(** Create a chain with the given name *)
let get_named_chain (id, _) = Named(id)

let create_named_chain id rules comment =
  let chain_id = get_named_chain id in
    set { id = chain_id; rules = rules; comment = comment }

(** Retrieve a chain id *)
let get chain_id =
  Chain_map.find chain_id !chains

(** Pass all chains to an emitter *)
let emit emitter =
  emitter !chains

(** Pass all chains through an optimizing pass *)
let optimize opt =
  chains := opt !chains
