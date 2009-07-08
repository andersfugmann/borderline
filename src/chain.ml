(* Handle chains, and hold all packet operations *)
open Common
open Ir

let next_id = ref 0
let chains = ref []

let cmp_chain_id = function
    Temporary(a), Temporary(b) -> a = b
  | Builtin(a), Builtin(b)     -> a = b
  | Named(a), Named(b)         -> a = b
  | _, _                       -> false

let get_chain_name = function
    Temporary(id) -> Printf.sprintf "temp_%d" id
  | Named(name) -> Printf.sprintf "%s" name
  | Builtin(tpe) -> match tpe with
        INPUT   -> "INPUT"
      | OUTPUT  -> "OUTPUT"
      | FORWARD -> "FORWARD"

let is_builtin = function
    Builtin(_) -> true
  | _ -> false

let compare a b =
  String.compare (get_chain_name a) (get_chain_name b)

let set chain =
(*  let c = List.filter ( fun chn -> cmp_chain_id (chain.id, chn.id)) !chains in *)
  chains := chain :: !chains; chain

let create rules comment =
  let id = !next_id in
  incr next_id; set { Ir.id = Temporary(id); rules = rules; comment = comment } 

let get_named_chain (id, _) = Named(id)

let create_named_chain id rules comment =
  let chain_id = get_named_chain id in
  (* if List.exists (fun chn -> chn.id = chain_id) !chains then raise (ParseError ("Dublicate id's defined", id)); *)
    set { id = chain_id; rules = rules; comment = comment }

let get chain_id =
  List.find ( fun chn -> cmp_chain_id (chain_id, chn.id) ) !chains

let emit emitter =
  emitter !chains

let optimize opt  =
  chains := opt !chains

let fold func acc =
  List.fold_left func acc !chains





