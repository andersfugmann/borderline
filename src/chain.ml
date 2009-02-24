(* Handle chains, and hold all packet operations *)
open Ir

type chain = { id: chain_id; rules : oper list; comment: string; }
let next_id = ref 0

let chains = ref []
  
let cmp_chain_id = function
    Temporary(a), Temporary(b) -> a = b
  | Builtin(a), Builtin(b)     -> a = b
  | _, _                       -> false

let get_chain_name = function
    Temporary(id) -> Printf.sprintf "temp_%d" id
  | Builtin(tpe) -> match tpe with 
        INPUT   -> "INPUT"
      | OUTPUT  -> "OUTPUT"
      | FORWARD -> "FORWARD"

let create rules comment = 
  let id = !next_id in
  let _ = next_id := id + 1 in
  let chn = { id = Temporary(id); rules = rules; comment = comment } in
  let _ = chains := chn :: !chains in
    chn

let set chain =
(*  let c = List.filter ( fun chn -> cmp_chain_id (chain.id, chn.id)) !chains in *)
    chains := chain :: !chains

let get chain_id = 
  List.find ( fun chn -> cmp_chain_id (chain_id, chn.id) ) !chains
   
let emit emitter =
  List.flatten ( List.map emitter !chains )
  



  
