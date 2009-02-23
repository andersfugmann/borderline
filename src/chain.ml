(* Handle chains, and hold all packet operations *)
type chain = { id : int; rules : Ir.oper list; comment: string; }
let next_id = ref 0
let chains = ref []
  
let get_next_id =
  let id = !next_id in
  let _ = next_id := !next_id + 1 in
    id
      
let create _rules _comment = 
  let chn = { id = get_next_id; rules = _rules; comment = _comment } in
  let _ = chains := chn :: !chains in
    chn
