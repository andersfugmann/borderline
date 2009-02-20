open Frontend

let rec gen_zone_oper zone direction = match zone with 
    Interface(name) -> Ir.Interface(direction, name)
  | Network(a, b, m) -> Ir.Address(direction, (a, b, m))
      

(* let process_zone zone : (Ir.condition * bool) list * Ir.action = match zone with *)
let process_zone = function
    Zone(name, nodes) -> let source_conditions = 
      List.map ( fun node -> ((gen_zone_oper node Ir.SOURCE), false) ) nodes in
      (source_conditions, Ir.MarkSourceZone(name))
  | _ -> raise ImpossibleError

  
