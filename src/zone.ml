open Frontend

module Zone = struct
  let rec as_source = function
      Interface(name) -> Ir.Interface(Ir.SOURCE, name)
    | Network(a, b, m) -> Ir.Address(Ir.SOURCE, (a, b, m))

        
  let process_zone zone : (Ir.condition * bool) list * Ir.action = match zone with
      Zone(name, nodes) -> let source_conditions = 
        List.map ( fun node -> (as_source node, false) ) nodes in
        (source_conditions, Ir.MarkSourceZone(name))
    | _ -> raise ImpossibleError
end          
  
  
