open Frontend
open Ir

let rec process_zone_data_as_source = function
    Interface(name) -> SourceInterface(name)
  | Ip(a, b, m) as ip -> SourceAddress(ip_to_ip ip)
  | _ -> raise ImpossibleError

let process_zone zone : (Ir.condition * bool) list * Ir.action = 
  match zone with
      Zone(name, nodes) -> let source_conditions = 
        List.map ( fun node -> (process_zone_data_as_source node, false) ) nodes in
        (source_conditions, MarkSourceZone(name))
    | _ -> raise ImpossibleError
    
  
  
