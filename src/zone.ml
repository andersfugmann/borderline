open Common 
open Frontend
open Chain

let rec gen_zone_oper zone direction = match zone with 
    Interface(name) -> Ir.Interface(direction, name)
  | Network(a, b, m) -> Ir.Address(direction, (a, b, m))
      

let process_zone = function
  Zone(name, nodes) -> 
    let src_conds = List.map ( fun node -> ((gen_zone_oper node Ir.SOURCE), None) ) nodes in 
    let dst_conds = List.map ( fun node -> ((gen_zone_oper node Ir.DESTINATION), None) ) nodes in
    let src_rule_list = (Some(Ir.build_cond_tree Ir.AND src_conds), Ir.MarkZone(Ir.SOURCE, name)) in
    let dst_rule_list = (Some(Ir.build_cond_tree Ir.AND dst_conds), Ir.MarkZone(Ir.DESTINATION, name)) in
      (src_rule_list, dst_rule_list)
  | _ -> raise InternalError

let emit_zones zone_list =
  let zone_opers = List.map process_zone zone_list in
  let src_zone_opers = List.map ( fun (a,b) -> a ) zone_opers in
  let dst_zone_opers = List.map ( fun (a,b) -> b ) zone_opers in
  let src_chain = Chain.create src_zone_opers "Src zones" in
  let dst_chain = Chain.create dst_zone_opers "Dst zones" in
    (src_chain, dst_chain)

      
  
  
  
  
