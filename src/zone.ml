open Common 
open Frontend
open Chain

let local = "self"
  
let gen_oper target op_func cond =
  (Some([(op_func cond, None)]), target)

let rec gen_zone_oper direction = function
    Interface(name) -> Ir.Interface(direction, name)
  | Network(a, b, m) -> Ir.Address(direction, (a, b, m))
      
(* Return a chain that will mark the zone based on direction *)
let create_zone_chain direction zone =
  match zone with
      Zone(name, nodes) -> 
        let networks = List.filter ( fun tpe -> match tpe with Network _ -> true | _ -> false ) nodes in
        let interfaces = List.filter ( fun tpe -> match tpe with Interface _ -> true | _ -> false ) nodes in
        let target_chain = Chain.create [(None, Ir.MarkZone (direction, name))] ("Mark zone " ^ name) in
          
        let network_chain = Chain.create (List.map (gen_oper (Ir.Jump target_chain.id) (gen_zone_oper direction)) networks) ("Match networks for zone " ^ name) in
        let interface_chain = Chain.create (List.map (gen_oper (Ir.Jump network_chain.id) (gen_zone_oper direction)) interfaces) ("Match interfaces for zone " ^ name) in
          interface_chain
    | _ -> raise InternalError


let emit_zones zone_list =
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zone_list in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zone_list in
  let src_chain = Chain.create (List.map (fun chn -> (None, Ir.Jump chn.id)) src_chains) "Mark source zones" in
  let dst_chain = Chain.create (List.map (fun chn -> (None, Ir.Jump chn.id)) dst_chains) "Mark destination zones" in
  
  let input_opers = [ None, Ir.MarkZone(Ir.DESTINATION, local) ; None, Ir.Jump src_chain.id  ] in
  let output_opers = [ None, Ir.MarkZone(Ir.SOURCE, local) ; None, Ir.Jump dst_chain.id ] in
  let forward_opers = [ None, Ir.Jump src_chain.id ; None, Ir.Jump dst_chain.id ] in
    Chain.set { id = Ir.Builtin(Ir.INPUT); rules = input_opers; comment = "Builtin" }; 
    Chain.set { id = Ir.Builtin(Ir.OUTPUT); rules = output_opers; comment = "Builtin" }; 
    Chain.set { id = Ir.Builtin(Ir.FORWARD); rules = forward_opers; comment = "Builtin" }; 


      


      
  
  
  
  
