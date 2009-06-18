open Common
open Frontend
open Chain

let self = "self"
let all_zones = "zones"

let gen_oper target op_func cond =
  ([(op_func cond, false)], target)

let rec gen_zone_oper direction = function
    Interface(name) -> Ir.Interface(direction, name)
  | Network(a, m) -> Ir.Address(direction, (a, m))

(* Return a chain that will mark the zone based on direction *)
let create_zone_chain direction zone =
  let Zone(name, nodes) = zone in
  let networks = List.filter ( fun tpe -> match tpe with Network _ -> true | _ -> false ) nodes in
  let interfaces = List.filter ( fun tpe -> match tpe with Interface _ -> true | _ -> false ) nodes in
  let chain =
    let tmp_chn = Chain.create [([], Ir.MarkZone (direction, name))] ("Mark zone " ^ name) in
      if List.length networks = 0 then
        tmp_chn
      else
        Chain.create (List.map (gen_oper (Ir.Jump tmp_chn.id) (gen_zone_oper direction)) networks) ("Match networks for zone " ^ name)
  in
    Chain.create (List.map (gen_oper (Ir.Jump chain.id) (gen_zone_oper direction)) interfaces) ("Match interfaces for zone " ^ name)


let emit_zones zone_list =
  let zone_list = Zone(self, [ Interface("lo") ]) :: zone_list in
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zone_list in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zone_list in
  let src_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.id)) src_chains) "Mark source zones" in
  let dst_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.id)) dst_chains) "Mark destination zones" in
  let _ = Chain.create_named_chain all_zones (List.map (fun z -> let Zone(id,_) = z in ([(Ir.Zone(Ir.DESTINATION, id), false)], Ir.Jump (get_named_chain id)) ) zone_list) "automatic chain" in

  let input_opers = [ [], Ir.MarkZone (Ir.DESTINATION, self); [], Ir.Jump src_chain.id  ] in
  let output_opers = [ [], Ir.MarkZone (Ir.SOURCE, self); [], Ir.Jump dst_chain.id ] in
  let forward_opers = [ [], Ir.Jump src_chain.id ; [], Ir.Jump dst_chain.id ] in
    (input_opers, output_opers, forward_opers)











