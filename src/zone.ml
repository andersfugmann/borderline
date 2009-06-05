open Common
open Frontend
open Chain

let gen_oper target op_func cond =
  ([(op_func cond, false)], target)

let rec gen_zone_oper direction = function
    Interface(name) -> Ir.Interface(direction, name)
  | Network(a, m) -> Ir.Address(direction, (a, m))

(* Return a chain that will mark the zone based on direction *)
let create_zone_chain direction = function
  Zone(name, nodes) ->
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
  | _ -> raise InternalError


let emit_zones zone_list =
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zone_list in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zone_list in
  let src_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.id)) src_chains) "Mark source zones" in
  let dst_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.id)) dst_chains) "Mark destination zones" in

  let input_opers = [  [], Ir.Jump src_chain.id  ] in
  let output_opers = [  [], Ir.Jump dst_chain.id ] in
  let forward_opers = [ [], Ir.Jump src_chain.id ; [], Ir.Jump dst_chain.id ] in
    (input_opers, output_opers, forward_opers)











