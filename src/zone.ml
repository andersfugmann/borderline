open Common
open Frontend
open Chain

let self = ("self", Lexing.dummy_pos)
let all_zones = ("zones", Lexing.dummy_pos)

let gen_oper target op_func cond =
  ([(op_func cond, false)], target)

let rec gen_zone_oper direction = function
    Interface(name) -> Ir.Interface(direction, name)
  | Network(a, m) -> let (low, high) = Ipv6.to_range (a, m) in
      Ir.IpRange(direction, low, high)
  | _ -> raise InternalError

let expand = function
    Zone(id, nodes) -> (id, nodes)
  | _ -> raise InternalError 
     
(* Return a chain that will mark the zone based on direction *)
let create_zone_chain direction (id, nodes) =
  let networks = List.filter ( fun tpe -> match tpe with Network _ -> true | _ -> false ) nodes in
  let interfaces = List.filter ( fun tpe -> match tpe with Interface _ -> true | _ -> false ) nodes in
  let tmp_chn = Chain.create [([], Ir.MarkZone(direction, id))] ("Mark zone " ^ (id2str id)) in
  let chain = 
    if List.length networks = 0 then
      tmp_chn
    else
      Chain.create (List.map (gen_oper (Ir.Jump tmp_chn.Ir.id) (gen_zone_oper direction)) networks) ("Match networks for zone " ^ (id2str id))
  in
    Chain.create (List.map (gen_oper (Ir.Jump chain.Ir.id) (gen_zone_oper direction)) interfaces) ("Match interfaces for zone " ^ (id2str id))
      
let rec filter = function
    Zone(id, nodes) :: xs -> (id, nodes) :: filter xs
  | x :: xs -> filter xs
  | [] -> []

(* Create auto_defines based on zones *)
let emit_nodes zones =
  let rec gen_rule_stems (zone_id, _) =  
    Rule([Filter(Ir.DESTINATION, FZone(zone_id)); Reference zone_id], Policy DENY)
  in
    [ Define(all_zones, List.map gen_rule_stems zones) ]


let emit zones =
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zones in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zones in
  let src_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) src_chains) "Mark source zones" in
  let dst_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) dst_chains) "Mark destination zones" in

  let input_opers = [ [], Ir.MarkZone (Ir.DESTINATION, self); [], Ir.Jump src_chain.Ir.id  ] in
  let output_opers = [ [], Ir.MarkZone (Ir.SOURCE, self); [], Ir.Jump dst_chain.Ir.id ] in
  let forward_opers = [ [], Ir.Jump src_chain.Ir.id ; [], Ir.Jump dst_chain.Ir.id ] in
    (input_opers, output_opers, forward_opers)
