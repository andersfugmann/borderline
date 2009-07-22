open Common
open Frontend_types
open Frontend
open Chain

let self = ("self", Lexing.dummy_pos)
let all_zones = ("zones", Lexing.dummy_pos)

let rec filter_interface = function 
    Interface(name) :: xs -> name :: filter_interface xs
  | _ :: xs -> filter_interface xs
  | [] -> []

let rec filter_network = function 
    Network(a, m) :: xs -> (a, m) :: filter_network xs
  | _ :: xs -> filter_network xs
  | [] -> []

let rec filter_zonerules table = function
    ZoneRules(t, r, p) :: xs when t = table-> (r, p) :: filter_zonerules table xs
  | _ :: xs -> filter_zonerules table xs
  | [] -> []

let expand = function
    Zone(id, nodes) -> (id, nodes)
  | _ -> raise InternalError 

(* Return a chain that will mark the zone based on direction *)
let create_zone_chain direction (id, nodes) =
  let create_network_rule chain (a, m) = 
    let (low, high) = Ipv6.to_range (a, m) in ([(Ir.IpRange(direction, low, high), false)], Ir.Jump chain.Ir.id) 
  in
  let create_interface_rule chain interface = 
    ([(Ir.Interface(direction, interface), false)], Ir.Jump chain.Ir.id) 
  in
  let chain = Chain.create [([], Ir.MarkZone(direction, id))] ("Mark zone " ^ (id2str id)) in
  let chain = Chain.create (List.map (create_network_rule chain) (filter_network nodes)) ("Match netowkrs for zone " ^ (id2str id)) in
  let chain = Chain.create (List.map (create_interface_rule chain) (filter_interface nodes)) ("Match interfaces for zone " ^ (id2str id)) in
    chain
      
let rec filter = function
    Zone(id, nodes) :: xs -> (id, nodes) :: filter xs
  | x :: xs -> filter xs
  | [] -> []

(* Create auto_defines based on zones *)
let emit_nodes table zones =
  let rec gen_rule_stems (zone_id, nodes) = 
    List.map (
      fun (rules, policy) -> Rule( [ Filter(Ir.DESTINATION, FZone(zone_id)) ] @ rules, Policy policy )
    ) (filter_zonerules table nodes)
  in
    [ DefineStms (all_zones, List.flatten (List.map gen_rule_stems zones)) ]

let emit table zones =
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zones in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zones in
  let src_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) src_chains) "Mark source zones" in
  let dst_chain = Chain.create (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) dst_chains) "Mark destination zones" in
  let input_opers = [ [], Ir.MarkZone (Ir.DESTINATION, self); [], Ir.Jump src_chain.Ir.id  ] in
  let output_opers = [ [], Ir.MarkZone (Ir.SOURCE, self); [], Ir.Jump dst_chain.Ir.id ] in
  let forward_opers = [ [], Ir.Jump src_chain.Ir.id ; [], Ir.Jump dst_chain.Ir.id ] in
    (input_opers, output_opers, forward_opers)
