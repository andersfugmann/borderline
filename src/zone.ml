open Batteries
open Common
module F = Frontend


(** Predefined zones. *)

(** The self zone is the machine it self. *)
let self = "self"

(** The martian zone. Networks packets that have no zone are declared
    martian, which is identified by this build in zone *)
let mars = "mars"

(** Reference to all zone chains. This build in rule traverses all
    zone rules *)
let all_zones = "zones"

(** List of build in zones. *)
let buildin_zones = [ mars ]

let rec filter_interface = function
  | F.Interface (name, _pos) :: xs -> name :: filter_interface xs
  | _ :: xs -> filter_interface xs
  | [] -> []

let rec filter_network = function
  | F.Network (a, m) :: xs -> (a, m) :: filter_network xs
  | _ :: xs -> filter_network xs
  | [] -> []

let rec filter_zonerules table = function
  | F.ZoneRules (t, r, p) :: xs when t = table-> (r, p) :: filter_zonerules table xs
  | _ :: xs -> filter_zonerules table xs
  | [] -> []

(** Return a chain that will mark the zone based on direction *)
let create_zone_chain direction (id, nodes) =
  let create_network_rule chain ips =
    ([(Ir.IpSet(direction, Ipset.from_ips ips), false)], Ir.Jump chain.Ir.id)
  in
  let create_interface_rule chain interface =
    ([(Ir.Interface(direction, [interface]), false)], Ir.Jump chain.Ir.id)
  in
  let chain = Chain.create [([], Ir.MarkZone(direction, id))] ("Mark zone " ^ id) in
  let network_nodes = filter_network nodes in
  let interface_nodes = filter_interface nodes in

  let chain =
    if List.length network_nodes > 0 then
      Chain.create [ create_network_rule chain (filter_network nodes) ] ("Match networks for zone " ^ id)
    else
      chain
  in
    if List.length interface_nodes > 0 then
      Chain.create (List.map (create_interface_rule chain) (filter_interface nodes)) ("Match interfaces for zone " ^ id)
    else
      chain

let rec filter = function
  | F.Zone(id, nodes) :: xs -> (id, nodes) :: filter xs
  | _ :: xs -> filter xs
  | [] -> []

(** Utility function to create an set of zone id's *)
let create_zone_set nodes =
  let rec traverse acc = function
    | F.Zone ((id, _pos), _) :: xs -> traverse (BatSet.add id acc) xs
    | _ :: xs -> traverse acc xs
    | [] -> acc
  in traverse (BatSet.of_list buildin_zones) nodes

(** Emit autogenerated nodes to be inserted in the stream of frontent nodes. *)
let emit_nodes table zones =
  let rec gen_rule_stems (zone_id, nodes) =
    List.map (
      fun (rules, policy) -> F.Rule( [ F.Filter(Ir.DESTINATION, F.FZone([F.Id zone_id]), false) ] @ rules, policy )
    ) (filter_zonerules table nodes)
  in
    [ F.DefineStms ((all_zones, Lexing.dummy_pos), List.flatten (List.map gen_rule_stems zones)) ]

let emit _table zones =
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zones in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zones in
  let src_chain = Chain.create (([], Ir.MarkZone(Ir.SOURCE, mars)) :: (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) src_chains)) "Mark source zones" in
  let dst_chain = Chain.create (([], Ir.MarkZone(Ir.DESTINATION, mars)) :: (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) dst_chains)) "Mark destination zones" in
  let input_opers = [ [], Ir.MarkZone (Ir.DESTINATION, self); [], Ir.Jump src_chain.Ir.id  ] in
  let output_opers = [ [], Ir.MarkZone (Ir.SOURCE, self); [], Ir.Jump dst_chain.Ir.id ] in
  let forward_opers = [ [], Ir.Jump src_chain.Ir.id ; [], Ir.Jump dst_chain.Ir.id ] in
    (input_opers, output_opers, forward_opers)
