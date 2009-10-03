(*
 * Copyright 2009 Anders Fugmann.
 * Distributed under the GNU General Public License v3
 *
 * This file is part of Borderline - A Firewall Generator
 *
 * Borderline is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Borderline is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Borderline.  If not, see <http://www.gnu.org/licenses/>.
 *)

open Common
open Frontend_types
open Frontend
open Chain

let self = ("self", Lexing.dummy_pos)
let mars = ("mars", Lexing.dummy_pos)
let ext_zones = ("external", Lexing.dummy_pos)
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

(* Return a chain that will mark the zone based on direction *)
let create_zone_chain direction (id, nodes) =
  let create_network_rule chain ip =
    ([(Ir.IpRange(direction, [ Ipv6.to_range ip ] ), false)], Ir.Jump chain.Ir.id)
  in
  let create_interface_rule chain interface =
    ([(Ir.Interface(direction, interface), false)], Ir.Jump chain.Ir.id)
  in
  let chain = Chain.create [([], Ir.MarkZone(direction, id))] ("Mark zone " ^ (id2str id)) in
  let network_nodes = filter_network nodes in
  let interface_nodes = filter_interface nodes in

  let chain =
    if List.length network_nodes > 0 then
      Chain.create (List.map (create_network_rule chain) (filter_network nodes)) ("Match networks for zone " ^ (id2str id))
    else
      chain
  in
    if List.length interface_nodes > 0 then
      Chain.create (List.map (create_interface_rule chain) (filter_interface nodes)) ("Match interfaces for zone " ^ (id2str id))
    else
      chain

let rec filter = function
    Zone(id, nodes) :: xs -> (id, nodes) :: filter xs
  | x :: xs -> filter xs
  | [] -> []

(* Utility function to create an id_set of zone id's *)
let rec create_zone_set acc = function
  | (id, _) :: xs -> create_zone_set (Id_set.add id acc) xs
  | [] -> Id_set.union (idset_from_list [self; mars; ext_zones; all_zones ]) acc

let emit_nodes table zones =
  let rec gen_rule_stems (zone_id, nodes) =
    List.map (
      fun (rules, policy) -> Rule( [ Filter(Ir.DESTINATION, FZone([Id zone_id]), false) ] @ rules, policy )
    ) (filter_zonerules table nodes)
  in
    [ DefineStms (all_zones, List.flatten (List.map gen_rule_stems zones)) ]

let emit table zones =
  let src_chains = List.map (create_zone_chain Ir.SOURCE) zones in
  let dst_chains = List.map (create_zone_chain Ir.DESTINATION) zones in
  let src_chain = Chain.create (([], Ir.MarkZone(Ir.SOURCE, mars)) :: (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) src_chains)) "Mark source zones" in
  let dst_chain = Chain.create (([], Ir.MarkZone(Ir.DESTINATION, mars)) :: (List.map (fun chn -> ([], Ir.Jump chn.Ir.id)) dst_chains)) "Mark destination zones" in
  let input_opers = [ [], Ir.MarkZone (Ir.DESTINATION, self); [], Ir.Jump src_chain.Ir.id  ] in
  let output_opers = [ [], Ir.MarkZone (Ir.SOURCE, self); [], Ir.Jump dst_chain.Ir.id ] in
  let forward_opers = [ [], Ir.Jump src_chain.Ir.id ; [], Ir.Jump dst_chain.Ir.id ] in
    (input_opers, output_opers, forward_opers)
