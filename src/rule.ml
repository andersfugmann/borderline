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
open Frontend
open Frontend_types
open Chain
open Big_int

let gen_policy = function
    ALLOW -> Ir.Accept
  | DENY -> Ir.Drop
  | REJECT -> Ir.Reject(0)

let rec list2ints = function
    Number (nr, _) :: xs -> nr :: list2ints xs
  | Ip (_, _) :: xs -> failwith "Unexpected ip in int list"
  | Id (_, _) :: xs -> failwith "No all ints have been expanded"
  | [] -> []

let rec list2ips = function
  | Number (_, _) :: xs -> failwith "Unexpected int in ip list"
  | Ip (ip, _) :: xs -> ip :: list2ips xs
  | Id (_, _) :: xs -> failwith "No all ints have been expanded"
  | [] -> []

let rec process_rule table (rules, targets') =
  let rec gen_op targets acc = function
      State(states, neg) :: xs -> gen_op targets ((Ir.State(states), neg) :: acc) xs
    | Filter(dir, TcpPort(ports), false) :: xs -> gen_op targets ( (Ir.Protocol([tcp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | Filter(dir, UdpPort(ports), false) :: xs-> gen_op targets ( (Ir.Protocol([udp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | Filter(dir, TcpPort(ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([tcp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Filter(dir, UdpPort(ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([udp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Filter(dir, Address(ips), neg) :: xs -> gen_op targets ( (Ir.IpRange(dir, List.map Ipv6.to_range (list2ips ips)), neg) :: acc ) xs
    | Filter(dir, FZone(id), neg) :: xs -> gen_op targets ((Ir.Zone(dir, id), neg) :: acc) xs

    | Rule(rls, tgs) :: xs ->
        let rule_chain = gen_op tgs [] rls in
        let cont = gen_op targets [] xs in
        let cont = Chain.replace cont.Ir.id (([], Ir.Jump rule_chain.Ir.id) :: cont.Ir.rules) cont.Ir.comment in
          Chain.create [ (acc, Ir.Jump cont.Ir.id) ] "Rule"


    | Protocol (protos, neg) :: xs -> gen_op targets ((Ir.Protocol(list2ints protos), neg) :: acc) xs
    | IcmpType (types, false) :: xs -> gen_op targets ( (Ir.Protocol([icmp6]), false) :: (Ir.IcmpType(list2ints types), false) :: acc) xs
    | IcmpType (types, true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([icmp6]), false);
                                                 (Ir.IcmpType(list2ints types), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Reference _ :: xs -> failwith "Reference to definition not expected"
    | [] -> let tg_chain = Chain.create (List.map (fun tg -> ([], gen_policy tg)) targets) "Target" in
        Chain.create [ (acc, Ir.Jump tg_chain.Ir.id) ] "Rule"
  in
    gen_op targets' [] rules

let process (table, rules, policies) = process_rule table (rules, policies)

let rec filter_process = function
    Process (table, rules, policy) :: xs -> (table, rules, policy) :: filter_process xs
  | _ :: xs -> filter_process xs
  | [] -> []








