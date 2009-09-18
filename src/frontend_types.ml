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
open Ipv6

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT


and node = Import of id
         | Zone of id * zone_stm list
         | DefineStms of id * rule_stm list
         | DefineList of id * data list
         | Process of processtype * rule_stm list * policytype list

and zone_stm = Interface of id
             | Network of ip
             | ZoneRules of processtype * rule_stm list * policytype list

and filter_stm = Address of data list
               | TcpPort of data list
               | UdpPort of data list
               | FZone of id list

and rule_stm = Filter of Ir.direction * filter_stm * Ir.pol
             | State of Ir.statetype list * Ir.pol
             | Protocol of data list * Ir.pol
             | IcmpType of data list * Ir.pol
             | Rule of rule_stm list * policytype list
             | Reference of id


and data = Number of int * Lexing.position
         | Id of id
         | Ip of ip * Lexing.position

