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
open Frontend_types

val lineno : int ref
val create_define_map : node list -> ( node Id_map.t)

val node_type : int -> node -> bool

val fold_rules : ('a -> rule_stm -> 'a) -> rule_stm list -> 'a -> 'a
val fold_nodes : ('a -> node -> 'a) -> node list -> 'a -> 'a
val fold : ('a -> rule_stm -> 'a) -> node list -> 'a -> 'a

val expand_rules : (rule_stm -> rule_stm list) -> rule_stm list -> rule_stm list
val expand_nodes : (node -> node list) -> node list -> node list
val expand : (rule_stm -> rule_stm list) -> node list -> node list


