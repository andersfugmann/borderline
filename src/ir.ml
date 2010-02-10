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

(* File containing intermidiate types and representation *)
(* These command can be translated into real code by the backend *)

(* The current IR can only hold rules valid for the filter table - Not Mangle or Nat. *)

open Common
open Ipv6

type statetype = NEW | ESTABLISHED | RELATED | INVALID

type zone = id
type mask = int
type icmp_type = int (* This seems to be missing a sub-type *)
type prefix = string

type chain_type = INPUT | OUTPUT | FORWARD

type chain_id = Temporary of int
              | Builtin of chain_type
              | Named of string

type tcp_flags = SYN | ACK | FIN | RST | URG | PSH
type direction = SOURCE | DESTINATION
type pol       = bool


type icmp_packet_type = int


type ip_range = (ip_number * ip_number)

type condition = Interface of direction * id
               | Zone of direction * zone list
               | State of statetype list
               | Ports of direction * int list
               | IpRange of direction * ip_range list
               | Protocol of int list
               | IcmpType of icmp_type list
               | Mark of int * int

type action = Jump of chain_id
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet_type
            | Notrack
            | Log of prefix

type oper = (condition * bool) list * action

type chain = { id: chain_id; rules : oper list; comment: string; }

let eq_cond (x, n) (y, m) =
  n = m && (
    match x, y with
        IpRange (d, r), IpRange (d', r') ->
          begin
            try d = d' && List.for_all2 (fun (x, y) (x', y') -> Ipv6.eq x x' && Ipv6.eq y y') r r'
            with Invalid_argument _ -> false
          end
      | Zone(dir, id_lst), Zone (dir', id_lst') -> dir = dir' && (List.for_all2 (fun id id' -> eq_id id id') id_lst id_lst')
      | Interface(dir, id), Interface(dir', id') -> dir = dir' && (eq_id id id')
      | x, y -> x = y
  )

let eq_oper (conds, action) (conds', action') =
  try action = action' && (List.for_all2 (fun c1 c2 -> eq_cond c1 c2) conds conds')
  with Invalid_argument _ -> false

let eq_rules a b =
  try List.for_all2 eq_oper a b
  with Invalid_argument _ -> false

let get_dir = function
    Interface _ -> None
  | Zone (direction, _) -> Some direction
  | State _ -> None
  | Ports (direction, _) -> Some direction
  | IpRange (direction, _) -> Some direction
  | Protocol _ -> None
  | IcmpType _ -> None
  | Mark _ -> None

let enumerate_cond = function
    Interface _ -> 1
  | Zone _ -> 2
  | State _ -> 3
  | Ports _ -> 4
  | IpRange _ -> 5
  | Protocol _ -> 6
  | IcmpType _ -> 7
  | Mark _ -> 8

let cond_type_identical cond1 cond2 =
  (enumerate_cond cond1) = (enumerate_cond cond2)

let compare (cond1, neg1) (cond2, neg2) =
  let res = compare (enumerate_cond cond1) (enumerate_cond cond2) in
    if res = 0 then compare neg1 neg2 else res

(* Test is a rule is at all satisfiable *)
let is_always value = function
  | Zone (_, []), neg 
  | State [], neg
  | Ports (_, []), neg
  | Protocol [], neg
  | IcmpType [], neg -> neg = value 

  | Interface _, _ 
  | Zone _, _ 
  | State _, _
  | Ports _, _ 
  | IpRange _, _
  | Protocol _, _
  | IcmpType _, _ 
  | Mark _, _ -> false
