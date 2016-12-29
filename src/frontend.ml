(** Type and utility function for the frontend *)
open !Batteries
open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

type prefix = string
type id = string * Lexing.position

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW
                | DENY
                | REJECT of (string * Lexing.position) option
                | LOG of prefix
                | Ref of id

type ip = Ipv6 of Ip6.ip | Ipv4 of Ip4.ip

and node = Import of id
         | Zone of id * zone_stm list
         | DefineStms of id * rule_stm list
         | DefineList of id * data list
         | DefinePolicy of id * policytype list
         | Process of processtype * rule_stm list * policytype list

and zone_stm = Interface of id
             | Network of ip
             | ZoneRules of processtype * rule_stm list * policytype list

and filter_stm = Address of data list
               | Ports of Ir.port_type * data list
               | FZone of data list

and rule_stm = Filter of Ir.direction * filter_stm * Ir.pol
             | State of State.states list * Ir.pol
             | Protocol of Ir.Protocol.layer * data list * Ir.pol
             | Icmp6 of data list * Ir.pol
             | Icmp4 of data list * Ir.pol
             | Rule of rule_stm list * policytype list
             | Reference of id
             | TcpFlags of data list * Ir.pol


and data = Number of int * Lexing.position
         | Id of id
         | Ip6 of Ip6.ip * Lexing.position
         | Ip4 of Ip4.ip * Lexing.position
         | String of string * Lexing.position

let node_type id = function
  | Zone _ -> 1 = id
  | Process _ -> 2 = id
  | DefineStms _ -> 3 = id
  | DefineList _ -> 4 = id
  | _ -> false

let rec fold_rules func acc = function
  | Rule (rules, _) as x :: xs -> fold_rules func (fold_rules func rules (func acc x)) xs
  | x :: xs -> fold_rules func (func acc x) xs
  | [] -> acc

let fold_nodes func nodes acc =
  List.fold_left func acc nodes

let fold func nodes acc =
  let node_func acc = function
    | DefineStms (_, rules)  -> fold_rules func rules acc
    | Process (_, rules, _) -> fold_rules func rules acc
    | _ -> acc
  in
  fold_nodes node_func nodes acc
