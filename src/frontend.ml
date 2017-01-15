(** Type and utility function for the frontend *)
open !Batteries
open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

type prefix = string
type id = string * Lexing.position

module Process = struct
  type t = Mangle | Filter | Nat
  let of_stringy (id, pos) =
    match String.lowercase id with
    | "mangle" -> Mangle
    | "filter" -> Filter
    | "nat" -> Nat
    | _ -> parse_error ~id ~pos "Unknown process type"
end

type ip = Ipv6 of Ip6.elt | Ipv4 of Ip4.elt

type policytype = Allow
                | Deny
                | Reject of (string * Lexing.position) option
                | Log of prefix
                | Ref of id
                | Snat of Ip4.elt

and node = Import of id
         | Zone of id * zone_stm list
         | DefineStms of id * rule_stm list
         | DefineList of id * data list
         | AppendList of id * data list
         | DefinePolicy of id * policytype list
         | Process of id * rule_stm list * policytype list

and zone_stm = Interface of id
             | Network of ip
             | ZoneRules of id * rule_stm list * policytype list
             | ZoneSnat of data list * Ip4.elt

and filter_stm = Address of data list
               | Ports of id * data list
               | FZone of data list

and rule_stm = Filter of id * filter_stm * Ir.pol
             | State of data list * Ir.pol
             | Protocol of Ir.Protocol.layer * data list * Ir.pol
             | Icmp6 of data list * Ir.pol
             | Icmp4 of data list * Ir.pol
             | Rule of rule_stm list * policytype list
             | Reference of id * bool
             | TcpFlags of data list * data list * Ir.pol
             | True
             | False


and data = Number of int * Lexing.position
         | Id of id
         | Ip of ip * Lexing.position
         | String of string * Lexing.position

let node_type id = function
  | Zone _ -> 1 = id
  | Process _ -> 2 = id
  | DefineStms _ -> 3 = id
  | DefineList _ -> 4 = id
  | AppendList _ -> 5 = id
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
