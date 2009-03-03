open Common
open Printf

let lineno = ref 1

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

type action_stm = Policy of policytype

type zone_stm = Interface of string
                | Network of ip

type filter_stm = Ip of ip
                | Port of int list


type rule_stm = Filter of Ir.direction * filter_stm
              | State of Ir.statetype list
              | Rule of rule_stm list * action_stm

type node = Import of string
          | Zone of string * zone_stm list
          | Define of string * rule_stm list
          | Process of processtype * rule_stm list * policytype

let dir_to_string = function
    Ir.SOURCE      -> "source"
  | Ir.DESTINATION -> "destination"

let filter_to_string = function
    Ip(ip)      -> "ip: " ^ (ip_to_string ip)
  | Port(ports) -> "port:" ^ String.concat ", " ( List.map string_of_int ports )

let policy_to_string = function
    ALLOW -> "allow"
  | DENY  -> "deny"
  | REJECT -> "reject"

let process_to_string = function
    MANGLE -> "mangle"
  | FILTER -> "filter"
  | NAT -> "nat"

let state_to_string = function
    Ir.NEW -> "new"
  | Ir.RELATED -> "related"
  | Ir.ESTABLISHED -> "established"
  | Ir.INVALID -> "invalid"

let print_zone_stm = function
    Network(ip)      -> printf "Network %s\n" (ip_to_string ip)
  | Interface(iface) -> printf "Interface %s\n" iface

let print_target_stm = function
    Policy(tpe) -> printf "policy %s\n" ( policy_to_string tpe )

let rec print_rule_stm = function
    Filter(dir, filter) -> printf "%s %s\n" (dir_to_string dir) (filter_to_string filter)
  | State(states)  -> printf "state %s\n" ( String.concat "," (List.map state_to_string states) )
  | Rule(rules, target) -> printf "rule {\n"; List.iter print_rule_stm rules; printf "}\n"


let rec pretty_print = function
  | Import(file)      -> printf "import <%s>\n" file
  | Zone(id, zone_stms)  -> (printf "zone %s {\n" id; List.iter print_zone_stm zone_stms; printf "}\n")
  | Define(id, rule_stms) -> (printf "define %s {\n" id; List.iter print_rule_stm rule_stms; printf "}\n")
  | Process(t, rule_stms, policy)  ->
      printf "Process %s policy %s {\n" (process_to_string t) (policy_to_string policy);
      List.iter print_rule_stm rule_stms;
      printf "}\n"

