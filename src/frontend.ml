open Printf

exception ImpossibleError

let lineno = ref 1

type filterdirection = SOURCE | DESTINATION
type processtype = MANGLE | INPUT | FORWARD | OUTPUT | NAT
type statetype = NEW | RELATED | ESTABLISHED | INVALID
type policytype = ALLOW | DENY | REJECT

type ip = int list * int list * int

type zone_stm = Interface of string
                | Network of ip

type filter_stm = Ip of ip
                | Port of int list

type rule_stm = Filter of filterdirection * filter_stm
              | Policy of policytype
              | State of statetype
              | Rule of rule_stm list

type node = Import of string
          | Zone of string * zone_stm list
          | Define of string * rule_stm list
          | Set of  processtype * rule_stm list

let ip_to_string (a, b, m) = 
  String.concat "" (List.map (sprintf "%x:") a @ List.map (sprintf ":%x") b @ [ sprintf "/%d" m ])

let dir_to_string = function
    SOURCE      -> "source"
  | DESTINATION -> "destination"

let filter_to_string = function
    Ip(ip)      -> "ip: " ^ ( ip_to_string ip )
  | Port(ports) -> "port:" ^ String.concat ", " ( List.map string_of_int ports ) 

let policy_to_string = function
    ALLOW -> "allow"
  | DENY  -> "deny"
  | REJECT -> "reject"

let state_to_string = function
    NEW -> "new"
  | RELATED -> "related"
  | ESTABLISHED -> "established"
  | INVALID -> "invalid"

let print_zone_stm = function
    Network(ip)      -> printf "Network %s\n" (ip_to_string ip)
  | Interface(iface) -> printf "Interface %s\n" iface

let rec print_rule_stm = function 
    Filter(dir, filter) -> printf "%s %s\n" (dir_to_string dir) (filter_to_string filter)
  | Policy(tpe) -> printf "policy %s\n" ( policy_to_string tpe )
  | State(state)  -> printf "state %s\n" ( state_to_string state )
  | Rule(rules) -> printf "rule {\n"; List.iter print_rule_stm rules; printf "}\n"


let rec pretty_print = function
  | Import(file)      -> printf "import <%s>\n" file 
  | Zone(id, zone_stms)  -> (printf "zone %s {\n" id; List.iter print_zone_stm zone_stms; printf "}\n")
  | Define(id, rule_stms) -> (printf "define %s {\n" id; List.iter print_rule_stm rule_stms; printf "}\n")
  | Set(t, rule_stms)     -> (printf "set ??? {\n"; List.iter print_rule_stm rule_stms; printf "}\n")
