open Printf

exception ImpossibleError

let lineno = ref 1

type filterdirection = SOURCE | DESTINATION
type processtype = MANGLE | INPUT | FORWARD | OUTPUT | NAT
type statetype = NEW | RELATED | ESTABLISHED | INVALID
type policytype = ALLOW | DENY | REJECT

type node = Import of string
          | Zone of string * node list
          | Define of string * node list
          | Set of  processtype * node list
          | Rule of node list
          | Interface of string
          | Filter of filterdirection * node
          | State of statetype
          | Policy of policytype
          | Port of int list
          | Ip of int list * int list * int


let rec pretty_print = function
  | Import(file)      -> printf "import <%s>\n" file 
  | Zone(id, nodes)   -> (printf "zone %s {\n" id; List.iter pretty_print nodes; printf "}\n")
  | Define(id, nodes) -> (printf "define %s {\n" id; List.iter pretty_print nodes; printf "}\n")
  | Set(t, nodes)     -> (printf "set ??? {\n"; List.iter pretty_print nodes; printf "}\n")
  | Rule(nodes)       -> (printf "rule: "; List.iter pretty_print nodes)

(* Simple constructs - Maybe these should be some other kind...*)
  | Interface(id)     -> printf "interface = %s \n" id
  | Filter(dir, node) -> (printf "filter ?"; pretty_print node)
  | State(state)      -> printf "state ?\n"
  | Policy(policy)    -> printf "policy ?\n"
  | Port(ports)       -> (printf "ports "; List.iter (printf "%d ") ports; printf "\n")
  | Ip(a,b,m)       -> (List.iter (printf "%x:") a;List.iter (printf ":%x") b; printf "/%d\n" m)
