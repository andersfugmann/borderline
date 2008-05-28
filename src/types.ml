open Printf
(* Way too many type definitions... *)
type id = string
type name = string

type ip = int * int * int * int * int option
type port = int

type process_type = MANGLE
		  | INPUT
		  | FORWARD
		  | OUTPUT
		  | NAT

type policy_type = POLICY
		 | ALLOW
		 | DENY
 		 | REJECT

type state_type = NEW
		| ESTABLISHED
		| RELATED
		| INVALID

type node_type = Zone of id * node_type list
	       | Process of process_type * list
	       | Definition of id * list
	       | Rule of node_type list
	       | Ip of ip
	       | Netmask of int
	       | Interface of name
	       | Policy of policy_type
type rule_type = SOURCE of direction_type
	       | DESTINATION of direction_type
	       | STATE of state_type
	       |


type direction_type = PORT of int
		    | IP of ip_mask list

type rule_type = SOURCE of direction_type
	       | DESTINATION of direction_type
	       | STATE of state_type

type zone_element = IP of ip
		  | NETMASK of int
		  | INTERFACE of name


type node_type = Zone of id * zone_element list
	       | Process of process_type * list
	       | Definition of id * list


type root = node_type list


(* Create a tree and print it *)

let rec pretty_print = function
    Zone(id, _)       -> (printf "Zone %s\n" id)
  | Process(id, _)    -> (printf "Process %s\n" id)
  | Definition(id, _) -> (printf "Definition %s\n" id)

let tree = Zone("ext1", [])

let _ =
  pretty_print tree




