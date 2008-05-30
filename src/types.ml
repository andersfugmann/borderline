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
	       | Process of process_type * node_type list
	       | Definition of id * node_type list
	       | Rule of node_type list
	       | Ip of ip
	       | Netmask of int
	       | Interface of name
	       | Policy of policy_type

type direction_type = PORT of int
		    | IP of ip list

type rule_type = SOURCE of direction_type
	       | DESTINATION of direction_type
	       | STATE of state_type

type zone_element = IP of ip
		  | NETMASK of int
		  | INTERFACE of name

type root = node_type list

module Zone =
struct
  let tbl = Hashtbl.create 256
  let exists zone =
    try
      let _ = Hashtbl.find tbl zone in
	true
    with Not_found -> false
  let add zone defs  = Hashtbl.add tbl zone defs
end

let rec pretty_print = function
    Zone(id, _)         -> printf "Zone %s\n" id; Zone.add id 0
  | Process(_, _)       -> printf "Process\n"
  | Definition(id, _)   -> printf "Definition %s\n" id
  | _                   -> printf "Unknown\n"

let tree = [ Zone("ext1", []) ; Definition("Wee", []) ]


let _ =
  let _ = List.map pretty_print tree
  in
  let exists z =
    let _val = Zone.exists z in
      printf "Exists %s %b\n" z _val; _val
  in
    exists "ext1"; printf "done\n"

