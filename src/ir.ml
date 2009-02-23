(* File containing intermidiate types and representation *)
(* These command can be translated into real code by the backend *)

(* The current IR can only hold rules valid for the filter table - Not Mangle or Nat. *)

(* There is no guard for conditions that only apply on tcp/udp or ICMP *)

open Frontend

type ip = int list * int list * int

let rec ip_to_ip = function
    Ip(a, b, m) -> (a, b, m)
  | _ -> raise ImpossibleError
      
type state_type = NEW | ESTABLISHED | RELATED | INVALID 

type zone = string
type mask = int

type protocol = TCP | UDP | ICMP

type tcp_flags = SYN | ACK | FIN | RST | URG | PSH
type direction = SOURCE | DESTINATION

type tcp_cond = Port of direction * int list
              | Flags of tcp_flags list * tcp_flags list

type udp_cond = Port of direction * int list

type icmp_packet = string

type chain = string

type condition = Interface of direction * string
               | Zone of direction * zone
               | State of state_type list
               | Port of direction * int list
               | Address of direction * ip
               | TcpProtocol of tcp_cond list option
               | UdpProtocol of udp_cond list option

type action = Jump of chain
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet
            | Notrack

type op = AND | OR

type cond_tree = Tree of op * cond_tree * cond_tree
               | Leaf of condition * bool option

type oper = cond_tree option * action

(* Utility to or / and a list of conditions *)
let rec build_cond_tree op = function
    (x,o) :: [] -> Leaf(x, o)
  | (x,o) :: xs -> Tree(op, Leaf(x, o), (build_cond_tree op xs))
  | _ -> raise ImpossibleError
      
  

