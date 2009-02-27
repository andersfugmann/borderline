(* File containing intermidiate types and representation *)
(* These command can be translated into real code by the backend *)

(* The current IR can only hold rules valid for the filter table - Not Mangle or Nat. *)

(* There is no guard for conditions that only apply on tcp/udp or ICMP *)

open Common
open Frontend

type state_type = NEW | ESTABLISHED | RELATED | INVALID 

type zone = string
type mask = int

type chain_type = INPUT | OUTPUT | FORWARD
type chain_id = Temporary of int
              | Builtin of chain_type 
 
type protocol = TCP | UDP | ICMP

type tcp_flags = SYN | ACK | FIN | RST | URG | PSH
type direction = SOURCE | DESTINATION

type tcp_cond = Port of direction * int list
              | Flags of tcp_flags list * tcp_flags list

type udp_cond = Port of direction * int list

type icmp_packet = string

type condition = Interface of direction * string
               | Zone of direction * zone
               | State of state_type list
               | Port of direction * int list
               | Address of direction * ip
               | TcpProtocol of tcp_cond list option
               | UdpProtocol of udp_cond list option

type action = Jump of chain_id
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet
            | Notrack

type op = AND | OR

type cond_option = condition * bool option

type oper = cond_option list option * action
