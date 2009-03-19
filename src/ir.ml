(* File containing intermidiate types and representation *)
(* These command can be translated into real code by the backend *)

(* The current IR can only hold rules valid for the filter table - Not Mangle or Nat. *)

(* There is no guard for conditions that only apply on tcp/udp or ICMP *)

open Common

type statetype = NEW | ESTABLISHED | RELATED | INVALID

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

type icmp_packet = ICMP_NET_UNREACHABLE | ICMP_HOST_UNREACHABLE
                   | ICMP_PORT_UNREACHABLE | ICMP_PROTO_UNREACHABLE
                   | ICMP_NET_PROHIBITED | ICMP_HOST_PROHIBITED
                   | ICMP_ADMIN_PROHIBITED | TCP_RESET


type condition = Interface of direction * string
               | Zone of direction * zone
               | State of statetype list
               | TcpPort of direction * int list
               | UdpPort of direction * int list
               | Address of direction * ip
               | Protocol of protocol

type action = Jump of chain_id
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet
            | Notrack

type op = AND | OR

type oper = (condition * bool) list * action
