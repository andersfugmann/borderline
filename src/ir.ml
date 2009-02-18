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

type tcp_cond = SourcePort of int list
              | DestinaionPort of int list
              | Flags of tcp_flags list * tcp_flags list


type udp_cond = SourcePort of int list
              | DestinaionPort of int list

type condition = SourceInterface of string
               | DestinationInterface of string
               | SourceZone of zone
               | DestinationZone of zone
               | State of state_type list
               | SourcePort of int list
               | DestinaionPort of int list
               | SourceAddress of ip
               | DestinationAddress of ip
               | Protocol of protocol * udp_cond list option

type icmp_packet = string

type chain = string

type action = Jump of chain
            | MarkSourceZone of zone
            | MarkDestinationZone of zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet
            | Notrack
                
type rule = (condition * bool option) list * action
