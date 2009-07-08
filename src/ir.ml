(* File containing intermidiate types and representation *)
(* These command can be translated into real code by the backend *)

(* The current IR can only hold rules valid for the filter table - Not Mangle or Nat. *)

(* There is no guard for conditions that only apply on tcp/udp or ICMP *)

open Common
open Ipv6

type statetype = NEW | ESTABLISHED | RELATED | INVALID

type zone = id
type mask = int

type chain_type = INPUT | OUTPUT | FORWARD

type chain_id = Temporary of int
              | Builtin of chain_type
              | Named of string

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


type condition = Interface of direction * id
               | Zone of direction * zone
               | State of statetype list
               | TcpPort of direction * int list
               | UdpPort of direction * int list
               | IpRange of direction * ip_number * ip_number
               | Protocol of protocol
               | Mark of int * int

type action = Jump of chain_id
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet
            | Notrack

type oper = (condition * bool) list * action

type chain = { id: chain_id; rules : oper list; comment: string; }

let eq_cond (x, n) (y, m) = 
  n = m && (
    match x, y with
        IpRange (d, x, y), IpRange (d', x', y') -> d = d' && Ipv6.eq x x' && Ipv6.eq y y'
      | Zone(dir, id), Zone (dir', id') -> dir = dir' && (eq_id id id')
      | Interface(dir, id), Interface(dir', id') -> dir = dir' && (eq_id id id')
      | x, y -> x = y
  )

let eq_oper (conds, action) (conds', action') =
  try action = action' && (List.for_all2 (fun c1 c2 -> eq_cond c1 c2) conds conds')
  with Invalid_argument _ -> false

let eq_rules a b = 
  try List.for_all2 eq_oper a b 
  with Invalid_argument _ -> false

let cond_type_identical cond1 cond2 = 
  match cond1 with
      Interface _ -> begin match cond2 with Interface _-> true | _ -> false end
    | Zone _ -> begin match cond2 with Zone _ -> true | _ -> false end
    | State _ -> begin match cond2 with State _ -> true | _ -> false end
    | TcpPort _ -> begin match cond2 with TcpPort _ -> true | _ -> false end
    | UdpPort _ -> begin match cond2 with UdpPort _ -> true | _ -> false end
    | IpRange _ -> begin match cond2 with IpRange _ -> true | _ -> false end
    | Protocol _ -> begin match cond2 with Protocol _ -> true | _ -> false end
    | Mark _ -> begin match cond2 with Mark _ -> true | _ -> false end

let compare (cond1, neg1) (cond2, neg2) = 
  let enumerate_cond = function
      Interface _ -> 1
    | Zone _ -> 2
    | State _ -> 3
    | TcpPort _ -> 4
    | UdpPort _ -> 5
    | IpRange _ -> 6
    | Protocol _ -> 7
    | Mark _ -> 8
  in
  let res = compare neg1 neg2 in
    if res = 0 then 
      compare (enumerate_cond cond1) (enumerate_cond cond2)
    else res

