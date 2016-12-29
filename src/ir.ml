(** Intermidiate representation. *)
open Batteries

open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

type id = string (* New addition *)
type zone = id
type mask = int
type prefix = string

type chain_type = INPUT | OUTPUT | FORWARD
type chain_id = Temporary of int
              | Builtin of chain_type
              | Named of string

type tcp_flag = Syn | Ack | Fin | Rst | Urg | Psh
type direction = SOURCE | DESTINATION
type pol       = bool
type port_type = Tcp | Udp

let tcpflag_of_string (flag, pos) =
  match String.lowercase flag with
  | "syn" -> Syn
  | "ack" -> Ack
  | "fin" -> Fin
  | "rst" -> Rst
  | "urg" -> Urg
  | "psh" -> Psh
  | _ -> parse_error ~id:flag ~pos "Unknown icmp type"

module Protocol = struct
  type layer = Ip4 | Ip6
  type t = Icmp | Tcp | Udp

  let of_string (s, pos) =
    match String.lowercase s with
    | "icmp" -> Icmp
    | "tcp" -> Tcp
    | "udp" -> Udp
    | s -> parse_error ~id:s ~pos "Unknown protocol identifier"
end

type reject_type = HostUnreachable | NoRoute | AdminProhibited | PortUnreachable | TcpReset

type condition = Interface of direction * id Set.t
               | Zone of direction * zone Set.t
               | State of State.t
               | Ports of direction * port_type * int Set.t
               | Ip6Set of direction * Ip6.t
               | Ip4Set of direction * Ip4.t
               | Protocol of Protocol.layer * Protocol.t Set.t
               | Icmp6 of Icmp.V6.t Set.t
               | Icmp4 of Icmp.V4.t Set.t
               | Mark of int * int
               | TcpFlags of tcp_flag Set.t

type action = Jump of chain_id
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of reject_type
            | Notrack
            | Log of prefix

type oper = (condition * bool) list * action

type chain = { id: chain_id; rules : oper list; comment: string; }


(** Test if two conditions are idential *)
let eq_cond (x, n) (y, m) =
  n = m && (
    match x, y with
      | Ip6Set (_d, r), Ip6Set (_d', r') -> Ip6.equal r r'
      | Zone(dir, ids), Zone (dir', ids') -> dir = dir' && Set.equal ids ids'
      | Interface(dir, ids), Interface(dir', ids') -> dir = dir' && Set.equal ids ids'
      | x, y -> x = y
      (* TODO: Add all rule types, and add as a function *)
  )

let eq_conds a b = List.length a == List.length b && List.for_all2 (fun c1 c2 -> eq_cond c1 c2) a b

let eq_oper (conds, action) (conds', action') =
  try action = action' && (List.for_all2 (fun c1 c2 -> eq_cond c1 c2) conds conds')
  with Invalid_argument _ -> false

let eq_rules a b =
  try List.for_all2 eq_oper a b
  with Invalid_argument _ -> false

let get_dir = function
  | Interface _ -> None
  | Zone (direction, _) -> Some direction
  | State _ -> None
  | Ports (direction, _, _) -> Some direction
  | Ip6Set (direction, _) -> Some direction
  | Ip4Set (direction, _) -> Some direction
  | Protocol _ -> None
  | Icmp6 _ -> None
  | Icmp4 _ -> None
  | Mark _ -> None
  | TcpFlags _ -> None

let enumerate_cond = function
  | Interface _ -> 1
  | Zone _ -> 2
  | State _ -> 3
  | Ports _ -> 4
  | Ip6Set _ -> 5
  | Ip4Set _ -> 6
  | Protocol _ -> 7
  | Icmp6 _ -> 8
  | Icmp4 _ -> 9
  | TcpFlags _ -> 10
  | Mark _ -> 11

let cond_type_identical cond1 cond2 =
  (enumerate_cond cond1) = (enumerate_cond cond2)

let compare (cond1, neg1) (cond2, neg2) =
  let res = compare (enumerate_cond cond1) (enumerate_cond cond2) in
    if res = 0 then compare neg1 neg2 else res

(** Test if expr always evaluates to value *)
let is_always value = function
  | State states, neg when State.is_empty states -> neg = value
  | Zone (_, s), neg when Set.is_empty s -> neg = value
  | Ports (_, _, s), neg when Set.is_empty s -> neg = value
  | Protocol (_, s), neg when Set.is_empty s -> neg = value
  | Icmp6 s, neg when Set.is_empty s -> neg = value
  | Icmp4 s, neg when Set.is_empty s -> neg = value
  | TcpFlags s, neg when Set.is_empty s -> neg = value
  | Interface _, _
  | Zone _, _
  | State _, _
  | Ports _, _
  | Ip6Set _, _ (* Could match for /0 *)
  | Ip4Set _, _ (* Could match for /0 *)
  | Protocol _, _
  | Icmp6 _, _
  | Icmp4 _, _
  | TcpFlags _, _
  | Mark _, _ -> false
