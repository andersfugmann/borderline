(** Intermidiate representation. *)
open Base
module Set = Set.Poly

open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

type id = string (* New addition *)
type zone = id
type mask = int
type prefix = string

type address_family = Ipv4 | Ipv6
type protocol = Udp | Tcp | Icmpv4 | Icmpv6 | Ipv6in4

module Chain_type = struct
  type t = Input | Output | Forward | Pre_routing | Post_routing [@@deriving compare, sexp]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
end

module Chain_id = struct
  type t = Temporary of int
         | Builtin of Chain_type.t
         | Named of string
  [@@deriving compare, sexp]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
end

type pol       = bool

module Port_type = struct
  type t = Tcp | Udp
  [@@deriving compare, sexp]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
  let of_string (id, pos) =
    match String.lowercase id with
    | "tcp" -> Tcp
    | "udp" -> Udp
    | _ -> parse_error ~id ~pos "'tcp' or 'udp' expected"
end

module Tcp_flags = struct
  type t = Syn | Ack | Fin | Rst | Urg | Psh | Ecn | Cwr
  [@@deriving compare, sexp]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
  let of_string (flag, pos) =
    match String.lowercase flag with
    | "syn" -> Syn
    | "ack" -> Ack
    | "fin" -> Fin
    | "rst" -> Rst
    | "urg" -> Urg
    | "psh" -> Psh
    | "ecn" -> Ecn
    | "cwr" -> Cwr
    | _ -> parse_error ~id:flag ~pos "Unknown tcp flag"
end

module Direction = struct
  type t = Source | Destination
  [@@deriving compare, sexp]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
  let of_string (s, pos) =
    match String.lowercase s with
    | "src" | "source" -> Source
    | "dst" | "destination" -> Destination
    | s -> parse_error ~id:s ~pos "'source' or 'destination' expected"
end

module Reject = struct
  type t = HostUnreachable | NoRoute | AdminProhibited | PortUnreachable | TcpReset
  [@@deriving compare, sexp]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
  let of_string (id, pos) =
    match String.lowercase id with
    | "host-unreachable" -> HostUnreachable
    | "no-route" -> NoRoute
    | "admin-prohibited" -> AdminProhibited
    | "port-unreachable" -> PortUnreachable
    | "tcp-reset" -> TcpReset
    | _ -> parse_error ~id ~pos "Unknown reject type"
end


type condition = Interface of Direction.t * id Set.t
               | If_group of Direction.t * [`Int of int | `String of string] Set.t
               | Zone of Direction.t * zone Set.t
               | State of State.t
               | Ports of Direction.t * Port_type.t * int Set.t
               | Ip6Set of Direction.t * Ip6.t
               | Ip4Set of Direction.t * Ip4.t
               | Protocol of protocol Set.t
               | Icmp6 of int Set.t
               | Icmp4 of int Set.t
               | Mark of int * int
               | TcpFlags of Tcp_flags.t Set.t * Tcp_flags.t Set.t
               | Hoplimit of int Set.t
               | Address_family of address_family Set.t
               | True

type effect_ = MarkZone of Direction.t * zone
             | Counter
             | Notrack
             | Log of prefix
             | Snat of Ipaddr.V4.t

type target = Jump of Chain_id.t
            | Accept
            | Drop
            | Return
            | Reject of Reject.t
            | Pass (* Not terminal *)

type oper = (condition * bool) list * effect_ list * target

type chain = { id: Chain_id.t; rules : oper list; comment: string; }

(** Test if two conditions are idential *)
let eq_cond (x, n) (y, m) =
  let (=) = Poly.equal in
  let eq = function
    | Interface (d, s) -> (function Interface (d', s') -> d = d' && Set.equal s s' | _ -> false)
    | If_group (d, s) -> (function If_group (d', s') -> d = d' && Set.equal s s' | _ -> false)
    | Zone (d, s) -> (function Zone (d', s') -> d = d' && Set.equal s s' | _ -> false)
    | State s -> (function State s' -> State.equal s s' | _ -> false)
    | Ports (d, t, s) -> (function Ports (d', t', s') -> d = d' && t = t' && Set.equal s s' | _ -> false)
    | Ip6Set (d, s) -> (function Ip6Set (d', s') -> d = d' && Ip6.equal s s' | _ -> false)
    | Ip4Set (d, s) -> (function Ip4Set (d', s') -> d = d' && Ip4.equal s s' | _ -> false)
    | Protocol s -> (function Protocol s' -> Set.equal s s' | _ -> false)
    | Icmp6 s -> (function Icmp6 s' -> Set.equal s s' | _ -> false)
    | Icmp4 s -> (function Icmp4 s' -> Set.equal s s' | _ -> false)
    | Mark (m1, m2) -> (function Mark (m1', m2') -> m1 = m1' && m2 = m2' | _ -> false)
    | TcpFlags (s1, s2) -> (function TcpFlags (s1', s2') -> Set.equal s1 s1' && Set.equal s2 s2' | _ -> false)
    | Hoplimit limit -> (function Hoplimit limit' -> Set.equal limit limit' | _ -> false)
    | True -> (function True -> true | _ -> false)
    | Address_family a -> (function Address_family a' -> Set.equal a a' | _ -> false)
  in
  Bool.equal n m && eq x y

let eq_conds a b =
  List.equal eq_cond a b

let eq_oper (conds, effects, action) (conds', effects', action') =
  let open Poly in
  action = action' && effects = effects' && eq_conds conds conds'

let eq_rules a b =
  List.equal eq_oper a b

let eq_effect =
  let (=) = Poly.equal in
  function
  | MarkZone (dir, zone) -> begin function MarkZone (dir', zone') -> dir = dir' && zone = zone' | _ -> false end
  | Counter -> begin function Counter -> true | _ -> false end
  | Notrack -> begin function Notrack -> true | _ -> false end
  | Log prefix -> begin function Log prefix' -> prefix = prefix' | _ -> false end
  | Snat ip -> begin function Snat ip' -> Ipaddr.V4.compare ip ip' = 0 | _ -> false end

let eq_effects a b =
  let order = function
    | MarkZone _ -> 1
    | Counter -> 2
    | Notrack -> 3
    | Log _ -> 4
    | Snat _ -> 5
  in
  let sort = List.sort ~compare:(fun x y -> compare (order x) (order y)) in
  List.equal eq_effect (sort a) (sort b)

let get_dir = function
  | Interface _ -> None
  | If_group _ -> None
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
  | Hoplimit _ -> None
  | True -> None
  | Address_family _ -> None

let enumerate_cond = function
  | Interface _ -> 1
  | If_group _ -> 1
  | Zone _ -> 2
  | State _ -> 3
  | Ports _ -> 4
  | Ip6Set _ -> 5
  | Ip4Set _ -> 6
  | Protocol _ -> 7
  | Icmp6 _ -> 8
  | Icmp4 _ -> 9
  | Address_family _ -> 10
  | TcpFlags _ -> 11
  | Mark _ -> 12
  | Hoplimit _ -> 13
  | True -> 14

let cond_type_identical cond1 cond2 =
  (enumerate_cond cond1) = (enumerate_cond cond2)

let compare (cond1, neg1) (cond2, neg2) =
  let res = compare (enumerate_cond cond1) (enumerate_cond cond2) in
    if res = 0 then compare neg1 neg2 else res

(** Test if expr always evaluates to value *)
let is_always value =
  let open Poly in
  function
  | State states, neg -> State.is_empty states && (neg = value)
  | Zone (_, zs), neg -> Set.is_empty zs && (neg = value)
  | Ports (_, _, ps), neg -> Set.is_empty ps && (neg = value)
  | Protocol s, neg -> Set.is_empty s && neg = value
  | TcpFlags (flags, mask), neg -> begin
      match Set.diff flags mask |> Set.is_empty with
      | true -> Set.is_empty mask && not neg = value
      | false -> neg = value
    end
  | Ip6Set (_, s), neg -> Ip6.is_empty s && (neg = value)
  | Ip4Set (_, s), neg -> Ip4.is_empty s && (neg = value)
  | Interface (_, ifs), neg -> Set.is_empty ifs && (neg = value)
  | If_group (_, if_groups), neg -> Set.is_empty if_groups && (neg = value)
  | Icmp6 is, neg -> Set.is_empty is && (neg = value)
  | Icmp4 is, neg -> Set.is_empty is && (neg = value)
  | Hoplimit cnts, neg -> Set.is_empty cnts && (neg = value)
  | True, neg -> not neg = value
  | Mark (0, 0), neg -> neg <> value
  | Mark (_, 0), neg -> neg = value
  | Mark _, _ -> false
  | Address_family a, neg ->
    (Set.length a = 2 && not neg) || Set.is_empty a && neg
