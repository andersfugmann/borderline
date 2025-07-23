(** Intermidiate representation. *)
open Base
module Set = Set.Poly

open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4


module Ipaddr = struct
  include Ipaddr
  module V4 = struct
    include V4
    let equal a b = compare a b = 1
  end
end

type id = string [@@deriving compare, equal]
type zone = id [@@deriving compare, equal]
type mask = int [@@deriving compare, equal]
type prefix = string [@@deriving compare, equal]

type address_family = Ipv4 | Ipv6

module Chain_type = struct
  type t = Input | Output | Forward | Pre_routing | Post_routing
  [@@deriving compare, sexp, equal, show]

  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
end

module Chain_id = struct
  type t = Temporary of int
         | Builtin of Chain_type.t
         | Named of string
  [@@deriving compare, sexp, equal, show]
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
  [@@deriving compare, sexp, equal]
  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
  let of_string (s, pos) =
    match String.lowercase s with
    | "src" | "source" -> Source
    | "dst" | "destination" -> Destination
    | s -> parse_error ~id:s ~pos "'source' or 'destination' expected"
end

module Reject = struct
  type t = HostUnreachable | NoRoute | AdminProhibited | PortUnreachable | TcpReset
  [@@deriving compare, sexp, equal, show]

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

type predicate = Interface of Direction.t * id Set.t
               | If_group of Direction.t * [`Int of int | `String of string] Set.t
               | Zone of Direction.t * zone Set.t
               | State of State.t
               | Ports of Direction.t * Port_type.t * int Set.t
               | Ip6Set of Direction.t * Ip6.t (* Merge into a generic set *)
               | Ip4Set of Direction.t * Ip4.t
               | Protocol of int Set.t
               | Icmp6 of int Set.t
               | Icmp4 of int Set.t
               | Mark of int * int
               | TcpFlags of Tcp_flags.t Set.t * Tcp_flags.t Set.t
               | Hoplimit of int Set.t
               | Address_family of address_family Set.t
               | True

let string_of_predicate =
  let int_set_to_list l =
    Set.to_list l
    |> List.map ~f:Int.to_string
    |> String.concat ~sep:";"
    |> Printf.sprintf "[ %s ]"
  in
  function
  | Interface (_, _) -> "Interface"
  | If_group (_, _) -> "If_group"
  | Zone (_, _) -> "Zone"
  | State _ -> "State"
  | Ports (_, _, _) -> "Ports"
  | Ip6Set (_, _) -> "Ip6Set"
  | Ip4Set (_, _) -> "Ip4Set"
  | Protocol s ->
    Printf.sprintf "Protocol %s" (int_set_to_list s)
  | Icmp6 _ -> "Icmp6"
  | Icmp4 _ -> "Icmp4"
  | Mark (_, _) -> "Mark"
  | TcpFlags (_, _) -> "TcpFlags"
  | Hoplimit l ->
    Printf.sprintf "Hoplimit %s" (int_set_to_list l)
  | Address_family _ -> "Address_family"
  | True -> "True"

(* Union - really? *)

let string_of_predicates preds =
  List.map ~f:(fun (p, n) -> Printf.sprintf "(%s,%b)" (string_of_predicate p) n) preds
  |> String.concat ~sep:"; "
  |> Printf.sprintf "[ %s ]"

type effect_ = MarkZone of Direction.t * zone
             | Counter
             | Notrack
             | Log of prefix
             | Snat of Ipaddr.V4.t option
[@@deriving equal]

type effects = effect_ list [@@driving equal]
let equal_effects = List.equal equal_effect_

type target = Jump of Chain_id.t
            | Accept
            | Drop
            | Return
            | Reject of Reject.t
            | Pass (* Not terminal *)
              [@@deriving equal, show]

type oper = (predicate * bool) list * effects * target

type chain = { id: Chain_id.t; rules : oper list; comment: string; }

(** Test if two predicates are idential *)
let eq_pred (x, n) (y, m) =
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

let eq_preds a b =
  List.equal eq_pred a b

let eq_rule (preds, effects, action) (preds', effects', action') =
  let open Poly in
  action = action' && effects = effects' && eq_preds preds preds'

let eq_rules a b =
  List.equal eq_rule a b

let eq_effect a b =
  let (=) = Poly.equal in
  match a, b with
  | MarkZone (dir, zone), MarkZone (dir', zone') -> dir = dir' && zone = zone'
  | MarkZone _, _ -> false
  | Counter, Counter -> true
  | Counter, _ -> false
  | Notrack, Notrack -> true
  | Notrack, _ -> false
  | Log prefix, Log prefix' -> String.equal prefix prefix'
  | Log _, _ -> false
  | Snat (Some ip), Snat (Some ip') -> Ipaddr.V4.equal ip ip'
  | Snat None, Snat None -> true
  | Snat _, _ -> false

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

let enumerate_pred = function
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

let pred_type_identical pred1 pred2 =
  (enumerate_pred pred1) = (enumerate_pred pred2)

let compare_predicate (pred1, neg1) (pred2, neg2) =
  match compare (enumerate_pred pred1) (enumerate_pred pred2) with
  | 0 -> begin
      match Bool.compare neg1 neg2 with
      | 0 -> Poly.compare pred1 pred2
      | n -> n
    end
  | n -> n

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
    match Set.length a with
    | 2 -> neg <> value
    | 0 -> neg = value
    | _ -> false


type string = id [@@ocaml.warning "-34"]
type int = mask [@@ocaml.warning "-34"]
type bool = pol [@@ocaml.warning "-34"]
