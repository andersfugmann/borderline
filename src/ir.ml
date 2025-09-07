(** Intermediate representation. *)
open Base
module Set = Set.Poly

open Common
module Ip6Set = Ipset.Ip6Set
module Ip4Set = Ipset.Ip4Set

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

type address_family = Ipv4 | Ipv6 [@@deriving show { with_path = false }]

module Chain_type = struct
  type t = Input | Output | Forward | Pre_routing | Post_routing
  [@@deriving compare, sexp, equal, show { with_path = false }]

  include Comparator.Make(struct type nonrec t = t let compare = compare let sexp_of_t = sexp_of_t end)
end

module Chain_id = struct
  type t = Temporary of int
         | Builtin of Chain_type.t
         | Named of string
  [@@deriving compare, sexp, equal, show { with_path = false }]
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

  let to_string = function
    | Tcp -> "tcp"
    | Udp -> "udp"
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

  let to_string = function
    | Source -> "source"
    | Destination -> "destination"

end

module Reject = struct
  type t = HostUnreachable | NoRoute | AdminProhibited | PortUnreachable | TcpReset
  [@@deriving compare, sexp, equal, show { with_path = false }]

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
               | Ports of Direction.t * Port_type.t * int Set.t (* Implies tcp or udp *)
               | Ip6Set of Direction.t * Ip6Set.t (* Implies ipv6 *)
               | Ip4Set of Direction.t * Ip4Set.t (* Implies ipv4 *)
               | Protocol of int Set.t
               | Icmp6 of int Set.t (* Implies ipv6 *)
               | Icmp4 of int Set.t (* Implies ipv4 *)
               | Mark of int * int
               | TcpFlags of Tcp_flags.t Set.t * Tcp_flags.t Set.t (* Implies tcp *)
               | Hoplimit of int Set.t (* Implies ipv6 *)
               | Address_family of address_family Set.t
               | True

let predicate_to_string =
  let sprintf = Printf.sprintf in
  let int_set_to_list l =
    Set.to_list l
    |> List.map ~f:Int.to_string
    |> String.concat ~sep:";"
    |> Printf.sprintf "[ %s ]"
  in
  let string_of_dir = function
    | Direction.Source -> "src"
    | Direction.Destination -> "dst"
  in
  function
  | Interface (dir, is) -> sprintf "Interface (%s,[%s])" (string_of_dir dir) (Set.to_list is |> String.concat ~sep:";")
  | If_group (dir, is) ->
    let string_of_group = function
      | `Int i -> Int.to_string i
      | `String s -> s
    in
    sprintf "If_group (%s,[%s])" (string_of_dir dir) (Set.to_list is |> List.map ~f:string_of_group |> String.concat ~sep:";")
  | Zone (dir, zs) -> sprintf "Zone (%s, [%s])" (string_of_dir dir) (Set.to_list zs |> String.concat ~sep:";")
  | State states -> sprintf "State [%s]" (Set.to_list states |> List.map ~f:State.show_state |> String.concat ~sep:";")
  | Ports (dir, tpe, ports) -> sprintf "Ports (%s, %s, %s)" (string_of_dir dir) (Port_type.to_string tpe) (int_set_to_list ports)
  | Ip6Set (d, s) -> sprintf "Ip6Set (%d),%s" (Ip6Set.cardinal s) (string_of_dir d)
  | Ip4Set (d, s) -> sprintf "Ip4Set (%d),%s" (Ip4Set.cardinal s) (string_of_dir d)
  | Protocol s -> Printf.sprintf "Protocol %s" (int_set_to_list s)
  | Icmp6 _ -> "Icmp6"
  | Icmp4 _ -> "Icmp4"
  | Mark (_, _) -> "Mark"
  | TcpFlags (_, _) -> "TcpFlags"
  | Hoplimit l ->
    Printf.sprintf "Hoplimit %s" (int_set_to_list l)
  | Address_family s -> Printf.sprintf "Address_family [%s]" (Set.to_list s |> List.map ~f:show_address_family |> String.concat ~sep:";")
  | True -> "True"

type effect_ = MarkZone of Direction.t * zone
             | Counter
             | Comment of string
             | Notrack
             | Log of prefix
             | Snat of Ipaddr.V4.t option
[@@deriving equal]

type effects = effect_ list [@@driving equal]
let equal_effects a b =
  let order = function
    | MarkZone _ -> 1
    | Counter -> 2
    | Notrack -> 3
    | Log _ -> 4
    | Snat _ -> 5
    | Comment _ -> 6
  in
  let sort = List.stable_sort ~compare:(fun x y -> compare (order x) (order y)) in
  List.equal equal_effect_ (sort a) (sort b)

type target = Jump of Chain_id.t
            | Accept
            | Drop
            | Return
            | Reject of Reject.t
            | Pass (* Not terminal *)
[@@deriving equal, show { with_path = false }]

type rule = (predicate * bool) list * effects * target

type chain = { id: Chain_id.t; rules : rule list; comment: string; }

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

type string = String.t [@@ocaml.warning "-34"]
type int = Int.t [@@ocaml.warning "-34"]
type bool = Bool.t [@@ocaml.warning "-34"]
