(** Intermidiate representation. *)
open Common
open Ipv6

type statetype = NEW | ESTABLISHED | RELATED | INVALID

type zone = id
type mask = int
type icmp_type = int (* This seems to be missing a sub-type *)
type prefix = string

type chain_type = INPUT | OUTPUT | FORWARD

type chain_id = Temporary of int
              | Builtin of chain_type
              | Named of string

type tcp_flags = SYN | ACK | FIN | RST | URG | PSH
type direction = SOURCE | DESTINATION
type pol       = bool


type icmp_packet_type = int


type ip_range = (ip_number * ip_number)

type condition = Interface of direction * id list
               | Zone of direction * zone list
               | State of statetype list
               | Ports of direction * int list
               | IpRange of direction * ip_range list
               | Protocol of int list
               | IcmpType of icmp_type list
               | Mark of int * int
               | TcpFlags of int list * int list

type action = Jump of chain_id
            | MarkZone of direction * zone
            | Accept
            | Drop
            | Return
            | Reject of icmp_packet_type
            | Notrack
            | Log of prefix

type oper = (condition * bool) list * action

type chain = { id: chain_id; rules : oper list; comment: string; }

(** Test if two conditions are idential *)
let eq_cond (x, n) (y, m) =
  n = m && (
    match x, y with
        IpRange (d, r), IpRange (d', r') ->
          begin
            try d = d' && List.for_all2 (fun (x, y) (x', y') -> Ipv6.eq x x' && Ipv6.eq y y') r r'
            with Invalid_argument _ -> false
          end
      | Zone(dir, id_lst), Zone (dir', id_lst') -> dir = dir' && eq_id_list id_lst id_lst' 
      | Interface(dir, id_lst), Interface(dir', id_lst') -> dir = dir' && eq_id_list id_lst id_lst'
      | x, y -> x = y
  )

let eq_conds a b = List.length a == List.length b && List.for_all2 (fun c1 c2 -> eq_cond c1 c2) a b

let eq_oper (conds, action) (conds', action') =
  try action = action' && (List.for_all2 (fun c1 c2 -> eq_cond c1 c2) conds conds')
  with Invalid_argument _ -> false

let eq_rules a b =
  try List.for_all2 eq_oper a b
  with Invalid_argument _ -> false

let get_dir = function
    Interface _ -> None
  | Zone (direction, _) -> Some direction
  | State _ -> None
  | Ports (direction, _) -> Some direction
  | IpRange (direction, _) -> Some direction
  | Protocol _ -> None
  | IcmpType _ -> None
  | Mark _ -> None
  | TcpFlags _ -> None

let enumerate_cond = function
    Interface _ -> 1
  | Zone _ -> 2
  | State _ -> 3
  | Ports _ -> 4
  | IpRange _ -> 5
  | Protocol _ -> 6
  | IcmpType _ -> 7
  | TcpFlags _ -> 8
  | Mark _ -> 9

let cond_type_identical cond1 cond2 =
  (enumerate_cond cond1) = (enumerate_cond cond2)

let compare (cond1, neg1) (cond2, neg2) =
  let res = compare (enumerate_cond cond1) (enumerate_cond cond2) in
    if res = 0 then compare neg1 neg2 else res

(** Test if expr always evaluates to value *)
let is_always value = function
  | Zone (_, []), neg 
  | State [], neg
  | Ports (_, []), neg
  | Protocol [], neg
  | IcmpType [], neg -> neg = value 
  | TcpFlags ([], _x :: _xs), neg -> neg = value 
  | TcpFlags (_, []), neg -> neg != value 

  | Interface _, _ 
  | Zone _, _ 
  | State _, _
  | Ports _, _ 
  | IpRange _, _
  | Protocol _, _
  | IcmpType _, _ 
  | TcpFlags _, _
  | Mark _, _ -> false
