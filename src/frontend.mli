open Common 
open Ipv6

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

type action_stm = Policy of policytype

type zone_stm = Interface of id
                | Network of ip

type filter_stm = Ip of ip
                | TcpPort of int list
                | UdpPort of int list
                | FZone of id

type rule_stm = Filter of Ir.direction * filter_stm
              | State of Ir.statetype list
              | Rule of rule_stm list * action_stm
              | Protocol of Ir.protocol
              | Reference of id

type node = Import of id
          | Zone of id * zone_stm list
          | Define of id * rule_stm list
          | Process of processtype * rule_stm list * policytype

val lineno : int ref
val create_define_map : node list -> ( (rule_stm list) Id_map.t)

val node_type : int -> node -> bool

val fold_rules : ('a -> rule_stm -> 'a) -> rule_stm list -> 'a -> 'a
val fold_nodes : ('a -> node -> 'a) -> node list -> 'a -> 'a
val fold : ('a -> rule_stm -> 'a) -> node list -> 'a -> 'a

val expand_rules : (rule_stm -> rule_stm list) -> rule_stm list -> rule_stm list
val expand_nodes : (node -> node list) -> node list -> node list
val expand : (rule_stm -> rule_stm list) -> node list -> node list


