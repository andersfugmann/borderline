open Common 
open Ipv6

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

type action_stm = Policy of policytype

and node = Import of id
         | Zone of id * zone_stm list
         | DefineRule of id * rule_stm list
         | DefinePort of id * port list
         | Process of processtype * rule_stm list * policytype

and zone_stm = Interface of id
             | Network of ip
             | ZoneRules of processtype * rule_stm list * policytype

and filter_stm = Ip of ip
               | TcpPort of port list
               | UdpPort of port list
               | FZone of id

and rule_stm = Filter of Ir.direction * filter_stm
             | State of Ir.statetype list
             | Rule of rule_stm list * action_stm
             | Protocol of Ir.protocol
             | Reference of id

and port = Port_nr of int
          | Port_id of id 

type address = Address_nr of ip
             | Address_id of id 


val lineno : int ref
val create_define_map : node list -> ( node Id_map.t)

val node_type : int -> node -> bool

val fold_rules : ('a -> rule_stm -> 'a) -> rule_stm list -> 'a -> 'a
val fold_nodes : ('a -> node -> 'a) -> node list -> 'a -> 'a
val fold : ('a -> rule_stm -> 'a) -> node list -> 'a -> 'a

val expand_rules : (rule_stm -> rule_stm list) -> rule_stm list -> rule_stm list
val expand_nodes : (node -> node list) -> node list -> node list
val expand : (rule_stm -> rule_stm list) -> node list -> node list


