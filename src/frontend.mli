open Common 
open Ipv6
open Frontend_types

val lineno : int ref
val create_define_map : node list -> ( node Id_map.t)

val node_type : int -> node -> bool

val fold_rules : ('a -> rule_stm -> 'a) -> rule_stm list -> 'a -> 'a
val fold_nodes : ('a -> node -> 'a) -> node list -> 'a -> 'a
val fold : ('a -> rule_stm -> 'a) -> node list -> 'a -> 'a

val expand_rules : (rule_stm -> rule_stm list) -> rule_stm list -> rule_stm list
val expand_nodes : (node -> node list) -> node list -> node list
val expand : (rule_stm -> rule_stm list) -> node list -> node list


