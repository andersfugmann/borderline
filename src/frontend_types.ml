open Common
open Ipv6

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

type action_stm = Policy of policytype

and node = Import of id
         | Zone of id * zone_stm list
         | DefineStms of id * rule_stm list
         | DefineInts of id * port list
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
             | Protocol of Ir.protocol list
             | Reference of id

and port = Port_nr of int
          | Port_id of id 

type address = Address_nr of ip
             | Address_id of id 


