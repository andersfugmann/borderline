open Common
open Ipv6

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

and node = Import of id
         | Zone of id * zone_stm list
         | DefineStms of id * rule_stm list
         | DefineInts of id * num list
         | Process of processtype * rule_stm list * policytype

and zone_stm = Interface of id
             | Network of ip
             | ZoneRules of processtype * rule_stm list * policytype

and filter_stm = Ip of ip
               | TcpPort of num list
               | UdpPort of num list
               | FZone of id

and rule_stm = Filter of Ir.direction * filter_stm * Ir.pol
             | State of Ir.statetype list * Ir.pol
             | Protocol of num list * Ir.pol
             | Rule of rule_stm list * policytype
             | Reference of id


and num = Number of int
        | Id of id

type address = Address_nr of ip
             | Address_id of id


