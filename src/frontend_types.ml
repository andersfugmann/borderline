open Common
open Ipv6

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

and node = Import of id
         | Zone of id * zone_stm list
         | DefineStms of id * rule_stm list
         | DefineList of id * data list
         | Process of processtype * rule_stm list * policytype

and zone_stm = Interface of id
             | Network of ip
             | ZoneRules of processtype * rule_stm list * policytype

and filter_stm = Address of data list
               | TcpPort of data list
               | UdpPort of data list
               | FZone of id

and rule_stm = Filter of Ir.direction * filter_stm * Ir.pol
             | State of Ir.statetype list * Ir.pol
             | Protocol of data list * Ir.pol
             | IcmpType of data list * Ir.pol
             | Rule of rule_stm list * policytype
             | Reference of id


and data = Number of int * Lexing.position
         | Id of id
         | Ip of ip * Lexing.position

