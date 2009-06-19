open Common
open Printf

let lineno = ref 1

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
          | Define of id * rule_stm list * policytype
          | Process of processtype * rule_stm list * policytype

let node_type id = function
    Zone _ -> 1 = id
  | Process _ -> 2 = id
  | Define _ -> 3 = id
  | _ -> false

