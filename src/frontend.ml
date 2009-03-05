open Common
open Printf

let lineno = ref 1

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

type action_stm = Policy of policytype

type zone_stm = Interface of string
                | Network of ip

type filter_stm = Ip of ip
                | Port of int list
                | FZone of string

type rule_stm = Filter of Ir.direction * filter_stm
              | State of Ir.statetype list
              | Protocol of Ir.protocol
              | Rule of rule_stm list * action_stm

type node = Import of string
          | Zone of string * zone_stm list
          | Define of string * rule_stm list
          | Process of processtype * rule_stm list * policytype
