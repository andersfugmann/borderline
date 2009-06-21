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
          | Define of id * rule_stm list
          | Process of processtype * rule_stm list * policytype

let rec create_define_map acc = function
    Define (id, stms) :: xs -> create_define_map (Id_map.add id stms acc) xs
  | _ :: xs -> create_define_map acc xs
  | [] -> acc

let node_type id = function
    Zone _ -> 1 = id
  | Process _ -> 2 = id
  | Define _ -> 3 = id
  | _ -> false
      
let rules_fold_left func acc nodes = 
  let rec traverse_rules acc = function 
    | Rule (rules, _) :: xs -> traverse_rules acc ( rules @ xs)
    | x :: xs -> traverse_rules (func acc x) xs 
    | [] -> acc
  in      
  let rec traverse_nodes acc = function
      Define (_, rules) :: xs -> traverse_nodes (traverse_rules acc rules) xs
    | Process (_, rules, _) :: xs -> traverse_nodes (traverse_rules acc rules) xs
    | _ :: xs -> traverse_nodes acc xs
    | [] -> acc      
  in traverse_nodes acc nodes

let map_rules func nodes = 
  let rec traverse_rules = function 
    | Rule (rules, p) :: xs -> Rule ((traverse_rules rules), p) :: (traverse_rules xs)
    | x :: xs -> (func x) :: traverse_rules xs
    | [] -> []
  in
  let rec traverse_nodes = function
      Define (id, rules) :: xs -> Define (id, traverse_rules rules) :: traverse_nodes xs
    | Process (t, rules, p) :: xs -> Process (t, traverse_rules rules, p) :: traverse_nodes xs
    | x :: xs -> x :: traverse_nodes xs
    | [] -> []
  in 
    traverse_nodes nodes
