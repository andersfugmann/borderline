open Common
open Ipv6

let lineno = ref 1

type processtype = MANGLE | FILTER | NAT
type policytype = ALLOW | DENY | REJECT

type action_stm = Policy of policytype

and node = Import of id
         | Zone of id * zone_stm list
         | Define of id * rule_stm list
         | Process of processtype * rule_stm list * policytype

and zone_stm = Interface of id
             | Network of ip
             | ZoneP of node

and filter_stm = Ip of ip
               | TcpPort of int list
               | UdpPort of int list
               | FZone of id

and rule_stm = Filter of Ir.direction * filter_stm
             | State of Ir.statetype list
             | Rule of rule_stm list * action_stm
             | Protocol of Ir.protocol
             | Reference of id

let rec create_define_map_rec acc = function
    Define (id, stms) :: xs -> create_define_map_rec (Id_map.add id stms acc) xs
  | _ :: xs -> create_define_map_rec acc xs
  | [] -> acc
let create_define_map = create_define_map_rec Id_map.empty

let node_type id = function
    Zone _ -> 1 = id
  | Process _ -> 2 = id
  | Define _ -> 3 = id
  | _ -> false
      
let rec fold_rules func rules acc = 
  match rules with
    | Rule (rules, _) :: xs -> fold_rules func xs (fold_rules func rules acc)
    | x :: xs -> fold_rules func xs (func acc x) 
    | [] -> acc

let fold_nodes func nodes acc = 
  List.fold_left func acc nodes

let rec fold func nodes acc =
  let node_func acc = function
      Define (_, rules)  -> fold_rules func rules acc 
    | Process (_, rules, _) -> fold_rules func rules acc 
    | _ -> acc
  in 
    fold_nodes node_func nodes acc

let rec expand_rules func = function 
  | Rule (rules, p) :: xs -> Rule ((expand_rules func rules), p) :: expand_rules func xs 
  | x :: xs -> (func x) @ expand_rules func xs
  | [] -> []

let rec expand_nodes func = function
    x :: xs -> (func x) @ (expand_nodes func xs)
  | [] -> []

let expand func nodes = 
  let node_map = function
      Define (id, rules) -> [ Define (id, expand_rules func rules) ] 
    | Process (t, rules, p) -> [ Process (t, expand_rules func rules, p) ]
    | x -> [ x ]
  in
    expand_nodes node_map nodes 
    
