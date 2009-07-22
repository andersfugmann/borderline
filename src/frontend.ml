open Common
open Ipv6
open Frontend_types

let lineno = ref 1

let rec create_define_map_rec acc = function
    DefineStms (id, _) as def :: xs -> create_define_map_rec (Id_map.add id def acc) xs
  | DefineInts (id, _) as def :: xs -> create_define_map_rec (Id_map.add id def acc) xs
  | _ :: xs -> create_define_map_rec acc xs 
  | [] -> acc
let create_define_map = create_define_map_rec Id_map.empty

let node_type id = function
    Zone _ -> 1 = id
  | Process _ -> 2 = id
  | DefineStms _ -> 3 = id
  | DefineInts _ -> 4 = id
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
      DefineStms (_, rules)  -> fold_rules func rules acc 
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
      DefineStms (id, rules) -> [ DefineStms (id, expand_rules func rules) ] 
    | Process (t, rules, p) -> [ Process (t, expand_rules func rules, p) ]
    | x -> [ x ]
  in
    expand_nodes node_map nodes 

    
