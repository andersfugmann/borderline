(* Emit iptables commands. Currently we have no interface to the iptables library, 
   so we use a shell script as an intermediate step. *)

open Ir
open Printf
open String

let ip_to_string (a, b, m) = 
  let pre = String.concat ":" (List.map string_of_int a) in
  let post = String.concat ":" (List.map string_of_int b) in
    sprintf "%s::%s/%d" pre post m

let gen_not = function
    Some(true) -> "!"
  | _ -> ""

(* val choose_dir : direction * string * string -> string *)
let choose_dir a b = function
    SOURCE      -> a 
  | DESTINATION -> b
  
let gen_condition cond neg = 
  let 
      cond_str = match cond with
          Address(direction, ip) -> sprintf "--%s %s" 
            (choose_dir "source" "destination" direction) 
            (ip_to_string ip)
        | Interface(direction, name) -> sprintf "--%s-interface %s"
            (choose_dir "in" "out" direction) name
        | _ -> "<unsupported>"
  in
    (gen_not neg) ^ " " ^ cond_str


let rec gen_conditions = function
    Tree(AND, left, right) -> (gen_conditions left) ^ " " ^ (gen_conditions right)
  | Tree(OR, left, right)  -> "Need to change the tree into chains"
  | Leaf(cond, neg)   -> (gen_condition cond neg)

let gen_action = function
    MarkSourceZone(zone) -> "-j MARK --set-mark " ^ zone ^ "/0x00FFFF"
  | _ -> "# Unsupported action"

let emit (cond_tree, action) = 
  let cond_str = match cond_tree with
      Some(conds) -> gen_conditions conds
    | None -> ""
  in
  let 
      target = gen_action action 
  in
    cond_str ^ target 
      
let emit_chain table chain rules =
  let ops = List.map emit rules in
  let lines = List.map ( sprintf "ip6tables -t %s -A %s %s" table chain ) ops in
    String.concat "\n" lines
