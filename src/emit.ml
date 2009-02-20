(* Emit iptables commands. Currently we have no interface to the iptables library, 
   so we use a shell script as an intermediate step. *)

open Ir
open Printf
open String

let ip_to_string (a, b, m) = 
  let pre = String.concat ":" (List.map string_of_int a) in
  let post = String.concat ":" (List.map string_of_int b) in
    sprintf "%s::%s/%d" pre post m

let map_not = function
    true -> "!"
  | _ -> ""

(* val choose_dir : direction * string * string -> string *)
let choose_dir dir a b = match dir with
    SOURCE      -> a 
  | DESTINATION -> b
  
let dir_interface = function SOURCE -> "--in-interface" | DESTINATION -> "--out_interface"
  
let emit_condition = function
    Address(direction, ip) -> sprintf "--%s %s" (choose_dir direction "source" "destination") (ip_to_string ip)
  | Interface(direction, name) -> sprintf "--%s-interface %s" (choose_dir direction "in" "out") name
  | _ -> "<unsupported>"


let emit_action = function
    MarkSourceZone(zone) -> "-j MARK --set-mark " ^ zone ^ "/0x00FFFF"
  | _ -> "# Unsupported action"

let emit (cond_list, action) = 
  let conditions = List.map (fun (cond, n) -> emit_condition cond) cond_list in
  let target = emit_action action in
    String.concat " " ( conditions @ [ target ] )

let emit_chain (table, chain, rules) =
  let ops = List.map emit rules in
  let lines = List.map ( sprintf "ip6tables -t %s -A %s %s" table chain ) ops in
    String.concat "\n" lines
