(* Emit iptables commands. Currently we have no interface to the iptables library, 
   so we use a shell script as an intermediate step. *)

open Ir
open Printf
open Str
open String
open Chain

module StringMap = Map.Make(String)
let zone_id = ref 1
let zone_map = ref StringMap.empty

let get_zone_id zone =
  try 
    StringMap.find zone !zone_map
  with Not_found ->
    let id = !zone_id in
    let _ = zone_id := !zone_id + 1 in
    let _ = zone_map := StringMap.add zone id !zone_map in
      id

let get_zone_id_mask zone = function
    SOURCE -> (get_zone_id zone, 0x00ff)
  | DESTINATION -> ((get_zone_id zone) * 0x100, 0xff00)
  

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
    MarkZone(direction, zone) -> 
      let id, mask = get_zone_id_mask zone direction in
        sprintf "-j MARK --set-mark %X/%X" id mask
  | _ -> "# Unsupported action"

let emit (cond_tree, action) = 
  let cond_str = match cond_tree with
      Some(conds) -> gen_conditions conds
    | None -> ""
  in
  let 
      target = gen_action action 
  in
    cond_str ^ " " ^ target 
      
let get_chain_name chain =
    sprintf "chn%d_%s" chain.id chain.comment

let emit_chain chain =
  let chain_name = get_chain_name chain in
  let ops = List.map emit chain.rules in
  let lines = List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops in
    (sprintf "ip6tables -C %s\n" chain_name) :: lines
