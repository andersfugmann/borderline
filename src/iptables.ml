(* Emit iptables commands. Currently we have no interface to the iptables library,
   so we use a shell script as an intermediate step. *)

open Common
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

let gen_neg = function
    true -> "! "
  | _ -> ""

let get_zone_id_mask zone = function
    SOURCE -> (get_zone_id zone, 0x00ff)
  | DESTINATION -> ((get_zone_id zone) * 0x100, 0xff00)

(* val choose_dir : direction * string * string -> string *)
let choose_dir a b = function
    SOURCE      -> a
  | DESTINATION -> b

let get_state_name = function
    NEW -> "new"
  | ESTABLISHED -> "established"
  | RELATED -> "related"
  | INVALID -> "invalid"

let get_protocol_name = function
    TCP -> "tcp"
  | UDP -> "udp"
  | ICMP -> "icmpv6"

(* Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
    Address(direction, ip) -> "", ((choose_dir "--source " "--destination " direction) ^ (ip_to_string ip))
  | Interface(direction, name) -> ("", (choose_dir "--in-interface " "--out-interface " direction) ^ name)
  | State(states) -> "-m conntrack ", ("--ctstate " ^ ( String.concat "," (List.map get_state_name states)))
  | Zone(direction, zone) -> let id, mask = get_zone_id_mask zone direction in
      "-m conmark ", ( sprintf "--mark 0x%04x/0x%04x" id mask )
  | Port(direction, ports) -> " -m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )
  | Protocol(protocol) -> ("", "-m " ^ (get_protocol_name protocol))
  | _ -> "", "<unsupported>"

let rec gen_conditions conditions =
  (* tuple to a string *)
  let gen_cond (cond, neg) =
    let pref, postf = gen_condition cond in
      pref ^ (gen_neg neg) ^ postf
  in
    String.concat " " (List.map gen_cond conditions)

let gen_action = function
    MarkZone(direction, zone) ->
      let id, mask = get_zone_id_mask zone direction in
        sprintf "-j MARK --set-mark 0x%04x/0x%04x" id mask
  | Jump(chain_id) -> "-j " ^ (Chain.get_chain_name chain_id)
  | Return -> "-j RETURN"
  | Accept -> "-j ACCEPT"
  | Drop   -> "-j DROP"
  | _ -> "#### Unsupported action"

let emit (cond_list, action) : string =
  let conditions = gen_conditions cond_list in
  let target = gen_action action in
    conditions ^ " " ^ target

let emit_chain chain =
  let chain_name = Chain.get_chain_name chain.id in
  let ops = List.map emit chain.rules in
  let lines = List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops in
    match chain.id with
        Builtin(_) -> lines
      | _          -> sprintf "ip6tables -N %s #%s" chain_name chain.comment :: lines

