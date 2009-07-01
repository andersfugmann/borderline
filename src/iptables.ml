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

let gen_zone_mask dir zone =
  let zone_id = get_zone_id (id2str zone) in
  let id, mask = match dir with
      Ir.SOURCE -> zone_id, 0x00ff
    | Ir.DESTINATION -> zone_id * 0x100, 0xff00
  in
    sprintf "0x%04x/0x%04x" id mask

(* Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
    IpRange(direction, low, high) -> 
      begin
        match Ipv6.range2mask (low, high) with
            Some(ip, mask) -> "", sprintf "--%s %s/%d" (choose_dir "src" "dst" direction) (Ipv6.to_string low) mask
          | None -> "-m iprange ", sprintf "--%s-range %s-%s" (choose_dir "src" "dst" direction) (Ipv6.to_string low) (Ipv6.to_string high) 
      end
  | Interface(direction, name) -> ("", (choose_dir "--in-interface " "--out-interface " direction) ^ (id2str name))
  | State(states) -> "-m conntrack ", ("--ctstate " ^ ( String.concat "," (List.map get_state_name states)))
  | Zone(dir, id) -> "-m conmark ", "--mark " ^ (gen_zone_mask dir id)
  | TcpPort(direction, ports) -> "-p tcp -m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )
  | UdpPort(direction, ports) -> "-p udp -m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )

  | Protocol(protocol) -> ("", "-p " ^ (get_protocol_name protocol))

let rec gen_conditions acc = function
    (cond, neg) :: xs -> 
      let pref, postf = gen_condition cond in 
        gen_conditions (pref ^ (gen_neg neg) ^ postf ^ " " ^ acc) xs
  | [] -> acc

let gen_action = function
    MarkZone(dir, id) -> "MARK --set-mark " ^ (gen_zone_mask dir id) 
  | Jump(chain_id) -> (Chain.get_chain_name chain_id)
  | Return -> "RETURN"
  | Accept -> "ACCEPT"
  | Drop   -> "DROP"
  | _ -> "#### Unsupported action"

let emit (cond_list, action) : string =
  let conditions = gen_conditions "" cond_list in
  let target = gen_action action in
    conditions ^ "-j " ^ target

let emit_chain chain =
  let chain_name = Chain.get_chain_name chain.id in
  let ops = List.map emit chain.rules in
  let lines = List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops in
    match chain.id with
        Builtin(_) -> lines
      | _          -> (sprintf "ip6tables -N %s #%s" chain_name chain.comment) :: lines

