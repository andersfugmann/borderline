(** Output a nft sctipt.
    nft is very close to our language, and should be easy to write.

    This script will only output ip6 rules - But will in time be
    functorized to handle ipv4 also.

    This module obsoletes ip6tables module
*)

open Batteries
open Printf
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

let zone_bits = 8 (* 256 zones ought to be enough *)
let zone_mask = 1 lsl zone_bits - 1

let str_of_set s =
  Set.to_list s
  |> List.map string_of_int
  |> String.concat ", "
  |> sprintf "{ %s }"

let zones = Hashtbl.create 100
let get_zone_id zone =
  match Hashtbl.find_option zones zone with
  | Some id -> id
  | None ->
      let id = Hashtbl.length zones + 1 in
      Hashtbl.add zones zone id;
      id

let chain_name = function
  | Ir.Temporary n -> sprintf "temp_%d" n
  | Ir.Builtin Ir.INPUT -> "input"
  | Ir.Builtin Ir.OUTPUT -> "output"
  | Ir.Builtin Ir.FORWARD  -> "forward"
  | Ir.Named name -> name

(* TODO Use chain_name *)
let chain_premable chain =
  let name = chain_name chain in
  match chain with
  | Ir.Builtin _ ->
    [ sprintf "chain %s {" name;
      sprintf "  type filter hook %s priority 0;" name;
      sprintf "  policy drop;" ]
  | Ir.Temporary _
  | Ir.Named _ ->
    [ sprintf "chain %s {" name ]

let gen_cond neg cond =
  let neg_str = match neg with
    | true -> "!= "
    | false -> ""
  in
  match cond with
  | Ir.Interface (dir, zones) ->
    let zones = sprintf "{ %s }" (Set.to_list zones |> String.concat ", ") in
    let classifier = match dir with
      | Ir.SOURCE -> "iif"
      | Ir.DESTINATION -> "oif"
    in
    sprintf "meta %s %s%s" classifier neg_str zones

  | Ir.Zone (dir, zones) ->
    let shift = match dir with
      | Ir.SOURCE -> 0
      | Ir.DESTINATION -> zone_bits
    in
    let mask = Set.fold (fun zone acc ->
        let zone_id = get_zone_id zone in
        let zone_val = zone_id lsl shift in
        acc + zone_val) zones 0
    in
    let neg_str = match neg with true -> '=' | false -> '>' in
    sprintf "meta mark & 0x%08x %c 0x0" mask neg_str

  | Ir.State states ->
    let string_of_state state = match state with
      | State.NEW -> "new"
      | State.ESTABLISHED -> "established"
      | State.RELATED -> "related"
      | State.INVALID -> "invalid"
    in
    let states =
      State.to_list states
      |> List.map string_of_state
      |> String.concat ", "
    in
    sprintf "ct state %s{ %s }" neg_str states

  | Ir.Ports (dir, port_type, ports) ->
    let cond = match dir with
      | Ir.SOURCE -> "sport"
      | Ir.DESTINATION -> "dport"
    in
    let classifier = match port_type with
      | Ir.Tcp -> "tcp"
      | Ir.Udp -> "udp"
    in
    sprintf "%s %s%s %s" classifier neg_str cond (str_of_set ports)

  | Ir.Ip6Set (dir, ips) ->
      (* Should define a true ip set. these sets can become very large. *)

    let classifier = match dir with
      | Ir.SOURCE -> "saddr"
      | Ir.DESTINATION  -> "daddr"
    in
    let ips =
      Ip6.to_ips ips
      |> List.map (fun (ip, mask) -> sprintf "%s/%d" (Ip6.string_of_ip ip) mask)
      |> String.concat ", "
    in
    sprintf "ip6 %s %s{ %s }" classifier neg_str ips
  | Ir.Ip4Set (dir, ips) ->
    let classifier = match dir with
      | Ir.SOURCE -> "saddr"
      | Ir.DESTINATION  -> "daddr"
    in
    let ips =
      Ip4.to_ips ips
      |> List.map (fun (ip, mask) -> sprintf "%s/%d" (Ip4.string_of_ip ip) mask)
      |> String.concat ", "
    in
    sprintf "ip %s %s{ %s }" classifier neg_str ips
  | Ir.Protocol protocols ->
    sprintf "meta protocol %s%s" neg_str (str_of_set protocols)

  | Ir.Icmp6Type types ->
      let set = Set.to_list types
                |> List.map Ir.string_of_icmp_type
                |> String.concat ", "
                |> sprintf "{ %s }"
      in
      sprintf "ip6 nexthdr icmpv6 icmpv6 type %s%s" neg_str set
  | Ir.Mark (value, mask) ->
    sprintf "meta mark and 0x%08x %s0x%08x" mask neg_str value
  | Ir.TcpFlags flags ->
      let set = Set.to_list flags
                |> List.map Ir.string_of_tcpflag
                |> String.concat ", "
                |> sprintf "{ %s }"
      in
      sprintf "tcp flags %s%s" neg_str set

let reject_to_string = function
  | Ir.HostUnreachable -> "reject with icmpx type host-unreachable"
  | Ir.NoRoute -> "reject with icmpx type no-route"
  | Ir.AdminProhibited -> "reject with icmpx type admin-prohibited"
  | Ir.PortUnreachable -> "reject with icmpx type port-unreachable"
  | Ir.TcpReset -> "reject with tcp reset"

let gen_target = function
  | Ir.MarkZone (dir, id) ->
      let shift = match dir with
        | Ir.SOURCE -> 0
        | Ir.DESTINATION -> zone_bits
      in
      let mask = zone_mask lsl (zone_bits - shift) in
      sprintf "meta mark set mark & 0x%08x or 0x%08x" mask ((get_zone_id id) lsl shift)
  | Ir.Accept -> "accept"
  | Ir.Drop -> "drop"
  | Ir.Return -> "return"
  | Ir.Notrack -> ""
  | Ir.Jump chain -> sprintf "jump %s" (chain_name chain)
  | Ir.Reject rsp -> reject_to_string rsp
  | Ir.Log prefix -> sprintf "log prefix %s level info" prefix

let gen_rule (conds, target) =
  let conds = List.map (fun (op, neg) -> gen_cond neg op) conds
            |> String.concat " "
  in
  let target = gen_target target in
  sprintf "%s %s;" conds target

let emit_chain { Ir.id; rules; comment } =
  let rules =
    List.map gen_rule rules
  in
  let premable = chain_premable id in

  [ "#" ^ comment ] @ premable @ rules @ [ "}" ]

let emit_chains (chains : (Ir.chain_id, Ir.chain) Map.t) : string list =
  let rules =
    Map.values chains
    |> Enum.map emit_chain
    |> Enum.map List.enum
    |> Enum.flatten
    |> List.of_enum
  in
  (* Dump zone mapping *)
  Hashtbl.iter (fun zone id -> printf "#zone %s -> %d\n" zone id) zones;
  [ "table inet filter {" ] @ rules @ [ "}" ]
