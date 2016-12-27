(** Output a nft sctipt.
    nft is very close to our language, and should be easy to write.

    This script will only output ip6 rules - But will in time be
    functorized to handle ipv4 also.

    This module obsoletes ip6tables module
*)

open Batteries
open Printf
module Ip6 = Ipset.Ip6

let zone_bits = 16
let zone_mask = 1 lsl zone_bits - 1

let str_of_set s =
  Set.to_list s
  |> List.map string_of_int
  |> String.concat ", "
  |> sprintf "{ %s }"

let string_of_flag = function
  | 1 -> "syn"
  | 2 -> "ack"
  | 3 -> "fin"
  | 4 -> "rst"
  | 5 -> "urg"
  | 6 -> "psh"
  | flag -> failwith "Unknown tcp flag: " ^ (string_of_int flag)

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

(* TODO: Handle negation *)
let gen_cond neg =
  let neg_str = match neg with
    | true -> "!= "
    | false -> ""
  in
  function
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
    let zone_ids =
      Set.to_list zones
      |> List.map get_zone_id
      |> List.map (fun i -> i lsl shift)
      |> List.map (sprintf "0x%08x")
      |> String.concat ", "
      |> sprintf "{ %s }"
    in
    let mask = zone_mask lsl shift in
    sprintf "meta mark & 0x%08x %s%s" mask neg_str zone_ids
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

  | Ir.Ports (dir, ports) ->
    let cond = match dir with
      | Ir.SOURCE -> "sport"
      | Ir.DESTINATION -> "dport"
    in
    sprintf "tcp %s%s %s" neg_str cond (str_of_set ports)

  | Ir.Ip6Set (dir, ips) ->
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
  | Ir.Protocol protocols ->
    sprintf "meta protocol %s%s" neg_str (str_of_set protocols)

  | Ir.IcmpType types ->
    sprintf "ip6 nexthdr icmpv6 icmpv6 type %s%s" neg_str (str_of_set types)
  | Ir.Mark (value, mask) ->
    sprintf "meta mark and 0x%08x %s0x%08x" mask neg_str value
  | Ir.TcpFlags (flags, mask) when neg = false ->
      let not_set = List.filter (fun f -> not (List.mem f flags)) mask in
      let set = flags in

      let to_string neg f =
        let neg_str = if neg then "!" else "" in
        sprintf "tcp flags %s= %s" neg_str (string_of_flag f)
      in
      List.map (to_string false) set @
      List.map (to_string true) not_set |>
      String.concat " "
  | Ir.TcpFlags (flags, _mask) (* when neg = true *) ->
      let to_string f =
        sprintf "tcp flags != %s" (string_of_flag f)
      in
      (* TODO: this is wrong. We need to add a temporary table to jump through. Maybe sideeffect? *)
      (List.map to_string flags |> String.concat " ")

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
  | Ir.Reject rsp -> sprintf "reject with  icmpv6 type %d" rsp
  | Ir.Log prefix -> sprintf "log prefix %s group 2" prefix

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
