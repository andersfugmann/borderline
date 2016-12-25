(** Output a nft sctipt.
    nft is very close to our language, and should be easy to write.

    This script will only output ip6 rules - But will in time be
    functorized to handle ipv4 also.

    This module obsoletes ip6tables module
*)

open Batteries
open Printf

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

let get_zone_id =
  let zones = Hashtbl.create 100 in
  fun zone ->
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
    | true -> " != "
    | false -> ""
  in
  function
  | Ir.Interface (dir, zones) ->
    let zones = sprintf "{ %s } " (Set.to_list zones |> String.concat ", ") in
    let classifier = match dir with
      | Ir.SOURCE -> "iif"
      | Ir.DESTINATION -> "oif"
    in
    sprintf "meta %s %s %s" classifier neg_str zones

  | Ir.Zone (dir, zones) ->
    let zone_ids =
      Set.to_list zones
      |> List.map get_zone_id
      |> List.map (fun i -> i * 0x100)
      |> List.map (sprintf "0x%04x")
      |> String.concat ", "
      |> sprintf "{ %s }"
    in
    let mask = match dir with
      | Ir.SOURCE -> 0x00ff (* Ahh. Ok. We get a mask as well *)
      | Ir.DESTINATION -> 0xff00
    in
    sprintf "ct mark and 0x%04x %s %s" mask neg_str zone_ids
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
    sprintf "ct state %s { %s }" neg_str states

  | Ir.Ports (dir, ports) ->
    let cond = match dir with
      | Ir.SOURCE -> "sport"
      | Ir.DESTINATION -> "dport"
    in
    sprintf "tcp %s %s %s" neg_str cond (str_of_set ports)

  | Ir.IpSet (dir, ips) ->
    let classifier = match dir with
      | Ir.SOURCE -> "saddr"
      | Ir.DESTINATION  -> "daddr"
    in
    let ips =
      Ipset.to_ips ips
      |> List.map (fun (ip, mask) -> sprintf "%s/%d" (Ipset.string_of_ip ip) mask)
      |> String.concat ", "
    in
    sprintf "ip6 %s %s { %s }" classifier neg_str ips
  | Ir.Protocol protocols ->
    (* TODO: Protocols should be an ADT:
       icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp
     * - Maybe also a match to ip4 / ip6 *)
    sprintf "tcp protocol %s %s" neg_str (str_of_set protocols)

  | Ir.IcmpType types ->
    sprintf "icmpv6 type %s %s" neg_str (str_of_set types)
  | Ir.Mark (value, mask) ->
    sprintf "meta mark and 0x%04x %s 0x%04x" mask neg_str value
  | Ir.TcpFlags (flags, mask) ->
    (* TODO: Use adt: fin, syn, rst, psh, ack, urg, ecn, cwr *)
    let unset = List.filter (fun v -> not (List.mem v flags)) mask in
    let to_string s =
      List.map string_of_flag s
      |> String.concat ","
      |> sprintf "{ %s }"
    in
    sprintf "tcp flags %s tcp flags != %s" (to_string flags) (to_string unset)

let gen_target = function
  | Ir.MarkZone (_dir, id) -> sprintf "meta mark set 0x%04x" (get_zone_id id)
  | Ir.Accept -> "accept"
  | Ir.Drop -> "drop"
  | Ir.Return -> "return"
  | Ir.Notrack -> ""
  | Ir.Jump chain -> sprintf "jump %s" (chain_name chain)
  | Ir.Reject _rsp -> "reject"
  | Ir.Log prefix -> sprintf "log prefix %s group 2" prefix

let gen_rule (conds, target) =
  let conds = List.map (fun (op, neg) -> gen_cond neg op) conds
            |> String.concat " "
  in
  let target = gen_target target in
  sprintf "%s %s" conds target

let emit_chain { Ir.id; rules; comment } =
  let rules =
    List.map gen_rule rules
  in
  let premable = chain_premable id in

  [ "#" ^ comment ] @ premable @ rules @ [ "}" ]

let emit_chains (chains : (Ir.chain_id, Ir.chain) Map.t) : string list =
  Map.values chains
  |> Enum.map emit_chain
  |> Enum.map List.enum
  |> Enum.flatten
  |> List.of_enum
