(**
   Output a nft sctipt.
   TODO: Fix negation of tcpflags
*)

open Batteries
open Printf
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

let zone_bits = 8 (* Number of zones *)
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
      let id = 1 lsl (Hashtbl.length zones + 1)  in
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

let string_of_icmp6_type = function
  | Icmp.V6.DestinationUnreachable -> "destination-unreachable"
  | Icmp.V6.PacketTooBig -> "packet-too-big"
  | Icmp.V6.TimeExceeded -> "time-exceeded"
  | Icmp.V6.EchoRequest -> "echo-request"
  | Icmp.V6.EchoReply -> "echo-reply"
  | Icmp.V6.ListenerQuery -> "mld-listener-query"
  | Icmp.V6.ListenerReport -> "mld-listener-report"
  | Icmp.V6.ListenerReduction -> "mld-listener-reduction"
  | Icmp.V6.RouterSolicitation -> "nd-router-solicit"
  | Icmp.V6.RouterAdvertisement -> "nd-router-advert"
  | Icmp.V6.NeighborSolicitation -> "nd-neighbor-solicit"
  | Icmp.V6.NeighborAdvertisement -> "nd-neighbor-advert"
  | Icmp.V6.Redirect -> "nd-redirect"
  | Icmp.V6.ParameterProblem -> "parameter-problem"
  | Icmp.V6.RouterRenumbering -> "router-renumbering"

let string_of_icmp4_type = function
  | Icmp.V4.EchoRequest -> "echo-request"
  | Icmp.V4.EchoReply -> "echo-reply"
  | Icmp.V4.DestinationUnreachable -> "destination-unreachable"
  | Icmp.V4.SourceQuench -> "source-quench"
  | Icmp.V4.Redirect -> "redirect"
  | Icmp.V4.TimeExceeded -> "time-exceeded"
  | Icmp.V4.ParameterProblem -> "parameter-problem"
  | Icmp.V4.TimestampRequest -> "timestamp-request"
  | Icmp.V4.TimestampReply -> "timestamp-reply"
  | Icmp.V4.InfoRequest -> "info-request"
  | Icmp.V4.InfoReply -> "info-reply"
  | Icmp.V4.RouterAdvertisement -> "router-advertisement"
  | Icmp.V4.RouterSolicitation -> "router-solicication"
  | Icmp.V4.AddressMaskRequest -> "address-mask-request"
  | Icmp.V4.AddressMaskReply -> "address-mask-reply"

let string_of_tcpflag = function
  | Ir.Syn -> "syn"
  | Ir.Ack -> "ack"
  | Ir.Fin -> "fin"
  | Ir.Rst -> "rst"
  | Ir.Urg -> "urg"
  | Ir.Psh -> "psh"

let string_of_layer = function
  | Ir.Protocol.Ip4 -> "ip protocol"
  | Ir.Protocol.Ip6 -> "ip6 nexthdr"

let string_of_protocol l = function
  | Ir.Protocol.Icmp when l = Ir.Protocol.Ip4 -> "icmpv6"
  | Ir.Protocol.Icmp -> "icmp"
  | Ir.Protocol.Tcp -> "tcp"
  | Ir.Protocol.Udp -> "udp"

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
      let neg_str = match neg with true -> "==" | false -> "!=" in
      sprintf "meta mark & 0x%08x %s 0x0" mask neg_str

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
  | Ir.Protocol (l, p) ->
      let prefix = string_of_layer l in
      let set = Set.to_list p |> List.map (string_of_protocol l) |> String.concat "," in
      sprintf "%s %s { %s }" prefix neg_str set


  | Ir.Icmp6 types ->
      let set = Set.to_list types
                |> List.map string_of_icmp6_type
                |> String.concat ", "
                |> sprintf "{ %s }"
      in
      sprintf "ip6 nexthdr icmpv6 icmpv6 type %s%s" neg_str set
  | Ir.Icmp4 types ->
      let set = Set.to_list types
                |> List.map string_of_icmp4_type
                |> String.concat ", "
                |> sprintf "{ %s }"
      in
      sprintf "ip protocol icmp icmp type %s%s" neg_str set
  | Ir.Mark (value, mask) ->
      sprintf "meta mark and 0x%08x %s0x%08x" mask neg_str value
  | Ir.TcpFlags (flags, mask) ->
      let to_list f = Set.to_list f
                      |> List.map string_of_tcpflag
                      |> String.concat "|"
      in
      let neg_str = match neg with true -> "!=" | false -> "==" in
      sprintf "tcp flags & (%s) %s %s" (to_list mask) neg_str (to_list flags)
  | Ir.True when neg ->
      (* Any false statement *)
      "meta mark | 0x1 == 0x0"
  | Ir.True ->
      ""
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
  | Ir.Log prefix -> sprintf "log prefix \"%s: \" level info" prefix

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
  (* How does this work. Dont we need a strict ordering of chains here? *)
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
