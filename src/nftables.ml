(**
   Output a nft sctipt.
*)

open Core.Std
open Printf
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

let zone_bits = 8 (* Number of zones *)
let zone_mask = 1 lsl zone_bits - 1

let str_of_set s =
  Set.to_list s
  |> List.map ~f:string_of_int
  |> String.concat ~sep:", "
  |> sprintf "{ %s }"

let zones = Hashtbl.Poly.create ~size:100 ()
let get_zone_id zone =
  match Hashtbl.Poly.find zones zone with
  | Some id -> id
  | None ->
      let id = 1 lsl (Hashtbl.length zones + 1)  in
      Hashtbl.add_exn ~key:zone ~data:id zones;
      id

let chain_name = function
  | Ir.Temporary n -> sprintf "temp_%d" n
  | Ir.Builtin Ir.Chain_type.Input -> "input"
  | Ir.Builtin Ir.Chain_type.Output -> "output"
  | Ir.Builtin Ir.Chain_type.Forward  -> "forward"
  | Ir.Builtin Ir.Chain_type.Pre_routing  -> "prerouting"
  | Ir.Builtin Ir.Chain_type.Post_routing  -> "postrouting"
  | Ir.Named name -> name

(* TODO Use chain_name *)
let chain_premable chain =
  let name = chain_name chain in
  match chain with
  | Ir.Builtin Ir.Chain_type.Pre_routing
  | Ir.Builtin Ir.Chain_type.Post_routing ->
      [ sprintf "chain %s {" name;
        sprintf "  type nat hook %s priority 0;" name;
        sprintf "  policy accept;" ]
  | Ir.Builtin Ir.Chain_type.Input
  | Ir.Builtin Ir.Chain_type.Output
  | Ir.Builtin Ir.Chain_type.Forward ->
      [ sprintf "chain %s {" name;
        sprintf "  type filter hook %s priority 0;" name;
        sprintf "  policy drop;" ]
  | Ir.Temporary _
  | Ir.Named _ ->
      [ sprintf "chain %s {" name ]

let string_of_icmp6_type = function
  | Icmp.V6.DestinationUnreachable -> "destination-unreachable"
  | Icmp.V6.PacketTooBig           -> "packet-too-big"
  | Icmp.V6.TimeExceeded           -> "time-exceeded"
  | Icmp.V6.EchoRequest            -> "echo-request"
  | Icmp.V6.EchoReply              -> "echo-reply"
  | Icmp.V6.ListenerQuery          -> "mld-listener-query"
  | Icmp.V6.ListenerReport         -> "mld-listener-report"
  | Icmp.V6.ListenerReduction      -> "mld-listener-reduction"
  | Icmp.V6.RouterSolicitation     -> "nd-router-solicit"
  | Icmp.V6.RouterAdvertisement    -> "nd-router-advert"
  | Icmp.V6.NeighborSolicitation   -> "nd-neighbor-solicit"
  | Icmp.V6.NeighborAdvertisement  -> "nd-neighbor-advert"
  | Icmp.V6.Redirect               -> "nd-redirect"
  | Icmp.V6.ParameterProblem       -> "parameter-problem"
  | Icmp.V6.RouterRenumbering      -> "router-renumbering"

let string_of_icmp4_type = function
  | Icmp.V4.EchoRequest            -> "echo-request"
  | Icmp.V4.EchoReply              -> "echo-reply"
  | Icmp.V4.DestinationUnreachable -> "destination-unreachable"
  | Icmp.V4.SourceQuench           -> "source-quench"
  | Icmp.V4.Redirect               -> "redirect"
  | Icmp.V4.TimeExceeded           -> "time-exceeded"
  | Icmp.V4.ParameterProblem       -> "parameter-problem"
  | Icmp.V4.TimestampRequest       -> "timestamp-request"
  | Icmp.V4.TimestampReply         -> "timestamp-reply"
  | Icmp.V4.InfoRequest            -> "info-request"
  | Icmp.V4.InfoReply              -> "info-reply"
  | Icmp.V4.RouterAdvertisement    -> "router-advertisement"
  | Icmp.V4.RouterSolicitation     -> "router-solicication"
  | Icmp.V4.AddressMaskRequest     -> "address-mask-request"
  | Icmp.V4.AddressMaskReply       -> "address-mask-reply"

let string_of_tcpflag = function
  | Ir.Tcp_flags.Syn -> "syn"
  | Ir.Tcp_flags.Ack -> "ack"
  | Ir.Tcp_flags.Fin -> "fin"
  | Ir.Tcp_flags.Rst -> "rst"
  | Ir.Tcp_flags.Urg -> "urg"
  | Ir.Tcp_flags.Psh -> "psh"

let string_of_layer = function
  | Ir.Protocol.Ip4 -> "ip protocol"
  | Ir.Protocol.Ip6 -> "ip6 nexthdr"

let string_of_protocol l = function
  | Ir.Protocol.Icmp when l = Ir.Protocol.Ip4 -> "icmpv6"
  | Ir.Protocol.Icmp -> "icmp"
  | Ir.Protocol.Tcp -> "tcp"
  | Ir.Protocol.Udp -> "udp"

let string_of_state state = match state with
  | State.New -> "new"
  | State.Established -> "established"
  | State.Related -> "related"
  | State.Invalid -> "invalid"


let gen_cond neg cond =
  let neg_str = match neg with
    | true -> "!= "
    | false -> ""
  in
  match cond with
  | Ir.Interface (dir, zones) ->
      let zones = sprintf "{ %s }" (Set.to_list zones |> List.map ~f:(sprintf "\"%s\"") |> String.concat ~sep:", ") in
      let classifier = match dir with
        | Ir.Direction.Source -> "iifname"
        | Ir.Direction.Destination -> "oifname"
      in
      sprintf "%s %s%s" classifier neg_str zones, None
  | Ir.Zone (dir, zones) ->
      let shift = match dir with
        | Ir.Direction.Source -> 0
        | Ir.Direction.Destination -> zone_bits
      in
      let mask = Set.Poly.fold ~f:(fun acc zone ->
          let zone_id = get_zone_id zone in
          let zone_val = zone_id lsl shift in
          acc + zone_val) zones ~init:0
      in
      let neg_str = match neg with true -> "==" | false -> "!=" in
      let comment =
        let neg = match neg with true -> "not " | false -> "" in
        let dir = match dir with
          | Ir.Direction.Source  -> "src"
          | Ir.Direction.Destination  -> "dest"
        in
        let zones = Set.to_list zones |> String.concat ~sep:", " in
        sprintf "%s%s zone in (%s)" neg dir zones
      in
      sprintf "meta mark & 0x%08x %s 0x0" mask neg_str, Some comment
  | Ir.State states ->
      let states =
        State.to_list states
        |> List.map ~f:string_of_state
        |> String.concat ~sep:", "
      in
      sprintf "ct state %s{ %s }" neg_str states, None
  | Ir.Ports (dir, port_type, ports) ->
      let cond = match dir with
        | Ir.Direction.Source -> "sport"
        | Ir.Direction.Destination -> "dport"
      in
      let classifier = match port_type with
        | Ir.Port_type.Tcp -> "tcp"
        | Ir.Port_type.Udp -> "udp"
      in
      sprintf "%s %s%s %s" classifier neg_str cond (str_of_set ports), None
  | Ir.Ip6Set (dir, ips) ->
      (* Should define a true ip set. these sets can become very large. *)

      let classifier = match dir with
        | Ir.Direction.Source -> "saddr"
                                     | Ir.Direction.Destination  -> "daddr"
      in
      let ips = Ip6.to_list ips
                |> Ip6.reduce
                |> List.map ~f:Ipaddr.V6.Prefix.to_string
                |> String.concat ~sep:", "
      in
      sprintf "ip6 %s %s{ %s }" classifier neg_str ips, None
  | Ir.Ip4Set (dir, ips) ->
      let classifier = match dir with
        | Ir.Direction.Source -> "saddr"
        | Ir.Direction.Destination  -> "daddr"
      in
      let ips = Ip4.to_list ips
                |> Ip4.reduce
                |> List.map ~f:Ipaddr.V4.Prefix.to_string
                |> String.concat ~sep:", "
      in
      sprintf "ip %s %s{ %s }" classifier neg_str ips, None
  | Ir.Protocol (l, p) ->
      let prefix = string_of_layer l in
      let set = Set.to_list p |> List.map ~f:(string_of_protocol l) |> String.concat ~sep:"," in
      sprintf "%s %s { %s }" prefix neg_str set, None
  | Ir.Icmp6 types ->
      let set = Set.to_list types
                |> List.map ~f:string_of_icmp6_type
                |> String.concat ~sep:", "
                |> sprintf "{ %s }"
      in
      sprintf "ip6 nexthdr icmpv6 icmpv6 type %s%s" neg_str set, None
  | Ir.Icmp4 types ->
      let set = Set.to_list types
                |> List.map ~f:string_of_icmp4_type
                |> String.concat ~sep:", "
                |> sprintf "{ %s }"
      in
      sprintf "ip protocol icmp icmp type %s%s" neg_str set, None
  | Ir.Mark (value, mask) ->
      sprintf "meta mark and 0x%08x %s0x%08x" mask neg_str value, None
  | Ir.TcpFlags (flags, mask) ->
      let to_list f = Set.to_list f
                      |> List.map ~f:string_of_tcpflag
                      |> String.concat ~sep:"|"
      in
      let neg_str = match neg with true -> "!=" | false -> "==" in
      sprintf "tcp flags & (%s) %s %s" (to_list mask) neg_str (to_list flags), None
  | Ir.True when neg ->
      (* Any false statement *)
      "meta mark | 0x1 == 0x0", None
  | Ir.True ->
      "", None

let reject_to_string = function
  | Ir.Reject.HostUnreachable -> "reject with icmpx type host-unreachable"
  | Ir.Reject.NoRoute -> "reject with icmpx type no-route"
  | Ir.Reject.AdminProhibited -> "reject with icmpx type admin-prohibited"
  | Ir.Reject.PortUnreachable -> "reject with icmpx type port-unreachable"
  | Ir.Reject.TcpReset -> "reject with tcp reset"

let gen_target = function
  | Ir.MarkZone (dir, id) ->
      let shift = match dir with
        | Ir.Direction.Source -> 0
        | Ir.Direction.Destination -> zone_bits
      in
      let mask = zone_mask lsl (zone_bits - shift) in
      sprintf "meta mark set mark & 0x%08x or 0x%08x" mask ((get_zone_id id) lsl shift)
  | Ir.Accept -> "accept"
  | Ir.Drop -> "drop"
  | Ir.Return -> "return"
  | Ir.Counter -> "counter"
  | Ir.Notrack -> ""
  | Ir.Jump chain -> sprintf "jump %s" (chain_name chain)
  | Ir.Reject rsp -> reject_to_string rsp
  | Ir.Log prefix -> sprintf "log prefix \"%s: \" level info" prefix
  | Ir.Snat ip -> sprintf "snat %s" (Ipaddr.V4.to_string ip)
let gen_rule (conds, target) =
  let conds, comments =
    let conds, comments =
      List.map ~f:(fun (op, neg) -> gen_cond neg op) conds
      |> List.unzip
    in
    let comments =
      List.filter_map ~f:Fn.id comments
      |> function [] -> []
                | cs -> "#" :: cs
    in
    String.concat ~sep:" " conds, String.concat ~sep:" " comments
  in
  let target = gen_target target in
  sprintf "%s %s; %s" conds target comments

let expand_rule (rls, tg) =
  let rec split (rules, (ip4, neg4), (ip6, neg6)) = function
    | (Ir.Ip4Set _, n) as r :: xs -> split (rules, (r :: ip4, neg4 && n), (ip6, neg6)) xs
    | (Ir.Ip6Set _, n) as r :: xs -> split (rules, (ip4, neg4), (r :: ip6, neg6 && n)) xs
    | r :: xs -> split (r :: rules, (ip4, neg4), (ip6, neg6)) xs
    | [] -> (List.rev rules, (List.rev ip4, neg4), (List.rev ip6, neg6))
  in
  let (rules, (ip4, neg4), (ip6, neg6)) = split ([], ([], true), ([], true)) rls in

  match (ip4, neg4), (ip6, neg6) with
  | ([], _), _
  | _, ([], _) -> [(rls, tg)]
  | (_, true), (ip6, false) -> [(ip6 @ rules, tg)] (* Slight optimization *)
  | (ip4, false), (_, true) -> [(ip4 @ rules, tg)]
  | (_, false), (_, false) -> [] (* Cannot both be an ipv4 and a ipv6 address *)
  | (ip4, true), (ip6, true) -> [(ip4 @ rules, tg); (ip6 @ rules, tg) ] (* Cannot both be an ipv4 and a ipv6 address *)

let emit_chain { Ir.id; rules; comment } =

  let rules =
    List.concat_map ~f:expand_rule rules
    |> List.map ~f:gen_rule
  in
  let premable = chain_premable id in

  [ "#" ^ comment ] @ premable @ rules @ [ "}" ]


let emit_filter_chains (chains : (Ir.chain_id, Ir.chain) Map.Poly.t) : string list =
  (* How does this work. Dont we need a strict ordering of chains here? *)
  let rules =
    Map.Poly.data chains
    |> List.concat_map ~f:emit_chain
  in
  (* Dump zone mapping *)

  Hashtbl.iteri ~f:(fun ~key:zone ~data:id -> printf "#zone %s -> 0x%04x\n" zone id) zones;
  [ "table inet filter {" ] @ rules @ [ "}" ]

let emit_nat_chain rules =
  (* Artificial chain *)
  let chains =
    { Ir.id = Ir.Builtin Ir.Chain_type.Pre_routing; rules=[]; comment = "Nat" } ::
    { Ir.id = Ir.Builtin Ir.Chain_type.Post_routing;rules; comment = "Nat" } ::
    []
  in
  let rules = List.concat_map ~f:emit_chain chains in
  [ "table ip nat {" ] @ rules @ [ "}" ]
