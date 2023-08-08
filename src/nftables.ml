(**
   Output a nft script.
*)

open Base
open Stdio
open Printf
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

let zone_bits = 8 (* Number of zones *)
let zone_mask = 1 lsl zone_bits - 1

let zones = Hashtbl.Poly.create ~size:100 ()

let get_zone_id zone =
  match Hashtbl.find zones zone with
  | Some id -> id
  | None ->
    let id = 1 lsl (Hashtbl.length zones) in
    Hashtbl.add_exn ~key:zone ~data:id zones;
    id

(* Mars has zone id 1 *)
let (_: int) = get_zone_id Zone.mars

let chain_name = function
  | Ir.Chain_id.Temporary n -> sprintf "temp_%d" n
  | Builtin Ir.Chain_type.Input -> "input"
  | Builtin Ir.Chain_type.Output -> "output"
  | Builtin Ir.Chain_type.Forward  -> "forward"
  | Builtin Ir.Chain_type.Pre_routing  -> "prerouting"
  | Builtin Ir.Chain_type.Post_routing  -> "postrouting"
  | Named name -> name

(* TODO Use chain_name *)
let chain_premable chain comment =
  let name = chain_name chain in
  match chain with
  | Ir.Chain_id.Builtin Ir.Chain_type.Pre_routing
  | Builtin Ir.Chain_type.Post_routing ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
      sprintf "  type nat hook %s priority 0;" name;
      sprintf "  policy accept;" ]
  | Builtin Ir.Chain_type.Input
  | Builtin Ir.Chain_type.Output
  | Builtin Ir.Chain_type.Forward ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
      sprintf "  type filter hook %s priority 0;" name;
      sprintf "  policy drop;" ]
  | Temporary _
  | Named _ ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
    ]

let string_of_tcpflag = function
  | Ir.Tcp_flags.Syn -> "syn"
  | Ir.Tcp_flags.Ack -> "ack"
  | Ir.Tcp_flags.Fin -> "fin"
  | Ir.Tcp_flags.Rst -> "rst"
  | Ir.Tcp_flags.Urg -> "urg"
  | Ir.Tcp_flags.Psh -> "psh"

let string_of_layer = function
  | Ir.Ipv4 -> "ip"
  | Ir.Ipv6 -> "ip6"

let string_of_protocol l = l

let string_of_state state = match state with
  | State.New -> "new"
  | State.Established -> "established"
  | State.Related -> "related"
  | State.Invalid -> "invalid"

let string_of_int_set s =
  Set.fold ~init:[] ~f:(fun acc e -> Int.to_string e :: acc) s
  |> String.concat ~sep:", "

let string_or_int_set s =
  Set.fold ~init:[] ~f:(fun acc -> function
    | `Int i -> Int.to_string i :: acc
    | `String s -> Printf.sprintf "\"%s\"" s :: acc) s
  |> String.concat ~sep:", "

let gen_cond neg cond =
  let neg_str = match neg with
    | true -> "!= "
    | false -> ""
  in
  match cond with
  | Ir.Interface (dir, interfaces) ->
      let interfaces = Set.to_list interfaces |> List.map ~f:(sprintf "\"%s\"") |> String.concat ~sep:", " in
      let classifier = match dir with
        | Ir.Direction.Source -> "iif"
        | Ir.Direction.Destination -> "oif"
      in
      sprintf "%s %s { %s }" classifier neg_str interfaces, None
  | Ir.If_group (dir, if_groups) ->
    let if_groups = string_or_int_set if_groups in
      let classifier = match dir with
        | Ir.Direction.Source -> "iifgroup"
        | Ir.Direction.Destination -> "oifgroup"
      in
      sprintf "%s %s { %s }" classifier neg_str if_groups, None
  | Ir.Zone (dir, zones) ->
      let shift = match dir with
        | Ir.Direction.Source -> 0
        | Ir.Direction.Destination -> zone_bits
      in
      let mask = Set.fold ~f:(fun acc zone ->
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
        let zones = Set.to_list zones |> String.concat ~sep:"; " in
        sprintf "%s%s zone in [ %s ]" neg dir zones
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
      sprintf "%s %s%s { %s }" classifier neg_str cond (string_of_int_set ports), None
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
  | Ir.Protocol p ->
      let set = Set.to_list p |> List.map ~f:Int.to_string |> String.concat ~sep:"," in
      sprintf "meta l4proto %s { %s }" neg_str set, None
  | Ir.Icmp6 types ->
      let set = string_of_int_set types in
      sprintf "icmpv6 type %s { %s }" neg_str set, None
  | Ir.Icmp4 types ->
    let set = string_of_int_set types in
    sprintf "icmp type %s { %s }" neg_str set, None
  | Ir.Mark (value, mask) ->
      sprintf "meta mark and 0x%08x %s0x%08x" mask neg_str value, None
  | Ir.TcpFlags (flags, mask) ->
      let to_list f = Set.to_list f
                      |> List.map ~f:string_of_tcpflag
                      |> String.concat ~sep:"|"
      in
      let neg_str = match neg with true -> "!=" | false -> "==" in
      sprintf "tcp flags & (%s) %s %s" (to_list mask) neg_str (to_list flags), None
  | Ir.Hoplimit limits ->
    let rule =
      string_of_int_set limits
      |> sprintf "ip6 hoplimit %s{ %s }" neg_str
    in rule, None
  | Ir.Address_family a ->
    let proto = match Set.to_list a with
      | [Ir.Ipv4] when not neg -> "ip"
      | [Ir.Ipv6] when neg -> "ip"
      | [Ir.Ipv6] when not neg -> "ip6"
      | [Ir.Ipv4] when neg -> "ip6"
      | _ -> failwith "Address family must be either ipv4 or ipv6"
    in
    sprintf "meta protocol %s" proto, None
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

let gen_effect = function
  | Ir.MarkZone (dir, id) ->
      let shift = match dir with
        | Ir.Direction.Source -> 0
        | Ir.Direction.Destination -> zone_bits
      in
      let mask = zone_mask lsl (zone_bits - shift) in
      sprintf "meta mark set mark & 0x%08x or 0x%08x" mask ((get_zone_id id) lsl shift)
  | Ir.Counter -> "counter"
  | Ir.Notrack -> ""
  | Ir.Log prefix -> sprintf "log prefix \"%s: \" level info" prefix
  | Ir.Snat ip -> sprintf "snat ip to %s" (Ipaddr.V4.to_string ip)

let gen_target = function
  | Ir.Accept -> "accept"
  | Ir.Drop -> "drop"
  | Ir.Return -> "return"
  | Ir.Jump chain -> sprintf "jump %s" (chain_name chain)
  | Ir.Reject rsp -> reject_to_string rsp
  | Ir.Pass -> ""

let gen_rule = function
  | ([], [], Ir.Pass) -> "# Empty rule"
  | (conds, effects, target) ->
      let conds, comments =
        let conds, comments =
          List.map ~f:(fun (op, neg) -> gen_cond neg op) conds
          |> List.unzip
        in
        let comments =
          List.filter_map ~f:Fn.id comments
          |> function [] -> ""
                    | cs -> String.concat ~sep:" " cs
                            |> sprintf "comment \"%s\""
        in
        String.concat ~sep:" " conds, comments
      in
      let effects = List.map ~f:gen_effect effects |> String.concat ~sep:" " in
      let target = gen_target target in
      sprintf "%s %s %s %s;" conds effects target comments

let expand_rule (rls, effects, target) =
  let rec split (rules, (ip4, neg4), (ip6, neg6)) = function
    | (Ir.Ip4Set _, n) as r :: xs -> split (rules, (r :: ip4, neg4 && n), (ip6, neg6)) xs
    | (Ir.Ip6Set _, n) as r :: xs -> split (rules, (ip4, neg4), (r :: ip6, neg6 && n)) xs
    | r :: xs -> split (r :: rules, (ip4, neg4), (ip6, neg6)) xs
    | [] -> (List.rev rules, (List.rev ip4, neg4), (List.rev ip6, neg6))
  in
  let (rules, (ip4, neg4), (ip6, neg6)) = split ([], ([], true), ([], true)) rls in

  match (ip4, neg4), (ip6, neg6) with
  | ([], _), _
  | _, ([], _) -> [(rls, effects, target)]
  | (_, true), (ip6, false) -> [(ip6 @ rules, effects, target)] (* Slight optimization *)
  | (ip4, false), (_, true) -> [(ip4 @ rules, effects, target)]
  | (_, false), (_, false) -> [] (* Cannot both be an ipv4 and a ipv6 address *)
  | (ip4, true), (ip6, true) -> [(ip4 @ rules, effects, target);
                                 (ip6 @ rules, effects, target) ] (* Cannot both be an ipv4 and a ipv6 address *)

let emit_chain { Ir.id; rules; comment } =

  let rules =
    List.concat_map ~f:expand_rule rules
    |> List.map ~f:gen_rule
  in
  let premable = chain_premable id comment in
  premable @ rules @ [ "}" ]


let emit_filter_rules (chains : (Ir.Chain_id.t, Ir.chain, 'a) Map.t) : string list =
  let rules =
    Map.data chains
    |> List.concat_map ~f:emit_chain
  in
  (* Dump zone mapping *)
  Hashtbl.iteri ~f:(fun ~key:zone ~data:id -> printf "#zone %s -> 0x%04x\n" zone id) zones;
  rules

let emit_nat_rules rules =
    { Ir.id = Ir.Chain_id.Builtin Ir.Chain_type.Post_routing; rules; comment = "Nat" }
  |> emit_chain

let emit rules =
  let zones =
    Hashtbl.to_alist zones
    |> List.sort ~compare:(fun (_, id) (_, id') -> Int.compare id id')
    |> List.map ~f:(fun (zone, id) ->
      sprintf "   iifname \"%s\" meta mark 0x%04x comment \"Zone %s\"" zone id zone)
  in
  "table inet borderline {" ::
  "  chain zones { " ::
  "    comment \"zone ids\"" :: zones @
  ["  }"] @
  rules @
  [ "}" ]
