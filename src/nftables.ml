(**
   Output a nft script.
*)

open Base
open Stdio
open Printf
module Ip6Set = Ipset.Ip6Set
module Ip4Set = Ipset.Ip4Set

let zone_bits = 8 (* Number of zones *)
let zone_mask = 1 lsl zone_bits - 1

let zones = Hashtbl.Poly.create ~size:100 ()

let sets = ref []
let create_set ipv4 ipv6 =
  let set_id = match !sets with
    | [] -> 0
    | (id, _, _, _) :: _ -> id + 1
  in
  let set_name = sprintf "bl_set_%d" set_id in
  sets := (set_id, set_name, ipv4, ipv6) :: !sets;
  set_name

(* create set is currently not in use *)
let () = ignore create_set

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
  | Ir.Chain_id.Builtin Ir.Chain_type.Input -> "input"
  | Ir.Chain_id.Builtin Ir.Chain_type.Output -> "output"
  | Ir.Chain_id.Builtin Ir.Chain_type.Forward  -> "forward"
  | Ir.Chain_id.Builtin Ir.Chain_type.Pre_routing  -> "prerouting"
  | Ir.Chain_id.Builtin Ir.Chain_type.Post_routing  -> "postrouting"
  | Ir.Chain_id.Named name -> name

let chain_premable chain comment =
  let name = chain_name chain in
  match chain with
  | Ir.Chain_id.Builtin Ir.Chain_type.Pre_routing
  | Builtin Ir.Chain_type.Post_routing ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
      sprintf "  type nat hook %s priority srcnat;" name;
      sprintf "  policy accept;" ]
  | Builtin Ir.Chain_type.Input
  | Builtin Ir.Chain_type.Output
  | Builtin Ir.Chain_type.Forward ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
      sprintf "  type filter hook %s priority filter;" name;
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
  | Ir.Tcp_flags.Ecn -> "ecn"
  | Ir.Tcp_flags.Cwr -> "cwr"

let string_of_state state = match state with
  | State.New -> "new"
  | State.Established -> "established"
  | State.Related -> "related"
  | State.Invalid -> "invalid"
  | State.Untracked -> "untracked"

let string_of_int_set s =
  Set.fold ~init:[] ~f:(fun acc e -> Int.to_string e :: acc) s
  |> String.concat ~sep:", "

let string_or_int_set s =
  Set.fold ~init:[] ~f:(fun acc -> function
    | `Int i -> Int.to_string i :: acc
    | `String s -> Printf.sprintf "\"%s\"" s :: acc) s
  |> String.concat ~sep:", "

let gen_pred neg pred =
  let neg_str = match neg with
    | true -> "!= "
    | false -> ""
  in

  let gen_ipset_filter: type t. (module Ipset.IpSet with type t = t) -> string -> Ir.Direction.t -> t -> bool -> string =
    fun (module IpSet) tpe dir ipset neg ->
      let classifier = match dir with
        | Ir.Direction.Source -> "saddr"
        | Ir.Direction.Destination  -> "daddr"
      in
      let classifier = sprintf "%s %s" tpe classifier in

      let string_of_list l =
        List.map ~f:IpSet.ip_to_string l
        |> String.concat ~sep:", "
      in
      let rec gen_filter (ipset, neg) =
        match IpSet.to_networks ipset with
        | incls, [] ->
          sprintf "%s %s{ %s }" classifier neg_str (string_of_list incls)
        | [incl], excl when neg && IpSet.is_any incl ->
          (* Exclude everything except excl *)
          sprintf "%s { %s }" classifier (string_of_list excl)
        | _, _ when neg ->
          gen_filter (IpSet.diff IpSet.any ipset, false)
        | incl, excl (* when not neg *) ->
          let incl = string_of_list incl in
          let excl = string_of_list excl in
          sprintf "%s { %s } %s != { %s }" classifier incl classifier excl
      in
      gen_filter (ipset, neg)
  in
  match pred with
  | Ir.Interface (dir, interfaces) ->
    let interfaces = Set.to_list interfaces |> List.map ~f:(sprintf "\"%s\"") |> String.concat ~sep:", " in
    let classifier = match dir with
      | Ir.Direction.Source -> "iifname"
      | Ir.Direction.Destination -> "oifname"
    in
    sprintf "%s%s { %s }" classifier neg_str interfaces, None
  | Ir.If_group (dir, if_groups) ->
    let if_groups = string_or_int_set if_groups in
    let classifier = match dir with
      | Ir.Direction.Source -> "iifgroup"
      | Ir.Direction.Destination -> "oifgroup"
    in
    sprintf "%s%s { %s }" classifier neg_str if_groups, None
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
    let pred = match dir with
      | Ir.Direction.Source -> "sport"
      | Ir.Direction.Destination -> "dport"
    in
    let classifier = match port_type with
      | Ir.Port_type.Tcp -> "tcp"
      | Ir.Port_type.Udp -> "udp"
    in
    sprintf "%s %s %s{ %s }" classifier pred neg_str (string_of_int_set ports), None
  | Ir.Ip6Set (dir, ips) ->
    gen_ipset_filter (module Ip6Set) "ip6" dir ips neg, None
  | Ir.Ip4Set (dir, ips) ->
    gen_ipset_filter (module Ip4Set) "ip" dir ips neg, None
  | Ir.Protocol p ->
    let set = Set.to_list p |> List.map ~f:Int.to_string |> String.concat ~sep:"," in
    sprintf "meta l4proto %s{ %s }" neg_str set, None
  | Ir.Icmp6 types ->
    let set = string_of_int_set types in
    sprintf "icmpv6 type %s{ %s }" neg_str set, None
  | Ir.Icmp4 types ->
    let set = string_of_int_set types in
    sprintf "icmp type %s{ %s }" neg_str set, None
  | Ir.Mark (value, mask) ->
    sprintf "meta mark and 0x%08x %s0x%08x" mask neg_str value, None
  | Ir.TcpFlags (flags, mask) ->
    let to_list f = Set.to_list f
                    |> List.map ~f:string_of_tcpflag
                    |> String.concat ~sep:"|"
    in
    let neg_str = match neg with true -> "!=" | false -> "==" in
    sprintf "tcp flags & (%s) %s %s" (to_list mask) neg_str (to_list flags), None
  | Ir.Hoplimit limits -> (* Hop limit implies ipv6 *)
    let rule =
      string_of_int_set limits
      |> sprintf "ip6 hoplimit %s{ %s }" neg_str
    in rule, None
  | Ir.Address_family a ->
    let proto_to_string = function
      | Ir.Ipv4 -> "ipv4"
      | Ir.Ipv6 -> "ipv6"
    in
    let set =
      Set.to_list a
      |> List.map ~f:proto_to_string
      |> String.concat ~sep:","
      |> sprintf "{ %s }"
    in
    sprintf "meta nfproto %s%s" neg_str set, None
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
  | Ir.Comment _ -> failwith "Illegal comment at this point. Comments must be added to the end of the rule"
  | Ir.Notrack -> ""
  | Ir.Log prefix -> sprintf "log prefix \"%s: \" level info" prefix
  | Ir.Snat (Some ip) -> sprintf "snat ip to %s" (Ipaddr.V4.to_string ip)
  | Ir.Snat None -> sprintf "masquerade"

let gen_target = function
  | Ir.Accept -> "accept"
  | Ir.Drop -> "drop"
  | Ir.Return -> "return"
  | Ir.Jump chain -> sprintf "jump %s" (chain_name chain)
  | Ir.Reject rsp -> reject_to_string rsp
  | Ir.Pass -> ""

let gen_rule = function
  | ([], [], Ir.Pass) -> "# Empty rule"
  | (preds, effects, target) ->
    let preds, comments =
      let preds, comments =
        List.map ~f:(fun (op, neg) -> gen_pred neg op) preds
        |> List.unzip
      in
      let comments = List.filter_opt comments in
      preds, comments
    in
    let comments', effects = List.partition_map ~f:(function Ir.Comment c -> Either.First c | effect_ -> Either.Second effect_ ) effects in
    (* Need to filter out comments, and place them at the end *)
    let comment_string =
      match comments @ comments' |> List.stable_dedup ~compare:String.compare with
      | [] -> ""
      | comments -> sprintf "comment \"%s\"" (String.concat ~sep:" && " comments)
    in
    let effects = List.map ~f:gen_effect effects in
    let target = gen_target target in
    let elements = preds @ effects @ [target] @ [comment_string] |> List.filter ~f:(fun s -> not (String.is_empty s)) in
    sprintf "%s;" (String.concat ~sep:" " elements)

(* Essentially we dont split at all *)
let expand_rule (rls, effects, target) =

  let rec split (rules, (ip4, neg4), (ip6, neg6)) = function
    | (Ir.Ip4Set _, n) as r :: xs -> split (rules, (r :: ip4, neg4 && n), (ip6, neg6)) xs
    | (Ir.Ip6Set _, n) as r :: xs -> split (rules, (ip4, neg4), (r :: ip6, neg6 && n)) xs
    | r :: xs -> split (r :: rules, (ip4, neg4), (ip6, neg6)) xs
    | [] -> (List.rev rules, (List.rev ip4, neg4), (List.rev ip6, neg6))
  in
  let (rules, (ip4, neg4), (ip6, neg6)) = split ([], ([], true), ([], true)) rls in

  match (ip4, neg4), (ip6, neg6) with
  | ([], _), ([], _) -> [(rls, effects, target)]
  | (ip4, _), ([], _) ->
    [(ip4 @ rules, effects, target)];
  | ([], _), (ip6, _) -> (* Must be ipv4 and not some ipv6 *)
    [(ip6 @ rules, effects, target)]
  | (_, _), (_, _) -> [] (* Cannot be both ipv4 and ipv6 address family *)

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

let rec pp_rules ?(acc = []) ?(indent = "") ?(indent_level = "    ")= function
  | [] -> List.rev acc
  | line :: lines ->
    let line = String.strip line in
    let line = match String.chop_suffix ~suffix:";" line with
      | Some line -> (String.strip line) ^ ";"
      | None -> line
    in
    let line, indent = match line.[String.length line - 1] with
      | '{' -> indent ^ line, indent_level ^ indent
      | '}' ->
        let indent = String.chop_prefix_if_exists ~prefix:indent_level indent in
        indent ^ line, indent
      | _ -> indent ^ line, indent
    in
    pp_rules ~acc:(line :: acc) ~indent ~indent_level lines

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
  "  }" :: rules @
  [ "}" ]
  |> pp_rules
