open! Base
open! Stdio
module Set = Set.Poly
open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4
module F = Frontend


(** Predefined zones. *)

(** The self zone is the machine it self. *)
let self = "self"

(** loopback interface to identify self zone *)
let loopback = "lo"

(** The martian zone. Networks packets that have no zone are declared
    martian, which is identified by this build in zone *)
let mars = "mars"

(** Reference to all zone chains. This build in rule traverses all
    zone rules *)
let all_zones = "zones"

(** List of built in zones. *)
let builtin_zones = [ mars ]

(* Aliases to which zones are added *)
let global_zone_alias = "global_zones"
let local_zone_alias = "local_zones"

(* Networks automatically added to network definitions *)
let ipv4_global_networks = "ipv4_global_networks"
let ipv6_global_networks = "ipv6_global_networks"
let ipv4_local_networks  = "ipv4_local_networks"
let ipv6_local_networks  = "ipv6_local_networks"

type t = {
  interfaces: F.data list;
  groups: F.data list;
  networks: F.data list;
}

let init stms =
  let inner acc = function
    | F.Interface ifs -> { acc with interfaces = ifs @ acc.interfaces }
    | F.If_group groups -> { acc with groups = groups @ acc.groups }
    | F.Network ips -> { acc with networks = ips @ acc.networks }
    | F.ZoneRules _ -> acc
    | F.ZoneSnat _ -> acc
  in
  List.fold_left ~init:{ interfaces = []; groups = []; networks = []; } ~f:inner stms

let is_loopback zone_stmts =
  List.exists ~f:(function
    | F.Interface [F.Id (iface, _)] -> String.Caseless.equal iface loopback
    | F.Interface [F.String (iface, _)] -> String.Caseless.equal iface loopback
    | _ -> false
  ) zone_stmts

(** Get the zone alias to add to *)
let get_zone_alias zone_stmts =
  match is_loopback zone_stmts with
  | true -> None
  | false ->
    match List.exists ~f:(function F.Network _ -> true | _ -> false) zone_stmts with
    | true -> Some local_zone_alias
    | false -> Some global_zone_alias

(** Get the aliases to include for the zone *)
let get_extra_network_aliases zone_stmts =
  let get_networks zone_stmts =
    List.fold ~init:(false, false) ~f:(fun acc -> function
      | F.Network networks ->
        List.fold ~init:acc ~f:(fun (has_ipv4, has_ipv6) -> function
          | F.Ip (F.Ipv4 _, _)-> (true, has_ipv6)
          | F.Ip (F.Ipv6 _, _)-> (has_ipv4, true)
          | _ -> (has_ipv4, has_ipv6)
        ) networks
      | _ -> acc
    ) zone_stmts
  in
  match is_loopback zone_stmts with
  | true -> []
  | false -> match get_networks zone_stmts with
    | (true, true)   -> [ ipv4_local_networks; ipv6_local_networks ]
    | (true, false)  -> [ ipv4_local_networks ]
    | (false, true)  -> [ ipv6_local_networks ]
    | (false, false) -> [ ipv4_global_networks; ipv6_global_networks ]


let rec filter_zonerules table = function
  | F.ZoneRules (t, r, p) :: xs when String.((fst t) = (fst table)) -> (r, p) :: filter_zonerules table xs
  | _ :: xs -> filter_zonerules table xs
  | [] -> []

(** Return a chain that will mark the zone based on direction *)
let create_zone_chain direction (id, nodes) =
  let create_network_rules chain = function
    | [] -> [ ([], [], Ir.Jump chain.Ir.id) ]
    | ips ->
        let (ip4, ip6) =
          List.fold_left
            ~f:(fun (ip4, ip6) -> function
                | F.Ip (F.Ipv4 i, _) -> ( i :: ip4, ip6)
                | F.Ip (F.Ipv6 i, _) -> (ip4, i :: ip6)
                | F.Number (i, pos) -> parse_errorf ~pos "Expected ip address, got number '%d'" i
                | F.Id (id, pos) -> parse_errorf ~pos "Expected ip address, got un-expanded id: %s" id
                | F.String (s, pos) -> parse_errorf ~pos "Expected ip address, got string '%s'" s
              ) ~init:([], []) ips
        in
        let ip4_rule =
          Option.some_if (List.is_empty ip4 |> not)
            ([(Ir.Ip4Set(direction, Ip4.of_list ip4), false)], [], Ir.Jump chain.Ir.id)
        in
        let ip6_rule =
          Option.some_if (List.is_empty ip6 |> not)
            ([(Ir.Ip6Set(direction, Ip6.of_list ip6), false)], [], Ir.Jump chain.Ir.id)
        in
        [ip4_rule; ip6_rule] |> List.filter_opt

  in
  let create_interface_rule chain interfaces =
    let pred = match interfaces with
      | [] -> []
      | is ->
          let ifaces =
            List.map ~f:(function
                | F.Ip (_, pos) -> parse_error ~pos "Expected string, got ip"
                | F.Number (_, pos) -> parse_error ~pos "Expected string, got number"
                | F.Id (s, _pos)
                | F.String (s, _pos) -> s
              ) is
          in
          [(Ir.Interface(direction, Set.of_list ifaces), false)]
    in
    [ (pred, [], Ir.Jump chain.Ir.id) ]
  in
  let create_group_rule chain if_groups =
    let pred = match if_groups with
      | [] -> []
      | gs ->
          let if_groups =
            List.map ~f:(function
              | F.Ip (_, pos) -> parse_error ~pos "Expected number, got ip"
              | F.Number (n, _pos) -> `Int n
              | F.Id (_, pos) -> parse_error ~pos "Expected number, got id"
              | F.String (s, _pos) -> `String s
            ) gs
          in
          [(Ir.If_group(direction, Set.of_list if_groups), false)]
    in
    [ (pred, [], Ir.Jump chain.Ir.id) ]
  in
  let { networks; interfaces; groups; } = init nodes in
  let comment =
    Printf.sprintf "Mark %s zone: %s" (Ir.Direction.to_string direction) id
  in
  Chain.create [([], [Ir.MarkZone(direction, id); Ir.Comment comment], Ir.Pass)] ("Mark zone " ^ id)
  |> (fun c -> Chain.create (create_network_rules c networks) ("Match networks for zone " ^ id))
  |> (fun c -> Chain.create (create_interface_rule c interfaces) ("Match interfaces for zone " ^ id))
  |> (fun c -> Chain.create (create_group_rule c groups) ("Match interface groups for zone " ^ id))


let rec filter = function
  | F.Zone(id, nodes) :: xs -> (id, nodes) :: filter xs
  | _ :: xs -> filter xs
  | [] -> []

(** Utility function to create an set of zone id's *)
let create_zone_set nodes =
  let rec traverse acc = function
    | F.Zone ((id, _pos), _) :: xs -> traverse (Set.add acc id) xs
    | _ :: xs -> traverse acc xs
    | [] -> acc
  in traverse (Set.of_list builtin_zones) nodes

(** Emit autogenerated nodes to be inserted in the stream of frontent nodes. *)
let emit_nodes table zones =
  let gen_rule_stems (zone_id, nodes) =
    let zonerules = filter_zonerules table nodes in
    List.map ~f:(
      fun (rules, policy) ->
        F.Rule( F.Filter(("destination", Lexing.dummy_pos),
                         F.FZone([F.Id zone_id]), false) :: rules, policy )
    ) zonerules
  in
  let rules = List.concat_map ~f:gen_rule_stems zones in
  F.DefineStms ((all_zones, Lexing.dummy_pos), rules)

let emit_filter zones =
  let src_chains = List.map ~f:(create_zone_chain Ir.Direction.Source) zones in
  let dst_chains = List.map ~f:(create_zone_chain Ir.Direction.Destination) zones in
  let src_chain =
    Chain.create (([], [Ir.MarkZone(Ir.Direction.Source, mars); Ir.Comment "Mark source zone: Mars"], Ir.Pass)
                  :: (List.map ~f:(fun chn -> ([], [], Ir.Jump chn.Ir.id)) src_chains)) "Mark source zones" in
  let dst_chain =
    Chain.create (([], [Ir.MarkZone(Ir.Direction.Destination, mars); Ir.Comment "Mark destination zone: Mars"], Ir.Pass) ::
                  (List.map ~f:(fun chn -> ([], [], Ir.Jump chn.Ir.id)) dst_chains)) "Mark destination zones" in

  let input_opers =   [ ([], [Ir.MarkZone (Ir.Direction.Destination, self)], Ir.Jump src_chain.Ir.id) ] in
  let output_opers =  [ ([], [Ir.MarkZone (Ir.Direction.Source, self)],      Ir.Jump dst_chain.Ir.id) ] in
  let forward_opers = [ ([], [], Ir.Jump src_chain.Ir.id);
                        ([], [], Ir.Jump dst_chain.Ir.id) ] in
  (input_opers, output_opers, forward_opers)

let emit_nat (zones : (string * F.zone_stm list) list) : Ir.rule list =
  let gen (zone : string) = function
    | F.ZoneSnat (src_zones, ip) ->
      let () = match ip with
        | Some ip when Ipaddr.V4.Prefix.bits ip < 32 -> parse_error "Snat not not work with network ranges"
        | _ -> ()
      in
      ((Ir.Zone (Ir.Direction.Source, Rule.list2ids src_zones |> List.map ~f:fst |> Set.of_list), false) ::
       (Ir.Zone (Ir.Direction.Destination, zone |> Set.singleton), false) :: [],
       [Ir.Snat (Option.map ~f:Ipaddr.V4.Prefix.network ip)],
       Ir.Pass) |> Option.some
    | F.Interface _
    | F.If_group _
    | F.Network _
    | F.ZoneRules _ -> None
  in

  List.concat_map ~f:(fun (zone, stms) -> List.filter_map ~f:(gen zone) stms) zones
