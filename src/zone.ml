open Core
open Common
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4
module F = Frontend


(** Predefined zones. *)

(** The self zone is the machine it self. *)
let self = "self"

(** The martian zone. Networks packets that have no zone are declared
    martian, which is identified by this build in zone *)
let mars = "mars"

(** Reference to all zone chains. This build in rule traverses all
    zone rules *)
let all_zones = "zones"

(** List of build in zones. *)
let buildin_zones = [ mars ]

type t = {
  interfaces: F.data list;
  groups: F.data list;
  networks: F.data list;
  vlans: F.data list;
}

let init stms =
  let inner acc = function
    | F.Interface ifs -> { acc with interfaces = ifs @ acc.interfaces }
    | F.If_group groups -> { acc with groups = groups @ acc.groups }
    | F.Network ips -> { acc with networks = ips @ acc.networks }
    | F.Vlan ids -> { acc with vlans = ids @ acc.vlans }
    | F.ZoneRules _ -> acc
    | F.ZoneSnat _ -> acc
  in
  List.fold_left ~init:{ interfaces = []; groups = []; networks = []; vlans = [] } ~f:inner stms

let rec filter_zonerules table = function
  | F.ZoneRules (t, r, p) :: xs when Poly.((fst t) = (fst table)) -> (r, p) :: filter_zonerules table xs
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
                | F.Number (_, pos) -> parse_error ~pos "Expected ip address, got number"
                | F.Id (_, pos) -> parse_error ~pos "Expected ip address, got id"
                | F.String (_, pos) -> parse_error ~pos "Expected ip address, got string"
              ) ~init:([], []) ips
        in
        [ ([(Ir.Ip6Set(direction, Ip6.of_list ip6), false)], [], Ir.Jump chain.Ir.id);
          ([(Ir.Ip4Set(direction, Ip4.of_list ip4), false)], [], Ir.Jump chain.Ir.id) ]

  in
  let create_interface_rule chain interfaces =
    let cond = match interfaces with
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
          [(Ir.Interface(direction, Set.Poly.of_list ifaces), false)]
    in
    [ (cond, [], Ir.Jump chain.Ir.id) ]
  in
  let create_group_rule chain if_groups =
    let cond = match if_groups with
      | [] -> []
      | gs ->
          let if_groups =
            List.map ~f:(function
              | F.Ip (_, pos) -> parse_error ~pos "Expected number, got ip"
              | F.Number (n, _pos) -> n
              | F.Id (_, pos) -> parse_error ~pos "Expected number, got id"
              | F.String (_, pos) -> parse_error ~pos "Expected number, got string"
            ) gs
          in
          [(Ir.If_group(direction, Set.Poly.of_list if_groups), false)]
    in
    [ (cond, [], Ir.Jump chain.Ir.id) ]
  in
  let create_vlan_rule chain vlans =
    let cond = match vlans with
      | [] -> []
      | vs ->
          let ids = List.map ~f:(function
              | F.Ip (_, pos) -> parse_error ~pos "Expected number, got ip"
              | F.Number (n, _pos) -> n
              | F.Id (_, pos) -> parse_error ~pos "Expected number, got id"
              | F.String (_, pos) -> parse_error ~pos "Expected number, got string"
            ) vs
          in
          [(Ir.Vlan(Set.Poly.of_list ids), false)]
    in
    [ (cond, [], Ir.Jump chain.Ir.id) ]
  in
  let { networks; interfaces; groups; vlans; } = init nodes in
  Chain.create [([], [Ir.MarkZone(direction, id)], Ir.Pass)] ("Mark zone " ^ id)
  |> (fun c -> Chain.create (create_network_rules c networks) ("Match networks for zone " ^ id))
  |> (fun c -> Chain.create (create_interface_rule c interfaces) ("Match interfaces for zone " ^ id))
  |> (fun c -> Chain.create (create_vlan_rule c vlans) ("Match vlans for zone " ^ id))
  |> (fun c -> Chain.create (create_group_rule c groups) ("Match vlans for zone " ^ id))


let rec filter = function
  | F.Zone(id, nodes) :: xs -> (id, nodes) :: filter xs
  | _ :: xs -> filter xs
  | [] -> []

(** Utility function to create an set of zone id's *)
let create_zone_set nodes =
  let rec traverse acc = function
    | F.Zone ((id, _pos), _) :: xs -> traverse (Set.Poly.add acc id) xs
    | _ :: xs -> traverse acc xs
    | [] -> acc
  in traverse (Set.Poly.of_list buildin_zones) nodes

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
  let src_chain = Chain.create (([], [Ir.MarkZone(Ir.Direction.Source, mars)], Ir.Pass) :: (List.map ~f:(fun chn -> ([], [], Ir.Jump chn.Ir.id)) src_chains)) "Mark source zones" in
  let dst_chain = Chain.create (([], [Ir.MarkZone(Ir.Direction.Destination, mars)], Ir.Pass) :: (List.map ~f:(fun chn -> ([], [], Ir.Jump chn.Ir.id)) dst_chains)) "Mark destination zones" in
  let input_opers =   [ ([], [Ir.MarkZone (Ir.Direction.Destination, self)], Ir.Jump src_chain.Ir.id) ] in
  let output_opers =  [ ([], [Ir.MarkZone (Ir.Direction.Source, self)],      Ir.Jump dst_chain.Ir.id) ] in
  let forward_opers = [ ([], [], Ir.Jump src_chain.Ir.id);
                        ([], [], Ir.Jump dst_chain.Ir.id) ] in
  (input_opers, output_opers, forward_opers)

let emit_nat (zones : (string * F.zone_stm list) list) : Ir.oper list =
  let gen (zone : string) = function
    | F.ZoneSnat (src_zones, ip) ->
        if (Ipaddr.V4.Prefix.bits ip < 32) then (parse_error "Snat not not work with network ranges");
        ((Ir.Zone (Ir.Direction.Source, Rule.list2ids src_zones |> List.map ~f:fst |> Set.Poly.of_list), false) ::
         (Ir.Zone (Ir.Direction.Destination, zone |> Set.Poly.singleton), false) :: [],
         [Ir.Snat (Ipaddr.V4.Prefix.network ip)],
         Ir.Pass) |> Option.some
    | F.Interface _
    | F.If_group _
    | F.Network _
    | F.Vlan _
    | F.ZoneRules _ -> None
  in

  List.concat_map ~f:(fun (zone, stms) -> List.filter_map ~f:(gen zone) stms) zones
