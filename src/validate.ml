(* Function for validating the AST *)
open Base
open Common
module F = Frontend

(** To make sure the graph does not contain any cycles, a list of
    visited nodes (id's) is maintained. The \verb|mark_seen| function
    either lists the cyclic reference or adds the new node to the list
    of visited nodes.
*)
let mark_seen id seen =
  match List.mem ~equal:String.equal seen id with
  | true  -> parse_errorf ~id "Cyclic reference.\nReferenced From: %s" (String.concat ~sep:"," seen)
  | false -> id :: seen

(** Create a map of defines. While creating the map, make sure that no
    defines are shadowed by other defines (defines with the same map,
    the function only adds a new id to the map if the id was not there
    already. If the id was present, a ParseError exception is raised in
    order to stop processing).
*)

(* All positions will be off. We should define equality operations, where we simply ignore lexing positions *)

let equal_data data data' =
  let get_value = function
    | F.Number (v, _) -> `Int v
    | F.Id (id, _) -> `Id id
    | F.Ip (ip, _) -> `Ip ip
    | F.String (s, _) -> `String s
  in
  let data = List.map ~f:get_value data in
  let data' = List.map ~f:get_value data' in
  Poly.equal data data'

let add_id_to_map (id, pos) (def : F.node) map =
  match Map.Poly.find map id, def with
  | Some F.DefineList (_, data), F.DefineList (_, data') when equal_data data data' -> map
  | Some _, _ -> parse_errorf ~pos "Definition redefines previous definition of '%s'" id
  | None, _ -> Map.Poly.add_exn ~key:id ~data:def map

let extend_id_to_map (id, pos) lst map =
  let create = function
    | None -> Some (F.DefineList((id, pos), lst))
    | Some F.DefineList(_, lst') -> Some (F.DefineList((id, pos), lst' @ lst))
    | Some F.Import _
    | Some F.Zone (_,_)
    | Some F.DefineStms (_,_)
    | Some F.AppendList (_,_)
    | Some F.DefinePolicy (_,_)
    | Some F.Process (_,_,_) -> parse_error ~id ~pos "Only list definitions can be extended"
  in
  Map.Poly.change map id ~f:create

let update_define_map id_map = function
  | F.DefineStms (id, _) as def -> add_id_to_map id def id_map
  | F.DefineList (id, _) as def -> add_id_to_map id def id_map
  | F.DefinePolicy (id, _) as def -> add_id_to_map id def id_map
  | F.AppendList (id, lst) -> extend_id_to_map id lst id_map
  | F.Import _
  | F.Process (_,_,_) -> id_map
  | F.Zone (id, zone_stmts) ->
    (** Auto-extend relevant zone aliases *)
    match Zone.get_zone_alias zone_stmts with
    | Some zone_alias ->
      extend_id_to_map (zone_alias, Lexing.dummy_pos) [ F.Id id ] id_map
    | None -> id_map


(** As the recursive version of the fuction needs an accumulator, add
    a function to hide this to users. *)
let create_define_map nodes =
  List.fold ~init:Map.Poly.empty ~f:update_define_map nodes

(** Expand and validation is the same problem, and should be solved as
    such.  We need to have a system that eases the task of describing
    the allowed constructs. *)
let expand nodes =
  (* List of actual zones *)
  let zones = Zone.create_zone_set nodes in

  (* Set of defines *)
  let defines = create_define_map nodes in

  let expand_rules (id, pos) =
    (* Expand single id reference into something semantically
       corect. This allows simple definitions to work as aliases
       for other types of definitions. It is important that the
       function does not resolve the id here, as the system would
       then end up in a infinite loop on recursive aliases (e.g
       \verb|define a = a|. Returning a virtual node allows the
       id to be inserted into the list of visited nodes, and
       cyclic reference dectection will prevent infinite loops,
       and allow error reporting to the users. *)
    match Map.Poly.find_exn defines id with
    | F.DefineList (_, [ F.Id id ]) -> [ F.Reference (id, false) ]
    | F.DefineStms (_, x) -> x
    | F.DefinePolicy (_, _)
    | F.Import _
    | F.Zone (_,_)
    | F.DefineList (_,_)
    | F.AppendList (_,_)
    | F.Process (_,_,_) -> parse_error ~id ~pos "Reference to Id of wrong type"
    | exception _ -> parse_error ~id ~pos "Reference to unknown id"
  in
  let expand (id, pos) =
    match Map.find defines id with
    | Some (F.DefineList (_id', x)) -> x
    | Some _ -> parse_error ~id ~pos "Reference to Id of wrong type"
    | None -> parse_error ~id ~pos "Reference to unknown id"
  in
  let expand_policy (id, pos) =
    match Map.find defines id with
    (* As before; allow simple defines work as aliases. *)
    | Some (F.DefineList (_, [ F.Id id ])) -> [ F.Ref id ]
    | Some (F.DefinePolicy (_id', x)) -> x
    | Some (F.DefineStms (_, _)
           | F.Import _
           | F.Zone (_, _)
           | F.DefineList (_, _)
           | F.AppendList (_, _)
           | F.Process (_, _, _)) -> parse_error ~id ~pos "Reference to Id of wrong type"
    | None -> parse_error ~id ~pos "Reference to unknown id"
  in

  (* As part of expanding the rules, a set of function to expand a
     list into more concreete data (such as list of ints, or list of
     addresses) are defined. *)
  let rec expand_list seen = function
    | F.Id id :: xs -> (expand_list (mark_seen (fst id) seen) (expand id)) @ (expand_list seen xs)
    | x :: xs -> x :: expand_list seen xs
    | [] -> []
  in

  let rec expand_zone_list seen = function
    | (F.Id (id, _)) as x :: xs when Set.mem zones id -> x :: expand_zone_list seen xs
    | F.Id id :: xs -> (expand_zone_list (mark_seen (fst id) seen) (expand id)) @ (expand_zone_list seen xs)
    | F.Number (d, pos) :: _ -> parse_errorf ~pos "Found integer '%d', expected zone name" d
    | F.Ip (_, pos) :: _ -> parse_error ~pos "Found ip address, expected zone name"
    | F.String (s, pos) :: _ -> parse_errorf ~pos "Found string \"%s\", expected zone name" s
    | [] -> []
  in
  let rec expand_policy_list seen = function
    | F.Ref id :: xs -> (expand_policy_list (mark_seen (fst id) seen) (expand_policy id)) @ (expand_policy_list seen xs)
    | x :: xs -> x :: expand_policy_list seen xs
    | [] -> []
  in
  let rec expand_rule_list seen rules =
    let expand_rule = function
      | F.Reference _ -> assert false
      | F.Filter (dir, F.Ports (port_type, ports), pol) -> F.Filter (dir, F.Ports (port_type, expand_list seen ports), pol)
      | F.Filter (dir, F.FZone zones, pol) -> F.Filter (dir, F.FZone (expand_zone_list seen zones), pol)
      | F.Filter (dir, F.Address addr_list, pol) -> F.Filter (dir, F.Address (expand_list seen addr_list), pol)
      | F.Protocol (protos, pol) -> F.Protocol (expand_list seen protos, pol)
      | F.Icmp6 (types, pol) -> F.Icmp6 (expand_list seen types, pol)
      | F.Icmp4 (types, pol) -> F.Icmp4 (expand_list seen types, pol)
      | F.State (states, pol) -> F.State (expand_list seen states, pol)
      | F.Rule (rls, pols) -> F.Rule (expand_rule_list seen rls, expand_policy_list seen pols)
      | F.TcpFlags (flags, mask, pol) -> F.TcpFlags (expand_list seen flags, expand_list seen mask, pol)
      | F.Hoplimit (limits, pol) -> F.Hoplimit (expand_list seen limits, pol)
      | F.True -> F.True
      | F.False -> F.False
      | F.Address_family _ as address_family -> address_family
      | F.Ifgroup (dir, groups, pol) -> F.Ifgroup (dir, expand_list seen groups, pol)
      | F.Ifinterface (dir, interfaces, pol) -> F.Ifgroup (dir, expand_list seen interfaces, pol)
    in
    match rules with
    | F.Reference (id, neg) :: xs ->
        let rules =
          match expand_rules id, neg with
          | x, false -> x
          | [ F.True ], true -> [ F.False ]
          | [ F.False ], true -> [ F.True ]
          | _, true -> parse_error ~pos:(snd id) "Only true / false aliases can be negated"
        in
        (expand_rule_list (mark_seen (fst id) seen) rules ) @ (expand_rule_list seen xs)
    | x :: xs -> expand_rule x :: expand_rule_list seen xs
    | [] -> []
  in

  let expand_network network = expand_list [] network in

  (* When expanding zone definitions, there is no need to carry a
     seen list, as zone stems are not recursive types. *)
  let expand_zone_stm = function
    | F.Interface _ as i -> i
    | F.If_group _ as i -> i
    | F.Network l  -> F.Network (expand_network l)
    | F.ZoneSnat _ as i -> i
    | F.ZoneRules (t, rules, policies)  ->
        F.ZoneRules (t, expand_rule_list [] rules, expand_policy_list [] policies)
  in
  let expand_nodes = function
    | F.DefineStms (_, _)
    | F.DefineList (_, _)
    | F.AppendList (_, _)
    | F.DefinePolicy (_, _) ->
      None
    | F.Process (t, rules, policies) ->
      F.Process (t, expand_rule_list [] rules, expand_policy_list [] policies)
      |> Option.some
    | F.Import _ -> failwith "Internal error: Import statement not expanded correctly"
    | F.Zone (id, zone_stms) ->
      let zone_stmts = List.map ~f:expand_zone_stm zone_stms in
      let additional_networks_aliases = Zone.get_extra_network_aliases zone_stmts in
      let aliases : F.data list = List.map ~f:(fun id -> F.Id (id, Lexing.dummy_pos)) additional_networks_aliases in
      let network = F.Network (expand_network aliases) in
      F.Zone(id, network :: zone_stmts)
      |> Option.some
  in
  List.filter_map ~f:expand_nodes nodes
