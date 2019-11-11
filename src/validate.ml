(* Function for validating the AST *)
open Core

open Common
module F = Frontend


(** To make sure the graph does not contain any cycles, a list of
    visited nodes (id's) is maintained. The \verb|mark_seen| function
    either lists the cyclic reference or adds the new node to the list
    of visited nodes.
*)
let mark_seen id seen =
  match List.mem ~equal:String.equal seen id with
  | true  -> parse_error ~id  ( "Cyclic reference.\nReferenced From: " ^ (String.concat ~sep:"," seen))
  | false -> id :: seen

(** Create a map of defines. While creating the map, make sure that no
    defines are shadowed by other defines (defines with the same map,
    the function only adds a new id to the map if the id was not there
    already. If the id was present, a ParseError exception is raised in
    order to stop processing).
*)
let add_id_to_map (id, pos) def map =
  match Map.Poly.mem map id with
  | true -> parse_error ~id ~pos "Defintion shadows previous definition"
  | false -> Map.Poly.add_exn ~key:id ~data:def map

let extend_id_to_map (id, pos) lst map =
  let create = function
    | None -> Some (F.DefineList((id, pos), lst))
    | Some F.DefineList(_, lst') -> Some (F.DefineList((id, pos), lst' @ lst))
    | Some F.Import _
    | Some F.Zone (_,_)
    | Some F.DefineStms (_,_)
    | Some F.AppendList (_,_)
    | Some F.DefinePolicy (_,_)
    | Some F.Process (_,_,_) -> parse_error ~id ~pos "Can only append to prevous list definition"
  in
  Map.Poly.change map id ~f:create

let rec create_define_map_rec acc = function
  | F.DefineStms (id, _) as def :: xs -> create_define_map_rec (add_id_to_map id def acc) xs
  | F.DefineList (id, _) as def :: xs -> create_define_map_rec (add_id_to_map id def acc) xs
  | F.DefinePolicy (id, _) as def :: xs -> create_define_map_rec (add_id_to_map id def acc) xs
  | F.AppendList (id, lst) :: xs -> create_define_map_rec (extend_id_to_map id lst acc) xs
  | F.Import _ :: xs
  | F.Zone (_,_) :: xs
  | F.Process (_,_,_) :: xs -> create_define_map_rec acc xs
  | [] -> acc

(** As the recursive version of the fuction needs an accumulator, add
    a function to hide this to users. *)
let create_define_map = create_define_map_rec Map.Poly.empty

(** Expand and validation is the same problem, and should be solved as
    such.  We need to have a system that eases the task of describing
    the allowed constructs. *)
let expand nodes =
  let zones = Zone.create_zone_set nodes in
  let defines = create_define_map nodes in

  let expand_rules (id, pos) =
    (* Expand single id reference into something sematically
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
    | (F.Id (id, _)) as x :: xs when Set.Poly.mem zones id -> x :: expand_zone_list seen xs
    | F.Id id :: xs -> (expand_zone_list (mark_seen (fst id) seen) (expand id)) @ (expand_zone_list seen xs)
    | F.Number (_, pos) :: _ -> parse_error ~pos "Find integer, expected zone name"
    | F.Ip (_, pos) :: _ -> parse_error ~pos "Found ip address, expected zone name"
    | F.String (_, pos) :: _ -> parse_error ~pos "Found string, expected zone name"
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
      | F.Protocol (l, protos, pol) -> F.Protocol (l, expand_list seen protos, pol)
      | F.Icmp6 (types, pol) -> F.Icmp6 (expand_list seen types, pol)
      | F.Icmp4 (types, pol) -> F.Icmp4 (expand_list seen types, pol)
      | F.State _ as state -> state
      | F.Rule (rls, pols) -> F.Rule (expand_rule_list seen rls, expand_policy_list seen pols)
      | F.TcpFlags (flags, mask, pol) -> F.TcpFlags (expand_list seen flags, expand_list seen mask, pol)
      | F.True -> F.True
      | F.False -> F.False
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

  (* When expanding zone definitions, there is no need to carry a
     seen list, as zone stems are not recursive types. *)
  let rec expand_zone_stms = function
    | F.Interface _ as i :: xs -> i :: expand_zone_stms xs
    | F.Network _ as i :: xs -> i :: expand_zone_stms xs
    | F.ZoneSnat _ as i :: xs -> i :: expand_zone_stms xs
    | F.Vlan _ as i :: xs -> i :: expand_zone_stms xs
    | F.ZoneRules (t, rules, policies) :: xs ->
        F.ZoneRules (t, expand_rule_list [] rules, expand_policy_list [] policies) :: expand_zone_stms xs
    | [] -> []
  in
  let rec expand_nodes = function
    | F.DefineStms (_, _) :: xs
    | F.DefineList (_, _) :: xs
    | F.AppendList (_, _) :: xs
    | F.DefinePolicy (_, _) :: xs -> expand_nodes xs
    | F.Process (t, rules, policies) :: xs -> F.Process (t, expand_rule_list [] rules, expand_policy_list [] policies) :: expand_nodes xs
    | F.Import _ :: _ -> assert false
    | F.Zone (id, zone_stms) :: xs -> F.Zone(id, expand_zone_stms zone_stms) :: expand_nodes xs
    | [] -> []
  in
  expand_nodes nodes
