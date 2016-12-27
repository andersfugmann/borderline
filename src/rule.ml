open Batteries
open Common
module F = Frontend
module Ip4 = Ipset.Ip4
module Ip6 = Ipset.Ip6

(* Frontend -> Ir *)
let reject_of_string = function
  | Some ("host-unreachable", _pos) -> Ir.HostUnreachable
  | Some ("no-route", _pos) -> Ir.NoRoute
  | Some ("admin-prohibited", _pos) -> Ir.AdminProhibited
  | Some ("port-unreachable", _pos) -> Ir.PortUnreachable
  | Some ("tcp-reset", _pos) -> Ir.TcpReset
  | Some (s, pos) -> parse_error ~id:s ~pos "Unknown reject type"
  | None -> Ir.PortUnreachable

let gen_policy = function
  | F.ALLOW -> Ir.Accept
  | F.DENY -> Ir.Drop
  | F.REJECT s -> Ir.Reject (reject_of_string s)
  | F.LOG prefix -> Ir.Log prefix
  | F.Ref (id, pos) -> parse_error ~id ~pos "Not all ids have been expanded"

let list2ints l =
  List.fold_left (fun acc ->
      function
      | F.Number (nr, _) -> Set.add nr acc
      | F.Ip4 (_, pos) -> parse_error ~pos "Unexpected ipv4 in int list"
      | F.Ip6 (_, pos) -> parse_error ~pos "Unexpected ipv6 in int list"
      | F.Id (id, pos) -> parse_error ~id ~pos "No all ints have been expanded")
    Set.empty l

let list2ip l =
  List.fold_left (fun (ip4, ip6) -> function
      | F.Number (_, pos) -> parse_error ~pos "Unexpected int in ip list"
      | F.Ip6 (ip, _) -> ip4, Ip6.add (Ip6.to_elt ip) ip6
      | F.Ip4 (ip, _) -> Ip4.add (Ip4.to_elt ip) ip4, ip6
      | F.Id (id, pos) -> parse_error ~id ~pos "No all ints have been expanded")
    (Ip4.empty, Ip6.empty) l

let list2ids l =
  List.fold_left (fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Unexpected int in id list"
      | F.Ip6 (_, pos) -> parse_error ~pos "Unexpected ipv6 in id list"
      | F.Ip4 (_, pos) -> parse_error ~pos "Unexpected ipv4 in id list"
      | F.Id (id, _) -> Set.add id acc)
    Set.empty l

let rec process_rule _table (rules, targets') =
  (* Generate the result of a rules that does not depend on the
     packet. If the packet must match some element in an empty list,
     the filter can never be satisfied. *)
  let rec gen_op targets acc = function
    | F.State(states, neg) :: xs -> gen_op targets ((Ir.State( State.of_list states), neg) :: acc) xs
    | F.Filter(dir, F.Ports(port_type, ports), false) :: xs -> gen_op targets ( (Ir.Ports(dir, port_type, list2ints ports), false) :: acc ) xs
    | F.Filter(dir, F.Ports(port_type, ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Ports(dir, port_type, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.Filter(dir, F.Address(ips), false) :: xs ->
        (* Split into ipv4 and ipv6 *)
        let (ip4, ip6) = list2ip ips in
        let chain = gen_op targets acc xs in
        (* Neg in this case needs to be chained *)
        Chain.create [
          [Ir.Ip6Set (dir, ip6), false], Ir.Jump chain.Ir.id;
          [Ir.Ip4Set (dir, ip4), false], Ir.Jump chain.Ir.id;
        ] "Rule"
    | F.Filter(dir, F.Address(ips), true) :: xs ->
        (* Split into ipv4 and ipv6 *)
        let chain = gen_op targets acc xs in
        let (ip4, ip6) = list2ip ips in
        (* Add first return rule in target chain *)
        Chain.replace chain.Ir.id (
            ([ Ir.Ip4Set (dir, ip4), false], Ir.Return) ::
            ([ Ir.Ip6Set (dir, ip6), false], Ir.Return) ::
            chain.Ir.rules) chain.Ir.comment
    | F.Filter(dir, F.FZone(ids), neg) :: xs -> gen_op targets ((Ir.Zone(dir, list2ids ids), neg) :: acc) xs
    | F.Protocol (protos, neg) :: xs -> gen_op targets ((Ir.Protocol(list2ints protos), neg) :: acc) xs
    | F.Icmp6Type (types, false) :: xs -> gen_op targets ((Ir.Icmp6Type(list2ints types), false) :: acc) xs
    | F.Icmp6Type (types, true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Icmp6Type(list2ints types), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment
        in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.TcpFlags((flags, mask), neg) :: xs ->
      gen_op targets ((Ir.TcpFlags(list2ints flags |> Set.to_list, list2ints mask |> Set.to_list), neg) :: acc) xs
    | F.Rule(rls, tgs) :: xs ->
      let rule_chain = gen_op tgs [] rls in
      let cont = gen_op targets [] xs in
      let cont = Chain.replace cont.Ir.id (([], Ir.Jump rule_chain.Ir.id) :: cont.Ir.rules) cont.Ir.comment in
      Chain.create [ (acc, Ir.Jump cont.Ir.id) ] "Rule"
    | F.Reference _ :: _ -> parse_error "Reference to definition not expected"
    | [] -> let tg_chain = Chain.create (List.map (fun tg -> ([], gen_policy tg)) targets) "Target" in
      Chain.create [ (acc, Ir.Jump tg_chain.Ir.id) ] "Rule"
  in
    gen_op targets' [] rules

let process (table, rules, policies) = process_rule table (rules, policies)

let rec filter_process = function
  | F.Process (table, rules, policy) :: xs -> (table, rules, policy) :: filter_process xs
  | _ :: xs -> filter_process xs
  | [] -> []
