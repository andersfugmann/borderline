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
      | F.String (_, pos) -> parse_error ~pos "Found string, expected integer while parsing list item"
      | F.Ip4 (_, pos) -> parse_error ~pos "Found ipv4 address, expected integer while parsing list item"
      | F.Ip6 (_, pos) -> parse_error ~pos "Found ipv6 address, expected integer while parsing list item"
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) Set.empty l

let list2ip l =
  List.fold_left (fun (ip4, ip6) -> function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected ip address while parsing list item"
      | F.String (_, pos) -> parse_error ~pos "Found string, expected ip address while parsing list item"
      | F.Ip6 (ip, _) -> ip4, Ip6.add (Ip6.to_elt ip) ip6
      | F.Ip4 (ip, _) -> Ip4.add (Ip4.to_elt ip) ip4, ip6
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) (Ip4.empty, Ip6.empty) l

let list2ids l =
  List.fold_left (fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected id while parsing list item"
      | F.String (_, pos) -> parse_error ~pos "Found string, expected id while parsing list item"
      | F.Ip4 (_, pos) -> parse_error ~pos "Found ipv4 address, expected id while parsing list item"
      | F.Ip6 (_, pos) -> parse_error ~pos "Found ipv6 address, expected id while parsing list item"
      | F.Id (id, _) -> Set.add id acc
    ) Set.empty l

let list2string l =
  List.fold_left (fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected string while parsing list item"
      | F.String (s, pos) -> Set.add (s, pos) acc
      | F.Ip4 (_, pos) -> parse_error ~pos "Found ipv4 address, expected string while parsing list item"
      | F.Ip6 (_, pos) -> parse_error ~pos "Found ipv6 address, expected string while parsing list item"
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) Set.empty l

let process_rule _table (rules, targets') =
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
    | F.Protocol (l, p, neg) :: xs ->
        let protocols = list2string p |> Set.map Ir.Protocol.of_string in
        gen_op targets ((Ir.Protocol(l, protocols), neg) :: acc) xs
    | F.Icmp6 (types, false) :: xs ->
        let types = list2string types |> Set.map Icmp.V6.of_string in
        gen_op targets ((Ir.Icmp6 types, false) :: acc) xs
    | F.Icmp6 (types, true) :: xs ->
        let types = list2string types |> Set.map Icmp.V6.of_string in
        let chain = gen_op targets [] xs in
        let chain = Chain.replace
            chain.Ir.id
            (([(Ir.Icmp6 types, false)], Ir.Return) :: chain.Ir.rules)
            chain.Ir.comment
        in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.Icmp4 (types, false) :: xs ->
        let types = list2string types |> Set.map Icmp.V4.of_string in
        gen_op targets ((Ir.Icmp4 types, false) :: acc) xs
    | F.Icmp4 (types, true) :: xs ->
        let types = list2string types |> Set.map Icmp.V4.of_string in
        let chain = gen_op targets [] xs in
        let chain = Chain.replace
            chain.Ir.id
            (([(Ir.Icmp4 types, false)], Ir.Return) :: chain.Ir.rules)
            chain.Ir.comment
        in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.TcpFlags(flags, false) :: xs ->
        let flags = list2string flags |> Set.map Ir.tcpflag_of_string in
        gen_op targets ((Ir.TcpFlags flags, false) :: acc) xs
    | F.TcpFlags(flags, true) :: xs ->
        let flags = list2string flags |> Set.map Ir.tcpflag_of_string in
        let chain = gen_op targets [] xs in
        let chain = Chain.replace
            chain.Ir.id
            (([(Ir.TcpFlags flags, false)], Ir.Return) :: chain.Ir.rules)
            chain.Ir.comment
        in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
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
