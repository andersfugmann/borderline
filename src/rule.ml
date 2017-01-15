open Batteries
open Common
module F = Frontend
module Ip4 = Ipset.Ip4
module Ip6 = Ipset.Ip6

let pos_of = function
  | F.Number (_, pos)
  | F.String (_, pos)
  | F.Ip (_, pos)
  | F.Id (_, pos) -> pos

(* Frontend -> Ir *)
let reject_of_string_opt = function
  | Some id -> Ir.Reject.of_string id
  | None -> Ir.Reject.PortUnreachable

let gen_policy = function
  | F.Allow -> Ir.Accept
  | F.Deny -> Ir.Drop
  | F.Reject s -> Ir.Reject (reject_of_string_opt s)
  | F.Log prefix -> Ir.Log prefix
  | F.Ref (id, pos) -> parse_error ~id ~pos "Not all ids have been expanded"
  | F.Snat ip ->
      if (Ipaddr.V4.Prefix.bits ip < 32) then (parse_error "Snat not not work with network ranges");
      Ir.Snat (Ipaddr.V4.Prefix.network ip)

let list2ints l =
  List.fold_left (fun acc ->
      function
      | F.Number (i, _) -> i :: acc
      | F.String (_, pos) -> parse_error ~pos "Found string, expected integer while parsing list item"
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected integer while parsing list item"
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) [] l

let list2ip l =
  List.fold_left (fun (ip4, ip6) -> function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected ip address while parsing list item"
      | F.String (_, pos) -> parse_error ~pos "Found string, expected ip address while parsing list item"
      | F.Ip (F.Ipv6 ip, _) -> ip4, ip :: ip6
      | F.Ip (F.Ipv4 ip, _) -> ip :: ip4, ip6
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) ([], []) l

let list2ids l =
  List.fold_left (fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected id while parsing list item"
      | F.String (_, pos) -> parse_error ~pos "Found string, expected id while parsing list item"
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected id while parsing list item"
      | F.Id id -> id :: acc
    ) [] l

let list2string l =
  List.fold_left (fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected string while parsing list item"
      | F.String (s, pos) -> (s, pos) :: acc
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected string while parsing list item"
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) [] l

let process_rule _table (rules, targets') =
  (* Generate the result of a rules that does not depend on the
     packet. If the packet must match some element in an empty list,
     the filter can never be satisfied. *)
  let rec gen_op targets acc = function
    | F.State(states, neg) :: xs ->
        gen_op targets ((Ir.State( list2ids states |> List.map State.of_string |> State.of_list), neg) :: acc) xs
    | F.Filter(dir, F.Ports(port_type, ports), false) :: xs ->
        gen_op targets ( (Ir.Ports(Ir.Direction.of_string dir, Ir.Port_type.of_string port_type, list2ints ports |> Set.of_list), false) :: acc ) xs
    | F.Filter(dir, F.Ports(port_type, ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Ports( Ir.Direction.of_string dir, Ir.Port_type.of_string port_type, list2ints ports |> Set.of_list), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.Filter(dir, F.Address(ips), false) :: xs ->
        (* Split into ipv4 and ipv6 *)
        let (ip4, ip6) = list2ip ips in
        let chain = gen_op targets acc xs in
        (* Neg in this case needs to be chained *)
        Chain.create [
          [Ir.Ip6Set (Ir.Direction.of_string dir, Ipset.Ip6.of_list ip6), false], Ir.Jump chain.Ir.id;
          [Ir.Ip4Set (Ir.Direction.of_string dir, Ipset.Ip4.of_list ip4), false], Ir.Jump chain.Ir.id;
        ] "Rule"
    | F.Filter(dir, F.Address(ips), true) :: xs ->
        (* Split into ipv4 and ipv6 *)
        let chain = gen_op targets acc xs in
        let (ip4, ip6) = list2ip ips in
        (* Add first return rule in target chain *)
        Chain.replace chain.Ir.id (
            ([ Ir.Ip4Set (Ir.Direction.of_string dir, Ipset.Ip4.of_list ip4), false], Ir.Return) ::
            ([ Ir.Ip6Set (Ir.Direction.of_string dir, Ipset.Ip6.of_list ip6), false], Ir.Return) ::
            chain.Ir.rules) chain.Ir.comment
    | F.Filter(dir, F.FZone(ids), neg) :: xs ->
        gen_op targets ((Ir.Zone(Ir.Direction.of_string dir,
                                 list2ids ids |> List.map fst |> Set.of_list), neg) :: acc) xs
    | F.Protocol (l, p, neg) :: xs ->
        let protocols = list2string p |> List.map Ir.Protocol.of_string |> Set.of_list in
        gen_op targets ((Ir.Protocol(l, protocols), neg) :: acc) xs
    | F.Icmp6 (types, false) :: xs ->
        let types = list2string types |> List.map Icmp.V6.of_string |> Set.of_list in
        gen_op targets ((Ir.Icmp6 types, false) :: acc) xs
    | F.Icmp6 (types, true) :: xs ->
        let types = list2string types |> List.map Icmp.V6.of_string |> Set.of_list in
        let chain = gen_op targets [] xs in
        let chain = Chain.replace
            chain.Ir.id
            (([(Ir.Icmp6 types, false)], Ir.Return) :: chain.Ir.rules)
            chain.Ir.comment
        in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.Icmp4 (types, false) :: xs ->
        let types = list2string types |> List.map Icmp.V4.of_string |> Set.of_list in
        gen_op targets ((Ir.Icmp4 types, false) :: acc) xs
    | F.Icmp4 (types, true) :: xs ->
        let types = list2string types |> List.map Icmp.V4.of_string |> Set.of_list in
        let chain = gen_op targets [] xs in
        let chain = Chain.replace
            chain.Ir.id
            (([(Ir.Icmp4 types, false)], Ir.Return) :: chain.Ir.rules)
            chain.Ir.comment
        in
        Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.TcpFlags(flags, mask, neg) :: xs -> begin
        let flags' = list2string flags |> List.map Ir.Tcp_flags.of_string |> Set.of_list in
        let mask' = list2string mask |> List.map Ir.Tcp_flags.of_string |> Set.of_list in

        (* Test that flags are all in mask *)
        match Set.subset flags' mask' with
        | false ->
            parse_error ~pos:(flags @ mask |> List.hd |> pos_of) "Tcp flag not in mask"
        | true ->
            gen_op targets ((Ir.TcpFlags (flags', mask'), neg) :: acc) xs
      end
    | F.True :: xs ->
        gen_op targets ((Ir.True, false) :: acc) xs
    | F.False :: xs ->
        gen_op targets ((Ir.True, true) :: acc) xs
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
