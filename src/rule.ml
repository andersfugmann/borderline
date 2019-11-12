open Core
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

let gen_target (effects, target) = function
  | F.Counter -> (Ir.Counter :: effects, target)
  | F.Log prefix -> (Ir.Log prefix :: effects, target)
  | F.Ref (id, pos) -> parse_error ~id ~pos "Not all ids have been expanded"
  | F.Snat ip ->
      if (Ipaddr.V4.Prefix.bits ip < 32) then (parse_error "Snat not not work with network ranges");
      (Ir.Snat (Ipaddr.V4.Prefix.network ip) :: effects, target)
  | F.Allow -> (effects, Ir.Accept)
  | F.Deny -> (effects, Ir.Drop)
  | F.Reject s -> (effects, Ir.Reject (reject_of_string_opt s))
  | F.User_chain (s, pos) ->
    Chain.create_named_chain (s, pos) [] "Userdefined chain";
    (effects, Ir.Jump (Ir.Chain_id.Named s))

let gen_targets targets =
  let (effect, target) = List.fold_left ~init:([], Ir.Pass) ~f:gen_target targets in
  (List.rev effect, target)

let list2ints l =
  List.fold_left ~f:(fun acc ->
      function
      | F.Number (i, _) -> i :: acc
      | F.String (_, pos) -> parse_error ~pos "Found string, expected integer while parsing list item"
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected integer while parsing list item"
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) ~init:[] l

let list2ip l =
  List.fold_left ~f:(fun (ip4, ip6) -> function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected ip address while parsing list item"
      | F.String (_, pos) -> parse_error ~pos "Found string, expected ip address while parsing list item"
      | F.Ip (F.Ipv6 ip, _) -> ip4, ip :: ip6
      | F.Ip (F.Ipv4 ip, _) -> ip :: ip4, ip6
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) ~init:([], []) l

let list2ids l =
  List.fold_left ~f:(fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected id while parsing list item"
      | F.String (_, pos) -> parse_error ~pos "Found string, expected id while parsing list item"
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected id while parsing list item"
      | F.Id id -> id :: acc
    ) ~init:[] l

let list2string l =
  List.fold_left ~f:(fun acc ->
      function
      | F.Number (_, pos) -> parse_error ~pos "Found integer, expected string while parsing list item"
      | F.String (s, pos) -> (s, pos) :: acc
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected string while parsing list item"
      | F.Id _ -> failwith "No all ids have been expanded correctly"
    ) ~init:[] l

let process_rule _table (rules, targets') =
  (* Generate the result of a rules that does not depend on the
     packet. If the packet must match some element in an empty list,
     the filter can never be satisfied. *)
  let rec gen_op targets acc = function
    | F.State(states, neg) :: xs ->
        gen_op targets ((Ir.State( list2ids states |> List.map ~f:State.of_string |> State.of_list), neg) :: acc) xs
    | F.Filter(dir, F.Ports(port_type, ports), neg) :: xs ->
        gen_op targets ( (Ir.Ports(Ir.Direction.of_string dir, Ir.Port_type.of_string port_type, list2ints ports |> Set.Poly.of_list), neg) :: acc ) xs
    | F.Filter(dir, F.Address(ips), neg) :: xs ->
        (* Split into ipv4 and ipv6 *)
        let (ip4, ip6) = list2ip ips in
        let chain = gen_op targets acc xs in
        (* Neg in this case needs to be chained *)
        Chain.create [
          [Ir.Ip6Set (Ir.Direction.of_string dir, Ipset.Ip6.of_list ip6), neg], [], Ir.Jump chain.Ir.id;
          [Ir.Ip4Set (Ir.Direction.of_string dir, Ipset.Ip4.of_list ip4), neg], [], Ir.Jump chain.Ir.id;
        ] "Rule"
    | F.Filter(dir, F.FZone(ids), neg) :: xs ->
        gen_op targets ((Ir.Zone(Ir.Direction.of_string dir,
                                 list2ids ids |> List.map ~f:fst |> Set.Poly.of_list), neg) :: acc) xs
    | F.Protocol (l, p, neg) :: xs ->
        let protocols = list2string p |> List.map ~f:Ir.Protocol.of_string |> Set.Poly.of_list in
        gen_op targets ((Ir.Protocol(l, protocols), neg) :: acc) xs
    | F.Icmp6 (types, neg) :: xs ->
        let types = list2string types |> List.map ~f:Icmp.V6.of_string |> Set.Poly.of_list in
        gen_op targets ((Ir.Icmp6 types, neg) :: acc) xs
    | F.Icmp4 (types, neg) :: xs ->
        let types = list2string types |> List.map ~f:Icmp.V4.of_string |> Set.Poly.of_list in
        gen_op targets ((Ir.Icmp4 types, neg) :: acc) xs
    | F.TcpFlags(flags, mask, neg) :: xs -> begin
        let flags' = list2string flags |> List.map ~f:Ir.Tcp_flags.of_string |> Set.Poly.of_list in
        let mask' = list2string mask |> List.map ~f:Ir.Tcp_flags.of_string |> Set.Poly.of_list in

        (* Test that flags are all in mask *)
        match Set.is_subset flags' ~of_:mask' with
        | false ->
            parse_error ~pos:(flags @ mask |> List.hd_exn |> pos_of) "Tcp flag not in mask"
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
      let cont = Chain.replace cont.Ir.id (([], [], Ir.Jump rule_chain.Ir.id) :: cont.Ir.rules) cont.Ir.comment in
      Chain.create [ (acc, [], Ir.Jump cont.Ir.id) ] "Rule"
    | F.Reference _ :: _ -> parse_error "Reference to definition not expected"
    | [] ->
        let (effects, target) = gen_targets targets in
        Chain.create [ (acc, effects, target) ] "Rule"
  in
    gen_op targets' [] rules

let process (table, rules, policies) = process_rule table (rules, policies)

let rec filter_process = function
  | F.Process (table, rules, policy) :: xs -> (table, rules, policy) :: filter_process xs
  | _ :: xs -> filter_process xs
  | [] -> []
