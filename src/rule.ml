open Base
module Set = Set.Poly
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

let list2ints : F.data list -> int list = fun l ->
  List.fold_left ~f:(fun acc ->
      function
      | F.Number (i, _) -> i :: acc
      | F.String (s, pos) -> parse_errorf ~pos "Found \"%s\", expected integer while parsing list item" s
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected integer while parsing list item"
      | F.Id (s, pos) -> parse_errorf ~pos "Unable to resolve '%s' to an integer" s
    ) ~init:[] l

let list2ip : F.data list -> Ip4.elt list * Ip6.elt list = fun l ->
  List.fold_left ~f:(fun (ip4, ip6) -> function
      | F.Number (d, pos) -> parse_errorf ~pos "Found integer '%d', expected ip address while parsing list item" d
      | F.String (s, pos) -> parse_errorf ~pos "Found string \"%s\", expected ip address while parsing list item" s
      | F.Ip (F.Ipv6 ip, _) -> ip4, ip :: ip6
      | F.Ip (F.Ipv4 ip, _) -> ip :: ip4, ip6
      | F.Id (s, pos) -> parse_errorf ~pos "Unable to resolve '%s' to an ip address" s
    ) ~init:([], []) l

let list2ids : F.data list -> F.id list = fun l ->
  List.fold_left ~f:(fun acc ->
      function
      | F.Number (d, pos) -> parse_errorf ~pos "Found integer '%d', expected id while parsing list item" d
      | F.String (s, pos) -> parse_errorf ~pos "Found string \"%s\", expected id while parsing list item" s
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected id while parsing list item"
      | F.Id id -> id :: acc
    ) ~init:[] l

let list2string : F.data list -> (string * Lexing.position) list = fun l ->
  List.fold_left ~f:(fun acc ->
      function
      | F.Number (d, pos) -> parse_errorf ~pos "Found integer '%d', expected string while parsing list item" d
      | F.String (s, pos) -> (s, pos) :: acc
      | F.Ip (_, pos) -> parse_error ~pos "Found ip address, expected string while parsing list item"
      | F.Id (s, pos) -> parse_errorf ~pos "Unable to resolve '%s' to a string" s
    ) ~init:[] l

let process_rule _table (rules, targets') =
  (* Generate the result of a rules that does not depend on the
     packet. If the packet must match some element in an empty list,
     the filter can never be satisfied. *)
  let rec gen_op targets acc = function
    | F.State(states, neg) :: xs ->
        gen_op targets ((Ir.State( list2ids states |> List.map ~f:State.of_string |> State.of_list), neg) :: acc) xs
    | F.Filter(dir, F.Ports(port_type, ports), neg) :: xs ->
        gen_op targets ( (Ir.Ports(Ir.Direction.of_string dir, Ir.Port_type.of_string port_type, list2ints ports |> Set.of_list), neg) :: acc ) xs
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
                                 list2ids ids |> List.map ~f:fst |> Set.of_list), neg) :: acc) xs
    | F.Protocol (p, neg) :: xs ->
        let protocols = list2ints p |> Set.of_list in
        gen_op targets ((Ir.Protocol protocols, neg) :: acc) xs
    | F.Icmp6 (types, neg) :: xs ->
        let types = list2ints types |> Set.of_list in
        gen_op targets ((Ir.Icmp6 types, neg) :: acc) xs
    | F.Icmp4 (types, neg) :: xs ->
        let types = list2ints types |> Set.of_list in
        gen_op targets ((Ir.Icmp4 types, neg) :: acc) xs
    | F.TcpFlags (flags, mask, neg) :: xs -> begin
        let flags' = list2string flags |> List.map ~f:Ir.Tcp_flags.of_string |> Set.of_list in
        let mask' = list2string mask |> List.map ~f:Ir.Tcp_flags.of_string |> Set.of_list in

        (* Test that flags are all in mask *)
        match Set.is_subset flags' ~of_:mask' with
        | false ->
            parse_error ~pos:(flags @ mask |> List.hd_exn |> pos_of) "Tcp flag not in mask"
        | true ->
            gen_op targets ((Ir.TcpFlags (flags', mask'), neg) :: acc) xs
      end
    | F.Hoplimit (limits, neg) :: xs ->
        let limits = list2ints limits |> Set.of_list in
        gen_op targets ((Ir.Hoplimit limits, neg) :: acc) xs
    | F.True :: xs ->
        gen_op targets ((Ir.True, false) :: acc) xs
    | F.False :: xs ->
        gen_op targets ((Ir.True, true) :: acc) xs
    | F.Rule(rls, tgs) :: xs ->
      let rule_chain = gen_op tgs [] rls in
      let cont = gen_op targets [] xs in
      let cont = Chain.replace cont.Ir.id (([], [], Ir.Jump rule_chain.Ir.id) :: cont.Ir.rules) cont.Ir.comment in
      Chain.create [ (acc, [], Ir.Jump cont.Ir.id) ] "Rule"
    | F.Reference ((s, pos), _) :: _ -> parse_errorf ~pos "Reference to definition '%s' not expected" s
    | F.Address_family (data, neg) :: xs ->
      let set =
        list2ids data
        |> List.map ~f:(function "ipv4", _ -> Ir.Ipv4 | "ipv6", _ -> Ir.Ipv6 | s, pos -> parse_errorf ~pos "Unknown address family: %s" s)
        |> Set.of_list
      in
      gen_op targets ((Ir.Address_family set, neg) :: acc) xs
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
