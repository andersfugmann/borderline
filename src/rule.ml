open Common
module F = Frontend
(* open Chain *)

(* Frontend -> Ir *)

let gen_policy = function
  | F.ALLOW -> Ir.Accept
  | F.DENY -> Ir.Drop
  | F.REJECT -> Ir.Reject(0)
  | F.LOG prefix -> Ir.Log(prefix)
  | F.Ref (id, pos) -> parse_error ~id ~pos "Not all ids have been expanded"

let rec list2ints = function
  | F.Number (nr, _) :: xs -> nr :: list2ints xs
  | F.Ip (_, _) :: _ -> parse_error "Unexpected ip in int list"
  | F.Id (id, pos) :: _ -> parse_error ~id ~pos "No all ints have been expanded"
  | [] -> []

let rec list2ips = function
  | F.Number (_, _) :: _ -> parse_error "Unexpected int in ip list"
  | F.Ip (ip, _) :: xs -> ip :: list2ips xs
  | F.Id (id, pos) :: _ -> parse_error ~id ~pos "No all ints have been expanded"
  | [] -> []

let rec list2zones = function
  | F.Number (_, _) :: _ -> failwith "Unexpected int in zone list"
  | F.Ip (_, _) :: _ -> failwith "Unexpected ip in zone list"
  | F.Id (id, _) :: xs -> id :: list2zones xs (* TODO: Should be a set *)
  | [] -> []

let rec process_rule _table (rules, targets') =
  (* Generate the result of a rules that does not depend on the
     packet. If the packet must match some element in an empty list,
     the filter can never be satisfied. *)
  let rec gen_op targets acc = function
    | F.State(states, neg) :: xs -> gen_op targets ((Ir.State( State.of_list states), neg) :: acc) xs
    | F.Filter(dir, F.TcpPort(ports), false) :: xs -> gen_op targets ( (Ir.Protocol([tcp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | F.Filter(dir, F.UdpPort(ports), false) :: xs-> gen_op targets ( (Ir.Protocol([udp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | F.Filter(dir, F.TcpPort(ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([tcp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.Filter(dir, F.UdpPort(ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([udp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.Filter(dir, F.Address(ips), neg) :: xs -> gen_op targets ( (Ir.IpSet(dir, Ipset.from_ips (list2ips ips)), neg) :: acc ) xs
    | F.Filter(dir, F.FZone(ids), neg) :: xs -> gen_op targets ((Ir.Zone(dir, list2zones ids), neg) :: acc) xs
    | F.Protocol (protos, neg) :: xs -> gen_op targets ((Ir.Protocol(list2ints protos), neg) :: acc) xs
    | F.IcmpType (types, false) :: xs -> gen_op targets ( (Ir.Protocol([icmp]), false) :: (Ir.IcmpType(list2ints types), false) :: acc) xs
    | F.IcmpType (types, true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([icmp]), false);
                                                 (Ir.IcmpType(list2ints types), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | F.TcpFlags((flags, mask), neg) :: xs -> gen_op targets ((Ir.TcpFlags(list2ints flags, list2ints mask), neg) :: acc) xs
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
