open Common
open Frontend
open Frontend_types
open Chain
open Big_int

let gen_policy : Frontend_types.policytype -> Ir.action = function
    ALLOW -> Ir.Accept
  | DENY -> Ir.Drop
  | REJECT -> Ir.Reject(0)
  | LOG prefix -> Ir.Log(prefix)
  | Ref id -> raise (ParseError [ ("Not all ids have been expanded", id) ])

let rec list2ints : Frontend_types.data list -> int list = function
    Number (nr, _) :: xs -> nr :: list2ints xs
  | Ip (_, _) :: xs -> failwith "Unexpected ip in int list"
  | Id (id, _) :: xs -> failwith ("No all ints have been expanded: " ^ id)
  | [] -> []

let rec list2ips : Frontend_types.data list -> Ipv6.ip list = function
  | Number (_, _) :: xs -> failwith "Unexpected int in ip list"
  | Ip (ip, _) :: xs -> ip :: list2ips xs
  | Id (id, _) :: xs -> failwith ("No all ints have been expanded: " ^ id)
  | [] -> []

let rec list2zones : Frontend_types.data list -> Common.id list = function
  | Number (_, _) :: xs -> failwith "Unexpected int in zone list"
  | Ip (_, _) :: xs -> failwith "Unexpected ip in zone list"
  | Id id :: xs -> id :: list2zones xs
  | [] -> []

let rec process_rule table (rules, targets') =
  (* Generate the result of a rules that does not depend on the
     packet.  If the packet must match some element in an empty list,
     the filter can never be satisfied. *)
  let rec gen_op targets acc = function
    | State(states, neg) :: xs -> gen_op targets ((Ir.State(states), neg) :: acc) xs
    | Filter(dir, TcpPort(ports), false) :: xs -> gen_op targets ( (Ir.Protocol([tcp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | Filter(dir, UdpPort(ports), false) :: xs-> gen_op targets ( (Ir.Protocol([udp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | Filter(dir, TcpPort(ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([tcp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Filter(dir, UdpPort(ports), true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([udp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Filter(dir, Address(ips), neg) :: xs -> gen_op targets ( (Ir.IpRange(dir, List.map Ipv6.to_range (list2ips ips)), neg) :: acc ) xs
    | Filter(dir, FZone(ids), neg) :: xs -> gen_op targets ((Ir.Zone(dir, list2zones ids), neg) :: acc) xs
    | Protocol (protos, neg) :: xs -> gen_op targets ((Ir.Protocol(list2ints protos), neg) :: acc) xs
    | IcmpType (types, false) :: xs -> gen_op targets ( (Ir.Protocol([icmp]), false) :: (Ir.IcmpType(list2ints types), false) :: acc) xs
    | IcmpType (types, true) :: xs ->
        let chain = gen_op targets [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([icmp]), false);
                                                 (Ir.IcmpType(list2ints types), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | TcpFlags((flags, mask), neg) :: xs -> gen_op targets ((Ir.TcpFlags(list2ints flags, list2ints mask), neg) :: acc) xs
    | Rule(rls, tgs) :: xs ->
        let rule_chain = gen_op tgs [] rls in
        let cont = gen_op targets [] xs in
        let cont = Chain.replace cont.Ir.id (([], Ir.Jump rule_chain.Ir.id) :: cont.Ir.rules) cont.Ir.comment in
          Chain.create [ (acc, Ir.Jump cont.Ir.id) ] "Rule"
    | Reference _ :: xs -> failwith "Reference to definition not expected"
    | [] -> let tg_chain = Chain.create (List.map (fun tg -> ([], gen_policy tg)) targets) "Target" in
        Chain.create [ (acc, Ir.Jump tg_chain.Ir.id) ] "Rule"
  in
    gen_op targets' [] rules

let process (table, rules, policies) = process_rule table (rules, policies)

let rec filter_process = function
    Process (table, rules, policy) :: xs -> (table, rules, policy) :: filter_process xs
  | _ :: xs -> filter_process xs
  | [] -> []








