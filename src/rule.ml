open Common
open Frontend
open Frontend_types
open Chain
open Big_int

let gen_policy = function
    ALLOW -> Ir.Accept
  | DENY -> Ir.Drop
  | REJECT -> Ir.Reject(Ir.ICMP_PORT_UNREACHABLE)

let rec list2ints = function
    Number (nr, _) :: xs -> nr :: list2ints xs
  | Ip (_, _) :: xs -> failwith "Unexpected ip in int list"
  | Id (_, _) :: xs -> failwith "No all ints have been expanded"
  | [] -> []

let rec list2ips = function
  | Number (_, _) :: xs -> failwith "Unexpected int in ip list"
  | Ip (ip, _) :: xs -> ip :: list2ips xs
  | Id (_, _) :: xs -> failwith "No all ints have been expanded"
  | [] -> []

let rec process_rule table (rules, target) =
  let gen_op table target = function
      State(states, neg) -> [( [ (Ir.State(states), not neg)], target) ]
    | Filter(dir, TcpPort(ports), neg) -> [ ( [(Ir.Protocol([tcp]), true); (Ir.Ports(dir, list2ints ports), not neg)], target ) ]
    | Filter(dir, UdpPort(ports), neg) -> [ ( [(Ir.Protocol([udp]), true); (Ir.Ports(dir, list2ints ports), not neg)], target ) ]
    | Filter(dir, Address(ips), neg) -> [ ( [(Ir.IpRange(dir, List.map Ipv6.to_range (list2ips ips)), not neg)], target ) ]
    | Filter(dir, FZone(id), neg) -> [ ( [(Ir.Zone(dir, id), not neg)], target ) ]
    | Rule(rls, tg)  -> let chain = process_rule table (rls, tg) in [([], Ir.Jump(chain.Ir.id))]
    | Protocol (protos, neg) -> [ ( [(Ir.Protocol(list2ints protos), not neg)], target) ]
    | Reference _ -> failwith "Reference to definition not expected"

  in
  let action = gen_policy target in

  let opers = List.flatten (List.map ( gen_op table Ir.Return) rules) in
  let chain = Chain.create (opers @ [ ([], action) ]) "Rule" in
    chain

(* New version *)
let rec process_rule' table (rules, target') =
  let rec gen_op target acc = function
      State(states, neg) :: xs -> gen_op target ((Ir.State(states), neg) :: acc) xs
    | Filter(dir, TcpPort(ports), false) :: xs -> gen_op target ( (Ir.Protocol([tcp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | Filter(dir, UdpPort(ports), false) :: xs-> gen_op target ( (Ir.Protocol([udp]), false) :: (Ir.Ports(dir, list2ints ports), false) :: acc ) xs
    | Filter(dir, TcpPort(ports), true) :: xs ->
        let chain = gen_op target [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([tcp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Filter(dir, UdpPort(ports), true) :: xs ->
        let chain = gen_op target [] xs in
        let chain = Chain.replace chain.Ir.id (([(Ir.Protocol([udp]), false); (Ir.Ports(dir, list2ints ports), false)], Ir.Return) :: chain.Ir.rules) chain.Ir.comment in
          Chain.create [ (acc, Ir.Jump chain.Ir.id) ] "Rule"
    | Filter(dir, Address(ips), neg) :: xs -> gen_op target ( (Ir.IpRange(dir, List.map Ipv6.to_range (list2ips ips)), neg) :: acc ) xs
    | Filter(dir, FZone(id), neg) :: xs -> gen_op target ((Ir.Zone(dir, id), neg) :: acc) xs

    | Rule(rls, tg) :: xs ->
        let rule_chain = gen_op (gen_policy tg) [] rls in
        let cont = gen_op target [] xs in
        let cont = Chain.replace cont.Ir.id (([], Ir.Jump rule_chain.Ir.id) :: cont.Ir.rules) cont.Ir.comment in
          Chain.create [ (acc, Ir.Jump cont.Ir.id) ] "Rule"


    | Protocol (protos, neg) :: xs -> gen_op target ((Ir.Protocol(list2ints protos), not neg) :: acc) xs
    | Reference _ :: xs -> failwith "Reference to definition not expected"
    | [] -> Chain.create [ (acc, target) ] "Rule"

  in
    gen_op (gen_policy target') [] rules

let process (table, rules, policy) = process_rule' table (rules, policy)

let rec filter_process = function
    Process (table, rules, policy) :: xs -> (table, rules, policy) :: filter_process xs
  | _ :: xs -> filter_process xs
  | [] -> []








