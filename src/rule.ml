open Common
open Frontend
open Frontend_types
open Chain
open Big_int

let gen_policy = function
    ALLOW -> Ir.Accept
  | DENY -> Ir.Drop
  | REJECT -> Ir.Reject(Ir.ICMP_PORT_UNREACHABLE)

let gen_action = function
    Policy(p_type) -> gen_policy p_type

let rec nums2ints = function
    Number nr :: xs -> nr :: nums2ints xs
  | _ :: xs -> failwith "No all ints have been expanded"
  | [] -> []

let rec process_rule table (rules, target) =
  let gen_op table target = function
      State(states) -> [( [ (Ir.State(states), true)], target) ]
    | Filter(dir, TcpPort(ports)) -> [ ( [(Ir.Protocol([tcp]), true); (Ir.Ports(dir, nums2ints ports), true)], target ) ]
    | Filter(dir, UdpPort(ports)) -> [ ( [(Ir.Protocol([udp]), true); (Ir.Ports(dir, nums2ints ports), true)], target ) ]
    | Filter(dir, Ip(ip)) -> let low, high = Ipv6.to_range ip in [ ( [(Ir.IpRange(dir, low, high), true)], target ) ]
    | Filter(dir, FZone(id)) -> [ ( [(Ir.Zone(dir, id), true)], target ) ]
    | Rule(rls, tg)  -> let chain = process_rule table (rls, tg) in [([], Ir.Jump(chain))]
    | Protocol protos -> [ ( [(Ir.Protocol(nums2ints protos), true)], target) ]
    | Reference _ -> failwith "Reference to definition not expected"

  in
  let action = gen_action target in
  let opers = List.flatten (List.map ( gen_op table Ir.Return) rules) in
  let chain = Chain.create (opers @ [ ([], action) ]) "Rule" in
    chain.Ir.id

let process (table, rules, policy) = process_rule table (rules, Policy(policy))

let rec filter_process = function
    Process (table, rules, policy) :: xs -> (table, rules, policy) :: filter_process xs
  | _ :: xs -> filter_process xs
  | [] -> []








