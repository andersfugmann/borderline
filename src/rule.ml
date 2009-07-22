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

let rec ports2ints = function
    Port_nr nr :: xs -> nr :: ports2ints xs
  | _ :: xs -> ports2ints xs (* raise InternalError *)
  | [] -> []

let gen_filter dir = function
    Ip(ip) -> let low, high = Ipv6.to_range ip in Ir.IpRange(dir, low, high)
  | TcpPort(ports) -> Ir.TcpPort(dir, ports2ints ports)
  | UdpPort(ports) -> Ir.UdpPort(dir, ports2ints ports)
  | FZone(id) -> Ir.Zone(dir, id)

let rec process_rule table (rules, target) =
  let gen_op table target = function
      State(states) -> [( [ (Ir.State(states), true)], target) ]
    | Filter(dir, TcpPort(ports)) -> [ ( [(Ir.Protocol(Ir.TCP), true); (Ir.TcpPort(dir, ports2ints ports), true)], target ) ]
    | Filter(dir, UdpPort(ports)) -> [ ( [(Ir.Protocol(Ir.UDP), true); (Ir.UdpPort(dir, ports2ints ports), true)], target ) ]
    | Filter(dir, stm) -> [ ( [(gen_filter dir stm, true)], target ) ]
    | Rule(rls, tg)  -> let chain = process_rule table (rls, tg) in [([], Ir.Jump(chain))]
    | Protocol proto -> [ ( [(Ir.Protocol(proto), true)], target) ]
    | Reference _ -> raise InternalError

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








