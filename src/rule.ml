open Common
open Frontend
open Chain

let gen_policy = function
    ALLOW -> Ir.Accept
  | DENY -> Ir.Drop
  | REJECT -> Ir.Reject(Ir.ICMP_PORT_UNREACHABLE)

let gen_action = function
    Policy(p_type) -> gen_policy p_type

let gen_filter dir = function
    Ip(ip) -> Ir.Address(dir, ip)
  | Port(ports) -> Ir.Port(dir, ports)
  | FZone(id) -> Ir.Zone(dir, id)

let rec process_rule table (rules, target) =
  let gen_op table target = function
      State(states) -> ( [(Ir.State(states), true)], target )
    | Filter(dir, stm) -> ( [(gen_filter dir stm, true)], target )
    | Rule(rls, tg)  -> let chain = process_rule table (rls, tg) in
        ([], Ir.Jump(chain))
  in
  let action = gen_action target in
  let opers = List.map ( gen_op table Ir.Return) rules in
  let chain = Chain.create (opers @ [ ([], action) ]) "Rule" in
    chain.id

let process = function
    Process(table, rules, policy) -> process_rule table (rules, Policy(policy))
  | _ -> raise InternalError



(* Create a chain, and all must match - So If one does not match, do a return (negation) *)
