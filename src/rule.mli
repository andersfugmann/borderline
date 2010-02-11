val process_rule : Frontend_types.processtype ->
  Frontend_types.rule_stm list * Frontend_types.policytype list -> Ir.chain

val process :
  Frontend_types.processtype * Frontend_types.rule_stm list * Frontend_types.policytype list ->
  Ir.chain

val filter_process : Frontend_types.node list -> 
  (Frontend_types.processtype * Frontend_types.rule_stm list * Frontend_types.policytype list)
    list
