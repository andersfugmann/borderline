val self : Common.id
val mars : Common.id 
val all_zones : Common.id
val buildin_zones : Common.id list
val filter_interface : Frontend_types.zone_stm list -> Common.id list
val filter_network : Frontend_types.zone_stm list -> (Ipv6.ip_number * Ipv6.mask) list
val filter_zonerules : Frontend_types.processtype -> Frontend_types.zone_stm list ->
  (Frontend_types.rule_stm list * Frontend_types.policytype list) list
val create_zone_chain :
  Ir.direction -> Ir.zone * Frontend_types.zone_stm list -> Ir.chain
val filter : Frontend_types.node list -> (Common.id * Frontend_types.zone_stm list) list
val create_zone_set : Frontend_types.node list -> Common.Id_set.t
val emit_nodes : Frontend_types.processtype ->
  (Common.id * Frontend_types.zone_stm list) list -> Frontend_types.node list
val emit : Frontend_types.processtype ->
  (Ir.zone * Frontend_types.zone_stm list) list -> Ir.oper list * Ir.oper list * Ir.oper list
