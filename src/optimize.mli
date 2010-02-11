val chain_reference_count : Ir.chain_id -> Ir.chain Chain.Chain_map.t -> int
val get_referring_rules : Ir.chain -> Ir.chain Chain.Chain_map.t -> Ir.oper list
val map_chain_rules : (Ir.oper list -> Ir.oper list) ->
  Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val map_chain_rules_expand :
  ((Ir.condition * bool) list -> (Ir.condition * bool) list list) ->
  Ir.chain list -> Ir.chain list
val merge_opers : (Ir.condition * bool) list -> (Ir.condition * bool) list
val reduce : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val fold_return_statements : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val remove_unreferenced_chains : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val remove_dublicate_chains : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val reorder : Ir.oper list -> Ir.oper list
val inline : (Ir.chain Chain.Chain_map.t -> Ir.chain -> bool) ->
  Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val eliminate_dead_rules : Ir.oper list -> Ir.oper list
val eliminate_dublicate_rules : Ir.oper list -> Ir.oper list
val remove_unsatisfiable_rules : Ir.oper list -> Ir.oper list
val remove_true_rules : Ir.oper list -> Ir.oper list
val count_rules : Ir.chain Chain.Chain_map.t -> int
val should_inline : Ir.chain Chain.Chain_map.t -> Ir.chain -> bool
val conds : Ir.chain Chain.Chain_map.t -> int
val optimize_pass : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val optimize : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
