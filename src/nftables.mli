val emit_filter_rules :
  (Ir.Chain_id.t, Ir.chain, 'a) Base.Map.t -> string list
val emit_nat_rules : Ir.rule list -> string list
val emit : string list -> string list
