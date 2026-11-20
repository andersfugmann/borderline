val emit_filter_rules :
  zones:string list -> (Ir.Chain_id.t, Ir.chain, 'a) Base.Map.t -> string list
val emit_nat_rules :
  zones:string list -> Ir.rule list -> string list
val emit : string list -> string list
