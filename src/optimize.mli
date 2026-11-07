val optimize :
  zones:(string * Frontend.zone_stm list) list ->
  (Ir.Chain_id.t, Ir.chain, Ir.Chain_id.comparator_witness)
    Base.Map.t ->
  (Ir.Chain_id.t, Ir.chain, Ir.Chain_id.comparator_witness)
    Base.Map.t
