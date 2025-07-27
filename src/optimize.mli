val optimize :
  ?iter:int ->
  (Ir.Chain_id.t, Ir.chain, Ir.Chain_id.comparator_witness)
    Base.Map.t ->
  (Ir.Chain_id.t, Ir.chain, Ir.Chain_id.comparator_witness)
    Base.Map.t


module Test : sig
  val unittest : OUnitTest.test
end
