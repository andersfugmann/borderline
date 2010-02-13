module File_set : Set.S with type elt = string 
val parse : string -> Frontend_types.node list
val expand : Frontend_types.node list -> Frontend_types.node list
val process_files :
  string list ->
  (Common.id * Frontend_types.zone_stm list) list *
  (Frontend_types.processtype * Frontend_types.rule_stm list *
   Frontend_types.policytype list)
  list
