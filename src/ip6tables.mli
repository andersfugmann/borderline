module StringMap: Map.S with type key = string

val elem : 'a list -> 'a
val get_zone_id : StringMap.key -> int
val gen_neg : bool -> string
val choose_dir : string -> string -> Ir.direction -> string
val get_state_name : Ir.statetype -> string
val gen_zone_mask : Ir.direction -> Common.id -> int * int
val gen_zone_mask_str : Ir.direction -> Common.id -> string
val gen_condition : Ir.condition -> string * string
val gen_conditions : string -> (Ir.condition * bool) list -> string
val gen_action : Ir.action -> string
val transform : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val emit_rule : Ir.oper -> string
val emit_rules : Ir.chain -> string list
val filter : Ir.chain Chain.Chain_map.t -> Ir.chain Chain.Chain_map.t
val create_chain : string list -> Ir.chain -> string list
val emit_chains : Ir.chain Chain.Chain_map.t -> string list
