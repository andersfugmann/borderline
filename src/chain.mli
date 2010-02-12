module Chain_map : Map.S with type key = Ir.chain_id 
val cmp_chain_id : Ir.chain_id * Ir.chain_id -> bool
val get_chain_name : Ir.chain_id -> string
val is_builtin : Ir.chain_id -> bool
val compare : Ir.chain_id -> Ir.chain_id -> int
val filter : ('a -> bool) -> 'a Chain_map.t -> 'a list
val set : Ir.chain -> Ir.chain
val delete : Chain_map.key -> unit
val create : Ir.oper list -> string -> Ir.chain
val replace : Ir.chain_id -> Ir.oper list -> string -> Ir.chain
val get_named_chain : string * 'a -> Ir.chain_id
val create_named_chain : string * 'a -> Ir.oper list -> string -> Ir.chain
val get : Chain_map.key -> Ir.chain
val emit : (Ir.chain Chain_map.t -> 'a) -> 'a
val optimize : (Ir.chain Chain_map.t -> Ir.chain Chain_map.t) -> unit
