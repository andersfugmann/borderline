val mark_seen : Common.id -> Common.id list -> Common.id list
val create_define_map_rec : Frontend_types.node Common.Id_map.t -> Frontend_types.node list -> Frontend_types.node Common.Id_map.t
val create_define_map : Frontend_types.node list -> Frontend_types.node Common.Id_map.t
val expand : Frontend_types.node list -> Frontend_types.node list
