type id = string * Lexing.position
exception ParseError of (string * id) list

module Id_set : Set.S with type elt = id
module Id_map : Map.S with type key = id

val tcp : int
val udp : int
val icmp : int

val error2string : (string * id) list -> string
val id2str : id -> string
val ints_to_string : int list -> string
val eq_id : id -> id -> bool
val eq_id_list : id list -> id list -> bool
val join : string -> string list -> string
val idset_from_list : Id_set.elt list -> Id_set.t
val combinations : 'a list -> 'a list -> ('a * 'a) list
val member : ('a -> 'a -> bool) -> 'a -> 'a list -> bool
val difference : ('a -> 'a -> bool) -> 'a list -> 'a list -> 'a list
val intersection : ('a -> 'a -> bool) -> 'a list -> 'a list -> 'a list
val union : ('a -> 'a -> bool) -> 'a list -> 'a list -> 'a list
val is_subset : ('a -> 'a -> bool) -> 'a list -> 'a list -> bool
val has_intersection : ('a -> 'a -> bool) -> 'a list -> 'a list -> bool
val group : ('a -> 'a -> bool) -> 'a list list -> 'a list -> 'a list list
val uniq : ('a -> 'a -> bool) -> 'a list -> 'a list list
val map_filter_exceptions : ('a -> 'a) -> 'a list -> 'a list
val identity : 'a -> 'a
val keys : 'a Id_map.t -> Id_map.key list
