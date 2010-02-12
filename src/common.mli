type id = string * Lexing.position
exception ParseError of (string * id) list

module Id_set : Set.S with type elt = id
module Id_map : Map.S with type key = id

val tcp : int
val udp : int
val icmp6 : int

val error2string : (string * id) list -> string
val id2str : id -> string
val ints_to_string : int list -> string
val eq_id : id -> id -> bool
val idset_from_list : Id_set.elt list -> Id_set.t
val combinations : 'a list -> 'b list -> ('a * 'b) list
val member : ('a -> 'b -> bool) -> 'a -> 'b list -> bool
val difference : ('a -> 'b -> bool) -> 'a list -> 'b list -> 'a list
val intersection : ('a -> 'b -> bool) -> 'a list -> 'b list -> 'a list
val is_subset : ('a -> 'b -> bool) -> 'a list -> 'b list -> bool
val has_intersection : ('a -> 'b -> bool) -> 'a list -> 'b list -> bool
val group : ('a -> 'a -> bool) -> 'a list list -> 'a list -> 'a list list
val uniq : ('a -> 'a -> bool) -> 'a list -> 'a list list
val map_filter_exceptions : ('a -> 'b) -> 'a list -> 'b list
val identity : 'a -> 'a
