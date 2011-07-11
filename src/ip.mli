(** Generic ip functions *)
type set 

val empty : set
type number 
type mask = int
type t = number * mask
type range = number * number

(* Get these from a functor 
val bits : int
val field_size : int
val sep : string
*)

val size : set -> int
val ip_of_string : int list -> number
val string_of_ip : number -> string

val add : range -> set -> set
val sub : range -> set -> set
val union : set -> set -> set 
val difference : set -> set -> set 
val intersection : set -> set -> set 
val subset : set -> set -> bool
val equality : set -> set -> bool
val to_range : t -> range 
val to_ips : set -> t list
val set_of_ips : t list -> set 
val to_ranges : set -> range list 



(** Unit tests *)
val tests : OUnit.test
