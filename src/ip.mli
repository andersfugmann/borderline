(** Generic ip functions *)
val empty : 'a list
type number = Big_int.big_int
type mask = int
type t = number * mask
type range = number * number
type set = range list
(*
val bits : int
val field_size : int
val sep : string
*)
val size : 'a list -> int
val ip_of_string : int list -> number
val string_of_ip : number -> string
(*
val string_of_range : Big_int.big_int * Big_int.big_int -> string
val to_string : (Big_int.big_int * Big_int.big_int) list -> string
*)
val add : range -> set -> set
val sub : range -> set -> set
val union : set -> set -> set 
val difference : set -> set -> set 
val intersection : set -> set -> set 
val subset : set -> set -> bool
val equality : set -> set -> bool
val to_range : t -> range 
val to_ips :
  set -> t list
val set_of_ips :
  t list -> set 

(** Unit tests *)
val tests : OUnit.test
