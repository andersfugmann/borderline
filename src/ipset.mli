(** Generic ip functions *)

(** Type of the set *)
type t

(** The empty set *)
val empty : t

(** Ip number. Anonymous type *)
type number

(** Ip mask *)
type mask = int

(** Type of t element *)
type ip = number * mask

(** Element type *)
type elt = number * number

(* Get these from a functor
val bits : int
val field_size : int
val sep : string
*)

val ip_of_string : int list -> number

(** Ip to string *)
val string_of_ip : number -> string

(** Create a set of with a single element *)
val singleton : elt -> t

(** Add a element to the t *)
val add : elt -> t -> t

(** Remove elements from the t *)
val remove : elt -> t -> t

(** A U B *)
val union : t -> t -> t

(** A but not B *)
val diff : t -> t -> t

(** Intersection between A and B *)
val inter : t -> t -> t

(** Test if a is a subset of b *)
val subset : t -> t -> bool

(** Test for t equality *)
val equal : t -> t -> bool

(** Convet an ip addres and mask to a t element *)
val to_elt : ip -> elt

(** Convert a t to a list of ips *)
val to_ips : t -> ip list

(** Convert a list of ips to a t *)
val from_ips : ip list -> t

(** Get the list of elements in the t *)
val elements : t -> elt list

(** Number of elements in a ip t *)
val cardinal : t -> int

(** Test if a range can be represented by just one ip / mask *)
val is_network_range : elt -> bool

(** Unit tests *)
val test : OUnit2.test
