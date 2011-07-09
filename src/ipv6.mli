(** Type of mask *)
type mask = int

(** raw ip number representation. Consider making it private *) 
type ip_number = Big_int.big_int

(** Ip number with mask *)
type ip = ip_number * mask

(** Test for equality *)
val eq : ip_number -> ip_number -> bool

(** Extract the mask *)
val get_mask : int -> int

(** Convert a list of decimals to an ip number *)
val to_number : int list -> ip_number

(** Convert an ip number to a list of ints *)
val to_ip : ip_number -> int list

(** To string *)
val to_string : ip_number -> string

(** Convert a range to string *)
val range_to_string : ip_number * ip_number -> string

(** A / B *)
val difference : ip_number * ip_number -> ip_number * ip_number -> (ip_number * ip_number) list

(** Intersection between two ip number ranges *)
val intersection : ip_number * ip_number -> ip_number * ip_number -> (ip_number * ip_number) option

(** Clear the lower bits *)
val clear_bits : ip_number -> int -> ip_number

(** Set the lower bits *)
val set_bits : ip_number -> int -> ip_number

(** Convert a ipnumber / mask to a range *)
val to_range : ip -> ip_number * ip_number

(** Convert a range to mask if possible *)
val range2mask : ip_number * ip_number -> (ip_number * int) option

(** Intersection between list of ip ranges A and ip ranges B *)
val list_intersection : (ip_number * ip_number) list -> (ip_number * ip_number) list -> (ip_number * ip_number) list

(** Difference between set of ip ranges A and set of ip ranges B *)
val list_difference : (ip_number * ip_number) list -> (ip_number * ip_number) list -> (ip_number * ip_number) list

