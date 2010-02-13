type mask = int
type ip_number = Big_int.big_int
type ip = ip_number * mask
val eq : ip_number -> ip_number -> bool
val get_mask : int -> int
val to_number : int list -> ip_number
val to_ip : ip_number -> int list
val to_string : ip_number -> string
val range_to_string : ip_number * ip_number -> string
val difference : ip_number * ip_number -> ip_number * ip_number -> (ip_number * ip_number) list
val intersection : ip_number * ip_number -> ip_number * ip_number -> (ip_number * ip_number) option
val clear_bits : ip_number -> int -> ip_number
val set_bits : ip_number -> int -> ip_number
val to_range : ip_number * int -> ip_number * ip_number
val range2mask : ip_number * ip_number -> (ip_number * int) option
val list_intersection : (ip_number * ip_number) list -> (ip_number * ip_number) list -> (ip_number * ip_number) list
val list_difference : (ip_number * ip_number) list -> (ip_number * ip_number) list -> (ip_number * ip_number) list
