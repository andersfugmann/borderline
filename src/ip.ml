(**
   Define a set type for ip addresses.
*)

open Printf
open Big_int

(** Just add all the normal integer operations *)

let min = min_big_int
let max = max_big_int
let succ = succ_big_int 
let pred = pred_big_int

let (<) = lt_big_int
let (<=) = le_big_int
let (>) = gt_big_int
let (>=) = ge_big_int

(* The empty set *)
let empty = []

type number = big_int 
type mask = int
type t = (big_int * mask)
type range = (number * number)

(** Define the set type *)
type set = range list 

(** Number of bits in ip number *)
let bits = 128

let field_size = 16
let sep = ":"

(** Number of elements in a ip set *)
let size = List.length

(** Print out a set in human readable form *)

let ip_of_string ip : big_int =
  List.fold_left (fun acc num -> add_int_big_int num (shift_left_big_int acc field_size)) zero_big_int ip  
  
(** Ip to string *)
let string_of_ip ip = 
  let mask = pred (power_int_positive_int 2 field_size) in
  let rec to_list ip = function 
    | 0 -> []
    | n -> int_of_big_int (and_big_int ip mask) :: to_list (shift_right_big_int ip 16) (n - field_size)
  in
  String.concat sep (List.map string_of_int (to_list ip bits))

(** Range to string *)
let string_of_range (low, high) = Printf.sprintf "(%s/%s)" (string_of_big_int low) (string_of_big_int high)

(** Set to string *)
let to_string set = String.concat "::" (List.map string_of_range set)

(** Add an ip number to the set *)
let rec add (low', high') = function
  | (low, high) :: xs when (succ high') < low -> (low', high') :: (low, high) :: xs
  | (low, high) :: xs when (succ high) < low' -> (low, high) :: add (low', high') xs
  | (low, high) :: xs -> add (min low low', max high high') xs 
  | [] -> [ (low', high') ]

(** Remove elements from the set *)
let rec sub (low', high') = function
  | (low, high) :: xs when high' < low -> (low, high) :: xs
  | (low, high) :: xs when high < low' -> (low, high) :: sub (low', high') xs
  | (low, high) :: xs when low < low' && high' < high -> (low, pred low') :: (succ high', high) :: xs
  | (low, high) :: xs when low' <= low && high' < high -> (succ high', high) :: xs
  | (low, high) :: xs when low < low' -> (low, pred low') :: sub (low', high') xs
  | (low, high) :: xs (* when low' <= low *) -> sub (low', high') xs
  | [] -> []

(** Return how much of the given range is part of the set *)
let rec part (low', high') = function 
  | (low, high) :: xs when high' < low -> part (low', high') xs
  | (low, high) :: xs when high < low' -> []
  | (low, high) :: xs -> (max low low', min high high') :: part (low', high') xs
  | [] -> []

(** A U B *)
let union a b = List.fold_right add a b

(** A but not B *)
let difference a b = List.fold_right sub b a

(** Intersection between A and B *)
let intersection a b =
  List.fold_left (fun acc e -> acc @ part e a) [] b

(** Test if a is a subset of b *) 
let rec subset a b =
  match (a, b) with
    | (low, high) :: xs, (low', high') :: xs' when high' < low -> subset ((low, high) :: xs) xs'
    | (low, high) :: xs, (low', high') :: xs' when low' <= low && high <= high' -> subset xs ((low', high') :: xs')
    | [], _ -> true
    | _, _ -> false 
  
(** Test for set equality *)
let equality a b = 
  subset a b && subset b a
  
(** Convet an ip addres and mask to an iprange *)
let to_range (ip, mask) =
  let mask = pred (power_int_positive_int 2 (bits - mask)) in
  let high = or_big_int ip mask in
  let low = xor_big_int high mask in
  (low, high)

(** Convert a set to a list of ips *)
let to_ips set = 
  let rec inner mask = function
    | [] -> []
    | ((low, high) :: xs) as lst -> 
      let ip = (low, mask) in
      let range = to_range ip in begin
        match subset [ range ] lst with
          | true -> ip :: inner 0 (sub range lst) 
          | false -> inner (mask + 1) lst
      end
  in
  inner 0 set
(** Allow access to ranges in the set *)
let to_ranges set = set


(** Convert a list of ips to a set *)
let set_of_ips ips =
  List.fold_left (fun acc ip -> add (to_range ip) acc) empty ips
    
(** Test *) 
let tests = 
  let r2br (a, b) = (big_int_of_int a, big_int_of_int b) in   
  let open OUnit in
  "Generic ip numbers" >::: [
    "Insertion" >:: ( fun () -> 
      let set = add (r2br (3, 5)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add (r2br (1, 2)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add (r2br (6, 10)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add (r2br (20, 100)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (size set);
      let set = add (r2br (11, 19)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add (r2br (50, 80)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add (r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      ()
    );
    "Removal" >:: ( fun () -> 
      let set = add (r2br (100, 200)) empty in
      let set = sub (r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = sub (r2br (170, 250)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = sub (r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (size set);
      let set = sub (r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (size set);
      ()
    );
    "Intersection" >:: ( fun () -> 
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (300, 400)) set1 in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size (intersection set1 set2));

      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (150, 250)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size (intersection set1 set2));
      ()
    );

    "Equality" >:: (fun () ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (300, 400)) set1 in
      assert_bool "Sets should be different" (not (equality set1 set2));

      let set1 = add ( r2br (250, 350)) empty in
      assert_bool "Sets should be different" (not (equality set1 set2));
      
      let set2 = add ( r2br (250, 350)) empty in
      assert_bool "Sets should be equal" (equality set1 set2);
      assert_bool "Sets should be equal" (equality set2 set1);
      assert_bool "Sets should be equal" (equality set1 set1);
      assert_bool "Sets should be equal" (equality set2 set2);
      ()
    );

    "Subset" >:: (fun () ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (150, 190)) empty in
      assert_bool "Set1 should not be a subset of set2" (not (subset set1 set2));
      assert_bool "Set2 should be a subset of set1" (subset set2 set1);
      
      let set2 = add ( r2br (150, 210)) empty in
      assert_bool "Set2 should now be a subset of set1" (not (subset set2 set1));
      assert_bool "Set1 should now be a subset of set2" (not (subset set1 set2));

      let set2 = add ( r2br (90, 190)) empty in
      assert_bool "Set2 should now be a subset of set1" (not (subset set2 set1));
      assert_bool "Set1 should be a subset of set1" (subset set1 set1);

      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (100, 100)) empty in
      assert_bool "Set2 should be a subset of set1" (subset set2 set1);

      ()
    ); 

    "Set to ip list" >:: (fun () ->
      let set = add (r2br (10000, 20000)) empty in
      let ips = to_ips set in
      let set2 = List.fold_left (fun set range -> add range set) empty (List.map to_range ips) in
      assert_bool "Sets must be equal" (equality set set2);
      ()
    );
      
  ]

