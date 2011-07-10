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
let (==) = eq_big_int

(* The empty set *)
let empty = []

type iprange = (big_int * big_int)

(** Define the set type *)
type t = iprange list 

(** Number of elements in a ip set *)
let size = List.length

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

(** True subset - All elements in a contained in b *)
(*let subset a b =
  let rec subset  
*)
(** Clear lower bits *)  
let clear_bits ip bits =
  let mask = power_int_positive_int 2 (128 - bits) in
  mult_big_int (div_big_int ip mask) mask
      
(** Set lower bits *)
let set_bits ip bits =
  let mask = power_int_positive_int 2 (128 - bits) in
  add_big_int (pred_big_int mask) (clear_bits ip bits)

(** Convet an ip addres and mask to an iprange *)
let to_range (ip, mask) =
  (clear_bits ip mask, set_bits ip mask)

let to_string set = 
  String.concat "::" (List.map (fun (a,b) -> Printf.sprintf "(%s, %s)" (string_of_big_int a) (string_of_big_int b)) set)


(** Convert a range to a list of ip-addresses/masks *)
let rec to_ip = function
  | x :: xs -> 
  


let tests = 
  let r2br (a, b) = (big_int_of_int a, big_int_of_int b) in   
  let open OUnit in
  "Generic ip numbers" >::: [
    "Insertion" >:: ( fun () -> 
      let set = add ( r2br (1, 10)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add ( r2br (20, 100)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (size set);
      let set = add ( r2br (11, 19)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add ( r2br (50, 80)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = add ( r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      ()
    );
    "Removal" >:: ( fun () -> 
      let set = add ( r2br (100, 200)) empty in
      let set = sub ( r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = sub ( r2br (170, 250)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (size set);
      let set = sub ( r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (size set);
      let set = sub ( r2br (155, 165)) set in
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
      
  ]

      
      
