(**
   Define a set type for ip addresses.
*)

open Printf
open Big_int

module type Ip_type =
  sig
    val bits : int
    val field_size : int
    val to_string : int list -> string
  end

module Ipv4 : Ip_type = struct
  let bits = 32
  let field_size = 8
  let to_string fields = String.concat "." (List.map (sprintf "%d") fields)
end

module Ipv6 : Ip_type = struct
  let bits = 128
  let field_size = 16
  let to_string fields = String.concat ":" (List.map (sprintf "%04x") fields)
end

module Make(Ip: Ip_type) =
struct

  let empty = []

  type number = big_int
  type mask = int
  type ip = (big_int * mask)
  type elt = (number * number)

  type t = elt list

  (** Just add all the normal integer operations. The is just for convenience *)

  let min = min_big_int
  let max = max_big_int
  let succ = succ_big_int
  let pred = pred_big_int

  let (<) = lt_big_int
  let (<=) = le_big_int
  let (=) = eq_big_int
  let (-) = sub_big_int
  let (&) = and_big_int

  let (-|) = Pervasives.(-)
  let (+|) = Pervasives.(+)


  let cardinal = List.length

(** Normalize the set, Removing overlaps, and merging ranges if possible *)
  let rec normalize = function
    | (low, high) :: (low', high') :: xs when (succ high) < low' -> (low, high) :: normalize ((low', high') :: xs)
    | (low, high) :: (_low', high') :: xs -> normalize ((low, max high high') :: xs)
    | set -> set

  let rec add (low', high') = function
    | (low, high) :: xs when (succ high') < low -> (low', high') :: (low, high) :: xs
    | (low, high) :: xs when (succ high) < low' -> (low, high) :: add (low', high') xs
    | (low, high) :: xs -> add (min low low', max high high') xs
    | [] -> [ (low', high') ]

  let rec remove (low', high') = function
    | (low, high) :: xs when high' < low -> (low, high) :: xs
    | (low, high) :: xs when high < low' -> (low, high) :: remove (low', high') xs
    | (low, high) :: xs when low < low' && high' < high -> (low, pred low') :: (succ high', high) :: xs
    | (low, high) :: xs when low' <= low && high' < high -> (succ high', high) :: xs
    | (low, _high) :: xs when low < low' -> (low, pred low') :: remove (low', high') xs
    | (_low, _high) :: xs (* when low' <= low *) -> remove (low', high') xs
    | [] -> []

(** Return how much of the given range is part of the set *)
  let rec part (low', high') = function
    | (low, _high) :: xs when high' < low -> part (low', high') xs
    | (_low, high) :: _ when high < low' -> []
    | (low, high) :: xs -> (max low low', min high high') :: part (low', high') xs
    | [] -> []

  let union a b =
    let u = List.merge (fun (l, _h) (l', _h') -> compare_big_int l l') a b in
    normalize u

  let diff a b = List.fold_right remove b a

  let inter a b =
    List.fold_left (fun acc e -> acc @ part e a) [] b

  let rec subset a b =
    match (a, b) with
      | (low, high) :: xs, (_low', high') :: xs' when high' < low -> subset ((low, high) :: xs) xs'
      | (low, high) :: xs, (low', high') :: xs' when low' <= low && high <= high' -> subset xs ((low', high') :: xs')
      | [], _ -> true
      | _, _ -> false

  let equal a b =
    subset a b && subset b a


  let ip_of_string ip =
    List.fold_left (fun acc num -> add_int_big_int num (shift_left_big_int acc Ip.field_size)) zero_big_int ip

  let string_of_ip ip =
    let mask = pred (power_int_positive_int 2 Ip.field_size) in
    let rec to_list ip = function
      | 0 -> []
      | n -> int_of_big_int (and_big_int ip mask) :: to_list (shift_right_big_int ip Ip.field_size) (n -| Ip.field_size)
    in
    Ip.to_string (List.rev (to_list ip Ip.bits))

  let to_elt (ip, mask) =
    let mask = pred (power_int_positive_int 2 (Ip.bits -| mask)) in
    let high = or_big_int ip mask in
    let low = xor_big_int high mask in
    (low, high)


  let to_ips set =
    let rec inner mask = function
      | [] -> []
      | ((low, _high) :: _xs) as lst ->
        let ip = (low, mask) in
        let range = to_elt ip in begin
          match subset [ range ] lst with
            | true -> ip :: inner 0 (remove range lst)
            | false -> inner (mask +| 1) lst
        end
    in
    inner 0 set


  let singleton elt = [ elt ]

  let elements set = set

(** Convert a list of ips to a set *)
  let from_ips ips =
    let ranges = List.map to_elt ips in
    (* Sort the ranges *)
    let ranges = List.sort (fun (l, _h) (l', _h') -> compare_big_int l l') ranges in
    normalize ranges

  let is_network_range (low, high) =
    let diff = high - low in
  (* Basically, diff must be all ones. *)
    ((succ diff) & diff) = zero_big_int

end

(** Be a IPv6_set.. *)
include Make(Ipv6)

(** Test *)
let test =
  let r2br (a, b) = (big_int_of_int a, big_int_of_int b) in
  let open OUnit in
  "Generic ip numbers" >::: [
    "Insertion" >:: ( fun () ->
      let set = add (r2br (3, 5)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (1, 2)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (6, 10)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (20, 100)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (cardinal set);
      let set = add (r2br (11, 19)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (50, 80)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      ()
    );
    "Removal" >:: ( fun () ->
      let set = add (r2br (100, 200)) empty in
      let set = remove (r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = remove (r2br (170, 250)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = remove (r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (cardinal set);
      let set = remove (r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (cardinal set);
      ()
    );
    "Intersection" >:: ( fun () ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (300, 400)) set1 in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal (inter set1 set2));

      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (150, 250)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal (inter set1 set2));
      ()
    );

    "Equality" >:: (fun () ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (300, 400)) set1 in
      assert_bool "Sets should be different" (not (equal set1 set2));

      let set1 = add ( r2br (250, 350)) empty in
      assert_bool "Sets should be different" (not (equal set1 set2));

      let set2 = add ( r2br (250, 350)) empty in
      assert_bool "Sets should be equal" (equal set1 set2);
      assert_bool "Sets should be equal" (equal set2 set1);
      assert_bool "Sets should be equal" (equal set1 set1);
      assert_bool "Sets should be equal" (equal set2 set2);
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
      let set2 = from_ips ips in
      assert_bool "Sets must be equal" (equal set set2);
      ()
    );
  ]
