(*i 
 * Copyright 2009 Anders Fugmann.
 * Distributed under the GNU General Public License v3 
 *  
 * This file is part of Borderline - A Firewall Generator
 * 
 * Borderline is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation. 
 *  
 * Borderline is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Borderline.  If not, see <http://www.gnu.org/licenses/>. 
i*)
open Printf
open Big_int

type mask = int

type ip_number = big_int
type ip = ip_number * mask

let eq a b = eq_big_int a b

let rec get_mask_rec acc = function
    0 -> acc
  | n -> get_mask_rec (2 * acc + 1) (n - 1)
let get_mask = get_mask_rec 0

let to_number ip : big_int =
  List.fold_left (fun acc num -> add_int_big_int num (mult_int_big_int 0x10000 acc)) zero_big_int ip

let to_ip num =
  let rec convert acc num =
    match List.length acc with
        8 -> acc
      | _ ->
          let (q,r) = quomod_big_int num (big_int_of_int 0x10000) in
            convert (int_of_big_int r :: acc) q
  in
    convert [] num

let to_string ip =
  let rec strip = function
      0 :: xs -> strip xs
    | n :: xs -> List.rev (n :: xs)
    | [] -> []
  in
  let ip_number = to_ip ip in
  let ip_number' = strip (List.rev ip_number) in
    String.concat ":" (List.map (Printf.sprintf "%04x") ip_number') ^ (if not (ip_number = ip_number') then "::" else "")


let range_to_string (low, high) =
  (to_string low) ^ " => " ^ (to_string high)


let difference (low_a, high_a) (low_b, high_b) =
  let member a (low, high) = ge_big_int a low && le_big_int a high in
  let low_m = member low_a (low_b, high_b) in
  let high_m = member high_a (low_b, high_b) in
    match (low_m, high_m) with
        true, true -> []
      | true, false -> [(succ_big_int high_b, high_a)]
      | false, true -> [(low_a, pred_big_int low_b)]
      | false, false when member low_b (low_a, high_a) ->
          [(succ_big_int high_b, high_a); (low_a, pred_big_int low_b)]
      | false, false -> [(low_a, high_a)]

(* Functions related to IPv6 addresses *)
let intersection (low_a, high_a) (low_b, high_b) =
  let low = max_big_int low_a low_b in
  let high = min_big_int high_a high_b in

    if le_big_int low high then Some(low, high)
    else None

let clear_bits ip bits =
  let mask = power_int_positive_int 2 (128-bits) in
    mult_big_int (div_big_int ip mask) mask

let set_bits ip bits =
  let mask = power_int_positive_int 2 (128-bits) in
    add_big_int (pred_big_int mask) (clear_bits ip bits)

let to_range (ip, mask) =
(*i
  let rec build_range low high mask = function
      x :: xs when mask = 0 -> build_range (x :: low) (x :: high) mask xs
    | x :: xs when mask < 16 -> let mask' = get_mask (mask) in
        build_range (x lor mask' :: low) (x land (0xffff - mask') :: high) 0 xs
    | x :: xs -> build_range (0 :: low) (0xffff :: high) (mask - 16) xs
    | [] -> (to_number low, to_number high)

  in build_range [] [] mask (List.rev ip)
i*)
  (clear_bits ip mask, set_bits ip mask)

let range2mask (low, high) =
  let two = big_int_of_int 2 in
  let rec get_highest_bit acc n =
      if le_big_int n zero_big_int then acc
      else get_highest_bit (acc + 1) (div_big_int n two)
  in
  let mask = get_highest_bit 0 (sub_big_int high low) in
  let high' = add_big_int low (pred_big_int (power_int_positive_int 2 mask)) in
    if eq_big_int high high' then Some(low, 128-mask)
    else None

let list_intersection a b =
  let combs = Common.combinations a b in
  let intersect = List.map (fun (a,b) -> intersection a b) combs in
  let filtered = List.filter (fun x -> not (x = None)) intersect in
  List.map (fun x -> match x with Some(low, high) -> (low, high) | None -> failwith "Impossible state") filtered


let rec list_difference a b =
  match b with
      y :: ys -> list_difference (List.flatten (List.map (fun x -> difference x y) a)) ys
    | [] -> a

(*i
let () =
  let marvin = (to_number [0x2001;0x16d8;0xdd2d;0x0;0x2e0;0x4cff;0xfe69;0x103d], 128) in
  let network = (to_number [0x2001;0x16d8;0xdd2d;0x0;0x2e0;0x4cff;0xfe69;0x103d], 64) in
  printf "Marvin: %s\n" (to_string (fst marvin));
  printf "Marvin: %s\n" (to_string (to_number (to_ip (fst marvin))));
  let range = to_range network in
  printf "Range: %s\n" (range_to_string range);
    match range2mask range with
        Some(ip, mask) -> printf "Range: %s, %d\n" (to_string ip) mask
      | None -> printf "No range possible\n"
          ;
  match intersection (to_range marvin) (to_range network) with
      Some range -> Printf.printf "Intersection: %s\n" (range_to_string range)
    | None -> Printf.printf "No intersection\n"
i*)
