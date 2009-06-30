open Printf 
open Big_int

type mask = int

(* Maybe this should be an array *)
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

(* Functions related to IPv6 addresses *)
let intersection (low_a, high_a) (low_b, high_b) =
  let low = max_big_int low_a low_b in
  let high = min_big_int high_a high_b in
    
    if le_big_int low high then Some(low, high)
    else None

let clear_bits ip bits =
  let mask = power_int_positive_int 2 bits in
    mult_big_int (div_big_int ip mask) mask

let set_bits ip bits = 
  let mask = power_int_positive_int 2 bits in
    add_big_int (pred_big_int mask) (clear_bits ip bits)
    
let to_range (ip, mask) =
(*
  let rec build_range low high mask = function      
      x :: xs when mask = 0 -> build_range (x :: low) (x :: high) mask xs
    | x :: xs when mask < 16 -> let mask' = get_mask (mask) in          
        build_range (x lor mask' :: low) (x land (0xffff - mask') :: high) 0 xs
    | x :: xs -> build_range (0 :: low) (0xffff :: high) (mask - 16) xs
    | [] -> (to_number low, to_number high)
        
  in build_range [] [] mask (List.rev ip)
*)
  (clear_bits ip mask, set_bits ip mask)

let to_string ip = 
  (String.concat ":" (List.map (Printf.sprintf "%04x") (to_ip ip)))

let range_to_string (low, high) = 
  (to_string low) ^ " => " ^ (to_string high) 

let range2mask (low,high) =
  let two = big_int_of_int 2 in
  let rec get_highest_bit acc n =
    if eq_big_int n zero_big_int then acc
    else get_highest_bit (acc + 1) (div_big_int n two)
  in
  let mask = get_highest_bit 0 (sub_big_int high low) in
  let high' = add_big_int low (pred_big_int (power_int_positive_int 2 mask)) in
    if eq_big_int high high' then Some(low, mask)
    else None
(*
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
*)
