(** General functions *)
open Batteries
open Printf

type id = string

exception ParseError of (string * id option * Lexing.position option)
let parse_error ?pos ?id str = raise (ParseError (str, id, pos))

(* Place these in a const.ml *)
let tcp = 6
let udp = 17
let icmp = 58

let error2string (error, id, pos) =
  let prefix = Option.map_default
      (fun pos -> sprintf "File \"%s\", line %d" pos.Lexing.pos_fname pos.Lexing.pos_lnum)
      "Unknown location" pos
  in
  let postfix = Option.map_default (sprintf "'%s'") "" id in
  sprintf "%s: %s %s" prefix error postfix

let ints_to_string ints =
 String.concat "," (List.map string_of_int ints)

let eq_id_list lst lst' =
  Set.equal (Set.of_list lst) (Set.of_list lst')

let member eq_oper x lst =
  List.exists (fun x' -> eq_oper x x') lst

let difference eq_oper a b =
  List.filter (fun x -> not (member eq_oper x b) ) a

let intersection eq_oper a b =
  List.filter ( fun x -> member eq_oper x b ) a

let union eq_oper a b =
  a @ (difference eq_oper b a)

(** Determine if a is a true subset of b *)
let is_subset eq_oper a b =
  List.for_all (fun x -> member eq_oper x b ) a

(** Group items into lists of identical elemenets *)
let rec group eq_oper acc = function
  | x :: xs ->
      let lst, rest = List.partition (eq_oper x) xs in
        group eq_oper ((x :: lst) :: acc) rest
  | [] -> acc

(** Create as few lists as possible with no identical items *)
let uniq eq_oper lst =
  let rec uniq' acc1 acc2 xs =
    match (acc2, xs) with
    | [], [] -> []
    | _, [] :: ys -> uniq' acc1 acc2 ys
    | _, (x :: xs) :: ys -> uniq' (x :: acc1) (xs :: acc2) ys
    | _, [] -> acc1 :: uniq' [] [] acc2
  in
  uniq' [] [] (group eq_oper [] lst)

(** Like a regular map, but filter exceptions *)
let map_filter_exceptions func list =
  let rec map acc = function
    | x :: xs -> begin
        try map ((func x) :: acc) xs
        with _ -> map acc xs
      end
    | [] -> List.rev acc
  in map [] list
