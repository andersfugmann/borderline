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
      (fun pos -> sprintf "File \"%s\", line %d:%d" pos.Lexing.pos_fname pos.Lexing.pos_lnum
          (pos.Lexing.pos_cnum - pos.Lexing.pos_bol))
      "Unknown location" pos
  in
  let postfix = Option.map_default (sprintf "'%s'") "" id in
  sprintf "%s: %s %s" prefix error postfix

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
