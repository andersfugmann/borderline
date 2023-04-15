(** General functions *)
open Base
open Printf

type id = string

exception ParseError of (string * id option * Lexing.position option)
let parse_error ?pos ?id str = raise (ParseError (str, id, pos))

let error2string (error, id, pos) =
  let prefix =
    let open Lexing in
    Option.value_map ~default:"Unknown location"
      ~f:(fun pos -> sprintf "File \"%s\", line %d:%d" pos.pos_fname pos.pos_lnum
             (pos.pos_cnum - pos.pos_bol))
      pos
  in
  let postfix = Option.value_map ~default:"" ~f:(sprintf "'%s'") id in
  sprintf "%s: %s %s" prefix error postfix

(** Group items into lists of identical elemenets *)
let rec group eq_oper acc = function
  | x :: xs ->
      let lst, rest = List.partition_tf ~f:(eq_oper x) xs in
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
