(* Geneal functions *)

open Printf

type id = string * Lexing.position

exception ParseError of (string * id) list

let tcp = 6
let udp = 17
let icmp6 = 58

let rec join sep = function
    x :: [] -> x
  | x :: xs -> x ^ sep ^ (join sep xs) 
  | [] -> "" 

let error2string errors =
  let err2str (err, (id, pos)) = sprintf "File \"%s\", line %d: Error. %s '%s'" pos.Lexing.pos_fname pos.Lexing.pos_lnum err id
  in
    String.concat "\n" (List.map err2str errors)

module Id_set = Set.Make (struct
  type t = id
  let compare = fun (a, _) (b, _) -> String.compare a b
 end)

module Id_map = Map.Make (struct
  type t = id
  let compare = fun (a, _) (b, _) -> String.compare a b
 end)

let id2str (str, _) = str

let ints_to_string ints =
 String.concat "," (List.map string_of_int ints)

let eq_id (a, _) (b, _) = a = b

let idset_from_list lst =
  List.fold_left (fun acc id -> Id_set.add id acc) Id_set.empty lst

let eq_id_list lst lst' = 
  Id_set.equal (idset_from_list lst) (idset_from_list lst')

let combinations a b =
  List.flatten (List.map (fun x -> List.map (fun y -> (x, y)) b) a)

let member eq_oper x lst =
  List.exists (fun x' -> eq_oper x x') lst

let difference eq_oper a b =
  List.filter (fun x -> not (member eq_oper x b) ) a

let intersection eq_oper a b =
  List.filter ( fun x -> member eq_oper x b ) a

let union eq_oper a b = 
  a @ (difference eq_oper b a)

(* Determine if a is a true subset of b *)
let is_subset eq_oper a b =
  List.for_all (fun x -> member eq_oper x b ) a

let has_intersection eq_oper a b =
  not (intersection eq_oper a b = [])

(* Group items into lists of identical elemenets *)
let rec group eq_oper acc = function
    x :: xs ->
      let lst, rest = List.partition (eq_oper x) xs in
        group eq_oper ((x :: lst) :: acc) rest
  | [] -> acc

(* Create as few lists as possible with no identical items *)
let uniq eq_oper lst =
  let rec uniq' acc1 acc2 xs =
    match (acc2, xs) with
        [], [] -> []
      | _, [] :: ys -> uniq' acc1 acc2 ys
      | _, (x :: xs) :: ys -> uniq' (x :: acc1) (xs :: acc2) ys
      | _, [] -> acc1 :: uniq' [] [] acc2
  in
  uniq' [] [] (group eq_oper [] lst)

(* Like a regular map, but filter exceptions *)
let map_filter_exceptions func list =
  let rec map acc = function
    | x :: xs -> begin
        try map ((func x) :: acc) xs
        with _ -> map acc xs
      end
    | [] -> List.rev acc
  in map [] list


(* Simple identity function *)
let identity a = a

let keys map =
 Id_map.fold (fun key _ acc -> key :: acc) map [] 
