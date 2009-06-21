open Printf

exception InternalError

type id = string * Lexing.position

exception ParseError of string * id

let error2string (err, (id, pos)) =
    sprintf "File \"%s\", line %d:\nError %s. Id was %s" pos.Lexing.pos_fname pos.Lexing.pos_lnum err id 

type ip = int list * int

let ip_to_string (a, m) = 
  (String.concat ":" (List.map (sprintf "%x") a)) ^ (sprintf "/%d" m) 

module Id_set = Set.Make (struct
  type t = id
  let compare = fun (a, _) (b, _) -> String.compare a b
 end)

module Id_map = Map.Make (struct
  type t = id
  let compare = fun (a, _) (b, _) -> String.compare a b
 end)


let id2str (str, _) = str



