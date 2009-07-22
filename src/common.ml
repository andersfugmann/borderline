open Printf

exception InternalError

type id = string * Lexing.position

exception ParseError of (string * id) list

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

let eq_id (a, _) (b, _) = a = b

let equality a b = a = b

let combinations acc conds : 'a list = 
    List.flatten (List.map (fun acc -> List.map (fun cl -> acc @ [cl]) conds) acc)

let member eq_oper x lst =
  List.exists (fun x' -> eq_oper x x') lst

let difference eq_oper a b = 
  List.filter (fun x -> not (member eq_oper x b) ) a
    
let intersection eq_oper a b = 
  List.filter ( fun x -> member eq_oper x b ) a

(* Determine if a is a true subset of b *)
let is_subset eq_oper a b = 
  List.for_all (fun x -> member eq_oper x b ) a

let has_intersection eq_oper a b =
  not (intersection eq_oper a b = [])



