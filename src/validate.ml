open Common
open Frontend

(* exception ParseError of string * int *)

(* Need to traverse the tree. If we encounter a unresolvable zone, raise and exception. *)
(* Can we detect cyclic references at the same time? *)

let rec get_zone_ids acc = function
    Zone (id, _) :: xs -> get_zone_ids (Id_set.add id acc) xs
  | _ :: xs -> get_zone_ids acc xs
  | [] -> acc


let rec get_referenced_ids nodes =
  let rec get_id acc = function
      Reference id -> Id_set.add id acc
    | _ -> acc
  in 
    fold get_id nodes Id_set.empty

let rec get_referenced_zones nodes =
  let rec get_id acc = function
      Filter (_, FZone id) -> Id_set.add id acc
    | _ -> acc
  in 
    fold get_id nodes Id_set.empty 
    
let test_cyclic_references defines start =
  let rec test_define acc define = 
    let test id = 
      try test_define (Id_set.add id acc) (Define(id, Id_map.find id defines))
      with Not_found -> raise (ParseError ("Unknown reference to definition", id))
    in
    let references = get_referenced_ids [define] in

    let cyclic_references = Id_set.inter acc references in
      if not (Id_set.is_empty cyclic_references) then 
        raise (ParseError ("Cyclic reference", Id_set.choose cyclic_references)) (* Should add more info here *); 
      Id_set.iter test references
  in
    test_define Id_set.empty start

let test_unresolved_zone_references nodes = 
  let zone_ids = get_zone_ids Id_set.empty nodes in
  let zone_refs = get_referenced_zones nodes in
    try raise (ParseError ("Unresolved zone reference", Id_set.choose (Id_set.diff zone_refs zone_ids)))
    with Not_found -> () 

let validate nodes =
  let defines = create_define_map nodes in
  let entries = Rule.filter_process nodes in
    List.iter (test_cyclic_references defines) entries; 
    test_unresolved_zone_references nodes 
    

