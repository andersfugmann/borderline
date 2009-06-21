open Common
open Frontend

(* exception ParseError of string * int *)

(* Need to traverse the tree. If we encounter a unresolvable zone, raise and exception. *)
(* Can we detect cyclic references at the same time? *)

let rec get_zone_ids acc = function
    Zone (id, _) :: xs -> get_zone_ids (Id_set.add id acc) xs
  | _ :: xs -> get_zone_ids acc xs
  | [] -> acc

let rec get_referenced_zones nodes =
  let rec get_id acc = function
      Filter (_, FZone id) -> Id_set.add id acc
    | _ -> acc
  in 
    rules_fold_left get_id Id_set.empty nodes

(* Test for any loops in the references. This can only occur in rule definitions. *) 
(* Assume defines to be a map id -> nodes *)

(* Need to be able to terminate compilation. We should really just raise an error *) 
let test_cyclic_references defines start =
  let print_cyclic_error id = prerr_endline (error2string ("Cyclic reference", id)) in (* Also print the referring def. *)
  let print_ref_error id = prerr_endline (error2string ("Unknown reference to definition", id)) in 
  let get_id acc = function 
      Reference id -> Id_set.add id acc 
    | _ -> acc
  in
  let get_references = rules_fold_left get_id Id_set.empty in
  let rec test_define acc define = 
    let references = get_references define in
    let cyclic_references = Id_set.inter acc references in
      (match Id_set.is_empty cyclic_references with
           false -> Id_set.iter print_cyclic_error cyclic_references
         | _ -> ()
      );
        Id_set.iter (fun id -> try test_define (Id_set.add id acc) (Id_map.find id defines)
                     with Not_found -> print_ref_error id) references
  in
    test_define Id_set.empty start

let test_unresolved_zone_references nodes = 
  let print_error id = prerr_endline (error2string ("Unresolved zone reference", id)) in
  let zone_ids = get_zone_ids Id_set.empty nodes in
  let zone_refs = get_referenced_zones nodes in
    Id_set.iter print_error (Id_set.diff zone_refs zone_ids)

let validate nodes =
  let defines = create_define_map Id_map.empty nodes in
  let entries = Rule.filter_process nodes in
    List.iter (test_cyclic_references defines) entries; 
    test_unresolved_zone_references nodes 
    

