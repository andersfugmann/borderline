open Common
open Frontend_types
open Frontend

let rec get_zone_ids acc = function
    Zone (id, _) :: xs -> get_zone_ids (Id_set.add id acc) xs
  | _ :: xs -> get_zone_ids acc xs
  | [] -> acc

let rec get_ids = function
    Id id :: xs -> id :: get_ids xs
  | _ :: xs -> get_ids xs
  | [] -> []

let rec get_referenced_ids node =
  let rec get_id acc = function
      Reference id -> Id_set.add id acc
    | Filter (_, TcpPort ports, _) -> List.fold_left (fun acc id -> Id_set.add id acc) acc (get_ids ports)
    | Filter (_, UdpPort ports, _) -> List.fold_left (fun acc id -> Id_set.add id acc) acc (get_ids ports)
    | Protocol (protos, _) -> List.fold_left (fun acc id -> Id_set.add id acc) acc (get_ids protos)
    | _ -> acc
  in
  match node with
      DefineStms _ as x -> fold get_id [ x ] Id_set.empty
    | DefineInts (id, ports) -> List.fold_left (fun acc id -> Id_set.add id acc) Id_set.empty (get_ids ports)
    | x -> fold get_id [ x ] Id_set.empty

let rec get_referenced_zones nodes =
  let rec get_id acc = function
      Filter (_, FZone id, _) -> Id_set.add id acc
    | _ -> acc
  in
    fold get_id nodes Id_set.empty

let rec detect_cyclic_references id_func defines seen elem =
  let recurse id =
    let next_elem = try Id_map.find id defines with Not_found -> raise (ParseError [("Unknown reference to definition", id)]) in
      match List.mem id seen with
          true -> raise (ParseError (("Cyclic reference", id) :: List.rev_map (fun id' -> ("Referenced from", id')) seen))
        | false -> detect_cyclic_references id_func defines (seen @ [id]) next_elem
  in
    List.iter recurse (id_func elem)

let test_unresolved_zone_references nodes =
  let zone_ids = get_zone_ids Id_set.empty nodes in
  let zone_refs = get_referenced_zones nodes in
    match Id_set.elements (Id_set.diff zone_refs zone_ids) with
        [] -> ()
      | diff -> raise (ParseError (List.map (fun id -> ("Unresolved zone reference", id)) diff))

let rec test_shadow_defines acc nodes =
  let get_id id = Id_set.fold (fun elt acc -> if eq_id elt acc then elt else acc) acc id
  in
  let test id = if Id_set.mem id acc then
                    raise (ParseError [("Definition shadows previous definition", id);
                                       ("Definition first seen here", get_id id)])
                 else ()
  in
    match nodes with
        DefineStms (id, _) :: xs -> test id; test_shadow_defines (Id_set.add id acc) xs
      | DefineInts (id, _) :: xs -> test id; test_shadow_defines (Id_set.add id acc) xs
      | _ :: xs -> test_shadow_defines acc xs
      | [] -> ()

let validate nodes =
  let defines = create_define_map nodes in
  let entries = List.map (fun (t, r, p) -> Process(t, r, p)) (Rule.filter_process nodes) in
    test_shadow_defines Id_set.empty nodes;
    test_unresolved_zone_references nodes;
    List.iter (fun entry -> detect_cyclic_references (fun node -> Id_set.elements (get_referenced_ids node)) defines [] entry) entries

