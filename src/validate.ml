(* Function for validating the AST *)

open Common
open Frontend_types
open Frontend


(* To make sure the graph does not contain any cycles, a list of
   visited nodes (id's) is maintained. The \verb|mark_seen| function
   either lists the cyclic reference or adds the new node to the list
   of visited nodes.
*)
let mark_seen id seen =
  match List.mem id seen with
      true -> raise (ParseError (("Cyclic reference", id) :: (List.map (fun id' -> ("Referenced from", id')) seen)))
    | false -> id :: seen

(* Create a map of defines. While creating the map, make sure that no
   defines are shadowed by other defines (defines with the same map,
   the function only adds a new id to the map if the id was not there
   already. If the id was present, a ParseError exception is raised in
   order to stop processing).
*)
let add_id_to_map id def map =
  match Id_map.mem id map with
      true -> raise (ParseError [("Defintion shadows previous definition", id)])
    | false -> Id_map.add id def map

let rec create_define_map_rec acc = function
    DefineStms (id, _) as def :: xs -> create_define_map_rec (Id_map.add id def acc) xs
  | DefineList (id, _) as def :: xs -> create_define_map_rec (Id_map.add id def acc) xs
  | DefinePolicy (id, _) as def :: xs -> create_define_map_rec (Id_map.add id def acc) xs
  | _ :: xs -> create_define_map_rec acc xs
  | [] -> acc
      
(* As the recursive version of the fuction needs an accumulator, add a
   function to hide this to users. *)

let create_define_map = create_define_map_rec Id_map.empty
  
(* Expand and validation is the same problem, and should be solved as
   such.  We need to have a system that eases the task of describing
   the allowed constructs. *)

let expand nodes =
  let zones = Zone.create_zone_set nodes in
  let defines = create_define_map nodes in

  let rec expand_rules id =
    try begin match Id_map.find id defines with

        (* Expand single id reference into something sematically
           corect. This allows simple definitions to work as aliases
           for other types of definitions. It is important that the
           function does not resolve the id here, as the system would
           then end up in a infinite loop on recursive aliases (e.g
           \verb|define a = a|. Returning a virtual node allows the id
           to be inserted into the list of visited nodes, and cyclic
           reference dectection will prevent infinite loops, and allow
           error reporting to the users. *)

        DefineList (_, [ Id id ]) -> [ Reference id ]
      | DefineStms (_, x) -> x
      | _ -> raise (ParseError [("Reference to Id of wrong type", id)])
    end with
        _ -> raise (ParseError [("Reference to unknown id", id)])
  in
  let expand_list id =
    try begin match Id_map.find id defines with
        DefineList (id', x) -> x
      | _ -> raise (ParseError [("Reference to Id of wrong type", id)])
    end with
        _ -> raise (ParseError [("Reference to unknown id", id)])
  in
  let expand_policy id =
    try begin match Id_map.find id defines with

        (* As before; allow simple defines work as aliases. *)
        DefineList (_, [ Id id ]) -> [ Ref id ]
      | DefinePolicy (id', x) -> x
      | _ -> raise (ParseError [("Reference to Id of wrong type", id)])
    end with
        _ -> raise (ParseError [("Reference to unknown id", id)])
  in

  (* As part of expanding the rules, a set of function to expand a
     list into more concreete data (such as list of ints, or list of
     addresses) are defined. *)

  let rec expand_int_list seen = function
      Id id :: xs -> (expand_int_list (mark_seen id seen) (expand_list id)) @ (expand_int_list seen xs)
    | Number _ as n :: xs -> n :: expand_int_list seen xs
    | Ip (_, pos) :: xs -> raise (ParseError [("Found ip address, expected integer", ("", pos))])
    | [] -> []
  in
  let rec expand_address_list seen = function
      Id id :: xs -> (expand_address_list (mark_seen id seen) (expand_list id)) @ (expand_address_list seen xs)
    | Number (_, pos) :: xs -> raise (ParseError [("Find integer, expected ip address ", ("", pos))])
    | Ip _ as ip :: xs -> ip :: expand_address_list seen xs
    | [] -> []
  in
  let rec expand_zone_list seen = function
      Id id as _id :: xs when Id_set.mem id zones -> _id :: expand_zone_list seen xs
    | Id id :: xs -> (expand_zone_list (mark_seen id seen) (expand_list id)) @ (expand_zone_list seen xs)
    | Number (_, pos) :: xs -> raise (ParseError [("Find integer, expected ip address ", ("", pos))])
    | Ip (_, pos) :: xs -> raise (ParseError [("Found ip address, expected integer", ("", pos))])
    | [] -> []
  in
  let rec expand_policy_list seen = function
      Ref id :: xs -> (expand_policy_list (mark_seen id seen) (expand_policy id)) @ (expand_policy_list seen xs)
    | x :: xs -> x :: expand_policy_list seen xs
    | [] -> []
  in
  let rec expand_rule_list seen rules =
    let expand_rule = function
        Reference _ -> assert false
      | Filter (dir, TcpPort ports, pol) -> Filter (dir, TcpPort (expand_int_list seen ports), pol)
      | Filter (dir, UdpPort ports, pol) -> Filter (dir, UdpPort (expand_int_list seen ports), pol)
      | Filter (dir, FZone zones, pol) -> Filter (dir, FZone (expand_zone_list seen zones), pol)
      | Filter (dir, Address addr_list, pol) -> Filter (dir, Address (expand_address_list seen addr_list), pol)
      | Protocol (protos, pol) -> Protocol (expand_int_list seen protos, pol)
      | IcmpType (types, pol) -> IcmpType (expand_int_list seen types, pol)
      | State _ as state -> state
      | Rule (rls, pols) -> Rule (expand_rule_list seen rls, expand_policy_list seen pols)
      | TcpFlags ((flags, mask), pol) -> TcpFlags ((expand_int_list seen flags, expand_int_list seen mask), pol) 
    in
      match rules with
          Reference id :: xs -> (expand_rule_list (mark_seen id seen) (expand_rules id)) @ (expand_rule_list seen xs)
        | x :: xs -> expand_rule x :: expand_rule_list seen xs
        | [] -> []
  in

    (* When expanding zone definitions, there is no need to carry a
    seen list, as zone stems are not recursive types. *)

  let rec expand_zone_stms = function
      Interface _ as i :: xs -> i :: expand_zone_stms xs 
    | Network _ as i :: xs -> i :: expand_zone_stms xs
    | ZoneRules (t, rules, policies) :: xs -> 
        ZoneRules (t, expand_rule_list [] rules, expand_policy_list [] policies) :: expand_zone_stms xs
    | [] -> []
  in
  let rec expand_nodes = function
      DefineStms (id, _) :: xs -> expand_nodes xs
    | DefineList (id, _) :: xs -> expand_nodes xs
    | DefinePolicy (id, _) :: xs -> expand_nodes xs
    | Process (t, rules, policies) :: xs -> Process (t, expand_rule_list [] rules, expand_policy_list [] policies) :: expand_nodes xs
    | Import _ :: _ -> assert false
    | Zone (id, zone_stms) :: xs -> Zone(id, expand_zone_stms zone_stms) :: expand_nodes xs
    | [] -> []
  in
    expand_nodes nodes
