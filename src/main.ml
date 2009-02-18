open Parse
open Frontend
open Zone
open Printf
 
let _ = 
  let nodes = parse "test.bl" in
  let zones = List.filter ( function node -> match node with Zone(_,_) -> true | _ -> false ) nodes in
    List.map pretty_print zones; 
