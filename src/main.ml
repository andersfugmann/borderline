open Parse
open Frontend
open Zone
open Emit
open Printf
 
let _ = 
  let nodes = parse "test.bl" in
  let zones = List.filter ( function node -> match node with Zone(_,_) -> true | _ -> false ) nodes in
  let _ = List.map pretty_print zones in
    printf "%s\n" ( emit_chain ("table", "chain", List.map Zone.process_zone zones) )
