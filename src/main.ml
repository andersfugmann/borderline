open Parse
open Frontend
open Zone
open Iptables
open Printf
 
let _ = 
  let nodes = parse "test.bl" in
  let zones = List.filter ( function node -> match node with Zone(_,_) -> true | _ -> false ) nodes in
  let _ = List.map pretty_print zones in
  let _ = Zone.emit_zones zones in
    List.iter (Printf.printf "%s\n") (Chain.emit Iptables.emit_chain)

