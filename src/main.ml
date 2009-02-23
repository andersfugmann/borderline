open Parse
open Frontend
open Zone
open Emit
open Printf
 
let _ = 
  let nodes = parse "test.bl" in
  let zones = List.filter ( function node -> match node with Zone(_,_) -> true | _ -> false ) nodes in
  let _ = List.map pretty_print zones in
  let src_zone_chain, dst_zone_chain = Zone.emit_zones zones in
  let data = List.flatten (List.map emit_chain [src_zone_chain; dst_zone_chain]) in
    List.map (printf "%s\n") data

