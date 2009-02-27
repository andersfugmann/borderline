open Parse
open Frontend
open Zone
open Iptables
open Printf
open Chain
 
let _ = 
  let nodes = parse "test.bl" in
  let zones = List.filter ( function node -> match node with Zone(_,_) -> true | _ -> false ) nodes in
  (* Only one filter set - please *)
  (* let sets = List.filter ( function node -> match node with Set(FILTER,_) -> true | _ -> false ) nodes in *)
  (* let chains = List.map Rule.process_set sets in *)
  let _ = List.map pretty_print zones in
  let input_opers, output_opers, forward_opers = Zone.emit_zones zones in
    Chain.set { id = Ir.Builtin Ir.INPUT ; rules = input_opers; comment = "Builtin" }; 
    Chain.set { id = Ir.Builtin Ir.OUTPUT ; rules = output_opers; comment = "Builtin" }; 
    Chain.set { id = Ir.Builtin Ir.FORWARD ; rules = forward_opers; comment = "Builtin" };
    List.iter (Printf.printf "%s\n") (Chain.emit Iptables.emit_chain)

