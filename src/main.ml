open Parse
open Frontend
open Iptables
open Printf
open Chain

(*
   Move all frontend parsing to parer.mly.
   All id's must contain a line number, to report unknown id at line n.
*)

let _ =
  let nodes = parse_file "test.bl" in
  let process_list =  List.filter (node_type 2) nodes in
  let defines = List.filter (node_type 3) nodes in
  (* Only one filter set - please *)
  (* let sets = List.filter ( function node -> match node with Set(FILTER,_) -> true | _ -> false ) nodes in *)
  (* let chains = List.map Rule.process_set sets in *)
  let input_opers, output_opers, forward_opers = Zone.emit (Zone.filter nodes) in

  let _ = List.map Rule.process defines in
  let filter_chains = List.map Rule.process process_list in
  let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn)) ) filter_chains in
  let _ = Chain.set { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" } in
  let _ = Chain.set { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" } in
  let _ = Chain.set { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" } in
  let _ = Chain.optimize Optimize.optimize in
    List.iter (Printf.printf "%s\n") (Chain.emit Iptables.emit_chain)

