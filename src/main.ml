open Common 
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
  let nodes = Zone.self_zone :: (parse_file "test.bl") in
  (* Validation pass. We must make sure that all ids are created correctly *)
  let defines = create_define_map Id_map.empty nodes in  
  let _ = Validate.validate nodes in

  let input_opers, output_opers, forward_opers = Zone.emit (Zone.filter nodes) in

  let filter_chains = List.map Rule.process (Rule.filter_process nodes) in
  let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn)) ) filter_chains in
  let _ = Chain.set { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" } in
  let _ = Chain.set { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" } in
  let _ = Chain.set { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" } in
  let _ = Chain.optimize Optimize.optimize in
    List.iter (Printf.printf "%s\n") (Chain.emit Iptables.emit_chain)

