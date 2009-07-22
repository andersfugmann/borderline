open Common 
open Parse
open Frontend_types
open Frontend
open Iptables
open Printf
open Chain

let _ =
  try
    let (zones, procs) = process_file "test.bl" in

    let input_opers, output_opers, forward_opers = Zone.emit FILTER (zones) in
      
    let filter_chains = List.map Rule.process procs in
    let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn)) ) filter_chains in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.optimize Optimize.optimize in
      List.iter (Printf.printf "%s\n") (Chain.emit Iptables.emit_chains)

  with ParseError err as excpt -> flush stdout; prerr_endline (error2string err); raise excpt


