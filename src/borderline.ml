(** Main file. *)
open Common
open Parse
open Frontend
open Printf
open Chain

let _ =
  Sys.set_signal 15 (Sys.Signal_handle (fun _ -> failwith "Stopped here"));

  try
    let files = List.tl (Array.to_list Sys.argv) in
      prerr_endline (Printf.sprintf "Parsing file(s): %s" (String.concat ", " files));

    let (zones, procs) = process_files files in

    let input_opers, output_opers, forward_opers = Zone.emit FILTER (zones) in

    let filter_chains = List.map Rule.process procs in
    let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn.Ir.id)) ) filter_chains in

    Chain.set { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" };
    Chain.set { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" };
    Chain.set { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" };
    Chain.optimize Optimize.optimize;

    let lines = Chain.emit Ip6tables.emit_chains in
      Printf.printf "%s\nLines: %d\n" (String.concat "\n" lines) (List.length lines)

  with ParseError err as excpt -> flush stdout; prerr_endline (error2string err); raise excpt


