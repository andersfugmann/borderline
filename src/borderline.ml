open Batteries
(** Main file. *)

open Common
open Printf

module F = Frontend

let _ =
  Sys.catch_break true;

  try
    let files = List.tl (Array.to_list Sys.argv) in
      prerr_endline (Printf.sprintf "#Parsing file(s): %s" (String.concat ", " files));

      let (zones, procs) = Parse.process_files files in
      let zones = List.map (fun ((id, _pos), stms) -> id, stms) zones in

      let input_opers, output_opers, forward_opers = Zone.emit F.FILTER zones in

      let filter_chains = List.map Rule.process procs in
      let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn.Ir.id)) ) filter_chains in

      Chain.add { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" };
      Chain.add { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" };
      Chain.add { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" };
      Chain.optimize Optimize.optimize;

      let lines = Chain.emit Nf6tables.emit_chains in
      List.iter (fun l -> print_endline l) lines;
      Printf.printf "\n#Lines: %d\n" (List.length lines)

  with ParseError err as excpt -> flush stdout; prerr_endline (error2string err); raise excpt
