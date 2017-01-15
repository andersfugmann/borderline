open Batteries
(** Main file. *)

open Common
open Printf

module F = Frontend

let _ =
  Sys.catch_break true;

  try
    let files = List.tl (Array.to_list Sys.argv) in
      Printf.eprintf "#Parsing file(s): %s\n%!" (String.concat ", " files);

      let (zones, procs) = Parse.process_files files in
      let zones = List.map (fun ((id, _pos), stms) -> id, stms) zones in

      let input_opers, output_opers, forward_opers = Zone.emit_filter zones in
      let post_routing = Zone.emit_nat zones in

      let filter_chains = List.map Rule.process procs in
      let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn.Ir.id)) ) filter_chains in

      Chain.add { Ir.id = Ir.Builtin Ir.Chain_type.Input ; rules = input_opers @ filter_ops; comment = "Builtin" };
      Chain.add { Ir.id = Ir.Builtin Ir.Chain_type.Output ; rules = output_opers @ filter_ops; comment = "Builtin" };
      Chain.add { Ir.id = Ir.Builtin Ir.Chain_type.Forward ; rules = forward_opers @ filter_ops; comment = "Builtin" };
      Chain.optimize Optimize.optimize;

      let lines = Chain.emit Nftables.emit_filter_chains @
                  (Nftables.emit_nat_chain post_routing)
      in
      List.iter (fun l -> print_endline l) lines;
      Printf.printf "\n#Lines: %d\n" (List.length lines)

  with
  | ParseError err as excpt ->
      flush stdout;
      prerr_endline (error2string err);
      raise excpt
(*   | Parser.Basics.Error as e -> raise e *)
