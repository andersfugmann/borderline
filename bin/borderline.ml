open Base
open Stdio
module Scanf = Stdlib.Scanf
module Printf = Stdlib.Printf

module Sys = Stdlib.Sys
(** Main file. *)

open Borderline_lib
open Common

module F = Frontend

let _ =
  Sys.catch_break true;

  try
    let files = List.tl_exn (Array.to_list Sys.argv) in
    Printf.eprintf "Parsing file%s: %s\n%!"
      (match List.length files > 1 with true -> "s" | false -> "")
      (String.concat ~sep:", " files);

    let (zones, procs) = Parse.process_files files in
    let zones = List.map ~f:(fun ((id, _pos), stms) -> id, stms) zones in

    let input_opers, output_opers, forward_opers = Zone.emit_filter zones in
    let post_routing = Zone.emit_nat zones in

    let filter_chains = List.map ~f:Rule.process procs in
    let filter_ops = List.map ~f:(fun chn -> ([], [], Ir.Jump(chn.Ir.id)) ) filter_chains in

    Chain.add { Ir.id = Ir.Chain_id.Builtin Ir.Chain_type.Input ; rules = input_opers @ filter_ops; comment = "Builtin" };
    Chain.add { Ir.id = Ir.Chain_id.Builtin Ir.Chain_type.Output ; rules = output_opers @ filter_ops; comment = "Builtin" };
    Chain.add { Ir.id = Ir.Chain_id.Builtin Ir.Chain_type.Forward ; rules = forward_opers @ filter_ops; comment = "Builtin" };
    Chain.optimize Optimize.optimize;

    let lines =
      Chain.emit Nftables.emit_filter_rules @
      (Nftables.emit_nat_rules post_routing)
      |> Nftables.emit
    in

    List.iter ~f:(fun l -> print_endline l) lines;
    Printf.printf "\n#Lines: %d\n" (List.length lines)

  with
  | ParseError err ->
    Out_channel.flush stdout;
    prerr_endline (error2string err);
    Stdlib.exit 1
    (* raise exn *)
