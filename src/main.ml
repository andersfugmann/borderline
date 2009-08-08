(* 
 * Copyright 2009 Anders Fugmann.
 * Distributed under the GNU General Public License v3 
 *  
 * This file is part of Borderline - A Firewall Generator
 * 
 * Borderline is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation. 
 *  
 * Borderline is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Borderline.  If not, see <http://www.gnu.org/licenses/>. 
 *)

open Common
open Parse
open Frontend_types
open Frontend
open Printf
open Chain

let _ =
  Sys.set_signal 15 (Sys.Signal_handle (fun _ -> failwith "Stopped here"));

  try
    let files = List.tl (Array.to_list Sys.argv) in
      prerr_endline (Printf.sprintf "Parsing files: %s" (String.concat ", " files));

    let (zones, procs) = process_files files in

    let input_opers, output_opers, forward_opers = Zone.emit FILTER (zones) in

    let filter_chains = List.map Rule.process procs in
    let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn.Ir.id)) ) filter_chains in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.optimize Optimize.optimize in
    let lines = Chain.emit Ip6tables.emit_chains in
      Printf.printf "%s\nLines: %d\n" (String.concat "\n" lines) (List.length lines)

  with ParseError err as excpt -> flush stdout; prerr_endline (error2string err); raise excpt


