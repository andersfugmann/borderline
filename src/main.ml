open Common 
open Parse
open Frontend
open Iptables
open Printf
open Chain

(*
   Move all frontend parsing to parer.mly.
*)

let rec inline_defines nodes = 
  let defines = create_define_map nodes in 
  let substitute = function 
      Reference id -> Id_map.find id defines 
    | rle -> [rle]
  in
  let nodes' = map_rules substitute nodes in
    match Id_set.is_empty (Validate.get_referenced_ids nodes') with
        true -> nodes'
      | false -> inline_defines nodes'   

let _ =
  try
    let nodes = parse_file "test.bl" in
    let zones = Zone.filter nodes in
      (* create the "zones" define *)
    let nodes  =     
      let rec gen_rule_stems = function
          (zone_id, _) :: xs -> 
            Rule([Filter(Ir.DESTINATION, FZone(zone_id)); Reference zone_id], Policy DENY) :: gen_rule_stems xs
        | [] -> []
      in
      let id = ("zones", Lexing.dummy_pos) in 
        Define(id, gen_rule_stems zones) :: nodes
    in
      
    (* Validation pass. We must make sure that all ids are created correctly *)
    let _ = Validate.validate nodes in
    let nodes = inline_defines nodes in
      
    (* Inline all the defines as long as there are defines to be inlined *)
    let procs = Rule.filter_process nodes in

    let input_opers, output_opers, forward_opers = Zone.emit (zones) in
      
    let filter_chains = List.map Rule.process procs in
    let filter_ops = List.map ( fun chn -> ([], Ir.Jump(chn)) ) filter_chains in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.INPUT ; rules = input_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.OUTPUT ; rules = output_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.set { Ir.id = Ir.Builtin Ir.FORWARD ; rules = forward_opers @ filter_ops; comment = "Builtin" } in
    let _ = Chain.optimize Optimize.optimize in
      List.iter (Printf.printf "%s\n") (Chain.emit Iptables.emit_chain)

  with ParseError (err, id) -> prerr_endline (error2string (err,id) )


