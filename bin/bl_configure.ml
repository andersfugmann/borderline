(* Parse output from ip route, and create zone example files for easy
   setup.
*)

open Core
open Arg

module Interface_map = Map.Make(struct
  type t = string
  let compare = String.compare
  let sexp_of_t _ = failwith "Not implemented - interfaces"
  let t_of_sexp _ = failwith "Not implemented - interfaces"
 end)

exception Usage_error of string

let commands = [ "/sbin/ip -f inet6 route";
                 "/sbin/ip -f inet route" ]

(* Read off lines one by one *)
let parse_route map line =
  let parse str =
    try
      Scanf.sscanf str "%s dev %s" (fun ip net -> (ip, net))
    with
    | _ -> Scanf.sscanf str "%s via %s dev %s" (fun ip _ net -> (ip, net))
  in

  let net, iface = parse line in
  Printf.printf "Parse line: %s %s\n" net iface;
  Interface_map.add_multi ~key:iface ~data:net map

let write_external_zone ch_out interface _networks =
    Printf.fprintf ch_out "zone %s {\n" interface;
    Printf.fprintf ch_out "    interface = %s;\n" interface;
    Printf.fprintf ch_out "    process filter { } policy log_allow;\n";
    Printf.fprintf ch_out "}\n";
    Printf.fprintf ch_out "define external += %s\n" interface

let write_internal_zone ch_out interface networks =
  let write_network network =
    Printf.fprintf ch_out "zone %s {\n" interface;
    Printf.fprintf ch_out "    network = %s;\n" network in
    Printf.fprintf ch_out "    interface = %s;\n" interface;
    List.iter ~f:write_network networks;
    Printf.fprintf ch_out "    process filter { } policy log_allow;\n";
    Printf.fprintf ch_out "}\n"

let is_external_zone networks = List.mem ~equal:String.equal networks "default"
let write_zone filename interface networks =
  print_endline ("Writing file: " ^ filename);
  let ch_out = Out_channel.create filename in
    (match is_external_zone networks with
      | true  -> write_external_zone ch_out interface networks
      | false -> write_internal_zone ch_out interface networks
    ); Out_channel.close ch_out


let has_external_zone interfaces =
  Interface_map.fold ~f:(fun ~key:_ ~data:nets acc -> acc || is_external_zone nets) interfaces ~init:false

let validate_dir output_dir =
  match Sys.is_directory output_dir with
  | `Yes -> ()
  | `No | `Unknown -> raise (Usage_error ("Not a directory: " ^ output_dir))

let validate_file force file =
  let exists = Poly.(Sys.file_exists file = `Yes) in
  match (force || exists) with
  | true -> ()
  | false -> raise (Usage_error ("File already exists: " ^ file))

let () =
  let output_dir = ref "/etc/borderline/zones" and
      force = ref false
  in
  let arg_spec =
    [ ("--output", Set_string(output_dir), "<dir>  Specify output directory");
      ("--force", Set(force), " Force override ov existing files");
    ] in
  let _ = Arg.parse arg_spec ignore "Autogenerate Borderline Zone Configuration files." in
    (* Test if the file exist. We only warn (and stop) if override is false *)

  let interfaces =
    let routes =
      List.map ~f:Unix.open_process_in commands
      |> List.concat_map ~f:In_channel.input_lines
    in
    List.fold_left ~f:parse_route ~init:Interface_map.empty routes
  in
  let create_file_name iface = !output_dir ^ "/" ^ iface ^ ".bl" in
  let found_external = has_external_zone interfaces in

  try
    validate_dir !output_dir;
    let file_list =
      let files = match found_external with
        | true -> []
        | false -> [ !output_dir ^ "/" ^ "ext.bl" ]
      in
      Interface_map.fold ~f:(fun ~key:iface ~data:_ acc -> (create_file_name iface) :: acc) ~init:files interfaces
    in
    let () = List.iter ~f:(validate_file !force) file_list in

    Interface_map.iteri ~f:(fun ~key:iface ~data:nets -> write_zone (create_file_name iface) iface nets) interfaces;
    begin
      match found_external with
      | false -> Printf.fprintf (Out_channel.create (!output_dir ^ "/" ^ "ext.bl")) "# No external interface found\ndefine external = "
      | true -> ()
    end
  with Usage_error msg -> print_endline ("Error: " ^  msg)
