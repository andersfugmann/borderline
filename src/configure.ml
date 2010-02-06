(* Parse output from ip route, and create zone example files for easy
   setup. 

   ip -f inet6 route

*)

open Arg

let rec join delim = function
    [] -> ""
  | x :: [] -> x
  | x :: xs -> x ^ delim ^ (join delim xs)


let parse str = 
  try 
    Scanf.sscanf str "%s dev %s" (fun ip net -> (ip, net))
  with
      _ -> Scanf.sscanf str "%s via %s dev %s" (fun ip _ net -> (ip, net))
        

let command = "cat /tmp/ip.out" (* /sbin/ip -f inet6 route *)

module Interface_map = Map.Make (struct
  type t = string
  let compare = String.compare
 end)


(* Read off lines one by one *)
let rec parse_routes ch_in map = 
  try
    let line = input_line ch_in in
    let net, iface = parse line in
    let networks = 
      try 
        Interface_map.find iface map
      with _ -> []
    in
      parse_routes ch_in (Interface_map.add iface (net :: networks) map)
  with
      End_of_file -> map

(* This function creates a writes the zone *)
let write_zone ch_out interface networks =
  let write_network network = Printf.fprintf ch_out "    network = %s;\n" network in
    Printf.fprintf ch_out "zone %s {\n" interface;
    Printf.fprintf ch_out "    interface = %s;\n" interface;
    (if List.mem "default" networks then
      Printf.fprintf ch_out "    process filter { } policy allow;\n"
     else
      (List.iter write_network networks;
      Printf.fprintf ch_out "    process filter { } policy log_deny;\n"));
    Printf.fprintf ch_out "}\n"
   

let in_channel = Unix.open_process_in command
  
exception Usage_error of string

let validate_dir output_dir =
  match Sys.is_directory output_dir with
      true -> ()
    | false -> raise (Usage_error ("Not a directory: " ^ output_dir))

let validate_file file force = 
  match force || (not (Sys.file_exists file)) with
      true -> ()
    | false -> raise (Usage_error ("File already exists: " ^ file))

let () = 
  let output_dir = ref "/tmp" in
  let force = ref false in
  let one_file = ref false in
  let name = ref "" in
  let arg_spec = 
    [ ("--output", Set_string(output_dir), "<dir>  Specify output directory");
      ("--force", Set(force), " Force override ov existing files");
      ("--one-file", Tuple([ Set(one_file); Set_string(name) ]), "<filename>  Keep all zone definitions in one file")
    ] in
  let _ = Arg.parse arg_spec ignore "Autogenerate Borderline Zone Configuration files." in
    (* Test if the file exist. We only warn (and stop) if override is false *)
    
  let interfaces = parse_routes in_channel Interface_map.empty in

  let create_file_name iface = (!output_dir) ^ "/" ^ iface ^ ".bl" in

  try
    validate_dir (!output_dir);

    if (!one_file) then 
      begin
        let file = (!output_dir ^ "/" ^ !name) in
        let () = validate_file file !force in         
        let ch_out = open_out file in
          Interface_map.iter (fun iface nets -> write_zone ch_out iface nets) interfaces;
          close_out ch_out
      end
    else 
      begin 
        Interface_map.iter (fun iface _ -> validate_file (create_file_name iface) !force) interfaces;
        Interface_map.iter (fun iface nets -> write_zone (open_out (create_file_name iface)) iface nets) interfaces
      end
  with Usage_error msg -> print_endline ("Error: " ^  msg)
          
          

      
    
      
    
