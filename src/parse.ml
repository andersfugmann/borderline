open Common
open Frontend_types
open Frontend
open Parser
open Lexer
open Str

(* Precompiled regular expressions *)
let include_regex = regexp "^.*[.]bl$"
let exclude_regex = regexp "^[.][#~].*$"

module File_set = Set.Make( String )

let imported = ref File_set.empty

let parse file =
  let full_path = (Unix.getcwd ()) ^ "/" ^ file in
  if File_set.mem full_path !imported then []
  else
    begin
      imported := (File_set.add full_path !imported);
      prerr_endline (Printf.sprintf "Parse: %s" full_path);
      let lexbuf = Lexing.from_channel (open_in file) in
        lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = full_path; };
        Parser.main Lexer.token lexbuf
    end

let rec parse_file file =
  if string_match include_regex file 0 && not (string_match exclude_regex file 0) then
    let prev_dir = Unix.getcwd () in
    let _ = Unix.chdir (Filename.dirname file) in
    let res = expand (parse (Filename.basename file)) in
    let _ = Unix.chdir prev_dir in
      res
  else
    []

and include_path dir_handle =
  try
    (* Do not include files ending on ~ or . files *)
    let file = Unix.readdir dir_handle in
    parse_file file @ (include_path dir_handle)
  with End_of_file -> []

and expand = function
    Import(path, _) :: xs when Sys.is_directory path ->
      let dir = Unix.opendir path in
      let prev_dir = Unix.getcwd () in
      let _ = Unix.chdir path in
      let res = include_path dir in
      let _ = Unix.chdir prev_dir in
        res @ expand xs
  | Import(file, _) :: xs when not (Sys.is_directory file) ->
      parse_file file @ expand xs
  | x :: xs -> x :: expand xs
  | [ ] -> [ ]

let rec inline_defines defines nodes =
  let rec expand_ints = function
      Number _ as num :: xs -> num :: expand_ints xs
    | Ip (_, pos) :: xs -> raise (ParseError [("Cannot use ip address in int list", ("", pos))])
    | Id id :: xs -> begin
          match Id_map.find id defines with
              DefineList(_, list) -> expand_ints list
            | DefineStms(id', _) -> raise (ParseError [("List definition required", id); ("But found rule definition", id')])
            | _ -> failwith "Unexpected node type"
        end @ expand_ints xs
    | [] -> []
  in
  let rec expand_ips = function
    | Ip _ as ip :: xs -> ip :: expand_ips xs
    | Number _ :: xs -> raise (ParseError [("Cannot use int in ip address list", ("", Lexing.dummy_pos))])
    | Id id :: xs -> begin
          match Id_map.find id defines with
              DefineList(_, list) -> expand_ips list
            | DefineStms(id', _) -> raise (ParseError [("List definition required", id); ("But found rule definition", id')])
            | _ -> failwith "Unexpected node type"
        end @ expand_ips xs
    | [] -> []
  in
  let rec expand_define = function
      Reference id -> begin
        match Id_map.find id defines with
            DefineStms(_, stm) -> expand_rules expand_define stm
          | DefineList(id', _) -> raise (ParseError [("Rule definition required", id); ("But found port definition", id')])
          | _ -> failwith "Unexpected node type"
      end
    | Filter (dir, TcpPort ports, neg) -> [ Filter (dir, TcpPort (expand_ints ports), neg) ]
    | Filter (dir, UdpPort ports, neg) -> [ Filter (dir, UdpPort (expand_ints ports), neg) ]
    | Filter (dir, Address ips, neg) -> [ Filter (dir, Address (expand_ips ips), neg) ]
    | Filter (dir, FZone _, neg) as rle -> [ rle ]
    | Protocol (protos, neg) -> [ Protocol ((expand_ints protos), neg) ]
    | IcmpType (types, neg) -> [ IcmpType ((expand_ints types), neg) ]
    | State _ as rle -> [ rle ]
    | Rule _ as rle -> [ rle ]

  in
    Frontend.expand expand_define nodes

let process_files files =
  let nodes = List.flatten (List.map parse_file files) in
  let zones = Zone.filter nodes in
  let nodes' = (Zone.emit_nodes Frontend_types.FILTER zones) @ nodes in
    Validate.validate nodes';
    (zones, Rule.filter_process (inline_defines (create_define_map nodes') nodes'))

