open Common
open Frontend_types
open Frontend
open Parser
open Lexer
open Str

let is_dir path = 
  let stat = Unix.stat path in
    stat.Unix.st_kind = Unix.S_DIR

(* Precompiled regular expressions *)
let exlude_regex = [ regexp "^.*[~]$"; regexp "^[.].*$" ]

let imported = ref []

let parse file =
  Printf.printf "Parse: %s\n" file;
  let lexbuf = Lexing.from_channel (open_in file) in
    lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = file; };
    Parser.main Lexer.token lexbuf

let exclude_file file = 
  List.exists (fun regex -> string_match regex file 0) exlude_regex
  
let rec parse_file file =
  let full_path = (Unix.getcwd ()) ^ "/" ^ file in
  match List.exists ( fun x -> x = full_path ) !imported || exclude_file file with
      true -> [ ]
    | false    ->
        imported := full_path :: !imported;
        expand (parse full_path)

and include_path dir_handle =
  try 
    (* Do not include files ending on ~ or . files *)
    let file = Unix.readdir dir_handle in
    parse_file file @ (include_path dir_handle)
  with End_of_file -> []
        
and expand = function
    Import(path, _) :: xs when is_dir path ->
      let dir = Unix.opendir path in
      let prev_dir = Unix.getcwd () in
      let _ = Unix.chdir path in
      let res = include_path dir in
      let _ = Unix.chdir prev_dir in
        res @ expand xs
  | Import(file, _) :: xs when not (is_dir file) ->
      parse_file file @ expand xs
  | x :: xs -> x :: expand xs
  | [ ] -> [ ]

let rec inline_defines defines nodes = 
  let rec expand_ports = function
      Port_nr _ as port :: xs -> port :: expand_ports xs
    | Port_id id :: xs -> begin 
          match Id_map.find id defines with
              DefineInts(_, ports) -> expand_ports ports
            | DefineStms(id', _) -> raise (ParseError [("Port definition required", id); ("But found rule definition", id')])
            | _ -> raise InternalError
        end @ expand_ports xs
    | [] -> []
  in    
  let rec expand_define = function 
      Reference id -> begin
        match Id_map.find id defines with
            DefineStms(_, stm) -> expand_rules expand_define stm
          | DefineInts(id', _) -> raise (ParseError [("Rule definition required", id); ("But found port definition", id')])
          | _ -> raise InternalError
      end
    | Filter (dir, TcpPort ports) -> [ Filter (dir, TcpPort (expand_ports ports)) ]
    | Filter (dir, UdpPort ports) -> [ Filter (dir, UdpPort (expand_ports ports)) ]
    | rle -> [rle]
  in
    Frontend.expand expand_define nodes 

let process_file file = 
  let nodes = parse_file "test.bl" in
  let zones = Zone.filter nodes in
  let nodes' = (Zone.emit_nodes Frontend_types.FILTER zones) @ nodes in 
    Validate.validate nodes';
    (zones, Rule.filter_process (inline_defines (create_define_map nodes') nodes'))

