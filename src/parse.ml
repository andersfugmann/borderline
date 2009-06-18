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
    Import(path) :: xs when is_dir path ->
      let dir = Unix.opendir path in
      let prev_dir = Unix.getcwd () in
      let _ = Unix.chdir path in
      let res = include_path dir in
      let _ = Unix.chdir prev_dir in
        res @ expand xs
  | Import(file) :: xs when not (is_dir file) ->
      parse_file file @ expand xs
  | x :: xs -> x :: expand xs
  | [ ] -> [ ]

let parse file = 
  let res = parse_file file in
    List.iter (fun f -> Printf.printf "included: %s\n" f) !imported;
    res
