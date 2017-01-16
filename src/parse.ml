open Batteries
module F = Frontend

(** Precompiled regular expressions *)
let include_regex = Str.regexp "^.*[.]bl$"
let exclude_regex = Str.regexp "^[.][#~].*$"

module File_set = Set.Make( String )

let imported = ref File_set.empty

let parse file =
  let full_path = (Unix.getcwd ()) ^ "/" ^ file in
  if File_set.mem full_path !imported then []
  else
    begin
      imported := (File_set.add full_path !imported);
      Printf.eprintf "Parse: %s\n%!" full_path;
      let lexbuf = Lexing.from_channel (open_in file) in
      lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = full_path; };
      try
        Parser.main Lexer.token lexbuf
      with
      | Parser.Error -> Common.parse_error ~pos:lexbuf.Lexing.lex_curr_p "Syntax error"
    end

let rec parse_file file =
  if Str.string_match include_regex file 0 && not (Str.string_match exclude_regex file 0) then
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
  | F.Import(path, _) :: xs when Sys.is_directory path ->
      let dir = Unix.opendir path in
      let prev_dir = Unix.getcwd () in
      let _ = Unix.chdir path in
      let res = include_path dir in
      let _ = Unix.chdir prev_dir in
        res @ expand xs
  | F.Import(file, _) :: xs when not (Sys.is_directory file) ->
      parse_file file @ expand xs
  | x :: xs -> x :: expand xs
  | [ ] -> [ ]

let process_files files =
  let nodes =
    let n = List.flatten (List.map parse_file files) in
    (Zone.emit_nodes ("filter", Lexing.dummy_pos) (Zone.filter n)) :: n
    |> Validate.expand
  in
  (Zone.filter nodes, Rule.filter_process nodes)
