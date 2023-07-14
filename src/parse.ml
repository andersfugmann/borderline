open Base
open Stdio
module F = Frontend
module V = Validate

(** Precompiled regular expressions *)
let include_regex = Str.regexp "^.*[.]bl$"
let exclude_regex = Str.regexp "^[.][#~].*$"

let imported = ref (Set.empty (module String))

let parse file =
  let full_path = (Unix.getcwd ()) ^ "/" ^ file in
  match Set.mem !imported full_path with
  | true -> []
  | false -> begin
      imported := (Set.add !imported full_path);
      eprintf "Parse: %s\n%!" full_path;
      let lexbuf = Lexing.from_channel (In_channel.create file) in
      lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = full_path; };
      try
        Parser.main Lexer.token lexbuf
      with
      | Parser.Error -> Common.parse_error ~pos:lexbuf.Lexing.lex_start_p "Syntax error"
    end

let rec parse_file file =
  if Str.string_match include_regex file 0 && not (Str.string_match exclude_regex file 0) then
    let prev_dir = Unix.getcwd () in
    let () = Unix.chdir (Stdlib.Filename.dirname file) in
    let res = expand (parse (Stdlib.Filename.basename file)) in
    let () = Unix.chdir prev_dir in
      res
  else
    []


and include_path dir_handle =
  match Unix.readdir dir_handle with
  | file ->
    parse_file file @ (include_path dir_handle)
  | exception _ -> []

and expand = function
  | F.Import(path, _) :: xs when Stdlib.Sys.is_directory path ->
      let dir = Unix.opendir path in
      let prev_dir = Unix.getcwd () in
      let () = Unix.chdir path in
      let res = include_path dir in
      let () = Unix.chdir prev_dir in
      res @ expand xs
  | F.Import(file, _) :: xs when not (Stdlib.Sys.is_directory file) ->
      parse_file file @ expand xs
  | x :: xs -> x :: expand xs
  | [ ] -> [ ]

let process_files files =
  let nodes =
    let n = List.concat_map ~f:parse_file files in
    (Zone.emit_nodes ("filter", Lexing.dummy_pos) (Zone.filter n)) :: n
    |> V.expand
  in
  (Zone.filter nodes, Rule.filter_process nodes)
