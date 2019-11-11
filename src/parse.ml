module V = Validate
open Core
module F = Frontend

(** Precompiled regular expressions *)
let include_regex = Str.regexp "^.*[.]bl$"
let exclude_regex = Str.regexp "^[.][#~].*$"

module File_set = Set.Make(String)

let imported = ref File_set.empty

let parse file =
  let full_path = (Unix.getcwd ()) ^ "/" ^ file in
  match File_set.mem !imported full_path with
  | true -> []
  | false -> begin
      imported := (File_set.add !imported full_path);
      Printf.eprintf "Parse: %s\n%!" full_path;
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
    let _ = Unix.chdir (Filename.dirname file) in
    let res = expand (parse (Filename.basename file)) in
    let _ = Unix.chdir prev_dir in
      res
  else
    []

and include_path dir_handle =
  match Unix.readdir_opt dir_handle with
  | Some file ->
    parse_file file @ (include_path dir_handle)
  | None -> []

and expand = function
  | F.Import(path, _) :: xs when Sys.is_directory path = `Yes ->
      let dir = Unix.opendir path in
      let prev_dir = Unix.getcwd () in
      let _ = Unix.chdir path in
      let res = include_path dir in
      let _ = Unix.chdir prev_dir in
      res @ expand xs
  | F.Import(file, _) :: xs when Sys.is_directory file <> `Yes ->
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
