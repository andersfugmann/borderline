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

let rec inline_defines defines zones nodes =

  let rec expand_list = function
    | Id id as _id :: xs when Id_set.mem id zones -> _id :: expand_list xs
    | Id id :: xs -> begin try
        begin match Id_map.find id defines with
          | DefineList(_, list) -> expand_list list
          | DefineStms(id', _) -> raise (ParseError [("List definition required", id); ("But found rule definition", id')])
          | _ -> failwith "Unexpected node type"
        end @ expand_list xs
      with _ -> raise (ParseError [("Undefined id", id)])
      end
    | Number _ as num :: xs -> num :: expand_list xs
    | Ip _ as ip :: xs -> ip :: expand_list xs
    | [] -> []
  in
  let rec expand_define = function
    | Reference id -> begin match Id_map.find id defines with
        | DefineStms(_, stm) -> expand_rules expand_define stm
        | DefineList(id', _) -> raise (ParseError [("Rule definition required", id); ("But found a reference to a list", id')])
        | _ -> failwith "Unexpected node type"
      end
    | Filter (dir, TcpPort ports, neg) -> [ Filter (dir, TcpPort (expand_list ports), neg) ]
    | Filter (dir, UdpPort ports, neg) -> [ Filter (dir, UdpPort (expand_list ports), neg) ]
    | Filter (dir, Address ips, neg) -> [ Filter (dir, Address (expand_list ips), neg) ]
    | Filter (dir, FZone zones, neg) -> [ Filter (dir, FZone (expand_list zones), neg) ]
    | Protocol (protos, neg) -> [ Protocol ((expand_list protos), neg) ]
    | IcmpType (types, neg) -> [ IcmpType ((expand_list types), neg) ]
    | State _ as rle -> [ rle ]
    | Rule _ as rle -> [ rle ]

  in
    Frontend.expand expand_define nodes

let process_files files =
  let nodes = List.flatten (List.map parse_file files) in
  let zones = Zone.filter nodes in
  let nodes' = (Zone.emit_nodes Frontend_types.FILTER zones) @ nodes in
    Validate.validate nodes';
    (zones, Rule.filter_process (inline_defines (create_define_map nodes') (Zone.create_zone_set Id_set.empty zones) nodes'))

