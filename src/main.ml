
let lineno = ref 1
open Irtypes
open Printf
open Parser
open Lexer

let imported = ref []

let parse_file file = 
  let exists = List.exists ( fun x -> x = file ) !imported in
  let _ = imported := file :: !imported in
  let in_channel = open_in file in
    match exists with
        true -> [ ]
      | _    -> Parser.main Lexer.token (Lexing.from_channel in_channel) 

let rec expand = function
    Import(file) :: xs -> expand (parse_file file) @ xs
  | _ as x :: xs -> x :: expand xs
  | [ ] -> [ ] 

 
let _ = 
  let nodes = expand [ Import("test.bl") ] in
    List.map pretty_print nodes


      
