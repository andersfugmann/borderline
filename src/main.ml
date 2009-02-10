let lineno = ref 1
open Irtypes
open Printf
open Parser
open Lexer

let _ = 
  let 
      in_channel = open_in "test.bl"
  in
    while true do
      let result = Parser.main Lexer.token (Lexing.from_channel in_channel) in        
        List.iter pretty_print result
    done


