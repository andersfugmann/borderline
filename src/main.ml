let lineno = ref 1
open Irtypes
open Printf
open Parser
open Lexer


let rec pretty_print = function
    Zone(id, nodes)  -> (printf "Zone: %s\n" id; List.iter pretty_print nodes)
  | Rule(nodes)    -> (printf "Rule: "; List.iter pretty_print nodes)
  | _ -> printf "Unknown Node"

let tree = Zone("ext1", [ Rule( [ Zone("test", []) ] ) ]  )

(*
let _ =
  pretty_print tree
*)
let _ = 
  let lexbuf = Lexing.from_channel stdin in
    while true do
      let result = Parser.main Lexer.token lexbuf in
        List.iter pretty_print result
    done


