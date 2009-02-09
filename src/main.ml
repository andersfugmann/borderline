open Irtypes
open Printf
open Parser


let rec pretty_print = function
    Zone(id, nodes)  -> (printf "Zone %s\n" id; List.iter pretty_print nodes)
  | Rule(nodes)    -> (printf "Rule: "; List.iter pretty_print nodes)
  | _ -> printf "Unknown Node"

let tree = Zone("ext1", [ Rule( [ Zone("test", []) ] ) ]  )

let _ =
  pretty_print tree


