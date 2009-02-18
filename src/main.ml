
let lineno = ref 1
open Parse
open Frontend
open Printf
 
let _ = 
  let nodes = parse "test.bl" in
    List.map pretty_print nodes


      
