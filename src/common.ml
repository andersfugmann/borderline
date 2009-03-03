open Printf

exception InternalError
exception ParseError of string * int

type ip = int list * int

let ip_to_string (a, m) = 
  (String.concat ":" (List.map (sprintf "%x") a)) ^ (sprintf "/%d" m) 



