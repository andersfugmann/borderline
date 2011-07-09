(** Read a dependancy file, and generate a list of modules to link *)

let sep_col = Str.regexp ":"
let sep_space = Str.regexp "[ ]+"

(** Default to bytecode *)
let suffix = ref ".cmo"   

(** Depends files are found here *)
let prefix = ref "."

(** Target go generate dependancy for *)
let target = ref ""

(** Signal that the file needs to be rebuild *)
let incomplete = ref false

let set_extention ext file = 
   (Filename.chop_extension file) ^ ext

(** Read a dependancy file and output a map, file -> dependancy list *)
let parse_dep filename = 
  let rec read_line fd =
    let line = input_line fd in
    try 
      let idx = String.index line '\\' in
      String.sub line 0 (idx - 1) ^ " " ^ read_line fd
    with
      | Not_found -> line
  in
  let rec parse_file fd = 
    try
      let line = read_line fd in
      match Str.split sep_col line with
        | [ l; r ] -> (l, Str.split sep_space r) :: parse_file fd
        | [ l ]  -> (l, []) :: parse_file fd 
        | _ -> Printf.printf "Parse error: %s\n" line; parse_file fd 
    with
      | _ -> []

  in
  let fd = open_in (!prefix ^ "/" ^ filename) in
  let res = parse_file fd in
  close_in fd; res

module FileSet = Set.Make(String)
exception Out

let rec gentree seen file =
  match FileSet.mem file seen with
    | true -> 
      prerr_endline ("Cyclic dependency detected on file: " ^ file);
      (file, [])
    | false -> 
      let deps = 
        try 
          List.assoc file (parse_dep (set_extention ".ml.d" file)) 
        with 
          | _ -> incomplete := true; prerr_endline (set_extention ".ml.d" file); [] 
      in
      let deps = List.map (set_extention !suffix) deps in
      let deps = List.filter ((<>) file) deps in
      (file, List.map (gentree (FileSet.add file seen)) deps)
        
let rec print_tree = function 
  | (f, []) -> Printf.printf "(%s)\n" f
  | (f, n) -> Printf.printf "%s:\n" f; List.iter print_tree n 


let rec flatten (f, deps) =
  f :: (List.flatten (List.map flatten deps))

let uniq lst =
  let rec uniq_acc acc = function
    | x :: xs when List.mem x acc -> uniq_acc acc xs
    | x :: xs -> uniq_acc (x :: acc ) xs 
    | [] -> acc
  in
  List.rev (uniq_acc [] lst)
  
let args = [
  "-prefix", Arg.Set_string prefix, "Base location of .d files";
  "-suffix", Arg.Set_string suffix, "Type of taget (file extension)"
]
  
let _ = 
  Arg.parse args (fun s -> target := s) "Generate dependancy file to stdout";
  let tree = gentree FileSet.empty (!target ^ !suffix) in
  let deps = uniq (List.rev (flatten tree)) in
  let self = Printf.sprintf "%s/%s.d" !prefix !target in
  
  Printf.printf "%s: %s\n" !target (String.concat " " deps);
  Printf.printf "%s: %s\n" self (String.concat " " (List.map (fun f -> !prefix ^ "/" ^ (set_extention ".ml.d" f)) deps))
  (* if !incomplete then Printf.printf "include %s" self  *)
(*  Printf.printf "-include %s\n" (String.concat " " (List.map (fun f -> !prefix ^ "/" ^ (set_extention ".ml.d" f)) deps));
  Printf.printf "# Incomplete: %b\n" !incomplete
 if !incomplete then Printf.printf "include %s" self *)
    
    

 
