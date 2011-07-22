(** Read a dependancy file, and generate a list of modules to link *)

let sep_col = Str.regexp ":"
let sep_space = Str.regexp "[ ]+"

(** Default to bytecode *)
let suffix = ref ".cmo"   

(** Depends files are found here *)
let prefix = ref "."

(** Target go generate dependancy for *)
let target = ref ""

(** Mark some files missing *)
let missing = ref false

let set_extention ext file = 
   (Filename.chop_extension file) ^ ext

(** Read a dependancy file and output a map, file -> dependancy list *)
let parse_dep filename = 
  let rec read_line fd =
    let line = input_line fd in
    try 
      let idx = String.index line '\\' in
      let deps = String.sub line 0 (idx - 1) in
      deps ^ " " ^ read_line fd
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

(** All dependency files *)
exception Out

let map_suffix file =
  match Filename.check_suffix file ".cmi" with
    | true -> set_extention ".mli.d" file
    | false -> set_extention ".ml.d" file

let rec gentree seen file =
  if FileSet.mem file seen then begin
    prerr_endline ("Cyclic dependency detected on file: " ^ file);
    raise Out
  end;
  let deps = 
    let dep_file = (set_extention ".ml.d" file) in
    try 
      let deps = parse_dep dep_file in
      List.assoc file deps
    with 
      | Sys_error _ -> missing := true; [] 
      | Not_found -> []
  in
  (* let deps = List.map (set_extention !suffix) deps in *)
  let deps = List.filter ((!=) file) deps in
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
  "-suffix", Arg.Set_string suffix, "Type of target (file extension)"
]

let _ = 
  let _ = Random.self_init () in
  Arg.parse args (fun s -> target := s) "Generate dependancy file to stdout";
  let tree = gentree FileSet.empty (!target ^ !suffix) in
  let deps = uniq (List.rev (flatten tree)) in
  let self = Printf.sprintf "%s/%s.d" !prefix !target in

  let implementation_files = List.filter (fun f -> Filename.check_suffix f !suffix) deps in  
  
  (* Make sure the makefile is recreated, if any dependancy files were missing *)
  if !missing then begin
    let force = Printf.sprintf "force%d" (Random.int 1073741823) in
    Printf.printf ".PHONY: %s\n" force;
    Printf.printf "%s: %s\n" !target force;
  end;
  
  Printf.printf "%s: %s\n\n" !target (String.concat " " implementation_files);
  let depend_files = List.map (fun f -> (!prefix ^ "/" ^ (map_suffix f))) deps in
  Printf.printf "%s: %s\n\n" self (String.concat " " depend_files);
  Printf.printf "-include %s\n\n" (String.concat " " depend_files);
  ()


 
