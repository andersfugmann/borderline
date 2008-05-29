(* Functions related to zones *)
module Zone =
struct
  let tbl = Hashtbl.create 256
  let exists zone =
    try
      let _ = Hashtbl.find tbl zone in
	true
    with Not_found -> false

  let add zone = Hashtbl.add tbl zone 0
end
