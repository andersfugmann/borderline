(* Handle chanis, and hold all packet operations *)
module Chain :
sig 
  type chain = { id : int }
  val create_chain : unit -> chain

end = 
struct
  type chain = Chain { name: string, table: string }
  let next_id = ref 0
    let id = !next_id in
    let _ = next_id := !next_id + 1 in
      id
    
  let create_chain = 
    let id = !next_id in
    let _ = next_id := !next_id + 1 in
      chain { id }

       
    
end
