open Batteries

type states = New | Established | Related | Invalid
let of_string (id, pos) =
  match String.lowercase id with
  | "new" -> New
  | "established" -> Established
  | "related" -> Related
  | "invalid" -> Invalid
  | _ -> Common.parse_error ~id ~pos "Unknown state"

module State_set = Set.Make(
  struct
    type t = states
    let compare = compare
  end)

include State_set
let intersect = inter

let all = of_list [ New; Established; Related; Invalid ]
