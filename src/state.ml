open Base
type state = New | Established | Related | Invalid | Untracked
let of_string (id, pos) =
  match String.lowercase id with
  | "new" -> New
  | "established" -> Established
  | "related" -> Related
  | "invalid" -> Invalid
  | "untracked" -> Untracked
  | _ -> Common.parse_error ~id ~pos "Unknown state"

include Set.Poly
type t = state Set.Poly.t
let intersect = inter

let all = of_list [ New; Established; Related; Invalid; Untracked ]
