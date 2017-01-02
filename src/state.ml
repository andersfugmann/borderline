open Batteries

type states = NEW | ESTABLISHED | RELATED | INVALID
module State_set = Set.Make(
  struct
    type t = states
    let compare = compare
  end)

include State_set
let intersect = inter

let all = of_list [ NEW; ESTABLISHED; RELATED; INVALID ]
