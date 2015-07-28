(** Output a nft sctipt.
    nft is very close to our language, and should be easy to write.

    This script will only output ip6 rules - But will in time be
    functorized to handle ipv4 also.

    This moduel obsoletes ip6tables module
*)

open Batteries

(** For each chain find the maximum depth. This is a recursive
    function. Keep a cache of chain depths (Makes the Algorithm from
    O(n^n) to O(n) Now order by depth. We know by definition that if
    depth(chain a) < depth(chain b) then chain a does not call chain
    b
*)
let chain_order chains =
  let cache = Hashtbl.create 0 in
  let rec depth chain =
    (* Go though all targets, and find referenced chains *)
    match Hashtbl.find_option cache chain.Ir.id with
    | Some n -> n
    | None ->
      let d = List.enum chain.Ir.rules
              |> Enum.map snd
              |> Enum.filter_map (function Ir.Jump id -> Some id | _ -> None)
              |> Enum.map (fun id -> Map.find id chains)
              |> Enum.map depth
              |> Enum.fold max 0
      in
      Hashtbl.add cache chain.Ir.id d;
      d
  in
  Map.values chains
  |> Enum.map depth
  |> List.of_enum
  |> List.sort Int.compare







(** Emit a chain. Give a list of strings as rules for a chain.
    Boilerplate to keep it all together comes later.
 *)
let emit_chain chain =
  ()

let emit_chains chains =
  ()
