(*
 * Copyright 2009 Anders Fugmann.
 * Distributed under the GNU General Public License v3
 *
 * This file is part of Borderline - A Firewall Generator
 *
 * Borderline is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Borderline is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Borderline.  If not, see <http://www.gnu.org/licenses/>.
 *)

open Common
open Ir
open Printf
open Chain

exception MergeImpossible

let max_inline_size = 1

let rec chain_reference_count id chains =
  let rec count_references = function
      (_, Jump chn_id) :: xs when chn_id = id -> 1 + count_references xs
    | x :: xs -> count_references xs
    | [] -> 0
  in
    Chain_map.fold (fun _ chn acc -> acc + (count_references chn.rules)) chains 0

let rec get_referring_rules chain chains =
  let test (conds, target) = target = Jump (chain.id) in
  let referring_chains = Chain.filter (fun chn -> List.exists test chn.rules) chains in
    List.fold_left (fun acc chn -> (List.filter test chn.rules) @ acc) [] referring_chains

(* Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains =
  Chain_map.map (fun chn -> { id = chn.id; rules = func chn.rules; comment = chn.comment }) chains

let rec map_chain_rules_expand func chains : Ir.chain list =
  let rec map_rules = function
      (opers, target) :: xs ->
        (try
          (List.map (fun opers' -> (opers', target)) (func opers))
         with _ -> printf "E"; []
        ) @ map_rules xs
    | [] -> []
  in
    List.map (fun chn -> { id = chn.id; rules = map_rules chn.rules; comment = chn.comment } ) chains

let merge_opers rle =
  let is_sibling (a, _) (b, _) =
    (cond_type_identical a b) && (get_dir a = get_dir b)
  in
  let test = function
      (x :: xs, _) as res -> res
    | ([], _) -> raise MergeImpossible
  in
  let merge_list (s, neg) (s', neg') =
    match neg, neg' with
        (true, true) | (false, false) -> test (intersection (=) s s', neg)
      | (false, true) -> test (difference (=) s s', false)
      | (true, false) -> test (difference (=) s' s, false)
  in
  let merge_elem (i, neg) (i', neg') =
    let (i'', neg'') = merge_list ([i], neg) ([i'], neg') in
      (List.hd i'', neg'')
  in
  let rec merge_oper = function
      (Interface (dir, i), neg), (Interface (dir', i'), neg') when dir = dir' ->
        let (i'', neg'') = merge_elem (i, neg) (i', neg') in [(Interface (dir, i''), neg'')]
    | (State s, neg), (State s', neg') ->
        let (s'', neg'') = merge_list (s, neg) (s', neg') in [(State s'', neg'')]
    | (Ports (dir, ports), neg), (Ports (dir', ports'), neg') when dir = dir' ->
        let (ports'', neg'') = merge_list (ports, neg) (ports', neg') in [(Ports (dir, ports''), neg'')]
    | (Protocol proto, neg), (Protocol proto', neg') ->
        let (proto'', neg'') = merge_list (proto, neg) (proto', neg') in [(Protocol (proto''), neg'')]
    | ((IpRange (dir, ips), true) as a), ((IpRange (dir', ips'), false) as b) when dir = dir' ->
        printf "X\n"; flush stdout; merge_oper (b,a)
    | (IpRange (dir, ips), false), (IpRange (dir', ips'), true) when dir = dir' ->
        [ (IpRange (dir, Ipv6.list_difference ips ips'), false) ]
    | (IpRange (dir, ips), neg), (IpRange (dir', ips'), neg') when dir = dir' && neg = neg' ->
        [ (IpRange (dir, Ipv6.list_intersection ips ips'), neg) ]
    | (Zone (dir, zones), neg), (Zone (dir', zones'), neg') when dir = dir' ->
        let (zones'', neg'') = merge_list (zones, neg) (zones', neg') in [(Zone (dir, zones''), neg'')]
    | _, _ -> raise MergeImpossible

  in
  let rec merge_siblings acc = function
      x :: xs -> let acc' = List.flatten ( List.map ( fun sib -> merge_oper (sib, x) ) acc ) in
                 merge_siblings acc' xs
    | [] -> acc
  in
    List.sort Ir.compare (List.flatten (List.map (fun lst -> merge_siblings [List.hd lst] (List.tl lst)) (group is_sibling [] rle)))

let reduce chains =
  (* Find the build-in chains *)
  let builtin = Chain_map.fold (fun id _ acc -> match id with Builtin _ -> id :: acc | _ -> acc) chains [] in
    (* Create a map of chains. The map is a reference, so all can access it and modify the chains within it *)
  let chain_map = ref chains in
  let reverse () =
    chain_map := Chain_map.map (fun c -> { id = c.id; rules = List.rev c.rules; comment = c.comment }) !chain_map
  in
  let is_terminal = function
    | Jump _ | MarkZone _ | Notrack | Return | Log _ -> false
    | Accept | Drop | Reject _ -> true
  in
  let conditions_equal conds conds' =
    try List.for_all2 (fun a b -> Ir.compare a b = 0) conds conds'
    with Invalid_argument _ -> false
  in
  let rec map_chain func chain_id =
    let chain = Chain_map.find chain_id !chain_map in
    let rules = func chain.rules in
      chain_map := Chain_map.add chain_id { id = chain_id; rules = rules; comment = chain.comment } !chain_map

  and reduce_rules (conds, target) = function
    | (conds', Jump chn_id) as rle :: xs ->
        (try
           map_chain (reduce_rules (merge_opers (conds @ conds'), target)) chn_id
         with
             MergeImpossible -> ()
        ); rle :: reduce_rules (conds, target) xs
    | (conds', Return) as rle :: xs -> begin
        try
          ignore (merge_opers (conds @ conds')); rle :: xs
        with MergeImpossible -> rle :: reduce_rules (conds, target) xs
      end
    | (conds', target') as rle :: xs -> begin
        try
          if conditions_equal (merge_opers (conds @ conds')) conds' then
            (printf "H";
             reduce_rules (conds, target) xs)
          else
            rle :: reduce_rules (conds, target) xs
        with
            MergeImpossible -> rle :: reduce_rules (conds, target) xs
      end
    | [] -> []

  (* This function needs an accumulator of all visited
     rules. Only rules which has no commonparts with already
     visited rules are elegiable for deletion.  *)
  and has_common_part conds = function
      conds' :: xs -> begin
        try
          ignore (merge_opers (conds @ conds')); true
        with
            MergeImpossible -> has_common_part conds xs
      end
    | [] -> false

  and reduce_rules_rev acc (conds, target) = function
    | (conds', Jump chn_id) as rle :: xs when (chain_reference_count chn_id !chain_map) = 1 -> begin
        try
          if conditions_equal (merge_opers (conds @ conds')) conds' && not (has_common_part conds' acc) then
            map_chain (reduce_rules_rev [] (conds, target)) chn_id
        with
          | MergeImpossible -> ()
      end; rle :: reduce_rules_rev (conds' :: acc) (conds, target) xs
    | (conds', target') as rle :: xs when target = target' -> begin
        try
          if conditions_equal (merge_opers (conds @ conds')) conds' && not (has_common_part conds' acc) then
            (printf "h"; reduce_rules_rev acc (conds, target) xs)
          else
            rle :: reduce_rules_rev (conds' :: acc) (conds, target) xs
        with
          | MergeImpossible -> rle :: reduce_rules_rev (conds' :: acc) (conds, target) xs
      end
    | (conds', _) as rle :: xs ->
        rle :: reduce_rules_rev (conds' :: acc) (conds, target) xs
    | [] -> []

  (* Dont find a terminal. For each terminal *)
  and traverse func = function
      (conds, target) as rle :: xs when is_terminal target ->
        rle :: traverse func (func (conds, target) xs)
    | (conds, Jump chn_id) as rle :: xs ->
        map_chain (traverse func) chn_id; rle :: traverse func xs
    | x :: xs -> x :: traverse func xs
    | [] -> []
  in
    ignore (traverse reduce_rules (List.map (fun id -> ([], Jump id)) builtin));

    (* And on the reversed chains *)
    reverse ();
    Chain_map.iter (fun id  _ -> map_chain (traverse (reduce_rules_rev [])) id) !chain_map;
    reverse ();

    (* Yeild the result. We might consider only using maps. Its far easier *)
    !chain_map


(* Remove all return statements, by creating new chains for each return statement *)
let rec fold_return_statements chains =
  let rec neg = List.map (fun (x, a) -> (x, not a)) in
  let rec fold_return acc = function
      (cl, Return) :: xs ->
        printf "F";
        let rls, chns = fold_return [] xs in
        let chn = Chain.create rls "Return stm inlined" in
          (acc @ [(neg cl, Jump(chn.id))], chn :: chns)
    | rle :: xs -> fold_return (acc @ [rle]) xs
    | [] -> (acc, [])
  in

  let fold_func _ chn acc =
    let rls, chns = fold_return [] chn.rules in
      List.fold_left (fun acc chn -> Chain_map.add chn.id chn acc) acc ( { id = chn.id; rules = rls; comment = chn.comment } :: chns )
  in
    Chain_map.fold fold_func chains Chain_map.empty

let remove_unreferenced_chains chains =
  let get_referenced_chains chain =
    List.fold_left (fun acc -> function (_, Jump id) -> (Chain_map.find id chains) :: acc | _ -> acc) [] chain.rules
  in
  let rec descend acc chain =
    List.fold_left (fun acc chn -> descend acc chn) (Chain_map.add chain.id chain acc) (get_referenced_chains chain)
  in
    Chain_map.fold (fun id chn acc -> match id with Builtin _ -> descend acc chn | _ -> acc) chains Chain_map.empty

(* Remove dublicate chains *)
let remove_dublicate_chains chains =
  let replace_chain_ids (id, ids) chns =
      map_chain_rules (List.map (function (c, Jump id') when List.mem id' ids -> (c, Jump id) | x -> x)) chns
  in
  let is_sibling a b = (Ir.eq_rules a.rules b.rules) && not (a.id = b.id) in
  let identical_chains chain chains = Chain_map.fold (fun id chn acc -> if is_sibling chain chn then id :: acc else acc) chains [] in
  let remap_list = Chain_map.fold (fun id chn acc -> (id, identical_chains chn chains) :: acc) chains [] in
    List.fold_left (fun acc (id, ids) -> if List.length ids > 0 then printf "D"; replace_chain_ids (id, ids) acc) chains remap_list

let a = function
    5 -> 7
  | n -> n

(* Move drops to the bottom. This allows improvement to dead code elimination, and helps reduce *)
let rec reorder rules =
  let can_reorder (cl1, act1) (cl2, act2) =
    if act1 = act2 then true else
      try
        let _ = merge_opers (cl1 @ cl2) in
          false (* The rules did not conflict. *)
      with MergeImpossible -> true
  in

  let order = function
    | Log _ -> 0
    | Notrack -> 1
    | Accept -> 2
    | MarkZone _ -> 3
    | Jump _ -> 4
    | Return -> 5
    | Reject _ -> 6
    | Drop -> 7
  in
  let should_reorder_rules (cl1, act1) (cl2, act2) =
    if can_reorder (cl1, act1) (cl2, act2) then
      match order act1 - order act2 with
          n when n > 0 -> true
        | 0 -> if List.length cl1 < List.length cl2 then true
          else (* Weight the types, and add them. *) false
        | _ -> false
    else
      false
  in
  let rec reorder_rules acc = function
      rule1 :: rule2 :: xs when should_reorder_rules rule1 rule2 ->
        printf "R";
        reorder_rules [] (acc @ rule2 :: rule1 :: xs)
    | rule1 :: xs ->
        reorder_rules (acc @ [ rule1]) xs
    | [] -> acc

  in
    reorder_rules [] rules

(* Inline chains that satifies p *)
let rec inline p chains =
  let has_target target rules =
    List.exists (fun (c, t) -> t = target) rules
  in
  let rec inline_chain chain = function
      (conds, target) :: xs when target = Jump(chain.id) ->
        begin
          let rec inline_rules conds = function
              (c, t) :: xs when t = Return -> raise MergeImpossible
            | (c, t) :: xs -> ( conds @ c, t ) :: inline_rules conds xs
            | [] -> []
          in
            (inline_rules conds chain.rules) @ (inline_chain chain xs)
        end
    | x :: xs -> x :: inline_chain chain xs
    | [] -> []
  in

  (* Find one chain that satifies p *)
  let p' chains chain = (not (has_target Return chain.rules || Chain.is_builtin chain.id) ) && chain_reference_count chain.id chains > 0 && p chains chain in
    try
      let chains_to_inline = List.hd (Chain.filter (p' chains) chains) in
        printf "I"; inline p (map_chain_rules (inline_chain chains_to_inline) chains)
    with Failure _ -> chains

let rec eliminate_dead_rules = function
    ([], Accept) | ([], Drop) | ([], Return) | ([], Reject _) as rle :: xs ->
      if List.length xs > 0 then printf "D";
      [ rle ]
  | rle :: xs -> rle :: eliminate_dead_rules xs
  | [] -> []

let rec eliminate_dublicate_rules = function
    rle1 :: rle2 :: xs when Ir.eq_oper rle1 rle2 ->
      printf "d";
      rle1 :: eliminate_dublicate_rules xs
  | rle :: xs -> rle :: eliminate_dublicate_rules xs
  | [] -> []

let rec count_rules chains =
    Chain_map.fold (fun _ chn acc -> acc + List.length chn.rules) chains 0

(* Determine if a chain should be linined. The algorithm is based on
   number of conditions before and after the merge, with a slight
   tendency to inline *)
let should_inline cs c =
  (* Number of conditions in the chain to be inlined *)
  let chain_conds = List.fold_left (fun acc (cl, t) -> acc + List.length cl) 0 c.rules in
  (* Number of conditions for each reference to the chain to be inlined. *)
  let rule_conds = List.map (fun (cl, t) -> List.length cl) (get_referring_rules c cs) in
  (* Current count of conditions + targets *)
  let old_conds = (List.fold_left (+) 0 rule_conds) + chain_conds + List.length rule_conds + List.length c.rules in
  (* Inlined count of conditions + targets *)
  let new_conds = List.fold_left (fun acc n -> acc + n * List.length c.rules + chain_conds) 0 rule_conds + (List.length rule_conds * List.length c.rules) in
    (new_conds - old_conds) * 100 / (old_conds) < 10

let conds chains =
  Chain_map.fold (fun _ chn acc -> List.fold_left (fun acc (cl, _) -> List.length cl + acc) (acc + 1) chn.rules) chains 0

let optimize_pass chains =
  printf "Optim: (%d, %d) " (count_rules chains) (conds chains); flush stdout;
  let chains' = chains in
  let chains' = fold_return_statements chains' in
  let chains' = remove_dublicate_chains chains' in
  let chains' = map_chain_rules eliminate_dead_rules chains' in
  let chains' = map_chain_rules eliminate_dublicate_rules chains' in
  let chains' = map_chain_rules reorder chains' in
  let chains' = reduce chains' in
  let chains' = inline should_inline chains' in
  let chains' = map_chain_rules (fun rls -> Common.map_filter_exceptions (fun (opers, tg) -> (merge_opers opers, tg)) rls) chains' in
  let chains' = remove_unreferenced_chains chains' in
    printf " (%d, %d)\n" (count_rules chains') (conds chains');
    chains'

let rec optimize chains =
  let chains' = optimize_pass chains in
    match (conds chains) = (conds chains') with
        true -> printf "Optimization done\n"; chains'
      | false -> optimize chains'

