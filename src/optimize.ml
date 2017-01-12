open Batteries
open Common
open Ir
open Printf
open Chain
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

(** Define the saving in conditions when inlining. *)
let min_inline_saving = -2
let max_inline_size = 0

let chain_reference_count id chains =
  let count_references rules =
    List.fold_left (fun acc -> function (_, Jump id') when id = id' -> acc + 1 | _ -> acc) 0 rules
  in
  Map.fold (fun chn acc -> acc + (count_references chn.rules)) chains 0

let get_referring_rules chain chains =
  let test (_conds, target) = target = Jump (chain.id) in
  let referring_chains = Chain.filter (fun chn -> List.exists test chn.rules) chains in
  List.fold_left (fun acc chn -> (List.filter test chn.rules) @ acc) [] referring_chains

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains =
  Map.map (fun chn -> { chn with rules = func chn.rules }) chains

let map_chain_rules_expand func chains : Ir.chain list =
  let rec map_rules = function
    | (opers, target) :: xs ->
      (try
         (List.map (fun opers' -> (opers', target)) (func opers))
       with _ -> printf "E"; []
      ) @ map_rules xs
    | [] -> []
  in
  List.map (fun chn -> { id = chn.id; rules = map_rules chn.rules; comment = chn.comment } ) chains

let merge_oper ?(tpe=`Inter) a b =
    (* !A => !B => X   =>  !(A | B) => X

     A => B => X     => A U B => X

     A => !B => X    => (A / B) => X
     !A => B => X    => (B / A) => X

  *)
  let merge_inter inter union diff (s, neg) (s', neg') =
    match neg, neg' with
    | false, false -> (inter s s', false)
    | true, true ->   (union s s', true)
    | false, true ->  (diff s  s', false)
    | true, false ->  (diff s' s, false)
  in

  let merge_union inter union diff (s, neg) (s', neg') =
    match neg, neg' with
    | false, false -> (union s s', false)
    | true, true ->   (inter s s', true)
    | false, true ->  (diff s'  s, true)
    | true, false ->  (diff s s',  true)
  in
  let merge = match tpe with
    | `Inter -> merge_inter
    | `Union -> merge_union
  in

  let merge_states = merge State.intersect State.union State.diff in
  let merge_ip6sets = merge Ip6.intersect Ip6.union Ip6.diff in
  let merge_ip4sets = merge Ip4.intersect Ip4.union Ip4.diff in
  let merge_sets a b = merge Set.intersect Set.union Set.diff a b in
  match a, b with
  |  (Interface (dir, is), neg), (Interface (dir', is'), neg') when dir = dir' ->
      let (is'', neg'') = merge_sets (is, neg) (is', neg') in
      (Interface (dir, is''), neg'') |> Option.some
  | (State s, neg), (State s', neg') ->
      let (s'', neg'') = merge_states (s, neg) (s', neg') in
      (State s'', neg'') |> Option.some
  | (Ports (dir, pt, ports), neg), (Ports (dir', pt', ports'), neg') when dir = dir' && pt = pt' ->
      let (ports'', neg'') = merge_sets (ports, neg) (ports', neg') in
      (Ports (dir, pt, ports''), neg'') |> Option.some
  | (Protocol (l, p), neg), (Protocol (l', p'), neg') when l = l' ->
      let (p'', neg'') = merge_sets (p, neg) (p', neg') in
      (Protocol (l, p''), neg'') |> Option.some
  | (Icmp6 types, neg), (Icmp6 types', neg') ->
      let (types'', neg'') = merge_sets (types, neg) (types', neg') in
      (Icmp6 types'', neg'') |> Option.some
  | (Icmp4 types, neg), (Icmp4 types', neg') ->
      let (types'', neg'') = merge_sets (types, neg) (types', neg') in
      (Icmp4 types'', neg'') |> Option.some
  | (Ip6Set (dir, set), neg), (Ip6Set (dir', set'), neg') when dir = dir' ->
      let (set'', neg'') = merge_ip6sets (set, neg) (set', neg') in
      (Ip6Set (dir, set''), neg'') |> Option.some
  | (Ip4Set (dir, set), neg), (Ip4Set (dir', set'), neg') when dir = dir' ->
      let (set'', neg'') = merge_ip4sets (set, neg) (set', neg') in
      Some (Ip4Set (dir, set''), neg'')
  | (Zone (dir, zones), neg), (Zone (dir', zones'), neg') when dir = dir' ->
      let (zones'', neg'') = merge_sets (zones, neg) (zones', neg') in
      Some (Zone (dir, zones''), neg'')
  | (TcpFlags (f, m), false), (TcpFlags (f', m'), false) -> begin
      let set_flags = Set.union f f' in
      let unset_flags = Set.union (Set.diff m f) (Set.diff m' f') in
      match Set.intersect set_flags unset_flags |> Set.is_empty with
      | true ->
          Some (TcpFlags (set_flags, Set.union m m'), false)
      | false -> Some (True, true)
    end
  | (True, neg), (True, neg') -> Some (True, neg || neg')
  | (_cond, _), (_cond', _) -> None

let merge_opers rle =
  let rec merge_siblings acc = function
    | x :: xs ->
        let (x', xs') = List.fold_left (
            fun (m, rest) op -> match merge_oper m op with
              | Some m' -> (m', rest)
              | None -> (m, op :: rest)
          ) (x, []) xs in
        merge_siblings (x' :: acc) xs'
    | [] -> acc
  in
  merge_siblings [] rle

let rec bind_list acc = function
  | Some x :: xs -> bind_list (x :: acc) xs
  | None :: _ -> None
  | [ ] -> Some (List.rev acc)


let rec merge_adjecent_rules = function
  | (ops, tg) :: (ops', tg') :: xs when tg = tg' -> begin
      let ops'' =
        List.group
          (fun a b -> Int.compare (enumerate_cond @@ fst a) (enumerate_cond @@ fst b))
          (ops @ ops')
        |> List.map (function [ op; op' ] -> merge_oper ~tpe:`Union op op' | _ -> None)
        |> bind_list []
      in
      match ops'' with
      | Some ops -> printf "M"; merge_adjecent_rules ((ops, tg) :: xs)
      | None -> (ops, tg) :: merge_adjecent_rules ((ops', tg') :: xs)
    end
  | x :: xs -> x :: merge_adjecent_rules xs
  | [] -> []

let is_satisfiable conds =
  not (List.exists (is_always false) conds)

(** Test if a set b is a subset of a. Meaning that B => A *)
let is_subset a b =
  not (List.exists (fun (cond, neg) -> is_satisfiable (merge_opers ((cond, not neg) :: a))) b)

(** Reduce rules. Walk the tree (forward and backwards) and eliminate
    unreachable rules. *)
let reduce chains =
  let false_rule = ([State State.empty, false], Notrack) in
  let is_terminal = function
    | Jump _ | MarkZone _ | Notrack | Log _ -> false
    | Accept | Drop | Reject _ | Return -> true
  in
  let chains = ref chains in
  let get_chain chain_id = Map.find chain_id !chains in
  let rec reduce_chain func chain_id =
    let chn = get_chain chain_id in
    let rls = func chn.rules in
    chains := Map.add chn.id { id = chn.id; rules = rls; comment = chn.comment } !chains;

  and reduce_jump conds rules chain_id =
    let rec filter_until pred = function
      | x :: _ when pred x -> []
      | x :: xs -> x :: filter_until pred xs
      | [] -> []
    in
    let terminal_rules = List.filter (fun (_, tg) -> is_terminal tg) (get_chain chain_id).rules in
    let terminals = filter_until (fun (_, tg) -> tg = Return) terminal_rules in
    List.fold_left (fun rules (conds', target') -> reduce_rules ((merge_opers conds @ conds'), target') rules) rules terminals

  and reduce_forward_jump = function
    | (cond', Jump chain_id) as rle :: xs ->
      rle :: reduce_forward_jump (reduce_jump cond' xs chain_id)
    | rle :: xs -> rle :: reduce_forward_jump xs
    | [] -> []

  and reduce_rules (cond, target) = function
    | (cond', _) :: xs when is_subset cond' cond ->
      print_string "E"; reduce_rules (cond, target) xs
    | (_cond', Jump chain_id) as rle :: xs when chain_reference_count chain_id !chains = 1 ->
      reduce_chain (reduce_rules (cond, target)) chain_id;
      rle :: reduce_rules (cond, target) xs
    | (cond', target') as rle :: xs when is_terminal target' ->
      rle :: reduce_rules (cond', target') (reduce_rules (cond, target) xs)
    | rle :: xs -> rle :: reduce_rules (cond,target) xs
    | [] -> []

  and reduce_rules_rev (cond, target) = function
    | (_cond', Return) as rle :: xs -> rle :: reduce_rules_rev false_rule xs
    | (cond', target') :: xs when target = target' && is_subset cond' cond ->
      print_string "F"; reduce_rules_rev (cond, target) xs
    | (_cond', target') as rle :: xs when target = target' ->
      let rls = reduce_rules_rev (cond, target) xs in rle :: reduce_rules_rev rle rls
    | (_cond', Jump chain_id) as rle :: xs ->
      reduce_chain (reduce_rules_reverse (cond, target)) chain_id;
      rle :: reduce_rules_rev false_rule xs
    | (_cond', target) as rle :: xs when is_terminal target -> rle :: reduce_rules_rev rle xs
    | rle :: xs -> rle :: reduce_rules_rev false_rule xs
    | [] -> []

  and reduce_rules_reverse (cond, target) rules =
    List.rev (reduce_rules_rev (cond, target) (List.rev rules))
  in

  let keys = Map.foldi (fun key _ acc -> key :: acc) !chains [] in
  List.iter (reduce_chain (reduce_rules false_rule)) keys;
  List.iter (reduce_chain (reduce_rules_reverse false_rule)) keys;
  List.iter (reduce_chain reduce_forward_jump) keys;
  !chains

(** Remove all return statements, by creating new chains for each
    return statement *)
let fold_return_statements chains =
  (* This is wrong. *)
  (* So we have:
       a ^ b -> return
       X
  must be
    !a jump 1
    !b jump 1
  1: X

  *)
  let neg tg = List.map (fun (x, a) -> [(x, not a)], tg) in
  let rec fold_return acc = function
    | (cl, Return) :: xs ->
      printf "F";
      let rls, chns = fold_return [] xs in
      let chn = Chain.create rls "Return stm inlined" in
      let jumps = neg (Jump (chn.id)) cl in
      (acc @ jumps, chn :: chns)
    | rle :: xs -> fold_return (acc @ [rle]) xs
    | [] -> (acc, [])
  in

  let fold_func chn acc =
    let rls, chns = fold_return [] chn.rules in
    List.fold_left (fun acc chn -> Map.add chn.id chn acc) acc ( { id = chn.id; rules = rls; comment = chn.comment } :: chns )
  in
  Map.fold fold_func chains Map.empty

let remove_unreferenced_chains chains =
  let get_referenced_chains chain =
    List.fold_left (fun acc -> function (_, Jump id) -> (Map.find id chains) :: acc | _ -> acc) [] chain.rules
  in
  let rec descend acc chain =
    List.fold_left (fun acc chn -> descend acc chn) (Map.add chain.id chain acc) (get_referenced_chains chain)
  in
  Map.foldi (fun id chn acc -> match id with Builtin _ -> descend acc chn | _ -> acc) chains Map.empty

(** Remove dublicate chains *)
let remove_dublicate_chains chains =
  let replace_chain_ids (id, ids) chns =
    map_chain_rules (List.map (function (c, Jump id') when List.mem id' ids -> (c, Jump id) | x -> x)) chns
  in
  let is_sibling a b = (Ir.eq_rules a.rules b.rules) && not (a.id = b.id) in
  let identical_chains chain chains = Map.foldi (fun id chn acc -> if is_sibling chain chn then id :: acc else acc) chains [] in
  let remap_list = Map.foldi (fun id chn acc -> (id, identical_chains chn chains) :: acc) chains [] in
  List.fold_left (fun acc (id, ids) -> if List.length ids > 0 then printf "D"; replace_chain_ids (id, ids) acc) chains remap_list

(** Move drops to the bottom. This allows improvement to dead code
    elimination, and helps reduce *)
let reorder rules =
  let can_reorder (cl1, act1) (cl2, act2) =
    act1 = act2 || not (is_satisfiable (merge_opers (cl1 @ cl2)))
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
      |  n when n > 0 -> true
      | 0 -> if List.length cl1 < List.length cl2 then true
        else (* Weight the types, and add them. *) false
      | _ -> false
    else
      false
  in
  let rec reorder_rules acc = function
    | rule1 :: rule2 :: xs when should_reorder_rules rule1 rule2 ->
      printf "R";
      reorder_rules [] (acc @ rule2 :: rule1 :: xs)
    | rule1 :: xs ->
      reorder_rules (acc @ [ rule1]) xs
    | [] -> acc

  in
  reorder_rules [] rules

let filter_protocol chain =
  let expand (l, p) = Set.to_list p |> List.map ( fun p -> (l, p) ) in
  let all =
    (expand (Protocol.Ip4, Protocol.all)) @
    (expand (Protocol.Ip6, Protocol.all))  |> Set.of_list
  in

  let to_protocol = function
    | Ir.Protocol (Protocol.Ip4, p), true ->
        (expand (Protocol.Ip4, Set.diff Protocol.all p)) @
        (expand (Protocol.Ip6, Protocol.all)) |> Set.of_list
    | Ir.Protocol (Protocol.Ip6, p), true ->
        (expand (Protocol.Ip6, Set.diff Protocol.all p)) @
        (expand (Protocol.Ip4, Protocol.all)) |> Set.of_list
    | Ir.Protocol (l, p), false -> expand (l, p) |> Set.of_list
    | Ir.True, _ -> all
    | Ir.Interface (_,_), _ -> all
    | Ir.Zone (_,_), _ -> all
    | Ir.State _, _ -> all
    | Ir.Ports (_,Ir.Tcp, _), false -> [
        Ir.Protocol.Ip4, Ir.Protocol.Tcp;
        Ir.Protocol.Ip6, Ir.Protocol.Tcp;
      ] |> Set.of_list
    | Ir.Ports (_,Ir.Udp, _), false -> [
        Ir.Protocol.Ip4, Ir.Protocol.Udp;
        Ir.Protocol.Ip6, Ir.Protocol.Udp;
      ] |> Set.of_list
    | Ir.Ports (_, _ , _), true -> all
    | Ir.Ip6Set (_,_), false ->
        expand (Ir.Protocol.Ip6, Ir.Protocol.all) |> Set.of_list
    | Ir.Ip6Set (_,_), true -> all
    | Ir.Ip4Set (_,_), false ->
        expand (Ir.Protocol.Ip4, Ir.Protocol.all)  |> Set.of_list
    | Ir.Ip4Set (_,_), true -> all
    | Ir.Icmp6 _, _ -> Set.singleton (Ir.Protocol.Ip6, Ir.Protocol.Icmp)
    | Ir.Icmp4 _, _ -> Set.singleton (Ir.Protocol.Ip4, Ir.Protocol.Icmp)
    | Ir.Mark (_,_), _ -> all
    | Ir.TcpFlags (_,_), _ -> [
        Ir.Protocol.Ip6, Ir.Protocol.Tcp;
        Ir.Protocol.Ip4, Ir.Protocol.Tcp;
      ] |> Set.of_list
  in
  let rec filter_chain = function
    | (rules, target) :: xs -> begin
        let protocols = List.fold_left (fun ps r -> Set.intersect ps (to_protocol r)) all rules in
        match Set.is_empty protocols with
        | true -> printf "P"; filter_chain xs
        | false -> (rules, target) :: filter_chain xs
      end
    | [] -> []
  in
  filter_chain chain

(** Inline chains that satifies p *)
let rec inline p chains =
  let has_target target rules =
    List.exists (fun (_, t) -> t = target) rules
  in
  let rec inline_chain chain = function
    | (conds, target) :: xs when target = Jump(chain.id) ->
      begin
        let rec inline_rules conds = function
          | (_c, t) :: _ when t = Return -> failwith "Inline of return target dosallowed."
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
  | ([], Accept)
  | ([], Drop)
  | ([], Return)
  | ([], Reject _) as rle :: xs ->
    if List.length xs > 0 then printf "D";
    [ rle ]
  | rle :: xs -> rle :: eliminate_dead_rules xs
  | [] -> []

let rec eliminate_dublicate_rules = function
  | rle1 :: rle2 :: xs when Ir.eq_oper rle1 rle2 ->
    printf "d";
    rle1 :: eliminate_dublicate_rules xs
  | rle :: xs -> rle :: eliminate_dublicate_rules xs
  | [] -> []

(** For each rule in a chain, tests is the conditions are satisfiable.
    All rules which contains an unsatisfiable rule are removed
    (including its target)
*)
let remove_unsatisfiable_rules rules =
  List.filter (fun (conds, _) -> is_satisfiable conds) rules

(** All conditions which is always true are removed *)
let remove_true_rules rules =
  List.map (fun (conds, target) -> (List.filter (fun cond -> not (is_always true cond)) conds, target)) rules

let rec remove_false_chains = function
  | (ops, _) :: xs when List.exists (is_always false) ops -> printf "r"; remove_false_chains xs
  | x :: xs -> x :: remove_false_chains xs
  | [] -> []

let count_rules chains =
  Map.fold (fun chn acc -> acc + List.length chn.rules) chains 0

(** Determine if a chain should be linined. The algorithm is based on
    number of conditions before and after the merge, with a slight
    tendency to inline *)
let should_inline cs c =
  (* Number of conditions in the chain to be inlined *)
  let chain_conds = List.fold_left (fun acc (cl, _t) -> acc + List.length cl) 0 c.rules in
  (* Number of conditions for each reference to the chain to be inlined. *)
  let rule_conds = List.map (fun (cl, _t) -> List.length cl) (get_referring_rules c cs) in
  (* Current count of conditions + targets *)
  let old_conds = (List.fold_left (+) 0 rule_conds) + chain_conds + List.length rule_conds + List.length c.rules in
  (* Inlined count of conditions + targets *)
  let new_conds = List.fold_left (fun acc n -> acc + n * List.length c.rules + chain_conds) 0 rule_conds + (List.length rule_conds * List.length c.rules) in
  old_conds - new_conds > min_inline_saving

let conds chains =
  Map.fold (fun chn acc -> List.fold_left (fun acc (cl, _) -> List.length cl + acc) (acc + 1) chn.rules) chains 0

let optimize_pass chains =
  printf "#Optim: (%d, %d) " (count_rules chains) (conds chains); flush stdout;
  let optimize_functions = [
    fold_return_statements;
    remove_dublicate_chains;
    map_chain_rules remove_unsatisfiable_rules;
    map_chain_rules remove_true_rules;
    map_chain_rules remove_false_chains;
    map_chain_rules eliminate_dead_rules;
    map_chain_rules eliminate_dublicate_rules;
    map_chain_rules merge_adjecent_rules;
    map_chain_rules reorder;
    map_chain_rules filter_protocol;
    reduce;
    inline should_inline;
    map_chain_rules (fun rls -> Common.map_filter_exceptions (fun (opers, tg) -> (merge_opers opers, tg)) rls);
    remove_unreferenced_chains;
  ] in
  let chains' = List.fold_left (fun chains' optim_func -> optim_func chains') chains optimize_functions in
  printf " (%d, %d)\n" (count_rules chains') (conds chains');
  chains'

let rec optimize chains =
  let chains' = optimize_pass chains in
  match (conds chains, count_rules chains) = (conds chains', count_rules chains') with
  | true -> printf "#Optimization done\n"; chains'
  | false -> optimize chains'
