open Core
open Ir
open Printf
open Poly
module Ip6 = Ipset.Ip6
module Ip4 = Ipset.Ip4

(** Define the saving in conditions when inlining. *)
let max_inline_cost = 1

let is_satisfiable conds =
  not (List.exists ~f:(is_always false) conds)

let is_subset_eq a b =
  List.for_all ~f:(fun a -> List.exists b ~f:((=) a)) a

let is_eq a b =
  is_subset_eq a b && is_subset_eq b a

let chain_reference_count id chains =
  let count_references rules =
    List.fold_left ~f:(fun acc -> function (_, _, Jump id') when id = id' -> acc + 1 | _ -> acc) ~init:0 rules
  in
  Map.fold ~f:(fun ~key:_ ~data:chn acc -> acc + (count_references chn.rules)) chains ~init:0

let get_referring_rules chain chains =
  let test (_conds, _effects, target) = target = Jump (chain.id) in
  let referring_chains = Chain.filter (fun chn -> List.exists ~f:test chn.rules) chains in
  List.fold_left ~f:(fun acc chn -> (List.filter ~f:test chn.rules) @ acc) ~init:[] referring_chains

(** Optimize rules in each chain. No chain insertion or removal is possible *)
let map_chain_rules func chains =
  Map.map ~f:(fun chn -> { chn with rules = func chn.rules }) chains

let map_chain_rules_expand func chains : Ir.chain list =
  let rec map_rules = function
    | (opers, effects, target) :: xs ->
      (try
         (List.map ~f:(fun opers' -> (opers', effects, target)) (func opers))
       with _ -> []
      ) @ map_rules xs
    | [] -> []
  in
  List.map ~f:(fun chn -> { id = chn.id; rules = map_rules chn.rules; comment = chn.comment } ) chains

let merge_oper ?(tpe=`Inter) a b =
    (* !A => !B => X   =>  !(A | B) => X

     A => B => X     => A U B => X

     A => !B => X    => (A / B) => X
     !A => B => X    => (B / A) => X

  *)
  let merge_inter inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (inter a b, false)
    | (a, true),  (b, true)  -> (union a b, true)
    | (a, false), (b, true)  -> (diff  a b, false)
    | (a, true),  (b, false) -> (diff  b a, false)
  in

  let merge_union inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (union a b, false)
    | (a, true),  (b, true)  -> (inter a b, true)
    | (a, false), (b, true)  -> (diff  b a, true)
    | (a, true),  (b, false) -> (diff  a b, true)
  in
  let merge_diff inter union diff a b =
    match a, b with
    | (a, false), (b, false) -> (diff  a b, false)
    | (a, true),  (b, true)  -> (diff  b a, false)
    | (a, false), (b, true)  -> (inter a b, false)
    | (a, true),  (b, false) -> (union a b, true)
  in

  let merge = match tpe with
    | `Inter -> merge_inter
    | `Union -> merge_union
    | `Diff -> merge_diff
  in

  let merge_states = merge State.intersect State.union State.diff in
  let merge_ip6sets = merge Ip6.intersect Ip6.union Ip6.diff in
  let merge_ip4sets = merge Ip4.intersect Ip4.union Ip4.diff in
  let merge_sets a b = merge Set.Poly.inter Set.union Set.diff a b in
  match a, b with
  | (Interface (dir, is), neg), (Interface (dir', is'), neg') when dir = dir' ->
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
      match Set.Poly.inter set_flags unset_flags |> Set.is_empty with
      | true ->
          Some (TcpFlags (set_flags, Set.union m m'), false)
      | false -> Some (True, true)
    end
  | (True, neg), (True, neg') -> Some (True, neg || neg')
  | (_cond, _), (_cond', _) -> None

let merge_opers rle =
  let rec merge_siblings acc = function
    | x :: xs ->
        let (x', xs') = List.fold_left ~f:(
            fun (m, rest) op -> match merge_oper m op with
              | Some m' -> (m', rest)
              | None -> (m, op :: rest)
          ) ~init:(x, []) xs in
        merge_siblings (x' :: acc) xs'
    | [] -> acc
  in
  merge_siblings [] rle


let is_subset a b =
  match merge_oper ~tpe:`Diff a b with
  | Some r ->
      (* if b - a is still satisfiable, then b covers more that a. *)
      is_always false r
  | None -> false

(* Subtract predicates bs from as.
   The idea is that all packets matched by as are removed from the chain,
   then we want to exclusde predicates in bs in order to reduce it.
*)
let subtract_conds preds preds' =
  let rec subtract acc = function
    | p :: ps ->
        let p' = match merge_oper ~tpe:`Diff acc p with
          | Some p' -> p'
          | None -> acc
        in subtract p' ps
    | [] -> acc
  in
  List.map ~f:(fun p -> subtract p preds') preds

let is_terminal = function
  | Pass | Jump _ -> false
  | Accept | Drop | Return | Reject _ -> true

let join chains =
  let has_cond cond = function
    | (conds, _effects, _target) ->
        List.exists ~f:(Ir.eq_cond cond) conds
  in
  let filter_cond cond (conds, effects, target) =
    (List.filter ~f:(fun c -> not (Ir.eq_cond cond c)) conds, effects, target)
  in
  let rec count_conds cond = function
    | x :: xs when has_cond cond x ->
        1 + count_conds cond xs
    | _ -> 0
  in
  let partition cond rules =
    List.partition_tf ~f:(has_cond cond) rules
  in
  let new_chains = ref [] in
  let rec inner acc = function
    | (conds, _effects, _target) as rule :: xs -> begin
        let x = List.map ~f:(fun cond -> (cond, count_conds cond acc, count_conds cond xs)) conds in
        let choose =
          List.reduce x ~f:(fun (c, p, n) (c', p', n') -> if p+n>=p'+n' then (c, p, n) else (c', p', n'))
        in
        match choose with
        | Some (cond, prev, next) when next = 0 && prev >= 3 ->
            printf "J";
            let (to_inline, rest) = partition cond (rule :: acc) in
            let chain_rules = List.map ~f:(filter_cond cond) to_inline in
            let chain = Chain.create chain_rules "Condition moved" in
            new_chains := chain :: !new_chains;
            (* Replace with a jump to the chain *)
            let acc = ([cond], [], Ir.Jump chain.id) :: rest in
            (List.rev acc) @ inner [] xs
        | _ -> inner (rule :: acc) xs
      end
    | [] -> List.rev acc
  in
  let chains = Map.map ~f:(fun chn -> { chn with rules = inner [] chn.rules }) chains in
  List.fold_left ~init:chains ~f:(fun chains chain -> Map.add_exn ~key:chain.id ~data:chain chains) !new_chains

let rec bind_list acc = function
  | Some x :: xs -> bind_list (x :: acc) xs
  | None :: _ -> None
  | [ ] -> Some (List.rev acc)

let group ~cmp l =
  let rec inner = function
    | ([], x :: xs) -> inner ([x], xs)
    | (xs, []) -> [xs]
    | (x :: _ as xs, y :: ys) when cmp x y = 0 -> inner (y :: xs, ys)
    | (xs, ys) -> xs :: inner ([], ys)
  in
  let sorted = List.sort ~compare l in
  inner ([], sorted)

(** Remove all return statements, by creating new chains for each
    return statement. Add an empty rule to the new chain to do the effects *)
let fold_return_statements chains =
  let neg tg conds = List.map ~f:(fun (x, a) -> [(x, not a)], [], tg) conds in
  let rec fold_return acc = function
    | (cl, _ef, Return) :: xs ->
        printf "F";
        let rls, chns = fold_return [] xs in
        let chn = Chain.create rls "Return stm inlined" in
        let jumps = neg (Jump (chn.id)) cl in
        (acc @ jumps, chn :: chns)
    | rle :: xs -> fold_return (acc @ [rle]) xs
    | [] -> (acc, [])
  in

  let fold_func ~key:_ ~data:chn acc =
    let rls, chns = fold_return [] chn.rules in
    List.fold_left ~f:(fun acc chn -> Map.add_exn ~key:chn.id ~data:chn acc) ~init:acc ( { id = chn.id; rules = rls; comment = chn.comment } :: chns )
  in
  Map.fold chains ~f:fold_func ~init:(Map.empty (module Ir.Chain_id))

let remove_unreferenced_chains chains =
  let get_referenced_chains chain =
    List.fold_left ~f:(fun acc -> function (_, _, Jump id) -> (Map.find_exn chains id) :: acc | _ -> acc) ~init:[] chain.rules
  in
  let rec descend acc chain =
    match Map.mem acc chain.id with
    | true -> acc
    | false ->
      List.fold_left
        ~init:(Map.add_exn ~key:chain.id ~data:chain acc)
        ~f:(fun acc chn -> descend acc chn)
        (get_referenced_chains chain)
  in
  Map.fold
    ~init:(Map.empty (module Ir.Chain_id))
    ~f:(fun ~key:id ~data:chn acc -> match id with Builtin _ -> descend acc chn | _ -> acc) chains

(** Remove dublicate chains *)
let remove_dublicate_chains chains =
  let replace_chain_ids (id, ids) chns =
    map_chain_rules (List.map ~f:(function (c, e, Jump id') when List.mem ~equal:(=) ids id' -> (c, e, Jump id) | x -> x)) chns
  in
  let is_sibling a b = (Ir.eq_rules a.rules b.rules) && not (a.id = b.id) && Chain.is_temp a.id && Chain.is_temp b.id in
  let identical_chains chain chains =
    Map.fold ~f:(fun ~key:id ~data:chn acc ->
        if is_sibling chain chn then id :: acc else acc) chains ~init:[] in
  let remap_list = Map.fold ~f:(fun ~key:id ~data:chn acc -> (id, identical_chains chn chains) :: acc) chains ~init:[] in
  List.fold_left ~f:(fun acc (id, ids) -> if List.length ids > 0 then printf "D"; replace_chain_ids (id, ids) acc) ~init:chains remap_list

(** Move drops to the bottom. This allows improvement to dead code
    elimination, and helps reduce *)
let reorder rules =
  let can_reorder (cl1, ef1, act1) (cl2, ef2, act2) =
    (is_eq ef1 ef2 && act1 = act2) || not (is_satisfiable (merge_opers (cl1 @ cl2)))
  in

  let order = function
    | Accept     -> 0
    | Reject _   -> 1
    | Drop       -> 2
    | Return     -> 3
    | Jump _     -> 4
    | Pass       -> 5
  in
  let should_reorder_rules (cl1, ef1, act1) (cl2, ef2, act2) =
    if can_reorder (cl1, ef1, act1) (cl2, ef2, act2) then
      match order act1 - order act2 with
      | n when n > 0 -> true
      | 0 when List.length cl1 + List.length ef1 < List.length cl2 + List.length cl2 -> true
      | _ -> false
    else
      false
  in
  let rec reorder_rules acc = function
    | rule1 :: rule2 :: xs when should_reorder_rules rule1 rule2 ->
      printf "R";
      reorder_rules (rule2 :: acc) (rule1 :: xs)
    | rule1 :: xs ->
      reorder_rules (rule1 :: acc) xs
    | [] -> List.rev acc
  in
  reorder_rules [] rules

let filter_protocol chain =
  let expand (l, p) = Set.to_list p |> List.map ~f:(fun p -> (l, p) ) in
  let all =
    (expand (Protocol.Ip4, Protocol.all)) @
    (expand (Protocol.Ip6, Protocol.all))
    |> Set.Poly.of_list
  in

  let to_protocol = function
    | Ir.Protocol (Protocol.Ip4, p), true ->
        (expand (Protocol.Ip4, Set.diff Protocol.all p)) @
        (expand (Protocol.Ip6, Protocol.all)) |> Set.Poly.of_list
    | Ir.Protocol (Protocol.Ip6, p), true ->
        (expand (Protocol.Ip6, Set.diff Protocol.all p)) @
        (expand (Protocol.Ip4, Protocol.all)) |> Set.Poly.of_list
    | Ir.Protocol (l, p), false -> expand (l, p) |> Set.Poly.of_list
    | Ir.True, _ -> all
    | Ir.Interface (_,_), _ -> all
    | Ir.Zone (_,_), _ -> all
    | Ir.State _, _ -> all
    | Ir.Vlan _, _ -> all
    | Ir.Ports (_, Ir.Port_type.Tcp, _), false -> [
        Ir.Protocol.Ip4, Ir.Protocol.Tcp;
        Ir.Protocol.Ip6, Ir.Protocol.Tcp;
      ] |> Set.Poly.of_list
    | Ir.Ports (_,Ir.Port_type.Udp, _), false -> [
        Ir.Protocol.Ip4, Ir.Protocol.Udp;
        Ir.Protocol.Ip6, Ir.Protocol.Udp;
      ] |> Set.Poly.of_list
    | Ir.Ports (_, _ , _), true -> all
    | Ir.Ip6Set (_,_), false ->
        expand (Ir.Protocol.Ip6, Ir.Protocol.all) |> Set.Poly.of_list
    | Ir.Ip6Set (_,_), true -> all
    | Ir.Ip4Set (_,_), false ->
        expand (Ir.Protocol.Ip4, Ir.Protocol.all)  |> Set.Poly.of_list
    | Ir.Ip4Set (_,_), true -> all
    | Ir.Icmp6 _, _ -> Set.Poly.singleton (Ir.Protocol.Ip6, Ir.Protocol.Icmp)
    | Ir.Icmp4 _, _ -> Set.Poly.singleton (Ir.Protocol.Ip4, Ir.Protocol.Icmp)
    | Ir.Mark (_,_), _ -> all
    | Ir.TcpFlags (_,_), _ -> [
        Ir.Protocol.Ip6, Ir.Protocol.Tcp;
        Ir.Protocol.Ip4, Ir.Protocol.Tcp;
      ] |> Set.Poly.of_list
  in
  let rec filter_chain = function
    | (rules, effect, target) :: xs -> begin
        let protocols = List.fold_left ~f:(fun ps r -> Set.Poly.inter ps (to_protocol r)) ~init:all rules in
        match Set.is_empty protocols with
        | true -> printf "P"; filter_chain xs
        | false -> (rules, effect, target) :: filter_chain xs
      end
    | [] -> []
  in
  filter_chain chain

(** Inline chains that satifies p *)
let rec inline cost_f chains =
  let rec inline_chain chain = function
    | (conds, effects, target) :: xs when target = Jump(chain.id) && (Chain.is_temp chain.id)-> begin
        let rec inline_rules (conds, effects) = function
          | (c, e, t) :: xs -> ( conds @ c, effects @ e, t ) :: inline_rules (conds, effects) xs
          | [] -> []
        in
        (inline_rules (conds, effects) chain.rules) @ (inline_chain chain xs)
      end
    | x :: xs -> x :: inline_chain chain xs
    | [] -> []
  in

  (* Select the chain with the least cost *)
  let chain_to_inline =
    Map.fold ~init:None
      ~f:(fun ~key:_ ~data:chain acc ->
          match Chain.is_temp chain.id &&
                chain_reference_count chain.id chains > 0 with
          | true -> begin
              let cost = cost_f chains chain in
              match cost, acc with
              | c, _ when c > max_inline_cost -> acc
              | _, Some (_, c) when c < cost -> acc
              | _ -> Some (chain, cost)
            end
          | false -> acc
        ) chains
    |> Option.map ~f:fst
  in
  (* Inline the chain *)
  match chain_to_inline with
  | Some chain ->
    printf "I";
    let chains = map_chain_rules (inline_chain chain) chains in
    inline cost_f chains
  | None -> chains


let rec eliminate_dead_rules = function
  | ([], effects, target) :: xs when is_terminal target ->
      if List.length xs > 0 then printf "D";
      [ ([], effects, target) ]
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
  List.filter ~f:(fun (conds, _, _) -> is_satisfiable conds) rules

let remove_empty_rules rules =
  List.filter ~f:(function (_, [], Ir.Pass) -> false | _ -> true) rules

let merge_adjecent_rules chains =
  let new_chains = ref [] in
  let rec merge = function
    | ([rule], effects, target) :: ([rule'], effects', target') :: xs when Ir.eq_cond rule rule' -> begin
        let chain = Chain.create [ ([], effects, target); ([], effects', target') ] "rule merged" in
        new_chains := chain :: !new_chains;
        merge (([rule], [], Jump chain.id) :: xs)
      end
    | ([rule], effects, target) :: ([rule'], effects', target') :: xs
      when Ir.eq_effects effects effects'
        && target = target'
        && merge_oper ~tpe:`Union rule rule' <> None ->
        let r = merge_oper ~tpe:`Union rule rule' in
        merge (([Option.value_exn r], effects, target) :: xs)
    | ([rule], effects, target) :: ([rule'], _, _) :: xs
      when is_terminal target && is_subset rule' rule ->
        merge (([rule], effects, target) :: xs)
    | x :: xs -> x :: merge xs
    | [] -> []
  in
  let chains = Map.map ~f:(fun c -> { c with rules = merge c.rules }) chains in
  List.fold_left ~init:chains ~f:(fun acc chain -> Map.add_exn acc ~key:chain.id ~data:chain) !new_chains

(** All conditions which is always true are removed *)
let remove_true_rules rules =
  List.map ~f:(fun (conds, effects, target) ->
      (List.filter ~f:(fun cond -> not (is_always true cond)) conds, effects,target)) rules

let count_rules chains =
  Map.fold ~f:(fun ~key:_ ~data:chn acc -> acc + List.length chn.rules) chains ~init:0

(** Determine the cost of inlining. *)
let inline_cost cs c =
  (* Number of conditions in the chain to be inlined *)
  let chain_conds = List.fold_left ~f:(fun acc (cl, _ef, _t) -> acc + List.length cl) ~init:0 c.rules in
  (* Number of conditions for each reference to the chain to be inlined. *)
  let rule_conds = List.map ~f:(fun (cl, _ef, _t) -> List.length cl) (get_referring_rules c cs) in
  (* Current count of conditions + targets *)
  let old_conds = (List.fold_left ~f:(+) ~init:0 rule_conds) + chain_conds + List.length rule_conds + List.length c.rules in
  (* Inlined count of conditions + targets *)
  let new_conds = List.fold_left ~f:(fun acc n -> acc + n * List.length c.rules + chain_conds) ~init:0 rule_conds + (List.length rule_conds * List.length c.rules) in
  new_conds - old_conds

let conds chains =
  Map.fold ~init:0 ~f:(fun ~key:_ ~data:chn acc ->
      List.fold_left chn.rules ~init:(acc + 1) ~f:(fun acc (cl, ef, _) ->
          List.length cl + List.length ef + acc) ) chains

let optimize_pass chains =
  printf "#Optim: (%d, %d) " (count_rules chains) (conds chains); Out_channel.flush stdout;
  let chains = fold_return_statements chains in

  let optimize_functions = [
    map_chain_rules eliminate_dead_rules;
    remove_dublicate_chains;
    map_chain_rules filter_protocol;
    map_chain_rules remove_unsatisfiable_rules;
    map_chain_rules remove_true_rules;
    map_chain_rules remove_empty_rules;
    map_chain_rules eliminate_dublicate_rules;
    map_chain_rules reorder;
    join;
    merge_adjecent_rules;
    (* reduce; *)
    inline inline_cost;
    map_chain_rules (fun rls -> Common.map_filter_exceptions (fun (opers, effect, tg) -> (merge_opers opers, effect, tg)) rls);
    remove_unreferenced_chains;
  ] in
  let chains' = List.fold_left ~f:(fun chains' optim_func -> optim_func chains') ~init:chains optimize_functions in
  printf " (%d, %d)\n" (count_rules chains') (conds chains');
  chains'

let rec optimize chains =
  let chains' = optimize_pass chains in
  match (conds chains, count_rules chains) = (conds chains', count_rules chains') with
  | true -> printf "#Optimization done\n"; chains'
  | false -> optimize chains'

module Test = struct
  open OUnit2
  let eq_cond_opt = function
    | Some m -> begin
        function Some n -> Ir.eq_cond m n
               | None -> false
      end
    | None -> begin
        function None -> true
               | Some _ -> false
      end

  let unittest = "Optimize" >::: [
      "merge_diff" >:: begin fun _ ->
        let expect = Ir.Zone (Ir.Direction.Source, ["int"] |> Set.Poly.of_list), false in
        let a = Ir.Zone (Ir.Direction.Source, ["int"; "ext"] |> Set.Poly.of_list), false in
        let b = Ir.Zone (Ir.Direction.Source, ["ext"; "other"] |> Set.Poly.of_list), false in
        let res = merge_oper ~tpe:`Diff a b
        in
        assert_equal ~cmp:eq_cond_opt ~msg:"Wrong result" res (Some expect);
      end;

      "subset" >:: begin fun _ ->
        let a = (Ir.State ([State.New] |> State.of_list), false) in
        let b = (Ir.State ([State.New; State.Established] |> State.of_list), false) in
        let c = (Ir.State ([State.Established] |> State.of_list), false) in

        assert_bool "a b must be a subset" (is_subset a b);
        assert_bool "b a must not be a subset" (not (is_subset b a));
        assert_bool "a c must not be a subset" (not (is_subset a c));
        assert_bool "c a must not be a subset" (not (is_subset c a));
        assert_bool "c b must be a subset" (is_subset c b);
        ()
      end;
    ]
end
