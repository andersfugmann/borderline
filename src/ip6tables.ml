(* Emit iptables commands. Currently we have no interface to the iptables library,
   so we use a shell script as an intermediate step. *)

open Common
open Ir
open Printf
open Str
open String
open Chain

module StringMap = Map.Make(String)
let zone_id = ref 1
let zone_map = ref StringMap.empty

let elem lst =
  assert (List.length lst = 1); List.hd lst

let get_zone_id zone =
  try
    StringMap.find zone !zone_map
  with Not_found ->
    let id = !zone_id in
    let _ = zone_map := StringMap.add zone id !zone_map in
      incr zone_id; printf "#Zone: %s -> %d\n" zone id; id

let gen_neg = function
    true -> "! "
  | _ -> ""

(* val choose_dir : direction * string * string -> string *)
let choose_dir a b = function
    SOURCE      -> a
  | DESTINATION -> b

let get_state_name = function
    NEW -> "new"
  | ESTABLISHED -> "established"
  | RELATED -> "related"
  | INVALID -> "invalid"


let gen_zone_mask dir zone =
  let zone_id = get_zone_id (id2str zone) in
  match dir with
      SOURCE -> zone_id, 0x00ff
    | DESTINATION -> zone_id * 0x100, 0xff00

let gen_zone_mask_str dir zone =
  let id, mask = gen_zone_mask dir zone in sprintf "0x%04x/0x%04x" id mask

(* Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
    IpRange(direction, ips) ->
      begin
        let low, high = elem ips in
        match Ipv6.range2mask (low, high) with
            Some(ip, mask) -> "", sprintf "--%s %s/%d" (choose_dir "src" "dst" direction) (Ipv6.to_string ip) mask
          | None -> "-m iprange ", sprintf "--%s-range %s-%s" (choose_dir "src" "dst" direction) (Ipv6.to_string low) (Ipv6.to_string high)
      end
  | Interface(direction, name) -> ("", (choose_dir "--in-interface " "--out-interface " direction) ^ (id2str name))
  | State(states) -> "-m conntrack ", ("--ctstate " ^ ( String.concat "," (List.map get_state_name states)))
  | Zone(dir, id) -> "-m mark ", "--mark " ^ (gen_zone_mask_str dir id)
  | Ports(direction, ports) -> "-m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )

  | Protocol(protocol) -> ("", sprintf "--protocol %d" (elem protocol))
  | IcmpType(types) -> ("-m icmp6", sprintf "--icmpv6-type %d" (elem types))
  | Mark (value, mask) -> "-m mark ", sprintf "--mark 0x%04x/0x%04x" value mask

let rec gen_conditions acc = function
    (Ports _ as cond, neg) :: xs -> let pref, postf = gen_condition cond in
      (gen_conditions acc xs) ^ pref ^ (gen_neg neg) ^ postf ^ " "
  | (cond, neg) :: xs ->
      let pref, postf = gen_condition cond in
        gen_conditions (pref ^ (gen_neg neg) ^ postf ^ " " ^ acc) xs
  | [] -> acc

let gen_action = function
    MarkZone(dir, id) -> "MARK --set-mark " ^ (gen_zone_mask_str dir id)
  | Jump(chain_id) -> (Chain.get_chain_name chain_id)
  | Return -> "RETURN"
  | Accept -> "ACCEPT"
  | Drop   -> "DROP"
  | _ -> "#### Unsupported action"

(* Transform rules into something emittable. This may introduce new chains. *)
let transform chains =
  (* Order of conditions. This is used when expanding the conditions, in order to move expanding conditions to the back *)
  let order a b =
    let value = function
        Interface _ -> 1
      | Zone _ -> 2
      | State _ -> 3
      | Ports (_, ports) -> 4
      | IpRange (_, ips) -> List.length ips
      | Protocol protocols -> List.length protocols
      | IcmpType types -> List.length types
      | Mark _ -> 2
    in
      -(Pervasives.compare (value a) (value b))
  in
  (* Return a list of chains, and a single rule *)
  let denormalize (conds, target) =
    let rec denorm_rule tg = function
        cl :: [] -> ([], (cl, tg))
      | cl :: xs ->
          let chn', rle = denorm_rule target xs in
          let chn = Chain.create [rle] "Denormalize" in
            (chn :: chn', (cl, Ir.Jump chn.id))
      | [] -> ([], ([], tg))
    in
      denorm_rule target (uniq (fun (a, _) (b, _) -> cond_type_identical a b) conds)
  in
  let expand (conds, target) =
    let expand_cond target cond_func lst = function
        false ->
          let rules = List.map (fun p -> ([(cond_func p, false)], target)) lst in
            Chain.create rules "Expanded"
      | true ->
          let rules = (List.map (fun p -> ([(cond_func p, false)], Ir.Return)) lst) in
            Chain.create ( rules @ [ ([], target) ]) "Expanded"
    in
    let rec expand_conds acc1 acc2 tg = function
        (Protocol protocols, neg) :: xs when List.length protocols > 1 ->
          let chain = expand_cond tg (fun p -> Protocol [p]) protocols neg in
            expand_conds (chain :: acc1) acc2 (Ir.Jump chain.id) xs
      | (IpRange(direction, ips), neg) :: xs when List.length ips > 1 ->
          let chain = expand_cond tg (fun ip -> IpRange(direction, [ip])) ips neg in
            expand_conds (chain :: acc1) acc2 (Ir.Jump chain.id) xs
      | cond :: xs -> expand_conds acc1 (cond :: acc2) tg xs
      | [] -> (acc1, (acc2, tg))
    in expand_conds [] [] target (List.sort (fun (a, _) (b, _) -> order a b) conds)
  in
  let fix_multiport (conds, target) =
    (* If multiport and no protocol spec, then extend into two rules in a new chain *)
    if not (List.exists (fun (cond, _) -> (cond_type_identical (Protocol []) cond)) conds) then
      let ports, rest = List.partition (fun (cond, _) -> (cond_type_identical (Ports (SOURCE, [])) cond)) conds in
      match List.length ports with
          0 -> ([], (conds, target))
        | 1 -> let chn = Chain.create [ ([(Protocol [tcp], false); elem ports], target);
                                        ([(Protocol [udp], false); elem ports], target)] "Fix multiport" in
            ([chn], (rest, Ir.Jump chn.id))
        | n -> failwith "Too many port filters in one rule. Denomalization must be broken"
    else
      ([], (conds, target))
  in
  let zone_to_mask (conds, target) =
    let rec zone_to_mask' = function
        (Zone (dir, zone), neg) :: (Zone(dir', zone'), neg') :: xs when neg = neg' && not (dir = dir') ->
          let v1, m1 = gen_zone_mask dir zone in
          let v2, m2 = gen_zone_mask dir' zone' in
            (Mark (v1 + v2, m1 + m2), neg) :: zone_to_mask' xs
      | (Zone (dir, zone), neg) :: xs ->
          let v, m = gen_zone_mask dir zone in (Mark (v, m), neg) :: zone_to_mask' xs
      | x :: xs -> x :: zone_to_mask' xs
      | [] -> []
    in
      ([], (zone_to_mask' (List.sort Ir.compare conds), target))
  in
  let rec map_chains acc func = function
      chain :: xs ->
        let chains, rules = List.split (List.map func chain.rules) in
        let chain' = { id = chain.id; rules = rules; comment = chain.comment } in
          map_chains (Chain_map.add chain'.id chain' acc) func ((List.flatten chains) @ xs)
    | [] -> acc
  in
  let map func chains = Chain_map.fold (fun _ chn acc -> map_chains acc func [chn]) chains Chain_map.empty in

  let chains = map zone_to_mask chains  in
  let chains = map expand chains in
  let chains = map denormalize chains in
  let chains = map fix_multiport chains in
    chains


let emit_rule (cond_list, action) : string =
  let conditions = gen_conditions "" cond_list in
  let target = gen_action action in
    conditions ^ "-j " ^ target

let emit_rules chain =
  let chain_name = Chain.get_chain_name chain.id in
  let ops = List.map emit_rule chain.rules in
    List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops

let create_chain acc chain =
  match chain.id with
      Builtin(_) -> acc
    | _ -> acc @ [sprintf "ip6tables -N %s #%s" (Chain.get_chain_name chain.id) chain.comment]

let emit_chains chains =
  let chains' = transform chains in
    (* Create all chains, with no rules *)
    Chain_map.fold (fun id chn acc -> create_chain acc chn) chains' []
    @ List.flatten (List.rev (Chain_map.fold (fun _ chn acc -> emit_rules chn :: acc) chains' []))


