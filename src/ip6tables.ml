open Batteries
(** Emit iptables commands. Currently we have no interface to the
    iptables library, so we use a shell script as an intermediate step.
*)

open Common
open Printf

module StringMap = Map.Make(String)
let zone_id = ref 1
let zone_map = ref StringMap.empty

let elem = function
  | [x] -> x
  | _ -> failwith "One and jsut one element required in list"

let set_elem s =
  match Set.to_list s with
  | [ x ] -> x
  | _ -> failwith "Set must be singleton"

let is_singleton s = Set.cardinal s = 1

let get_zone_id zone =
  try
    StringMap.find zone !zone_map
  with Not_found ->
    let id = !zone_id in
    let _ = zone_map := StringMap.add zone id !zone_map in
    incr zone_id; printf "#Zone: %s -> %d\n" zone id; id

let gen_neg = function
  | true -> "! "
  | false -> ""

let choose_dir a b = function
  | Ir.SOURCE      -> a
  | Ir.DESTINATION -> b

let get_state_name = function
  | State.NEW -> "new"
  | State.ESTABLISHED -> "established"
  | State.RELATED -> "related"
  | State.INVALID -> "invalid"

let gen_zone_mask dir zone =
  let zone_id = get_zone_id zone in
  match dir with
  | Ir.SOURCE -> zone_id, 0x00ff
  | Ir.DESTINATION -> zone_id * 0x100, 0xff00

let gen_zone_mask_str dir zone =
  let id, mask = gen_zone_mask dir zone in sprintf "0x%04x/0x%04x" id mask

let tcp_flags flags =
  let string_of_flag = function
    | 1 -> "SYN"
    | 2 -> "ACK"
    | 3 -> "FIN"
    | 4 -> "RST"
    | 5 -> "URG"
    | 6 -> "PSH"
    | flag -> failwith "Unknown tcp flag: " ^ (string_of_int flag)
  in
  match flags with
    | [] -> "NONE"
    | xs -> String.concat "," (List.map string_of_flag xs)

(** Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
  | Ir.IpSet(direction, ips) ->
    begin
      match Ipset.to_ips ips with
      | [ (ip, mask) ] -> "", sprintf "--%s %s/%d" (choose_dir "source" "destination" direction) (Ipset.string_of_ip ip) mask
      | _ -> let low, high = elem (Ipset.elements ips) in
        "-m iprange ", sprintf "--%s-range %s-%s"
          (choose_dir "src" "dst" direction)
          (Ipset.string_of_ip low) (Ipset.string_of_ip high)
    end
  | Ir.Interface(direction, ifaces) -> "",
    (choose_dir "--in-interface " "--out-interface " direction) ^ (set_elem ifaces)
  | Ir.State(states) -> "-m conntrack ",
    ("--ctstate " ^ ( String.concat "," (State.fold (fun s acc -> get_state_name s :: acc) states [])))
  | Ir.Zone(dir, ids) -> "-m mark ",
    "--mark " ^ (gen_zone_mask_str dir (set_elem ids))
  | Ir.Ports(direction, ports) when is_singleton ports ->
    "",
    ( "--" ^ (choose_dir "source" "destination" direction) ^ "-port " ^ (string_of_int (set_elem ports)))
  | Ir.Ports(direction, ports) -> "-m multiport ",
    ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (Set.to_list ports |> List.map string_of_int |> String.concat ","))
  | Ir.Protocol(protocols) -> ("", sprintf "--protocol %d" (set_elem protocols))
  | Ir.IcmpType(types) -> "-m icmp6 ",
    sprintf "--icmpv6-type %d" (set_elem types)
  | Ir.Mark (value, mask) -> "-m mark ",
    sprintf "--mark 0x%04x/0x%04x" value mask
  | Ir.TcpFlags (flags, mask) -> "",
    sprintf "--tcp-flags " ^ (tcp_flags mask) ^ " " ^ (tcp_flags flags)

let rec gen_conditions acc = function
  | (Ir.State states, true) :: xs when State.is_empty states -> gen_conditions acc xs
  | (Ir.State states, false) :: _ when State.is_empty states -> failwith "Unsatifiable rule in code-gen"
  | (Ir.Ports (_, ports), true) :: xs when Set.is_empty ports -> gen_conditions acc xs
  | (Ir.Zone (_, zones), true) :: xs when Set.is_empty zones -> gen_conditions acc xs
  | (Ir.Protocol protocols, true) :: xs when Set.is_empty protocols -> gen_conditions acc xs
  | (Ir.IcmpType types, true) :: xs when Set.is_empty types -> gen_conditions acc xs
  | (Ir.Ports (_, ports), false) :: _ when Set.is_empty ports -> failwith "Unsatifiable rule in code-gen"
  | (Ir.Zone (_, zones), false) :: _ when Set.is_empty zones -> failwith "Unsatifiable rule in code-gen"
  | (Ir.Protocol protocols, false) :: _ when Set.is_empty protocols -> failwith "Unsatifiable rule in code-gen"
  | (Ir.IcmpType types, false) :: _ when Set.is_empty types -> failwith "Unsatifiable rule in code-gen"
  | (cond, neg) :: xs ->
      let pref, postf = gen_condition cond in
        gen_conditions (acc ^ pref ^ (gen_neg neg) ^ postf ^ " ") xs
  | [] -> acc

let gen_action = function
  | Ir.MarkZone(dir, id) -> "MARK --set-mark " ^ (gen_zone_mask_str dir id)
  | Ir.Jump(chain_id) -> (Chain.get_chain_name chain_id)
  | Ir.Return -> "RETURN"
  | Ir.Accept -> "ACCEPT"
  | Ir.Drop   -> "DROP"
  | Ir.Reject _ -> "REJECT"
  | Ir.Notrack -> "NOTRACK" (* The NoTrack will not work, as it must be placed in the 'raw' table *)
  | Ir.Log prefix -> "LOG --log-prefix \"" ^ prefix ^ ":\""

(** To make a direct mapping to iptables rules, the IR tree needs to
    be denormalized. The transform pass does excatly this. It expands
    constructs into something trivially convertible to netfilter
    rules. *)
let transform chains =
  (* Order of conditions. This is used when expanding the conditions,
     in order to move expanding conditions to the back *)
  let order a b =
    let value = function
      | Ir.Interface _ -> 1
      | Ir.Zone _ -> 2
      | Ir.State _ -> 3
      | Ir.Ports (_, _ports) -> 4
      | Ir.IpSet (_, ips) -> Ipset.cardinal ips
      | Ir.Protocol protocols -> Set.cardinal protocols
      | Ir.IcmpType types -> Set.cardinal types
      | Ir.Mark _ -> 2
      | Ir.TcpFlags _ -> 2
    in
      (* Reverse the order given above, by making the value negative *)
      Pervasives.compare (value b) (value a)
  in
  (* Return a list of chains, and a single rule *)
  let denormalize (conds, target) =
    let rec denorm_rule tg = function
      | cl :: [] -> ([], (cl, tg))
      | cl :: xs ->
          let chn', rle = denorm_rule target xs in
          let chn = Chain.create [rle] "Denormalize" in
            (chn :: chn', (cl, Ir.Jump chn.Ir.id))
      | [] -> ([], ([], tg))
    in
      denorm_rule target (uniq (fun (a, _) (b, _) -> Ir.cond_type_identical a b && (Ir.get_dir a = None || Ir.get_dir a == Ir.get_dir b)) conds)
  in
  let expand (conds, target) =
    let expand_cond target cond_func lst = function
      | false ->
          let rules = List.map (fun p -> ([(cond_func p, false)], target)) lst in
            Chain.create rules "Expanded"
      | true ->
          let rules = (List.map (fun p -> ([(cond_func p, false)], Ir.Return)) lst) in
            Chain.create ( rules @ [ ([], target) ]) "Expanded"
    in
    let rec expand_conds acc1 acc2 tg = function
      | (Ir.Protocol protocols, neg) :: xs when Set.cardinal protocols > 1 ->
        let chain = expand_cond tg (fun p -> Ir.Protocol (Set.singleton p)) (Set.to_list protocols) neg in
        expand_conds (chain :: acc1) acc2 (Ir.Jump chain.Ir.id) xs
      | (Ir.IpSet(direction, set), neg) :: xs when Ipset.cardinal set > 1 ->
        let chain = expand_cond tg (fun range -> Ir.IpSet(direction, Ipset.singleton range)) (Ipset.elements set) neg in
        expand_conds (chain :: acc1) acc2 (Ir.Jump chain.Ir.id) xs
      | (Ir.Zone(direction, zones), neg) :: xs when Set.cardinal zones > 1 ->
        let chain = expand_cond tg (fun zone -> Ir.Zone(direction, Set.singleton zone)) (Set.to_list zones) neg in
        expand_conds (chain :: acc1) acc2 (Ir.Jump chain.Ir.id) xs
      | (Ir.IcmpType(types), neg) :: xs when Set.cardinal types > 1 ->
        let chain = expand_cond tg (fun t -> Ir.IcmpType(Set.singleton t)) (Set.to_list types) neg in
        expand_conds (chain :: acc1) acc2 (Ir.Jump chain.Ir.id) xs
      | cond :: xs -> expand_conds acc1 (cond :: acc2) tg xs
      | [] -> (acc1, (acc2, tg))
    in expand_conds [] [] target (List.sort (fun (a, _) (b, _) -> order a b) conds)
  in

  (* Some conditions needs a protocol specifier to work*)
  let add_protocol_specifiers (conds, target) =
    let rec fold proto target = function
      | (Ir.IcmpType _, false) as cond :: xs when proto != icmp ->
          let chains, (conds, target) = fold proto target xs in chains, ((Ir.Protocol (Set.singleton icmp), false) :: cond :: conds, target)
      | (Ir.IcmpType _ as op, true) :: xs  ->
          let chain = Chain.create [ ([ (Ir.Protocol((Set.singleton icmp)), false);
                                        (op, false)], Ir.Return); ([], target) ] "expanded" in
          let chains, (conds, target) = fold proto (Ir.Jump chain.Ir.id) xs in
            chain :: chains, (conds, target)

(*
      | (Ir.TcpFlags _, false) as cond :: xs when proto != tcp ->
          let chains, (conds, target) = fold proto target xs in chains, ((Ir.Protocol [tcp], false) :: cond :: conds, target)

      | (Ir.TcpFlags _ as op, true) :: xs  ->
          let chain = Chain.create [ ([ (Ir.Protocol([tcp]), false);
                                        (op, false)], Ir.Return); ([], target) ] "expanded" in
          let chains, (conds, target) = fold proto (Ir.Jump chain.Ir.id) xs in
            chain :: chains, (conds, target)
*)

      | (Ir.Ports _, false) as cond :: xs when proto != tcp && proto != udp ->
          let chain = Chain.create [ ([(Ir.Protocol((Set.singleton tcp)), false); cond], target);
                                     ([(Ir.Protocol((Set.singleton udp)), false); cond], target) ] "Expanded"
          in
          let chains, (conds, target) = fold proto (Ir.Jump chain.Ir.id) xs in
            chain :: chains, (conds, target)

      | (Ir.Ports _, true) as cond :: xs ->
          let chain = Chain.create [ ([(Ir.Protocol (Set.singleton tcp), false); cond], Ir.Return);
                                     ([(Ir.Protocol (Set.singleton udp), false); cond], Ir.Return);
                                     ([], target) ] "Expanded"
          in
          let chains, (conds, target) = fold proto (Ir.Jump chain.Ir.id) xs in
            chain :: chains, (conds, target)

      | cond :: xs ->
          let chains, (conds, target) = fold proto target xs in chains, (cond :: conds, target)
      | [] -> [], ([], target)
    in
    let protocols, conds' = List.partition (fun (cond, _) -> (Ir.cond_type_identical (Ir.Protocol Set.empty) cond)) conds in
    let protocol = match protocols with
      | [ Ir.Protocol ps, false ] when is_singleton ps -> set_elem ps
      | [] -> -1
      | _ -> failwith "More than one protocol specifier in rule."
    in
      fold protocol target (protocols @ conds')

  in
  (* Netfilter does not support the notion of zones. By marking the
     packets and matching the mark on the packet, the functionality can
     be emulated. *)
  let zone_to_mask (conds, target) =
    let rec zone_to_mask' = function
      | (Ir.Zone (dir, zones), neg) :: (Ir.Zone(dir', zones'), neg') :: xs when neg = neg' && not (dir = dir') && is_singleton zones && is_singleton zones' ->
        let v1, m1 = gen_zone_mask dir (set_elem zones) in
        let v2, m2 = gen_zone_mask dir' (set_elem zones') in
        (Ir.Mark (v1 + v2, m1 + m2), neg) :: zone_to_mask' xs
      | (Ir.Zone (dir, zones), neg) :: xs when is_singleton zones ->
        let v, m = gen_zone_mask dir (set_elem zones) in (Ir.Mark (v, m), neg) :: zone_to_mask' xs
      | x :: xs -> x :: zone_to_mask' xs
      | [] -> []
    in
      ([], (zone_to_mask' (List.sort Ir.compare conds), target))
  in
  let rec map_chains acc func = function
    | chain :: xs ->
      let chains, rules = List.split (List.map func chain.Ir.rules) in
      let chain' = { Ir.id = chain.Ir.id; rules = rules; comment = chain.Ir.comment } in
      map_chains (Map.add chain'.Ir.id chain' acc) func ((List.flatten chains) @ xs)
    | [] -> acc
  in
  (* Some packets are 'stateless', and thus not regarded as 'new' by
     netfilter. Fix this by using negated states:
     new => ! related, established, invalid
     new, related => !established, invalid
     new, established => !related, invalid
  *)
  let fix_state_match (conds, target) =
    (* Transform the list of state so the 'new' state is avoided *)
    let tranform = function
      | (Ir.State states, neg) when State.mem State.NEW states ->
          (Ir.State (State.diff State.all states), not neg)
      | x -> x
    in
      ([], (List.map tranform conds, target))
  in
  let map chains func = Map.fold (fun chn acc -> map_chains acc func [chn]) chains Map.empty in

  let transformations = [ expand; zone_to_mask;
                          denormalize;
                          add_protocol_specifiers;
                          fix_state_match ] in

    List.fold_left map chains transformations

let emit_rule (cond_list, action) : string =
  let conditions = gen_conditions "" cond_list in
  let target = gen_action action in
    conditions ^ "-j " ^ target

let emit_rules chain =
  let chain_name = Chain.get_chain_name chain.Ir.id in
  let ops = List.map emit_rule chain.Ir.rules in
    List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops

let filter chains =
  (* Filter rules must take a condition as argument, and return true
     for rules to be kepts, and false for rules to be removed *)
  let is_tautologically_false (conds, _) =
      List.fold_left (fun acc cond -> acc && not (Ir.is_always false cond)) true conds
  in
  let filter func chain = { Ir.id = chain.Ir.id; rules = List.filter func chain.Ir.rules; comment = chain.Ir.comment } in
    Map.map (filter is_tautologically_false) chains

let create_chain acc chain =
  match chain.Ir.id with
    | Ir.Builtin(_) -> acc
    | _ -> acc @ [sprintf "ip6tables -N %s #%s" (Chain.get_chain_name chain.Ir.id) chain.Ir.comment]

(** Main entrypoint. *)
let emit_chains chains =
  let funcs = [ transform; filter ] in
  let chains' = List.fold_left (fun acc func -> func acc) chains funcs in
    (* Create all chains, with no rules *)
    Map.fold (fun chn acc -> create_chain acc chn) chains' []
    (* Order the rules to make sure that buildin chains are emitted last. *)
    @ List.flatten (List.rev (Map.fold (fun chn acc -> emit_rules chn :: acc) chains' []))
