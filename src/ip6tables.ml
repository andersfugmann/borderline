(*
   Emit iptables commands. Currently we have no interface to the
   iptables library, so we use a shell script as an intermediate step.
*)

open Common
open Ir
open Printf
open Str
open String
open Chain

module StringMap = Map.Make(String)
let zone_id = ref 1
let zone_map = ref StringMap.empty

let elem = function
    x :: [] -> x
  | xs -> failwith "One and jsut one element required in list"

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

let tcp_flags flags =
  let string_of_flag = function
      1 -> "SYN"
    | 2 -> "ACK"
    | 3 -> "FIN"
    | 4 -> "RST"
    | 5 -> "URG"
    | 6 -> "PSH"
    | flag -> failwith "Unknown tcp flag: " ^ (string_of_int flag)
  in
    match flags with
        [] -> "NONE"
      | xs -> String.concat "," (List.map string_of_flag xs)

(* Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
  | IpSet(direction, ips) ->
    begin
      match Ip.to_ips ips with
        | [ (ip, mask) ] -> "", sprintf "--%s %s/%d" (choose_dir "source" "destination" direction) (Ip.string_of_ip ip) mask
        | _ -> let low, high = elem ips in
               "-m iprange ", sprintf "--%s-range %s-%s" 
                 (choose_dir "src" "dst" direction) 
                 (Ip.string_of_ip low) (Ip.string_of_ip high)
    end
  | Interface(direction, iface_list) -> ("", (choose_dir "--in-interface " "--out-interface " direction) ^ (id2str (elem iface_list)))
  | State(states) -> "-m conntrack ", ("--ctstate " ^ ( String.concat "," (List.map get_state_name states)))
  | Zone(dir, id_lst) -> "-m mark ", "--mark " ^ (gen_zone_mask_str dir (elem id_lst))
  | Ports(direction, port :: []) -> "",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-port " ^ (string_of_int port))
  | Ports(direction, ports) -> "-m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )
  | Protocol(protocols) -> ("", sprintf "--protocol %d" (elem protocols))
  | IcmpType(types) -> ("-m icmp6 ", sprintf "--icmpv6-type %d" (elem types))
  | Mark (value, mask) -> "-m mark ", sprintf "--mark 0x%04x/0x%04x" value mask
  | TcpFlags (flags, mask) -> "", sprintf "--tcp-flags " ^ (tcp_flags mask) ^ " " ^ (tcp_flags flags)

let rec gen_conditions acc = function
    (Ports (_, []), true) :: xs
  | (State [], true) :: xs
  | (Zone (_, []), true) :: xs
  | (Protocol [], true) :: xs
  | (IcmpType [], true) :: xs -> gen_conditions acc xs
  | (Ports (_, []), false) :: xs
  | (State [], false) :: xs
  | (Zone (_, []), false) :: xs
  | (Protocol [], false) :: xs
  | (IcmpType [], false) :: xs -> failwith "Unsatifiable rule in code-gen"
  | (cond, neg) :: xs ->
      let pref, postf = gen_condition cond in
        gen_conditions (acc ^ pref ^ (gen_neg neg) ^ postf ^ " ") xs
  | [] -> acc

let gen_action = function
    MarkZone(dir, id) -> "MARK --set-mark " ^ (gen_zone_mask_str dir id)
  | Jump(chain_id) -> (Chain.get_chain_name chain_id)
  | Return -> "RETURN"
  | Accept -> "ACCEPT"
  | Drop   -> "DROP"
  | Reject _ -> "REJECT"
  | Notrack -> "NOTRACK" (* The NoTrack will not work, as it must be placed in the 'raw' table *)
  | Log prefix -> "LOG --log-prefix \"" ^ prefix ^ ":\""

(* To make a direct mapping to iptables rules, the IR tree needs to be
   denormalized. The transform pass does excatly this. It expands
   constructs into something trivially convertible to netfilter rules. *)

let transform chains =
  (* Order of conditions. This is used when expanding the conditions,
     in order to move expanding conditions to the back *)
  let order a b =
    let value = function
        Interface _ -> 1
      | Zone _ -> 2
      | State _ -> 3
      | Ports (_, ports) -> 4
      | IpSet (_, ips) -> List.length ips
      | Protocol protocols -> List.length protocols
      | IcmpType types -> List.length types
      | Mark _ -> 2
      | TcpFlags _ -> 2
    in
      (* Reverse the order given above, by making the value negative *)
      Pervasives.compare (value b) (value a)
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
      denorm_rule target (uniq (fun (a, _) (b, _) -> cond_type_identical a b && (get_dir a = None || get_dir a == get_dir b)) conds)
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
      | (IpSet(direction, ips), neg) :: xs when List.length ips > 1 ->
          let chain = expand_cond tg (fun ip -> IpSet(direction, [ip])) ips neg in
            expand_conds (chain :: acc1) acc2 (Ir.Jump chain.id) xs
      | (Zone(direction, zones), neg) :: xs when List.length zones > 1 ->
          let chain = expand_cond tg (fun zone -> Zone(direction, [zone])) zones neg in
            expand_conds (chain :: acc1) acc2 (Ir.Jump chain.id) xs
      | (IcmpType(types), neg) :: xs when List.length types > 1 ->
          let chain = expand_cond tg (fun t -> IcmpType([t])) types neg in
            expand_conds (chain :: acc1) acc2 (Ir.Jump chain.id) xs
      | cond :: xs -> expand_conds acc1 (cond :: acc2) tg xs
      | [] -> (acc1, (acc2, tg))
    in expand_conds [] [] target (List.sort (fun (a, _) (b, _) -> order a b) conds)
  in
    (* Some conditions needs a protocol specifier to work*)
  let add_protocol_specifiers (conds, target) =
    let rec fold proto target = function
      | (IcmpType _, false) as cond :: xs when proto != icmp ->
          let chains, (conds, target) = fold proto target xs in chains, ((Protocol [icmp], false) :: cond :: conds, target)
      | (IcmpType types as op, true) :: xs  ->
          let chain = Chain.create [ ([ (Protocol([icmp]), false);
                                        (op, false)], Ir.Return); ([], target) ] "expanded" in
          let chains, (conds, target) = fold proto (Ir.Jump chain.id) xs in
            chain :: chains, (conds, target)

      | (TcpFlags _, false) as cond :: xs when proto != tcp ->
          let chains, (conds, target) = fold proto target xs in chains, ((Protocol [tcp], false) :: cond :: conds, target)

      | (TcpFlags _ as op, true) :: xs  ->
          let chain = Chain.create [ ([ (Protocol([tcp]), false);
                                        (op, false)], Ir.Return); ([], target) ] "expanded" in
          let chains, (conds, target) = fold proto (Ir.Jump chain.id) xs in
            chain :: chains, (conds, target)

      | (Ports _, false) as cond :: xs when proto != tcp && proto != udp ->
          let chain = Chain.create [ ([(Protocol([tcp]), false); cond], target);
                                     ([(Protocol([udp]), false); cond], target) ] "Expanded"
          in
          let chains, (conds, target) = fold proto (Ir.Jump chain.id) xs in
            chain :: chains, (conds, target)

      | (Ports _, true) as cond :: xs ->
          let chain = Chain.create [ ([(Protocol([tcp]), false); cond], Ir.Return);
                                     ([(Protocol([udp]), false); cond], Ir.Return);
                                     ([], target) ] "Expanded"
          in
          let chains, (conds, target) = fold proto (Ir.Jump chain.id) xs in
            chain :: chains, (conds, target)

      | cond :: xs ->
          let chains, (conds, target) = fold proto target xs in chains, (cond :: conds, target)
      | [] -> [], ([], target)
    in
    let protocols, conds'  = List.partition (fun (cond, _) -> (cond_type_identical (Protocol []) cond)) conds in
    let protocol = match protocols with
      | (Protocol [p], false) :: [] -> p
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
        (Zone (dir, zone :: []), neg) :: (Zone(dir', zone' :: []), neg') :: xs when neg = neg' && not (dir = dir') ->
          let v1, m1 = gen_zone_mask dir zone in
          let v2, m2 = gen_zone_mask dir' zone' in
            (Mark (v1 + v2, m1 + m2), neg) :: zone_to_mask' xs
      | (Zone (dir, zone :: []), neg) :: xs ->
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
    (* Some packets are 'stateless', and thus not regarded as 'new' by
       netfilter. Fix this by using negated states:
       new => ! related, established, invalid
       new, related => !established, invalid
       new, established => !related, invalid
    *)
  let fix_state_match (conds, target) =
    (* Transform the list of state so the 'new' state is avoided *)
    let tranform = function
        (State states, neg) when List.mem NEW states ->
          (State (difference (=) [INVALID; RELATED; ESTABLISHED] states), not neg)
      | x -> x
    in
      ([], (List.map tranform conds, target))
  in
  let map chains func = Chain_map.fold (fun _ chn acc -> map_chains acc func [chn]) chains Chain_map.empty in

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
  let chain_name = Chain.get_chain_name chain.id in
  let ops = List.map emit_rule chain.rules in
    List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops

let filter chains =
  (* Filter rules must take a condition as argument, and return true
     for rules to be kepts, and false for rules to be removed *)
  let is_tautologically_false (conds, _) =
      List.fold_left (fun acc cond -> acc && not (is_always false cond)) true conds
  in
  let filter func chain = { id = chain.id; rules = List.filter func chain.rules; comment = chain.comment } in
    Chain_map.map (filter is_tautologically_false) chains

let create_chain acc chain =
  match chain.id with
      Builtin(_) -> acc
    | _ -> acc @ [sprintf "ip6tables -N %s #%s" (Chain.get_chain_name chain.id) chain.comment]


(* Main entrypoint. *)
let emit_chains chains =
  let funcs = [ transform; filter ] in
  let chains' = List.fold_left (fun acc func -> func acc) chains funcs in
    (* Create all chains, with no rules *)
    Chain_map.fold (fun id chn acc -> create_chain acc chn) chains' []
    (* Order the rules to make sure that buildin chains are emitted last. *)
    @ List.flatten (List.rev (Chain_map.fold (fun _ chn acc -> emit_rules chn :: acc) chains' []))

