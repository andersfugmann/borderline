(*i
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
i*)

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
  let val2str = function
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
      | xs -> Common.join "," (List.map val2str xs)

(* Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
    IpRange(direction, ips) ->
      begin
        let low, high = elem ips in
        match Ipv6.range2mask (low, high) with
            Some(ip, mask) -> "", sprintf "--%s %s/%d" (choose_dir "source" "destination" direction) (Ipv6.to_string ip) mask
          | None -> "-m iprange ", sprintf "--%s-range %s-%s" (choose_dir "src" "dst" direction) (Ipv6.to_string low) (Ipv6.to_string high)
      end
  | Interface(direction, iface_list) -> ("", (choose_dir "--in-interface " "--out-interface " direction) ^ (id2str (elem iface_list)))
  | State(states) -> "-m conntrack ", ("--ctstate " ^ ( String.concat "," (List.map get_state_name states)))
  | Zone(dir, id_lst) -> "-m mark ", "--mark " ^ (gen_zone_mask_str dir (elem id_lst))
  | Ports(direction, ports) -> "-m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )

  | Protocol(protocols) -> ("", sprintf "--protocol %d" (elem protocols))
  | IcmpType(types) -> ("-m icmp6 ", sprintf "--icmpv6-type %d" (elem types))
  | Mark (value, mask) -> "-m mark ", sprintf "--mark 0x%04x/0x%04x" value mask
  | TcpFlags (flags, mask) -> "-m tcp ", sprintf "--tcp-flags " ^ (tcp_flags mask) ^ " " ^ (tcp_flags flags)

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
  | (Ports _ as cond, neg) :: xs -> 
      let pref, postf = gen_condition cond in
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
      | IpRange (_, ips) -> List.length ips
      | Protocol protocols -> List.length protocols
      | IcmpType types -> List.length types
      | Mark _ -> 2
      | TcpFlags _ -> 2
    in
      (* Reverse the order given above, by making the value negative *)
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
      | (IpRange(direction, ips), neg) :: xs when List.length ips > 1 ->
          let chain = expand_cond tg (fun ip -> IpRange(direction, [ip])) ips neg in
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
    (* Multiport needs a protocol specificer. Add it here *)
  let add_protocol_to_multiport (conds, target) =
    let multiports, rest = List.partition (fun (cond, _) -> (cond_type_identical (Ports (SOURCE, [])) cond)) conds in
    let protocols = List.filter (fun (cond, _) -> (cond_type_identical (Protocol []) cond)) conds in
      match multiports, protocols with
          (x, y) when List.length x > 1 or List.length y > 1 -> failwith "Normalization broken"
        | ([], _) -> ([], (conds, target))
        | ([(Ports(dir, ports), false) as cond], []) ->
            let chain = Chain.create [ ([(Protocol([tcp]), false); cond], target); ([(Protocol([udp]), false); cond], target) ] "Expanded" in
              ([chain], (rest, Ir.Jump chain.id))

        | ([(Ports(dir, ports), true) as cond], []) ->
            let chain = Chain.create [ ([(Protocol([tcp]), false); cond], Ir.Return); ([(Protocol([udp]), false); cond], Ir.Return); ([], target) ] "Expanded" in
              ([chain], (rest, Ir.Jump chain.id))

        | (_, [(Protocol(protos), _)]) when not (List.mem (List.hd protos) [tcp; udp]) ->
            failwith (sprintf "Port has wrong protocol specifier: %s." (ints_to_string protos))

        | _ -> ([], (conds, target)) (* Catch all *)
  in
    (* ICMP type match needs a protocol specifier. Add it here *)
  let add_protocol_to_icmptype (conds, target) =
    let icmptypes, rest = (List.partition (fun (cond, _) -> (cond_type_identical (IcmpType []) cond)) conds) in
    let protocols = (List.filter (fun (cond, _) -> (cond_type_identical (Protocol []) cond)) conds) in
      match (icmptypes, protocols) with
          (it, p) when List.length it > 1 or List.length p > 1 -> failwith "Normalization broken"
        | ([], _) -> ([], (conds, target))
        | ([(IcmpType(types), false)], []) -> ([], ((Protocol([icmp6]), false) :: conds, target))
        | ([(IcmpType(types), true)], []) ->
            let chain = Chain.create [ ([(Protocol([icmp6]), false); (IcmpType(types), false)], Ir.Return); ([], target) ] "expanded"
            in ([chain], (rest,  Ir.Jump chain.id))
        | (_, [ (Protocol(protos), false)] ) when not (List.hd protos = icmp6) ->
            failwith (sprintf "IcmpType has wrong protocol specifier: %s." (ints_to_string protos))
        | _ -> ([], (conds, target)) (* Catch all *)
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

  let transformations = [ expand; zone_to_mask; denormalize; add_protocol_to_multiport; add_protocol_to_icmptype; fix_state_match ] in
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
  
