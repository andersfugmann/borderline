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

let get_zone_id zone =
  try
    StringMap.find zone !zone_map
  with Not_found ->
    let id = !zone_id in
    let _ = zone_id := !zone_id + 1 in
    let _ = zone_map := StringMap.add zone id !zone_map in
      id

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

let get_protocol_name = function
    TCP -> "tcp"
  | UDP -> "udp"
  | ICMP -> "icmpv6"

let gen_zone_mask dir zone =
  let zone_id = get_zone_id (id2str zone) in
  match dir with
      SOURCE -> zone_id, 0x00ff
    | DESTINATION -> zone_id * 0x100, 0xff00

let gen_zone_mask_str dir zone = 
  let id, mask = gen_zone_mask dir zone in sprintf "0x%04x/0x%04x" id mask
    
(* Return a prefix and condition, between which a negation can be inserted *)
let gen_condition = function
    IpRange(direction, low, high) -> 
      begin
        match Ipv6.range2mask (low, high) with
            Some(ip, mask) -> "", sprintf "--%s %s/%d" (choose_dir "src" "dst" direction) (Ipv6.to_string low) mask
          | None -> "-m iprange ", sprintf "--%s-range %s-%s" (choose_dir "src" "dst" direction) (Ipv6.to_string low) (Ipv6.to_string high) 
      end
  | Interface(direction, name) -> ("", (choose_dir "--in-interface " "--out-interface " direction) ^ (id2str name))
  | State(states) -> "-m conntrack ", ("--ctstate " ^ ( String.concat "," (List.map get_state_name states)))
  | Zone(dir, id) -> "-m conmark ", "--mark " ^ (gen_zone_mask_str dir id)
  | TcpPort(direction, ports) -> "-m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )
  | UdpPort(direction, ports) -> "-m multiport ",
      ( "--" ^ (choose_dir "source" "destination" direction) ^ "-ports " ^ (String.concat "," (List.map string_of_int ports)) )

  | Protocol(protocol) -> ("", "-p " ^ (get_protocol_name protocol))
  | Mark (value, mask) -> "-m conmark ", sprintf "--mark 0x%04x/0x%04x" value mask

let rec gen_conditions acc = function
    (cond, neg) :: xs -> 
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
  let zone_to_mask conds =
    let rec map = function
        (Zone (dir, zone), neg) :: (Zone(dir', zone'), neg') :: xs when neg = neg' && not (dir = dir') ->
          let v1, m1 = gen_zone_mask dir zone in
          let v2, m2 = gen_zone_mask dir' zone' in
            (Mark (v1 + v2, m1 + m2), neg) :: map xs
      | (Zone (dir, zone), neg) :: xs -> 
          let v, m = gen_zone_mask dir zone in (Mark (v, m), neg) :: map xs
      | x :: xs -> x :: map xs
      | [] -> []
    in
      map (List.sort Ir.compare conds)
  in  
  let rec map_rules = function
      (conds, target) :: xs -> 
        (zone_to_mask conds, target) :: map_rules xs
    | [] -> []
  in
  let rec split_opers acc = function 
      (x, neg) :: xs -> 
        if List.exists (fun (y, _) -> cond_type_identical x y) acc then
          acc :: (split_opers [(x, neg)] xs)
        else
          split_opers (acc @ [(x, neg)]) xs
    | [] -> [ acc ]

  in
    (* Return rule and a list of new chains *)
  let rec create_chains chains target = function       
      []  -> (([], target), chains)
    | rle :: [] -> ((rle, target), chains)
    | rle :: xs -> 
        let chain = Chain.create [ (rle, target) ] "Continuation" in
          create_chains (chain :: chains) (Jump(chain.id)) xs 
  in 
  let map_chain chain =
    let (rules, chains) = List.split (List.map (fun (ops, target) -> create_chains [] target (split_opers [] ops) ) chain.rules)
    in { id = chain.id; rules = rules; comment = chain.comment } :: (List.flatten chains)
         
  in 
  let chains = List.map (fun chn -> {id = chn.id; rules = map_rules chn.rules; comment = chn.comment }) chains in
  let chains = List.flatten (List.map map_chain chains) in
    chains
    

let emit (cond_list, action) : string =
  let conditions = gen_conditions "" cond_list in
  let target = gen_action action in
    conditions ^ "-j " ^ target

let emit_chain chain =  
  let chain_name = Chain.get_chain_name chain.id in
  let ops = List.map emit chain.rules in
  let lines = List.map ( sprintf "ip6tables -A %s %s" chain_name ) ops in
    match chain.id with
        Builtin(_) -> lines
      | _          -> (sprintf "ip6tables -N %s #%s" chain_name chain.comment) :: lines

let emit_chains chains = 
  let chains' = transform chains in
    List.flatten (List.map emit_chain chains')


