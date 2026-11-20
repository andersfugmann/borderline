(**
   Output a nft script.
*)

open Base
open Stdio
open Printf
module Ip6Set = Ipset.Ip6Set
module Ip4Set = Ipset.Ip4Set

(* Render a value match as a scalar comparison or a set lookup. *)
let membership neg selector values =
  match neg, values with
  | false, [] -> "meta mark | 0x1 == 0x0"
  | _, [value] ->
    let op = match neg with true -> "!=" | false -> "==" in
    sprintf "%s %s %s" selector op value
  | false, _ -> sprintf "%s { %s }" selector (String.concat ~sep:", " values)
  | true, _ -> sprintf "%s != { %s }" selector (String.concat ~sep:", " values)

module Mark = struct
  type t = { value: int; mask: int }
  type pred = Equal_to of t | Different_from of t

  (* Convert a masked value and its IR negation flag into a mark predicate. *)
  let of_ir (value, mask) ~neg =
    match neg with
    | false -> Equal_to { value; mask }
    | true -> Different_from { value; mask }

  (* Render a masked packet-mark equality or inequality. *)
  let emit pred =
    let { value; mask }, op = match pred with
      | Equal_to mark -> mark, "=="
      | Different_from mark -> mark, "!="
    in
    sprintf "meta mark & 0x%08x %s 0x%08x" mask op value

  (* Merge masked equalities, or return None when they cannot all match. *)
  let rec merge = function
    | [] -> Some { value = 0; mask = 0 }
    | { value; mask } :: _ when value land mask <> value -> None
    | [equality] -> Some equality
    | { value; mask } :: { value = value'; mask = mask' } :: _
      when value' land mask' <> value' ||
          (value lxor value') land (mask land mask') <> 0 -> None
    | { value; mask } :: { value = value'; mask = mask' } :: rest ->
      merge ({ value = value lor value'; mask = mask lor mask' } :: rest)

  (* Check whether all marks matching this equality also match of_. *)
  let is_subset { value; mask } ~of_:{ value = value'; mask = mask' } =
    mask' land mask = mask' && value land mask' = value'

  type guard = {
    equality: t;
    inequalities: t list;
  }

  type normalized = Impossible | Guard of guard

  (* Turn a single-bit inequality into an equality requiring the opposite bit. *)
  let normalize_pred = function
    | Different_from { value; mask }
      when mask <> 0 && mask land (mask - 1) = 0 && value land mask = value ->
      Equal_to { value = value lxor mask; mask }
    | pred -> pred

  (* Simplify a group of mark conditions that must all match. *)
  let normalize_conjunction preds =
    let equalities, inequalities =
      List.map preds ~f:normalize_pred
      |> List.partition_map ~f:(function
          | Equal_to equality -> Either.First equality
          | Different_from equality -> Either.Second equality
        )
    in
    match merge equalities with
    | None -> Impossible
    | Some equality when List.exists inequalities
        ~f:(fun excluded -> is_subset equality ~of_:excluded) -> Impossible
    | Some equality ->
      let inequalities = List.dedup_and_sort inequalities ~compare:Poly.compare in
      Guard { equality; inequalities }

  (* Remove impossible or duplicate alternatives and inequalities redundant in every alternative. *)
  let normalize_alternatives alternatives =
    let alternatives = List.concat_map alternatives ~f:(fun guard ->
      match normalize_conjunction guard with
      | Impossible -> []
      | Guard guard -> [guard]) in
    (* Remove an inequality only when every surviving assignment proves it.
       Keeping common conditions shared makes the disjunction one guarded body. *)
    List.map alternatives ~f:(fun guard ->
      let inequalities = List.filter guard.inequalities ~f:(fun excluded ->
        List.exists alternatives ~f:(fun alternative ->
          Option.is_some (merge [alternative.equality; excluded]))) in
      { guard with inequalities })
      |> List.dedup_and_sort ~compare:Poly.compare

  (* Check whether guards share a nonempty equality mask and the same inequality set. *)
  let same_shape a b =
    a.equality.mask <> 0 && a.equality.mask = b.equality.mask &&
    List.for_all a.inequalities ~f:(fun inequality ->
      List.mem b.inequalities inequality ~equal:Poly.equal) &&
    List.for_all b.inequalities ~f:(fun inequality ->
      List.mem a.inequalities inequality ~equal:Poly.equal)

  type match_ =
    | Comparisons of guard
    | Membership of int * int list * t list

  (* Check whether a mark match imposes no conditions on the packet. *)
  let is_unrestricted = function
    | Comparisons { equality = { mask = 0; _ }; inequalities = [] } -> true
    | Comparisons _ | Membership _ -> false

  (* Use a value set for multiple same-mask alternatives; keep a single guard as comparisons. *)
  let build_membership = function
    | [guard] -> Comparisons guard
    | guard :: alternatives ->
      let values = List.map (guard :: alternatives) ~f:(function
        | alternative when same_shape guard alternative -> alternative.equality.value
        | _ -> failwith "Mark alternatives must share a mask and remaining conditions")
        |> List.dedup_and_sort ~compare:Int.compare
      in
      Membership (guard.equality.mask, values, guard.inequalities)
    | [] -> failwith "Expected a nonempty normalized mark guard"

  (* Render mark comparisons or a masked value-set lookup. *)
  let gen_match marks =
    let matches, inequalities = match marks with
      | Comparisons { equality; inequalities } ->
        let matches = match equality.mask with
          | 0 -> []
          | _ -> [emit (Equal_to equality)]
        in
        matches, inequalities
      | Membership (mask, values, inequalities) ->
        [membership false (sprintf "meta mark & 0x%08x" mask)
          (List.map values ~f:(sprintf "0x%08x"))], inequalities
    in
    matches @ List.map inequalities ~f:(fun excluded -> emit (Different_from excluded))
end

type zone = {
  bits: int;
  mask: int;
  (* ids_: int Map.M(String); *)
  ids: (string, int, String.comparator_witness) Map.t;
}

let init_zones zones =
  let zones = Zone.mars :: zones in
  let zones = match List.mem zones Zone.self ~equal:String.equal with
    | false -> Zone.self :: zones
    | true -> zones
  in
  let bits = List.length zones in
  assert (bits <= 16);
  let mask = 1 lsl bits - 1 in
  let ids =
    zones
    |> List.mapi ~f:(fun i zone -> zone, 1 lsl i)
    |> Map.of_alist_exn (module String)
  in
  { bits;
    mask;
    ids
  }

let sets = ref []
let create_set ipv4 ipv6 =
  let set_id = match !sets with
    | [] -> 0
    | (id, _, _, _) :: _ -> id + 1
  in
  let set_name = sprintf "bl_set_%d" set_id in
  sets := (set_id, set_name, ipv4, ipv6) :: !sets;
  set_name

(* create set is currently not in use *)
let () = ignore create_set

let get_zone_id t zone =
  Map.find_exn t.ids zone

let chain_name = function
  | Ir.Chain_id.Temporary n -> sprintf "temp_%d" n
  | Ir.Chain_id.Builtin Ir.Chain_type.Input -> "input"
  | Ir.Chain_id.Builtin Ir.Chain_type.Output -> "output"
  | Ir.Chain_id.Builtin Ir.Chain_type.Forward  -> "forward"
  | Ir.Chain_id.Builtin Ir.Chain_type.Pre_routing  -> "prerouting"
  | Ir.Chain_id.Builtin Ir.Chain_type.Post_routing  -> "postrouting"
  | Ir.Chain_id.Named name -> name

let chain_premable chain comment =
  let name = chain_name chain in
  match chain with
  | Ir.Chain_id.Builtin Ir.Chain_type.Pre_routing
  | Builtin Ir.Chain_type.Post_routing ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
      sprintf "  type nat hook %s priority srcnat;" name;
      sprintf "  policy accept;" ]
  | Builtin Ir.Chain_type.Input
  | Builtin Ir.Chain_type.Output
  | Builtin Ir.Chain_type.Forward ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
      sprintf "  type filter hook %s priority filter;" name;
      sprintf "  policy drop;" ]
  | Temporary _
  | Named _ ->
    [ sprintf "chain %s {" name;
      sprintf "  comment \"%s\"" comment;
    ]

let string_of_tcpflag = function
  | Ir.Tcp_flags.Syn -> "syn"
  | Ir.Tcp_flags.Ack -> "ack"
  | Ir.Tcp_flags.Fin -> "fin"
  | Ir.Tcp_flags.Rst -> "rst"
  | Ir.Tcp_flags.Urg -> "urg"
  | Ir.Tcp_flags.Psh -> "psh"
  | Ir.Tcp_flags.Ecn -> "ecn"
  | Ir.Tcp_flags.Cwr -> "cwr"

let string_of_state state = match state with
  | State.New -> "new"
  | State.Established -> "established"
  | State.Related -> "related"
  | State.Invalid -> "invalid"
  | State.Untracked -> "untracked"

let string_or_int_set s =
  Set.fold ~init:[] ~f:(fun acc -> function
    | `Int i -> Int.to_string i :: acc
    | `String s -> Printf.sprintf "\"%s\"" s :: acc) s
  |> String.concat ~sep:", "

(* Convert integer set members to strings for nftables output. *)
let int_values values = Set.to_list values |> List.rev_map ~f:Int.to_string

let gen_pred neg pred =
  let neg_str = match neg with
    | true -> "!= "
    | false -> ""
  in

  let gen_ipset_filter: type t. (module Ipset.IpSet with type t = t) -> string -> Ir.Direction.t -> t -> bool -> string =
    fun (module IpSet) tpe dir ipset neg ->
      let classifier = match dir with
        | Ir.Direction.Source -> "saddr"
        | Ir.Direction.Destination  -> "daddr"
      in
      let classifier = sprintf "%s %s" tpe classifier in

      let string_of_list l =
        List.map ~f:IpSet.ip_to_string l
        |> String.concat ~sep:", "
      in
      let rec gen_filter (ipset, neg) =
        match IpSet.to_networks ipset with
        | incls, [] ->
          sprintf "%s %s{ %s }" classifier neg_str (string_of_list incls)
        | [incl], excl when neg && IpSet.is_any incl ->
          (* Exclude everything except excl *)
          sprintf "%s { %s }" classifier (string_of_list excl)
        | _, _ when neg ->
          gen_filter (IpSet.diff IpSet.any ipset, false)
        | incl, excl (* when not neg *) ->
          let incl = string_of_list incl in
          let excl = string_of_list excl in
          sprintf "%s { %s } %s != { %s }" classifier incl classifier excl
      in
      gen_filter (ipset, neg)
  in
  match pred with
  | Ir.Interface (dir, interfaces) ->
    let only_loopback = Set.mem interfaces Zone.loopback && Set.length interfaces = 1 in
    let interfaces = Set.to_list interfaces |> List.map ~f:(sprintf "\"%s\"") |> String.concat ~sep:", " in
    let classifier = match dir with
      | Ir.Direction.Source when only_loopback -> "iif"
      | Ir.Direction.Destination when only_loopback-> "oif"
      | Ir.Direction.Source -> "iifname"
      | Ir.Direction.Destination -> "oifname"
    in
    sprintf "%s %s{ %s }" classifier neg_str interfaces, None
  | Ir.If_group (dir, if_groups) ->
    let if_groups = string_or_int_set if_groups in
    let classifier = match dir with
      | Ir.Direction.Source -> "iifgroup"
      | Ir.Direction.Destination -> "oifgroup"
    in
    sprintf "%s %s{ %s }" classifier neg_str if_groups, None
  | Ir.Zone _ ->
    failwith "Zone predicates must be lowered before rendering"
  | Ir.State states ->
    let states =
      State.to_list states
      |> List.map ~f:string_of_state
      |> String.concat ~sep:", "
    in
    sprintf "ct state %s{ %s }" neg_str states, None
  | Ir.Ports (dir, port_type, ports) ->
    let pred = match dir with
      | Ir.Direction.Source -> "sport"
      | Ir.Direction.Destination -> "dport"
    in
    let classifier = match port_type with
      | Ir.Port_type.Tcp -> "tcp"
      | Ir.Port_type.Udp -> "udp"
    in
    membership neg (classifier ^ " " ^ pred) (int_values ports), None
  | Ir.Ip6Set (dir, ips) ->
    gen_ipset_filter (module Ip6Set) "ip6" dir ips neg, None
  | Ir.Ip4Set (dir, ips) ->
    gen_ipset_filter (module Ip4Set) "ip" dir ips neg, None
  | Ir.Protocol p ->
    membership neg "meta l4proto" (Set.to_list p |> List.map ~f:Int.to_string), None
  | Ir.Icmp6 types ->
    membership neg "icmpv6 type" (int_values types), None
  | Ir.Icmp4 types ->
    membership neg "icmp type" (int_values types), None
  | Ir.Mark (value, mask) ->
    Mark.emit (Mark.of_ir (value, mask) ~neg), None
  | Ir.TcpFlags (flags, mask) ->
    let flags_to_string flags =
      if Set.is_empty flags then "0"
      else
        Set.to_list flags
        |> List.map ~f:string_of_tcpflag
        |> String.concat ~sep:"|"
    in
    let neg_str = match neg with true -> "!=" | false -> "==" in
    sprintf "tcp flags & (%s) %s %s" (flags_to_string mask) neg_str (flags_to_string flags), None
  | Ir.Hoplimit limits -> (* Hop limit implies ipv6 *)
    membership neg "ip6 hoplimit" (int_values limits), None
  | Ir.Address_family a ->
    let proto_to_string = function
      | Ir.Ipv4 -> "ipv4"
      | Ir.Ipv6 -> "ipv6"
    in
    let set =
      Set.to_list a
      |> List.map ~f:proto_to_string
    in
    membership neg "meta nfproto" set, None
  | Ir.True when neg ->
    (* Any false statement *)
    "meta mark | 0x1 == 0x0", None
  | Ir.True ->
    "", None

let reject_to_string = function
  | Ir.Reject.HostUnreachable -> "reject with icmpx type host-unreachable"
  | Ir.Reject.NoRoute -> "reject with icmpx type no-route"
  | Ir.Reject.AdminProhibited -> "reject with icmpx type admin-prohibited"
  | Ir.Reject.PortUnreachable -> "reject with icmpx type port-unreachable"
  | Ir.Reject.TcpReset -> "reject with tcp reset"

let gen_effect t = function
  | Ir.MarkZone (dir, id) ->
    let shift = match dir with
      | Ir.Direction.Source -> 0
      | Ir.Direction.Destination -> t.bits
    in
    let mask = t.mask lsl (t.bits - shift) in
    sprintf "meta mark set mark & 0x%08x or 0x%08x" mask ((get_zone_id t id) lsl shift)
  | Ir.Counter -> "counter"
  | Ir.Comment _ -> failwith "Illegal comment at this point. Comments must be added to the end of the rule"
  | Ir.Notrack -> ""
  | Ir.Log prefix -> sprintf "log prefix \"%s: \" level info" prefix
  | Ir.Snat (Some ip) -> sprintf "snat ip to %s" (Ipaddr.V4.to_string ip)
  | Ir.Snat None -> sprintf "masquerade"

let gen_target = function
  | Ir.Accept -> "accept"
  | Ir.Drop -> "drop"
  | Ir.Return -> "return"
  | Ir.Jump chain -> sprintf "jump %s" (chain_name chain)
  | Ir.Reject rsp -> reject_to_string rsp
  | Ir.Pass -> ""

type 'guard guarded_rule = {
  mark_predicates: 'guard list;
  body: Ir.rule;
  comments: string list;
}

(* Turn zone matches into alternative mark comparisons without duplicating the rule body. *)
let lower_zones t (preds, effects, target) =
  (* Separate mark conditions from other predicates while expanding allowed zone choices. *)
  let rec lower = function
    | (Ir.Zone (dir, zones), neg) :: rest ->
      let shift = match dir with Ir.Direction.Source -> 0 | Ir.Direction.Destination -> t.bits in
      let values = Set.to_list zones |> List.map ~f:(fun zone -> get_zone_id t zone lsl shift) in
      let guards = match neg with
        | false -> List.map values ~f:(fun value ->
          [Mark.Equal_to { value; mask = t.mask lsl shift }])
        | true -> [[Mark.Equal_to { value = 0; mask = List.fold values ~init:0 ~f:(lor) }]]
      in
      let direction = match dir with Ir.Direction.Source -> "src" | Ir.Direction.Destination -> "dest" in
      let prefix = match neg with true -> "not " | false -> "" in
      let comment = sprintf "%s%s zone in [ %s ]" prefix direction
          (String.concat ~sep:"; " (Set.to_list zones)) in
      let mark_predicates, preds, comments = lower rest in
      (* Enumerate only zone assignments, never independent packet predicates. *)
      List.cartesian_product guards mark_predicates
      |> List.map ~f:(fun (guard, alternative) -> guard @ alternative), preds, comment :: comments
    | (Ir.Mark (value, mask), neg) :: rest ->
      let mark_predicates, preds, comments = lower rest in
      let pred = Mark.of_ir (value, mask) ~neg in
      List.map mark_predicates ~f:(fun guard -> pred :: guard), preds, comments
    | pred :: rest ->
      let mark_predicates, preds, comments = lower rest in
      mark_predicates, pred :: preds, comments
    | [] -> [[]], [], []
  in
  let mark_predicates, preds, comments = lower preds in
  let effect_comments, effects = List.partition_map effects ~f:(function
    | Ir.Comment comment -> Either.First comment
    | effect_ -> Either.Second effect_) in
  { mark_predicates; body = preds, effects, target; comments = comments @ effect_comments }

(* Combine adjacent rules with the same terminal body by joining their mark alternatives. *)
let rec merge_adjacent_mark_rules = function
  | ({ mark_predicates = guard :: _; body = preds, effects,
       ((Ir.Accept | Ir.Drop | Ir.Return | Ir.Reject _) as target); _ } as rule) ::
    ({ mark_predicates = guard' :: _; body = preds', effects', target'; _ } as rule') :: rest
    when Mark.same_shape guard guard' &&
        Predicate.equal_predicates preds preds' &&
        Ir.equal_effects effects effects' && Ir.equal_target target target' ->
    (* Terminal bodies cannot fall through to execute another alternative.
       Only annotations true for both guards survive their disjunction. *)
    let rule = { rule with
      mark_predicates = rule.mark_predicates @ rule'.mark_predicates;
      comments = List.filter rule.comments ~f:(fun comment -> List.mem rule'.comments comment ~equal:String.equal);
    } in
    merge_adjacent_mark_rules (rule :: rest)
  | rule :: rest -> rule :: merge_adjacent_mark_rules rest
  | [] -> []

let gen_rule t marks annotations = function
  | ([], [], Ir.Pass) when Mark.is_unrestricted marks && List.is_empty annotations -> "# Empty rule"
  | (preds, effects, target) ->
    let preds, comments =
      let preds, comments =
        List.map ~f:(fun (op, neg) -> gen_pred neg op) preds
        |> List.unzip
      in
      let comments = List.filter_opt comments in
      Mark.gen_match marks @ preds, annotations @ comments
    in
    let comments', effects = List.partition_map ~f:(function Ir.Comment c -> Either.First c | effect_ -> Either.Second effect_ ) effects in
    (* Need to filter out comments, and place them at the end *)
    let comment_string =
      match comments @ comments' |> List.stable_dedup ~compare:String.compare with
      | [] -> ""
      | comments -> sprintf "comment \"%s\"" (String.concat ~sep:" && " comments)
    in
    (* Remove duplicate counters *)
    let counters, effects = List.partition_map ~f:(function
        | Ir.Counter -> Either.First Ir.Counter
        | effect_ -> Either.Second effect_ ) effects
    in
    let effects = match counters with
      | c :: _ -> c :: effects
      | [] -> effects
    in

    let effects = List.map ~f:(gen_effect t) effects in
    let target = gen_target target in
    let elements = preds @ effects @ [target] @ [comment_string] |> List.filter ~f:(fun s -> not (String.is_empty s)) in
    sprintf "%s;" (String.concat ~sep:" " elements)

(* Essentially we dont split at all *)
let expand_rule ((preds, _, _) as rule) =
  let has_ipv4 =
    List.exists preds ~f:(function Ir.Ip4Set _, _ -> true | _ -> false)
  in
  let has_ipv6 =
    List.exists preds ~f:(function Ir.Ip6Set _, _ -> true | _ -> false)
  in
  if has_ipv4 && has_ipv6 then [] else [rule]

let emit_chain t { Ir.id; rules; comment } =
  let rules =
    List.concat_map ~f:expand_rule rules
    |> List.map ~f:(lower_zones t)
    |> List.concat_map ~f:(fun rule ->
      match Mark.normalize_alternatives rule.mark_predicates with
      | [] -> []
      | mark_predicates -> [{ rule with mark_predicates }])
    |> merge_adjacent_mark_rules
    |> List.map ~f:(fun rule ->
      gen_rule t (Mark.build_membership rule.mark_predicates) rule.comments rule.body)
  in
  let premable = chain_premable id comment in
  premable @ rules @ [ "}" ]


let emit_filter_rules ~zones (chains : (Ir.Chain_id.t, Ir.chain, 'a) Map.t) : string list =
  let zones = init_zones zones in
  let rules =
    Map.data chains
    |> List.concat_map ~f:(emit_chain zones)
  in
  (* Dump zone mapping *)
  let () =
    Map.to_alist zones.ids
    |> List.sort ~compare:(fun (_, a) (_, b) -> Int.compare a b)
    |> List.iter ~f:(fun (zone, id) -> printf "#zone 0x%04x : %s\n" id zone)
  in
  rules

let emit_nat_rules ~zones rules =
  let zones = init_zones zones in
  { Ir.id = Ir.Chain_id.Builtin Ir.Chain_type.Post_routing; rules; comment = "Nat" }
  |> emit_chain zones

let rec pp_rules ?(acc = []) ?(indent = "") ?(indent_level = "    ")= function
  | [] -> List.rev acc
  | line :: lines ->
    let line = String.strip line in
    let line = match String.chop_suffix ~suffix:";" line with
      | Some line -> (String.strip line) ^ ";"
      | None -> line
    in
    let line, indent = match line.[String.length line - 1] with
      | '{' -> indent ^ line, indent_level ^ indent
      | '}' ->
        let indent = String.chop_prefix_if_exists ~prefix:indent_level indent in
        indent ^ line, indent
      | _ -> indent ^ line, indent
    in
    pp_rules ~acc:(line :: acc) ~indent ~indent_level lines

let emit rules =
  "table inet borderline {" ::
  rules
  @ [ "}" ]
  |> pp_rules
