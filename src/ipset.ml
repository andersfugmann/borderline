(**
   Define a set type for ip addresses.
*)
open Batteries

open Printf
open Big_int

module type Ip_type =
  sig
    val bits : int
    val field_size : int
    val to_string : int list -> string
  end

module Ipv4 : Ip_type = struct
  let bits = 32
  let field_size = 8
  let to_string fields = String.concat "." (List.map (sprintf "%d") fields)
end

module Ipv6 : Ip_type = struct
  let bits = 128
  let field_size = 16
  let to_string fields =
    let (hd, tl) = List.partition (fun part -> part != 0) fields in
    (* Now strip 0 from tl *)
    let (_, tl) = List.partition (fun part -> part = 0) tl in
    (String.concat ":" (List.map (sprintf "%04x") hd)) ^ "::" ^
    (String.concat ":" (List.map (sprintf "%04x") tl))

end

module Make(Ip: Ip_type) =
struct

  (* Top is a range *)
  (* Left are less, Right are more *)

  type number = big_int
  type mask = int
  type ip = (big_int * mask)
  type elt = (number * number)
  type t = elt BatAvlTree.tree

  let empty = BatAvlTree.empty

  (** Just add all the normal integer operations. The is just for convenience *)

  let min = min_big_int
  let max = max_big_int
  let succ = succ_big_int
  let pred = pred_big_int

  let (<) = lt_big_int
  let (<=) = le_big_int
  let (=) = eq_big_int
  let (-) = sub_big_int
  let (&) = and_big_int

  let (-|) = Pervasives.(-)
  let (+|) = Pervasives.(+)

  let compare (low, high) = function
    | (_, high') when succ high' < low -> `Less
    | (low', _) when succ high < low' -> `Greater
    | _ -> `Overlap

  let merge (l, h) (l', h') =
    (min l l', max h h')

  let rec add elt t =
    let open BatAvlTree in
    if is_empty t then singleton_tree elt
    else
      let root_elt = root t in
      match compare elt root_elt with
      | `Less ->
        let l = add elt (left_branch t) in
        make_tree l root_elt (right_branch t)
      | `Greater ->
        let r = add elt (right_branch t) in
        make_tree (left_branch t) root_elt r
      | `Overlap ->
        begin
          let left =
            try
              let elt', t = split_rightmost (left_branch t) in
              Some (compare elt' elt , elt', t)
            with
            | Not_found -> None
          in
          let right =
            try
              let elt', t = split_leftmost (right_branch t) in
              Some (compare elt' elt , elt', t)
            with
            | Not_found -> None
          in
          match (left, right) with
          | Some (`Less, _, _), Some (`Greater, _, _)
          | Some (`Less, _, _), None
          | None, Some (`Greater, _, _)
          | None, None ->
            make_tree (left_branch t) (merge elt root_elt) (right_branch t)

          | Some (`Overlap, l_elt, l), Some (`Greater, _, _)
          | Some (`Overlap, l_elt, l), None -> add (merge elt l_elt) (make_tree l root_elt (right_branch t))
          | _                        , Some (`Less, _, _) -> failwith "Inconsistent tree: Right is less"

          | Some (`Less, _, _), Some (`Overlap, r_elt, r)
          | None, Some (`Overlap, r_elt, r) -> add (merge elt r_elt) (make_tree (left_branch t) root_elt r)
          | Some (`Greater, _,_ ), _ -> failwith "Inconsistent tree: Left is greater"


          | Some (`Overlap, l_elt, l), Some (`Overlap, r_elt, r) ->
            add (merge (merge elt l_elt) r_elt) (make_tree l root_elt r)

        end

  let delete_top_node t =
    let open BatAvlTree in
    let l = left_branch t in
    let r = right_branch t in
    match is_empty l, is_empty r with
    | true, true -> empty
    | false, _ ->
      let elt, l = split_rightmost l in
      make_tree l elt r
    | true, false ->
      let elt, r = split_leftmost r in
      make_tree l elt r


  let rec delete elt t =
    let open BatAvlTree in
    try
      let lt, (root_l, root_h), rt = left_branch t, root t, right_branch t in
      match elt with
      | (l, h) when l <= root_l && root_h <= h  ->
        delete elt (delete_top_node t)
      | (l, h) when l < root_l ->
        let lt = delete elt lt in
        let root_elt = (succ h, root_h) in
        make_tree lt root_elt rt
      | (l, h) when root_h < h ->
        let rt = delete elt rt in
        let root_elt = (root_l, pred l) in
        make_tree lt root_elt rt
      | (l, h) ->
        (* Two parts left. We construct a new tree based on the first part,
           and add the missing part *)
        let l_elt = (root_l, pred l) in
        let r_elt = (succ h, root_h) in
        make_tree lt l_elt rt |> add r_elt
    with
    | Not_found -> empty

  let remove = delete

  let cardinal t = BatAvlTree.fold (fun _ a -> a +| 1) t 0

  let union a b = BatAvlTree.fold add b a
  let diff a b = BatAvlTree.fold delete b a

  (* Intersection *)
  let inter a b =
    let rec inter_elt (l, h) t =
      let open BatAvlTree in
      match root t with
      | (root_l, root_h) when root_l <= l && h <= root_h -> [l, h]
      | (root_l, root_h) when root_l <= l ->
        (l, root_h) :: inter_elt (l, h) (right_branch t)
      | (root_l, root_h) when h <= root_h ->
        (root_l, h) :: inter_elt (l, h) (left_branch t)
      | (root_l, root_h) ->
        (root_l, root_h) :: (inter_elt (l, h) (right_branch t) @ inter_elt (l, h) (left_branch t))
      | exception Not_found -> []
    in
    BatAvlTree.enum a
    |> Enum.map (fun elt -> inter_elt elt b)
    |> Enum.map List.enum
    |> Enum.flatten
    |> Enum.fold (fun t elt -> add elt t) BatAvlTree.empty

  let rec contains (low, high) t =
    let open BatAvlTree in
    match root t with
    | (l, h) when l <= low && high <= h -> true
    | (l, _) when low < l ->
      contains (low, high) (right_branch t)
    | (_, h) when h < high ->
      contains (low, high) (left_branch t)
    | _ -> false
    | exception Not_found -> false

  let subset a b =
    (* Are all elements in a also in b? *)
    BatAvlTree.enum a
    |> Enum.for_all (fun elt -> contains elt b)

  let equal a b =
    subset a b && subset b a

  let ip_of_string ip =
    List.fold_left (fun acc num -> add_int_big_int num (shift_left_big_int acc Ip.field_size)) zero_big_int ip

  let string_of_ip ip =
    let mask = pred (power_int_positive_int 2 Ip.field_size) in
    let rec to_list ip = function
      | 0 -> []
      | n -> int_of_big_int (and_big_int ip mask) :: to_list (shift_right_big_int ip Ip.field_size) (n -| Ip.field_size)
    in
    Ip.to_string (List.rev (to_list ip Ip.bits))

  let to_elt (ip, mask) =
    let mask = pred (power_int_positive_int 2 (Ip.bits -| mask)) in
    let high = or_big_int ip mask in
    let low = xor_big_int high mask in
    (low, high)

  let elt2str (l, h) =
    sprintf "(%s,%s)" (Big_int.string_of_big_int l) (Big_int.string_of_big_int h)

  let ip2str (i, mask) =
    sprintf "%s/%i %s"
      (Big_int.string_of_big_int i) mask
      (elt2str (to_elt (i, mask)))

  let _ = ip2str

  let to_string t =
    BatAvlTree.fold (fun elt s -> (elt2str elt) :: s) t [] |> List.rev |> String.join ", "

  (* Convert a range of ip numbers to a list of ip/mask *)
  let rec to_ip (l, h) =
    let rec inner mask =
      match to_elt (l, mask) with
      | (l', h') when l' = l && h = h' ->
        [ (l, mask) ]
      | (l', h') when l' < l || h < h' -> inner (mask +| 1)
      | (_, h') ->
        let ip = (l, mask) in
        ip :: to_ip (succ h', h)
    in
    inner 0

  let to_ips t =
    BatAvlTree.fold (fun elt acc -> (to_ip elt) @ acc) t []

  let singleton elt = BatAvlTree.(make_tree empty elt empty)

  let elements set = BatAvlTree.enum set |> List.of_enum

(** Convert a list of ips to a set *)
  let from_ips ips =
    List.enum ips
    |> Enum.map to_elt
    |> Enum.fold (fun t elt -> add elt t) BatAvlTree.empty

  let is_network_range (low, high) =
    let diff = high - low in
  (* Basically, diff must be all ones. *)
    ((succ diff) & diff) = zero_big_int

end

module Ip6 = Make(Ipv6)
module Ip4 = Make(Ipv4)

(** Test *)
let test =
  let open Ip6 in
  let open OUnit2 in
  let r2br (a, b) = (big_int_of_int a, big_int_of_int b) in
  "Generic ip numbers" >::: [
    "Simple" >:: ( fun _ ->
        let t = empty |> add (r2br (0, 127)) in
        assert_bool "Should be part" (contains (r2br (0, 127)) t);
        assert_bool "Should not be part" (not (contains (r2br (256, 256)) t));
        assert_bool "Should be part" (contains (r2br (45, 48)) t);
        assert_bool "Should not be part" (not (contains (r2br (100, 256)) t));
      );

    "Insertion" >:: ( fun _ ->
      let set = add (r2br (3, 5)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (1, 2)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (6, 10)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (20, 100)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (cardinal set);
      let set = add (r2br (11, 19)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (50, 80)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = add (r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      ()
    );
    "Removal" >:: ( fun _ ->
      let set = add (r2br (100, 200)) empty in
      let set = remove (r2br (50, 150)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = remove (r2br (170, 250)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal set);
      let set = remove (r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (cardinal set);
      let set = remove (r2br (155, 165)) set in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 2 (cardinal set);
      ()
    );
    "Intersection" >:: ( fun _ ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (300, 400)) set1 in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal (inter set1 set2));

      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (150, 250)) empty in
      assert_equal ~msg:"Wrong set size" ~printer:string_of_int 1 (cardinal (inter set1 set2));
      ()
    );

    "Equality" >:: (fun _ ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (300, 400)) set1 in
      assert_bool "Sets should be different" (not (equal set1 set2));

      let set1 = add ( r2br (250, 350)) empty in
      assert_bool "Sets should be different" (not (equal set1 set2));

      let set2 = add ( r2br (250, 350)) empty in
      assert_bool "Sets should be equal" (equal set1 set2);
      assert_bool "Sets should be equal" (equal set2 set1);
      assert_bool "Sets should be equal" (equal set1 set1);
      assert_bool "Sets should be equal" (equal set2 set2);
      ()
    );

    "Subset" >:: (fun _ ->
      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (150, 190)) empty in
      assert_bool "Set1 should not be a subset of set2" (not (subset set1 set2));
      assert_bool "Set2 should be a subset of set1" (subset set2 set1);

      let set2 = add ( r2br (150, 210)) empty in
      assert_bool "Set2 should now be a subset of set1" (not (subset set2 set1));
      assert_bool "Set1 should now be a subset of set2" (not (subset set1 set2));

      let set2 = add ( r2br (90, 190)) empty in
      assert_bool "Set2 should now be a subset of set1" (not (subset set2 set1));
      assert_bool "Set1 should be a subset of set1" (subset set1 set1);

      let set1 = add ( r2br (100, 200)) empty in
      let set2 = add ( r2br (100, 100)) empty in
      assert_bool "Set2 should be a subset of set1" (subset set2 set1);

      ()
    );

    "Set to ip list" >:: (fun _ ->
        let set = add (r2br (10000, 20000)) empty in
        printf "Tree: %s\n%!" (to_string set);
        let ips = to_ips set in
        printf "Ip's: %s\n%!" (List.map ip2str ips |> String.join ", ");
        let set2 = from_ips ips in
        printf "Tree: %s\n%!" (to_string set2);
        assert_bool "Sets must be equal" (equal set set2);
        ()
    );
  ]
