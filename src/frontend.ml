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
open Frontend_types

let lineno = ref 1

let node_type id = function
    Zone _ -> 1 = id
  | Process _ -> 2 = id
  | DefineStms _ -> 3 = id
  | DefineList _ -> 4 = id
  | _ -> false

let rec fold_rules func rules acc =
  match rules with
    | Rule (rules, _) as x :: xs -> fold_rules func xs (fold_rules func rules (func acc x))
    | x :: xs -> fold_rules func xs (func acc x)
    | [] -> acc

let fold_nodes func nodes acc =
  List.fold_left func acc nodes

let rec fold func nodes acc =
  let node_func acc = function
      DefineStms (_, rules)  -> fold_rules func rules acc
    | Process (_, rules, _) -> fold_rules func rules acc
    | _ -> acc
  in
    fold_nodes node_func nodes acc



