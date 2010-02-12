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

open Common
open Ir

let next_id = ref 0

let cmp_chain_id = function
    Temporary(a), Temporary(b) -> a = b
  | Builtin(a), Builtin(b)     -> a = b
  | Named(a), Named(b)         -> a = b
  | _, _                       -> false

let get_chain_name = function
    Temporary(id) -> Printf.sprintf "temp_%04d" id
  | Named(name) -> Printf.sprintf "%s" name
  | Builtin(tpe) -> match tpe with
        INPUT   -> "INPUT"
      | OUTPUT  -> "OUTPUT"
      | FORWARD -> "FORWARD"

let is_builtin = function
    Builtin(_) -> true
  | _ -> false

let compare a b =
  String.compare (get_chain_name a) (get_chain_name b)

module Chain_map = Map.Make (struct
                               type t = Ir.chain_id
                               let compare = compare
                             end)

let chains = ref Chain_map.empty

let filter p chains =
  Chain_map.fold (fun _ chn acc -> if p chn then chn :: acc else acc) chains []

let set chain =
  chains := Chain_map.add chain.id chain !chains; chain

let delete id =
  chains := Chain_map.remove id !chains

let create rules comment =
  let id = !next_id in
  incr next_id; set { id = Temporary(id); rules = rules; comment = comment }

let replace id rules comment =
  set { id = id; rules = rules; comment = comment }

let get_named_chain (id, _) = Named(id)

let create_named_chain id rules comment =
  let chain_id = get_named_chain id in
    set { id = chain_id; rules = rules; comment = comment }

let get chain_id =
  Chain_map.find chain_id !chains

let emit emitter =
  emitter !chains

let optimize opt  =
  chains := opt !chains
