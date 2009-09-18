{
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

open Parser
open Parsing
open Frontend
open Scanf

exception Lexer_error of int

let hex_of_string h : int =
  sscanf h "%x" (fun i -> i)

let new_line lexbuf =
  let pos = lexbuf.Lexing.lex_curr_p in
    lexbuf.Lexing.lex_curr_p <- { pos with
      Lexing.pos_lnum = pos.Lexing.pos_lnum + 1;
      Lexing.pos_bol = pos.Lexing.pos_cnum;
    }
}

rule token = parse
    [' ' '\t']     { token lexbuf }     (* skip blanks *)
  | '\n'           { new_line lexbuf; token lexbuf }
  | "zone"         { ZONE }
  | "process"      { PROCESS }
  | "rule"         { RULE }
  | "define"       { DEFINE }
  | "import"       { IMPORT }

(* zone definitions *)
  | "network"      { NETWORK }
  | "interface"    { INTERFACE }

(* process targets *)
  | "mangle"       { Parser.MANGLE }
  | "filter"       { Parser.FILTER }
  | "nat"          { Parser.NAT }

(* Policy *)
  | "policy"       { Parser.POLICY }
  | "allow"        { Parser.ALLOW }
  | "deny"         { Parser.DENY }
  | "accept"       { Parser.ALLOW }
  | "drop"         { Parser.DENY }
  | "reject"       { Parser.REJECT }

(* filters *)
  | "source"
  | "src"          { Parser.SOURCE }
  | "destination"
  | "dst"          { Parser.DESTINATION }
  | "udp port"     { Parser.UDPPORT }
  | "tcp port"     { Parser.TCPPORT }
  | "icmptype"     { Parser.ICMPTYPE }
  | "state"        { Parser.STATE }
  | "address"      { Parser.ADDRESS }
  | "use"          { Parser.USE }
  | "protocol"     { Parser.PROTOCOL }

(* State types *)
  | "new"          { Parser.NEW }
  | "established"  { Parser.ESTABLISHED }
  | "related"      { Parser.RELATED }
  | "invalid"      { Parser.INVALID }

(* Data *)
  | (['0'-'9''a'-'f''A'-'F']+ as x1) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x2) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x3) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x4) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x5) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x6) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x7) ':'
    (['0'-'9''a'-'f''A'-'F']+ as x8) ('/' ((['0'-'9']+) as mask))?
    { let addrs = List.map hex_of_string [x1; x2; x3; x4; x5; x6; x7; x8] in
      let mask = match mask with
          Some(mask) -> int_of_string mask
        | _ -> 128
      in
        IPv6(addrs, mask, lexbuf.Lexing.lex_curr_p)
    }
  | (((['0'-'9''a'-'f''A'-'F']+ ':')* ['0'-'9''a'-'f''A'-'F']+)? as hd)?
    "::"
    (((['0'-'9''a'-'f''A'-'F']+ ':')* ['0'-'9''a'-'f''A'-'F']+)? as tl)?
    ('/' ((['0'-'9']+) as mask))?
    {
      let seq2lst = function
          Some(str) -> List.map hex_of_string (Str.split (Str.regexp ":") str)
        | None -> []
      in
      let rec gen = function
          0 -> []
        | n -> 0 :: gen (n-1)
      in
      let sl = seq2lst hd in
      let el = seq2lst tl in
      let rem = 8 - (List.length sl) - (List.length el) in
      let mask = match mask with
          Some(mask) -> int_of_string mask
        | _ -> 128
      in
        assert (rem >= 0); (* No more than eight fields *)
        IPv6(sl @ (gen rem) @ el, mask, lexbuf.Lexing.lex_curr_p)
    }
  | ['0'-'9']+ as lxm { INT(int_of_string lxm, lexbuf.Lexing.lex_curr_p) }
  | ['a'-'z''A'-'Z''_']['a'-'z''A'-'Z''0'-'9''_''-''.']* as lxm { ID (lxm, lexbuf.Lexing.lex_curr_p) }
  | '"'(['0'-'9' 'a'-'z' 'A'-'Z' '.' '/' '_' '-' ]+ as str)'"' { STRING (str, lexbuf.Lexing.lex_curr_p) }

(* Simple tokens *)
  | '{'            { LBRACE }
  | '}'            { RBRACE }
  | ','            { COMMA }
  | '.'            { DOT }
  | ':'            { COLON }
  | "::"           { DCOLON }
  | '/'            { SLASH }
  | "!="           { NE }
  | '='            { EQ }
  | ';'            { SEMI }
  | '#'            { comment lexbuf }
  | eof            { END }
  | _ as c         { CHAR(c) }

and comment = parse
    '\n'           { new_line lexbuf; token lexbuf }
  | eof            { END }
  | _              { comment lexbuf }
