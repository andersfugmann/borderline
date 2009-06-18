{
(* FCS - Firewall compiler suite
 * Copyright Anders Fugmann
 *)
open Parser
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
  | "reject"       { Parser.REJECT }

(* filters *)
  | "source"
  | "src"          { Parser.SOURCE }
  | "destination"
  | "dst"          { Parser.DESTINATION }
  | "port"         { Parser.PORT }
  | "state"        { Parser.STATE }
  | "ip"           { Parser.IP }
  | "call"         { Parser.CALL }

(* State types *)
  | "new"          { Parser.NEW }
  | "established"  { Parser.ESTABLISHED }
  | "related"      { Parser.RELATED }
  | "invalid"      { Parser.INVALID }

(* Protocols *)
  | "protocol"     { Parser.PROTOCOL }
  | "tcp"          { Parser.TCP }
  | "udp"          { Parser.UDP }
  | "icmp"         { Parser.ICMP }

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
        IPv6(addrs, mask)

    }
  | ['0'-'9']+ as lxm { INT(int_of_string lxm) }
  | ['a'-'z''A'-'Z''_']?['a'-'z''A'-'Z''0'-'9''_']+ as lxm { ID(lxm) }
  | ['"'](['0'-'9''a'-'z''.''/']+ as str)['"'] { STRING(str) }

(* Simple tokens *)
  | '{'            { LBRACE }
  | '}'            { RBRACE }
  | ','            { COMMA }
  | '.'            { DOT }
  | ':'            { COLON }
  | "::"           { DCOLON }
  | '/'            { SLASH }
  | '='            { EQ }
  | ';'            { SEMI }
  | '#'            { comment lexbuf; token lexbuf }
  | eof            { END }
  | _              { raise (Lexer_error !lineno) }

and comment = parse
    '\n'           { new_line lexbuf }
  | eof            { }
  | _              { comment lexbuf }
