{
(* FCS - Firewall compiler suite
 * Copyright Anders Fugmann
 *)
open Parser
open Frontend
open Scanf

exception Lexer_error of int
}
rule token = parse
    [' ' '\t']     { token lexbuf }     (* skip blanks *)
  | '\n'           { lineno := 1+ !lineno; token lexbuf } 
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
  | "source"       { Parser.SOURCE }
  | "destination"  { Parser.DESTINATION }
  | "port"         { Parser.PORT }
  | "state"        { Parser.STATE }

(* State types *)
  | "new"          { Parser.NEW }
  | "established"  { Parser.ESTABLISHED }
  | "releated"     { Parser.RELATED }
  | "invalid"      { Parser.INVALID }

(* Data *)
  | ['0'-'9']+ as lxm { INT(int_of_string lxm) }
  | ['a'-'z''A'-'Z''_']?['a'-'z''A'-'Z''0'-'9''_']+ as lxm { ID(lxm) }

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
  | "#"            { comment lexbuf; token lexbuf }
  | eof            { END }
  | _              { raise (Lexer_error !lineno) }

and comment = parse
    '\n'           { lineno := !lineno + 1}
  | eof            { }
  | _              { comment lexbuf }

