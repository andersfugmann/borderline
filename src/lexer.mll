{
(* FCS - Firewall compiler suite
 * Copyright Anders Fugmann
 *)

(* open Parser *)        (* The type token is defined in parser.mli *)
open Scanf
exception Lexer_error of int
}
rule token = parse
    [' ' '\t']     { token lexbuf }     (* skip blanks *)
  | ['\n' ]        { lineno := 1+ !lineno; token lexbuf } (* skip eol *)
  | "zone"         { ZONE }
  | "process"      { PROCESS }
  | "rule"         { RULE }
  | "define"       { DEFINE }

(* zone definitions *)
  | "ip"           { IP }
  | "netmask"      { NETMASK }
  | "interface"    { INTERFACE }

(* process targets *)
  | "mangle"       { MANGLE }
  | "input"        { INPUT }
  | "forward"      { FORWARD }
  | "output"       { OUTPUT }
  | "nat"          { NAT }

(* Policy *)
  | "policy"       { POLICY }
  | "allow"        { ALLOW }
  | "deny"         { DENY }
  | "reject"       { REJECT }

(* filters *)
  | "source"       { SOURCE }
  | "destination"  { DESTINATION }
  | "port"         { PORT }
  | "state"        { STATE }

(* State types *)
  | "new"          { STATE_NEW }
  | "established"  { STATE_ESTABLISHED }
  | "releated"     { STATE_RELATED }
  | "invalid"      { STATE_INVALID }

(* Data *)
  | ['0'-'9']+ as lxm { INT(int_of_string lxm) }
  | ['a'-'z''A'-'Z''_']?['a'-'z''A'-'Z''0'-'9''_']+ as lxm { ID(lxm) }

(* Simple tokens *)
  | '{'            { LBRACE }
  | '}'            { RBRACE }
  | ','            { COMMA }
  | '.'            { DOT }
  | '/'            { SLASH }
  | "#"            { comment lexbuf; token lexbuf }
  | eof            { END }
  | _              { raise (Lexer_error !lineno) }

and line_comment = parse
    '\n'           { lineno := !lineno + 1}
  | eof            { }
  | _              { line_comment lexbuf }

