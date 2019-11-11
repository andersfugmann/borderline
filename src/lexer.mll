{

open Parser
open Scanf

let value_map = Core.Option.value_map

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
  | [' ' '\t']     { token lexbuf }     (* skip blanks *)
  | '\n'           { new_line lexbuf; token lexbuf }
  | "zone"         { ZONE }
  | "process"      { PROCESS }
  | "rule"         { RULE }
  | "define"       { DEFINE }
  | "import"       { IMPORT }

(* zone definitions *)
  | "network"      { NETWORK }
  | "interface"    { INTERFACE }
  | "vlan"         { VLAN }
  | "snat"         { SNAT }

(* Policy *)
  | "policy"       { Parser.POLICY }
  | "allow"        { Parser.ALLOW }
  | "deny"         { Parser.DENY }
  | "accept"       { Parser.ALLOW }
  | "drop"         { Parser.DENY }
  | "reject"       { Parser.REJECT }
  | "log"          { Parser.LOG }
  | "counter"      { Parser.COUNTER }

(* filters *)
  | "port"         { Parser.PORT }
  | "icmp6"        { Parser.ICMP6 }
  | "icmp4"        { Parser.ICMP4 }
  | "state"        { Parser.STATE }
  | "address"      { Parser.ADDRESS }
  | "use"          { Parser.USE }
  | "ipv4"         { Parser.IPV4 }
  | "ipv6"         { Parser.IPV6 }
  | "tcpflags"     { Parser.TCPFLAGS }
  | "true"         { Parser.TRUE }
  | "false"        { Parser.FALSE }

(* Data *)
  | (['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ ':'
     ['0'-'9''a'-'f''A'-'F']+ as addr)
     ('/' (['0'-'9']+ as mask))?
    { IPv6 (addr, value_map ~default:128 ~f:int_of_string mask, lexbuf.Lexing.lex_start_p) }
  | ((((['0'-'9''a'-'f''A'-'F']+ ':')* ['0'-'9''a'-'f''A'-'F']+)?)?
    "::"
    (((['0'-'9''a'-'f''A'-'F']+ ':')* ['0'-'9''a'-'f''A'-'F']+)?)? as addr)
    ('/' ((['0'-'9']+) as mask))?
    { IPv6 (addr, value_map ~default:128 ~f:int_of_string mask, lexbuf.Lexing.lex_start_p) }
  | (['0'-'9']+ '.'
     ['0'-'9']+ '.'
     ['0'-'9']+ '.'
     ['0'-'9']+) as addr
    ('/' ((['0'-'9']+) as mask))?
    { IPv4 (addr, value_map ~default:32 ~f:int_of_string mask, lexbuf.Lexing.lex_start_p) }
  | ['0'-'9']+ as lxm { INT(int_of_string lxm, lexbuf.Lexing.lex_curr_p) }
  | ['a'-'z''A'-'Z''_']['a'-'z''A'-'Z''0'-'9''_''.''-']* as lxm { IDENT (lxm, lexbuf.Lexing.lex_start_p) }
  | '"'(['0'-'9' 'a'-'z' 'A'-'Z' '.' '/' '_' '-' ' ']+ as str)'"' { QUOTE (str, lexbuf.Lexing.lex_start_p) }


(* Simple tokens *)
  | '{'            { LBRACE }
  | '}'            { RBRACE }
  | '['            { LBRACKET }
  | ']'            { RBRACKET }
  | ','            { COMMA }
  | "!="           { NE }
  | "+="           { APPEND }
  | '='            { EQ }
  | ';'            { SEMI }
  | '#'            { comment lexbuf }
  | '/'            { SLASH }
  | '!'            { NOT }
  | eof            { END }

and comment = parse
    '\n'           { new_line lexbuf; token lexbuf }
  | eof            { END }
  | _              { comment lexbuf }
