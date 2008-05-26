/* fcs - Firewall compiler suite
 * Copyright Anders Fugmann
 */
{
open Parser        (* The type token is defined in parser.mli *)
open Scanf
exception Lexer_error of int
open Fcs

rule token = parse
    [' ' '\t']     { token lexbuf }     (* skip blanks *)
  | ['\n' ]        { lineno := 1+ !lineno; token lexbuf } (* skip eol *)
  | "zone"         { ZONE }
  | "set"          { SET }
  | "input"        { INPUT }
  | "forward"      { FORWARD }
  | "output"       { OUTPUT }
  | "rule"         { RULE }
  | '='            { ASSIGN }
  | '{'            { LBRACE }
  | '}'            { RBRACE }
  | ','            { COMMA }
  | ['0'-'9']+ as lxm { INT(int_of_string lxm) }
  | ['a'-'z''A'-'Z''_']?['a'-'z''A'-'Z''0'-'9''_']+ as lxm { ID(lxm) }
  | eof            { END }
  | "#"            { comment lexbuf; token lexbuf }
  | "/*"           { c_comment lexbuf; token lexbuf }
  | "//"           { line_comment lexbuf; token lexbuf }
  | _              { raise (Lexer_error !lineno) }

and c_comment = parse
    "*/"           { }
  | '\n'           { lineno := 1+ !lineno; c_comment lexbuf }
  | eof            { raise (Failure "Unterminated comment") }
  | _              { c_comment lexbuf }

and comment = parse
    '\n'           { lineno := 1+ !lineno }
  | eof            { }

}
