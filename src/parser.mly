/* Borderline firewall
 * Copyright Anders Fugmann
 */
%{
  open Frontend
  open Frontend_types
  open Printf
  open Scanf
  open Lexing

  let parse_error s =
    let pos_end = Parsing.symbol_end_pos () in
    let pos_start = Parsing.symbol_start_pos () in
    let c_end = pos_end.pos_cnum - pos_end.pos_bol + 1 in
    let c_start = pos_start.pos_cnum - pos_start.pos_bol + 1 in
      printf "File \"%s\", line %d, character %d-%d:\n" pos_end.pos_fname pos_end.pos_lnum c_start c_end;
      printf "%s after here\n" s
%}

%token ZONE PROCESS RULE DEFINE IMPORT
%token NETWORK INTERFACE
%token MANGLE FILTER NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION ADDRESS STATE USE
%token NEW ESTABLISHED RELATED INVALID
%token START EQ ENDL SEMI PROTOCOL
%token TCPPORT UDPPORT
%token EQ NE

%token <int * Lexing.position> INT
%token <string * Lexing.position> ID
%token <int list * int * Lexing.position> IPv6
%token <string * Lexing.position> STRING

%token LBRACE RBRACE COMMA DOT COLON DCOLON SLASH END

%start main
%type <Frontend_types.node list> main
%%

main:
  | statement                                                     { [ $1 ] }
  | statement main                                                { $1 :: $2 }
  | END                                                           { [] }
;

process:
  | process_type rule_seq action                                  { ($1, $2, $3) }

statement:
  | IMPORT STRING                                                 { Import($2) }
  | ZONE ID zone_seq                                              { Zone($2, $3) }
  | DEFINE ID EQ rule_seq                                         { DefineStms($2, $4) }
  | DEFINE ID EQ data_list                                        { DefineList($2, $4) }
  | PROCESS process                                               { let a, b, c = $2 in Process(a, b, c) }
;

zone_stm:
  | NETWORK EQ IPv6                                               { let i, p, pos = $3 in Network(Ipv6.to_number i, p) }
  | INTERFACE EQ ID                                               { Interface($3)}
  | PROCESS process                                               { let a, b, c = $2 in ZoneRules(a, b, c) }
;

zone_stms:
  | zone_seq SEMI zone_stms                                       { $1 @ $3 }
  | zone_seq                                                      { $1 }
  | SEMI                                                          { [] }
  |                                                               { [] }
;

zone_seq:
  | zone_stm                                                      { [ $1 ] }
  | LBRACE zone_stms RBRACE                                       { $2 }

process_type:
  | MANGLE                                                        { MANGLE }
  | FILTER                                                        { FILTER }
  | NAT                                                           { NAT }
;

rule_stm:
  | RULE rule_seq action                                          { Rule($2, $3) }
  | USE ID                                                        { Reference($2) }
  | filter_direction filter_stm                                   { let stm, pol = $2 in
                                                                      Filter($1, stm, pol) }
  | STATE oper state_list                                         { State($3, $2) }
  | PROTOCOL oper data_list                                       { Protocol($3, $2) }
;

rule_stms:
  | rule_seq SEMI rule_stms                                       { $1 @ $3 }
  | rule_seq                                                      { $1 }
  | SEMI                                                          { [] }
  |                                                               { [] }
;

rule_seq:
  | rule_stm                                                      { [$1] }
  | LBRACE rule_stms RBRACE                                       { $2 }


action:
  | POLICY policy                                                 { $2 }

policy:
  | ALLOW                                                         { ALLOW }
  | DENY                                                          { DENY }
  | REJECT                                                        { REJECT }
;

filter_direction:
  | SOURCE                                                        { Ir.SOURCE }
  | DESTINATION                                                   { Ir.DESTINATION }
;

filter_stm:
  | TCPPORT oper data_list                                        { (TcpPort($3), $2) }
  | UDPPORT oper data_list                                        { (UdpPort($3), $2) }
  | ADDRESS oper data_list                                        { (Address($3), $2) }
  | ZONE oper ID                                                  { (FZone($3), $2) }
;

oper:
  | EQ                                                            { false }
  | NE                                                            { true }

state_list:
  | state                                                         { [ $1 ] }
  | state COMMA state_list                                        { $1 :: $3 }

state:
  | NEW                                                           { Ir.NEW }
  | ESTABLISHED                                                   { Ir.ESTABLISHED }
  | RELATED                                                       { Ir.RELATED }
  | INVALID                                                       { Ir.INVALID }
;

data_list:
  | data                                                          { [ $1 ] }
  | data COMMA data_list                                          { $1 :: $3 }

data:
  | INT                                                           { let n, pos = $1 in Number (n, pos) }
  | ID                                                            { Id     ($1) }
  | IPv6                                                          { let i, p, pos = $1 in Ip ((Ipv6.to_number i, p), pos) }
