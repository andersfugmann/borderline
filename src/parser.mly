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
%token SOURCE DESTINATION ADDRESS STATE CALL
%token NEW ESTABLISHED RELATED INVALID
%token START EQ ENDL SEMI PROTOCOL
%token TCPPORT UDPPORT

%token <int> INT
%token <string * Lexing.position> ID
%token <int list * int> IPv6
%token <string * Lexing.position> STRING

%token LBRACE RBRACE COMMA DOT COLON DCOLON SLASH END

%start main
%type <Frontend_types.node list> main
%%

main:
  | statements END                                                { $1 }
  | END                                                           { [] }
;

statements:
  | statement                                                     { [ $1 ] }
  | statement statements                                          { $1 :: $2 }
;

process:
  process_type rule_seq action                                    { ($1, $2, $3) }

statement:
  | IMPORT STRING                                                 { Import($2) }
  | ZONE ID zone_seq                                              { Zone($2, $3) }
  | DEFINE ID EQ rule_seq                                         { DefineStms($2, $4) }
  | DEFINE ID EQ int_list                                         { DefineInts($2, $4) }
  | PROCESS process                                               { let a, b, c = $2 in Process(a, b, c) }
;

zone_stm:
  | NETWORK EQ IPv6                                               { let i, p = $3 in Network(Ipv6.to_number i, p) }
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
  | CALL ID                                                       { Reference($2) }
  | filter_direction filter_stm                                   { Filter($1, $2) }
  | STATE EQ state_list                                           { State($3) }
  | PROTOCOL EQ int_list                                          { Protocol($3) }
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
  | TCPPORT EQ int_list                                           { TcpPort($3) }
  | UDPPORT EQ int_list                                           { UdpPort($3) }
  | ADDRESS EQ IPv6                                               { let i, p = $3 in Ip(Ipv6.to_number i, p) }
  | ZONE EQ ID                                                    { FZone($3) }
;

state_list:
  | state                                                         { [ $1 ] }
  | state COMMA state_list                                        { $1 :: $3 }

state:
  | NEW                                                           { Ir.NEW }
  | ESTABLISHED                                                   { Ir.ESTABLISHED }
  | RELATED                                                       { Ir.RELATED }
  | INVALID                                                       { Ir.INVALID }
;

int_list:
  | int                                                           { [ $1 ] }
  | int COMMA int_list                                            { $1 :: $3 }

int:
  | INT                                                           { Number ($1) }
  | ID                                                            { Id     ($1) }
;
