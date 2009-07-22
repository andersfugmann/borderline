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
      printf "%s\n" s        
%}

%token ZONE PROCESS RULE DEFINE IMPORT
%token NETWORK INTERFACE
%token MANGLE FILTER NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION PORT ADDRESS STATE CALL
%token NEW ESTABLISHED RELATED INVALID
%token START EQ ENDL SEMI PROTOCOL
%token TCP UDP ICMP

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

statement:
  | IMPORT STRING                                                 { Import($2) }
  | ZONE ID LBRACE zone_stms RBRACE                               { Zone($2, $4)   }
  | DEFINE ID EQ rule_stms                                        { DefineStms($2, $4) }
  | DEFINE ID EQ port_list                                        { DefineInts($2, $4) }
  | PROCESS process_type LBRACE rule_stms RBRACE POLICY policy    { Process($2, $4, $7) }
;

zone_stm:
  | NETWORK EQ IPv6                                               { let i, p = $3 in Network(Ipv6.to_number i, p) }
  | INTERFACE EQ ID                                               { Interface($3) }
  | PROCESS process_type LBRACE rule_stms RBRACE POLICY policy    { ZoneRules($2, $4, $7) }
;

zone_stms:
  | zone_stm SEMI zone_stms                                       { $1 :: $3 }
  | zone_stm SEMI                                                 { [ $1 ] }
  | zone_stm                                                      { [ $1 ] }
;

process_type:
  | MANGLE                                                        { MANGLE }
  | FILTER                                                        { FILTER }
  | NAT                                                           { NAT }
;

rule_stm:
  | RULE LBRACE rule_stms RBRACE action                           { Rule($3, $5) }
  | CALL ID                                                       { Reference($2) }
  | filter_direction filter_stm                                   { Filter($1, $2) }
  | STATE EQ state_list                                           { State($3) }
  | PROTOCOL EQ protocol                                          { Protocol($3) }
;

rule_stms:
  | rule_stm SEMI rule_stms                                       { $1 :: $3 }
  | rule_stm                                                      { [ $1 ] }
  |                                                               { [] }
;

action:
  | POLICY policy                                                 { Policy($2) }

policy:
  | ALLOW                                                         { ALLOW }
  | DENY                                                          { DENY }
  | REJECT                                                        { REJECT }
;

protocol:
  | TCP                                                           { Ir.TCP }
  | UDP                                                           { Ir.UDP }

filter_direction:
  | SOURCE                                                        { Ir.SOURCE }
  | DESTINATION                                                   { Ir.DESTINATION }
;

filter_stm:
  | TCP PORT EQ port_list                                         { TcpPort($4) }
  | UDP PORT EQ port_list                                         { UdpPort($4) }
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

port_list:
  | port                                                          { [ $1 ] }
  | port COMMA port_list                                          { $1 :: $3 }

port:
  | INT                                                           { Port_nr ($1) }
  | ID                                                            { Port_id ($1) }
;
