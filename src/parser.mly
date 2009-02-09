/* FCS - Firewall compiler suite
 * Copyright Anders Fugmann
 */
%{
  open Irtypes
%}

%token ZONE PROCESS RULE DEFINE IMPORT
%token IP NETMASK INTERFACE
%token MANGLE INPUT FORWARD OUTPUT NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION PORT IP STATE
%token NEW ESTABLISHED RELATED INVALID
%token SET EQ ENDL

%token <int> INT
%token <string> ID

%token LBRACE RBRACE COMMA DOT SLASH END

%start main
%type <Irtypes.node list> main
%%

main:
  | statements END                           { $1 }
;

statements:
  | statement                                { [ $1 ] }
  | statement statements                     { $1 :: $2 }
;

statement:
  | IMPORT filename                          { Import($2)     }
  | ZONE ID LBRACE zone_stms RBRACE          { Zone($2, $4)   }
  | DEFINE ID LBRACE rule_stms RBRACE        { Define($2, $4) }
  | SET process_type LBRACE rule_stms RBRACE { Set($2, $4)    }
;

filename:
  | ID SLASH filename { $1 :: $3 }
  | ID                { [ $1 ] }
;

zone_stms:
  | zone_stm           { [ $1 ] }
  | zone_stm zone_stms { $1 :: $2 }
;

zone_stm:
  | IP ip            { $2 }
  | INTERFACE ID     { Interface($2) }
;

process_type:
  | MANGLE          { MANGLE }
  | INPUT           { INPUT }
  | FORWARD         { FORWARD }
  | OUTPUT          { OUTPUT }
  | NAT             { NAT }
;

rule_stms:
  | rule_stm            { [ $1 ] }
  | rule_stm rule_stms  { $1 :: $2 }
;

rule_stm:
  | RULE LBRACE rule_body_stms RBRACE { Rule($3) }
;

rule_body_stms:
  | rule_body_stm                 { [ $1 ] }
  | rule_body_stm rule_body_stms  { $1 :: $2 }
;

rule_body_stm:
  | filter_direction filter_ip      { Filter($1, $2) }
  | STATE EQ state                  { State($3) }
  | POLICY policy                   { Policy($2) }
;

policy:
  | ALLOW   { ALLOW }
  | DENY    { DENY }
  | REJECT  { REJECT }
;


filter_direction:
  | SOURCE       { SOURCE }
  | DESTINATION  { DESTINATION }
;

filter_ip:
  | PORT EQ port  { $3 }
  | IP EQ ip      { $3 }
;

state:
  | NEW          { NEW }
  | ESTABLISHED  { ESTABLISHED }
  | RELATED      { RELATED }
  | INVALID      { INVALID }
;

ip:
  | INT DOT INT DOT INT DOT INT { Ip($1, $3, $5, $7, 32) }
  | INT DOT INT DOT INT DOT INT SLASH INT { Ip($1, $3, $5, $7, $9) }
;

port:
  int_list { Port($1) }
;

int_list:
  | INT { [ $1 ] }
  | INT COMMA int_list { $1 :: $3 }
;
