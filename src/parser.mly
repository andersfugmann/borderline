/* FCS - Firewall compiler suite
 * Copyright Anders Fugmann
 */
%{
  open Frontend
  open Printf
  open Scanf
%}

%token ZONE PROCESS RULE DEFINE IMPORT
%token NETWORK INTERFACE
%token MANGLE FILTER NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION PORT IP STATE
%token NEW ESTABLISHED RELATED INVALID
%token START EQ ENDL SEMI

%token <int> INT
%token <string> ID
%token <int list * int> IPv6

%token LBRACE RBRACE COMMA DOT COLON DCOLON SLASH END

%start main
%type <Frontend.node list> main
%%

main:
  | statements END                           { $1 }
;

statements:
  | statement                                { [ $1 ] }
  | statement statements                     { $1 :: $2 }
;

statement:
  | IMPORT filename                               { Import($2)     }
  | ZONE ID LBRACE zone_stms RBRACE               { Zone($2, $4)   }
  | DEFINE ID rule_stms                           { Define($2, $3) }
  | PROCESS process_type LBRACE rule_stms RBRACE POLICY policy    { Process($2, $7, $4) } 
  | PROCESS process_type LBRACE RBRACE POLICY policy              { Process($2, $6, []) } 
;

filename:
  | path SLASH filename { $1 ^ $3 }
  | path                { $1 }
;
path:
  | ID DOT path       { $1 ^ "." ^ $3 }
  | ID                { $1 }

zone_stm:
  | NETWORK EQ IPv6     { Network($3) }
  | INTERFACE EQ ID     { Interface($3) }
;

zone_stms:
  | zone_stm SEMI            { [ $1 ] }
  | zone_stm SEMI zone_stms  { $1 :: $3 }
;


process_type:
  | MANGLE          { MANGLE }
  | FILTER          { FILTER }
  | NAT             { NAT } 
;

rule_stm:
  | RULE LBRACE rule_stms RBRACE action { Rule($3, $5) }
  | RULE LBRACE RBRACE action           { Rule([], $4) }
  | filter_direction filter_ip          { Filter($1, $2) }
  | STATE EQ state                      { State($3) }
;

rule_stms:
  | rule_stm SEMI       { [ $1 ] }
  | rule_stm rule_stms  { $1 :: $2 }
;

action:
  | POLICY policy                   { Policy($2) }

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
  | PORT EQ int_list  { Port($3) }
  | IP EQ IPv6        { Ip($3) }
;

state:
  | NEW          { NEW }
  | ESTABLISHED  { ESTABLISHED }
  | RELATED      { RELATED }
  | INVALID      { INVALID }
;
  
  
int_list:
  | INT { [ $1 ] }
  | INT COMMA int_list { $1 :: $3 }
;
