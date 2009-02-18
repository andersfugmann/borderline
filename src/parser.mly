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
%token MANGLE INPUT FORWARD OUTPUT NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION PORT IP STATE
%token NEW ESTABLISHED RELATED INVALID
%token SET EQ ENDL

%token <int> INT
%token <string> ID

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
  | IMPORT filename                          { Import($2) }
  | ZONE ID LBRACE zone_stms RBRACE          { Zone($2, $4)   }
  | DEFINE ID LBRACE rule_stms RBRACE        { Define($2, $4) }
  | SET process_type LBRACE rule_stms RBRACE { Set($2, $4)    }
;

filename:
  | path SLASH filename { $1 ^ $3 }
  | path                { $1 }
;
path:
  | ID DOT path       { $1 ^ "." ^ $3 }
  | ID                { $1 }

zone_stms:
  | zone_stm           { [ $1 ] }
  | zone_stm zone_stms { $1 :: $2 }
;

zone_stm:
  | NETWORK EQ ipv6     { $3 }
  | INTERFACE EQ ID     { Interface($3) }
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
  | IP EQ ipv6    { $3 }
;

state:
  | NEW          { NEW }
  | ESTABLISHED  { ESTABLISHED }
  | RELATED      { RELATED }
  | INVALID      { INVALID }
;

hex: 
  | ID           { sscanf $1 "%x" (fun i -> i) }
  | INT ID       { let s = sprintf "%d%s" $1 $2 in
                     sscanf s "%x" (fun i -> i) }
  | INT          { let s = sprintf "%d" $1 in
                     sscanf s "%x" (fun i -> i) }

hex_list:
  | hex                {  [ $1 ] }
  | hex COLON hex_list {  $1 :: $3 }
  
ipv6:
  | hex_list DCOLON hex_list SLASH INT { Ip($1, $3, $5) }
  | hex_list SLASH INT                 { Ip($1, [], $3) }
  | hex_list DCOLON hex_list           { Ip($1, $3, 128) }
  | hex_list                           { Ip($1, [], 128) }
;

port:
  int_list { Port($1) }
;

int_list:
  | INT { [ $1 ] }
  | INT COMMA int_list { $1 :: $3 }
;
