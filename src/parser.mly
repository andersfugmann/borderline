/* FCS - Firewall compiler suite
 * Copyright Anders Fugmann
 */
%{
module Zone =
struct
  let tbl = Hashtbl.create 256
  let exists zone =
    try
      let _ = Hashtbl.find tbl zone in
	true
    with Not_found -> false

  let add zone zonedefs = Hashtbl.add tbl zone zonedefs
end
%}

%token ZONE PROCESS RULE DEFINE IMPORT
%token IP NETMASK INTERFACE
%token MANGLE INPUT FORWARD OUTPUT NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION PORT IP STATE
%token NEW ESTABLISHED RELATED INVALID

%token <int> INT
%token <string> ID

%token LBRACE RBRACE COMMA DOT SLASH END

%start statements
%type <fcs.statements> statements
%%

statements:
  | statements statement { [] }
  | END { [] }
;;

statement:
  | ZONE ID LBRACE zone_defs RBRACE { Zone.add $2 $4 }
  | PROCESS process_type LBRACE rule_body RBRACE { [] }
  | define  { [] }
  | IMPORT filename { [] }
;;

filename:
  | filename SLASH ID { [] }
  | ID                { [] }
;;

zone_defs:
  | zone_defs IP ip { $1 :: [$3] }
  | zone_defs NETMASK ip { $1 :: [$3] }
  | zone_defs INTERFACE ID { $1 :: [$3] }
  | { [] }
;;

process_type:
  | MANGLE  { [] }
  | INPUT   { [] }
  | FORWARD { [] }
  | OUTPUT  { [] }
  | NAT     { [] }
;;

rule:
  | RULE LBRACE rule_body RBRACE { [] }
;;

rule_body:
  | rule_body rule  { [] }
  | rule_body filter_expr { [] }
  | rule_end { [] }
;;

rule_end:
  | policy { [$1] }
  |        { [] }
;;

policy:
  | POLICY ALLOW  { [] }
  | POLICY DENY   { [] }
  | POLICY REJECT { [] }
;;

filter_expr:
  | SOURCE filter_ip      { [] }
  | DESTINATION filter_ip { [] }
  | STATE state           { [] }
;;
filter_ip:
  | PORT port  { [] }
  | IP ip      { [] }
;;

state:
  | NEW          { [] }
  | ESTABLISHED  { [] }
  | RELATED      { [] }
  | INVALID      { [] }
;;

define:
  | DEFINE ID rule { [] }
  | DEFINE ID port { [] }
  | DEFINE ID ip { [] }
;;

ip:
  | INT DOT INT DOT INT DOT INT { [] }
  | INT DOT INT DOT INT DOT INT SLASH INT { [] }
  | ID { }
;;

port:
  | port COMMA PORT { [] }
  | INT { [] }
;;
