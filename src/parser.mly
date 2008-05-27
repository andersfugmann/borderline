%{
(* fcs - Firewall compiler suite
 * Copyright Anders Fugmann
 *)

%}

%token ZONE PROCESS RULE DEFINE
%token IP NETMASK INTERFACE
%token MANGLE INPUT FORWARD OUTPUT NAT
%token POLICY ALLOW DENY REJECT
%token SOURCE DESTINATION PORT IP STATE
%token STATE_NEW STATE_ESTABLISHED STATE_RELATED STATE_INVALID

%token <int> INT
%token <string> ID

%token LBRACE RBRACE COMMA DOT SLASH END

%start statements
%type <fcs.statements> statements
%%

statements:
  | zone statements { $1 :: $2 }
  | process statements { $1 :: $2 }
  | define statements { $1 :: $2 }
  | END { [] }

zone:
  | ZONE ID LBRACE zone_defs RBRACE { $2 :: $4 }

zone_defs:
  | zone_def zone_defs { $1 :: $2 }
  | { [] }

zone_def:
  | IP ip_number { [$2] }
  | NETMASK ip_number { [$2] }
  | INTERFACE ID { [$2] }

process:
  | PROCESS process_type LBRACE rule_body RBRACE { [] }

process_type:
  | MANGLE  { [] }
  | INPUT   { [] }
  | FORWARD { [] }
  | OUTPUT  { [] }
  | NAT     { [] }

rule:
  | RULE LBRACE rule_body RBRACE { [$3] }

rule_body:
  | rule  { [$1] }
  | filter_expr { [$1] }
  | policy { [$1] }

policy:
  | POLICY policy_type { [$2] }

policy_type:
  | ALLOW  { [] }
  | DENY   { [] }
  | REJECT { [] }

filter_expr:
  | SOURCE filter_expr_src_or_dst       { [$2] }
  | DESTINATION filter_expr_src_or_dst  { [$2] }
  | STATE state_type                    { [$2] }

filter_expr_src_or_dst:
  | PORT port_list        { [$2] }
  | IP ip_number_opt_mask { [$2] }

state_type:
  | STATE_NEW          { [] }
  | STATE_ESTABLISHED  { [] }
  | STATE_RELATED      { [] }
  | STATE_INVALID      { [] }

define:
  | DEFINE ID RULE LBRACE rule_body RBRACE { $2 :: $5 }
  | DEFINE ID port_list { $2 :: $3 }
  | DEFINE ID ip_number_opt_mask { $2 :: $3 }

ip_number:
  | ip_int DOT ip_int DOT ip_int DOT ip_int { [( $1, $3, $5, $7 )] }
  | ID { [$1] }

ip_int:
  | INT { [$1] } /* Could test that the number is within range here */

ip_number_opt_mask:
  | ip_number mask_opt { [$1 :: $2] }

mask_opt:
  | SLASH INT { [$2] }
  | { [] }

port_list:
  | INT { [$1] }
  | INT COMMA port_list { $1 :: $3 }
;
