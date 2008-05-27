(* fcs - Firewall compiler suite
 * Copyright Anders Fugmann
 *)

%{
%}

%token ZONE PROCESS RULE DEFINE ALIAS
%token IP NETMASK INTERFACE
%token MANGLE INPUT FORWARD OUTPUT NAT
%token POLICY ALLOW DENY REJECT
%token NOT SOURCE DESTINATION PORT IP STATE

%token <int> INT
%token <string> ID

%token LBRACE RBRACE COMMA DOT SLASH END

%start statements
%type <fcs.statements> statements
%%

statements:
  | zone statements { $1 :: $2 }
  | process  statements { $1 :: $2 }
  | define statements { $1 :: $2 }
  | alias statements { $1 :: $2 }
  | END { [] }

zone:
  | ZONE ID LBRACE zone_defs RBRACE { $2 :: $4 }

zone_defs:
  | zone_def zone_defs { $1 :: $2 }
  | { [] }

zone_def:
  | IP ip_number { $1 :: $2 }
  | NETMASK ip_number { $1 :: $2 }
  | INTERFACE STRING { $1 :: $2 }

ip_number:
  | ip_int DOT ip_int DOT ip_int DOT ip_int { [( $1, $3, $5, $7 )] }
  | ID { [$1] }

ip_int:
  | INT { [$1] } /* Could test that the number is within range here */

;
