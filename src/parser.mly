/* fcs - Firewall compiler suite
 * Copyright Anders Fugmann
 */

%{
%}

%token <int> INT
%token <string> ID
%token <string> STRING
%token END
%token ZONE DEFINE RULE
%token LBRACE RBRACE SEMI DOT
%token IPNUMBER NETMASK INTERFACE

%start statements
%type <fcs.statements> statements
%%

statements:
  | zone statements { $1 :: $3 }
  | set_def statements { $1 :: $3 }
  | named_rule statements { $1 :: $3 }
  | END { [] }

zone:
  | ZONE ID LBRACE zone_defs RBRACE

zone_defs:
  | zone_def zone_defs { $1 :: $2 }
  | zone_def { $1 }

zone_def:
  | IPNUMBER ip_number { $1 :: $2 }
  | NETMASK ip_number { $1 :: $2 }
  | INTERFACE STRING { $1 :: $2 }

ip_number:
  | ip_int DOT ip_int DOT ip_int DOT ip_int { ( $1, $3, $5, $7 ) }
  | ID { $1 }

ip_int:
  | INT { $1 } /* Could test that the number is within range here */



;
