%{
  (* Include commonly used modules *)

module F = Frontend
open Lexing

(* Define a function to be called whenever a syntax error is
   encountered. The function prints line number along with a
   description. *)
let parse_error pos s =
  prerr_string (s ^ "\n");
  Printf.eprintf "%s\nFile \"%s\", line %d\n" s pos.Lexing.pos_fname pos.Lexing.pos_lnum;
  exit 1
%}
%token ZONE PROCESS RULE IMPORT
%token DEFINE
%token NETWORK INTERFACE
%token MANGLE FILTER NAT
%token POLICY ALLOW DENY REJECT LOG
%token SOURCE DESTINATION ADDRESS STATE USE
%token NEW ESTABLISHED RELATED INVALID
%token SEMI PROTOCOL
%token TCP_PORT UDP_PORT ICMPTYPE TCPFLAGS
%token EQ NE


%token <int * Lexing.position> INT
%token <string * Lexing.position> ID
%token <int list * int * Lexing.position> IPv6
%token <string * Lexing.position> STRING

%token LBRACE RBRACE COMMA SLASH END

%start main
%type <Frontend.node list> main
%%

/* Scan a list of statements, until the end of the list is encountered. */

main:
  | statement main                        { $1 :: $2 }
  | END                                   { [] }
;

process:
  | process_type rule_seq action          { ($1, $2, $3) }
  | error                                 { parse_error $startpos "Expected process definition" }
;

statement:
  | IMPORT STRING                         { F.Import($2) }
  | ZONE ID LBRACE zone_stms RBRACE       { F.Zone($2, $4) }
  | DEFINE ID EQ rule_seq                 { F.DefineStms($2, $4) }
  | DEFINE ID EQ POLICY policy_seq        { F.DefinePolicy($2, $5) }
  | DEFINE ID EQ data_list                { F.DefineList($2, $4) }
  | PROCESS process                       { let a, b, c = $2 in F.Process(a, b, c) }
;

/* Scan elements within a zone. */

zone_stm:
  | NETWORK EQ IPv6                       { let i, p, _pos = $3 in F.Network(Ipset.ip_of_string i, p) }
  | INTERFACE EQ ID                       { F.Interface($3)}
  | PROCESS process                       { let a, b, c = $2 in F.ZoneRules(a, b, c) }
;

zone_stms:
  | zone_stm SEMI zone_stms               { $1 :: $3 }
  | zone_stm                              { [ $1 ] }
  |                                       { [] }
;

process_type:
  | MANGLE                                { F.MANGLE }
  | FILTER                                { F.FILTER }
  | NAT                                   { F.NAT }
;

/* Rules statements can be a single rule, or a list
   of rules enclosed in curly braces, seperated by semicolon. */

rule_stm:
  | RULE rule_seq action                  { F.Rule ($2, $3) }
  | USE ID                                { F.Reference ($2) }
  | filter_direction filter_stm           { F.Filter ($1, fst $2, snd $2) }
  | STATE oper state_list                 { F.State ($3, $2) }
  | PROTOCOL oper data_list               { F.Protocol ($3, $2) }
  | ICMPTYPE oper data_list               { F.IcmpType ($3, $2) }
  | TCPFLAGS oper data_list SLASH data_list { F.TcpFlags (($3, $5), $2) }
;

rule_stms:
  | rule_seq SEMI rule_stms               { $1 @ $3 }
  | rule_seq                              { $1 }
  |                                       { [] }
;

rule_seq:
  | rule_stm                              { [$1] }
  | LBRACE rule_stms RBRACE               { $2 }
  | error                                 { parse_error $startpos "Missing semi colon?" }
;

/* A policy can be a single policy, or a list of policies
   enclosed in curly braces seperated by semicolon. */

policy_seq:
  | policy                                { [ $1 ] }
  | LBRACE policy_stms RBRACE             { $2 }
  | error                                 { parse_error $startpos "Expected policy" }
;

policy_stms:
  | policy SEMI policy_stms               { $1 :: $3 }
  | policy                                { [ $1 ] }
  |                                       { [ ] }
;

string:
  | STRING                                { fst $1 }
  | error                                 { parse_error $startpos "Expected string" }
;

policy:
  | ALLOW                                 { F.ALLOW }
  | DENY                                  { F.DENY }
  | REJECT                                { F.REJECT }
  | LOG string                            { F.LOG($2) }
  | ID                                    { F.Ref($1) }
;

action:
  | POLICY policy_seq                     { $2 }
  |                                       { [] }
;

/* Rules for a generic filter. */

filter_direction:
  | SOURCE                                { Ir.SOURCE }
  | DESTINATION                           { Ir.DESTINATION }
;

filter_stm:
  | TCP_PORT oper data_list               { (F.TcpPort $3, $2) }
  | UDP_PORT oper data_list               { (F.UdpPort $3, $2) }
  | ADDRESS oper data_list                { (F.Address $3, $2) }
  | ZONE oper data_list                   { (F.FZone $3, $2) }
  | error                                 { parse_error $startpos "Expected filter" }
;

oper:
  | EQ                                    { false }
  | NE                                    { true }
  | error                                 { parse_error $startpos "Expected = or '!='" }
;

state_list:
  | state                                 { [ $1 ] }
  | state COMMA state_list                { $1 :: $3 }
  |                                       { [] }
;

state:
  | NEW                                   { Ir.NEW }
  | ESTABLISHED                           { Ir.ESTABLISHED }
  | RELATED                               { Ir.RELATED }
  | INVALID                               { Ir.INVALID }
;

/* Data lists are polymorphic data sets. The types are
   validated when mapping the frontend language to the Ir tree */

data_list:
  | data COMMA data_list                  { $1 :: $3 }
  | data                                  { [ $1 ] }
  |                                       { [ ] }
;

data:
  | INT                                   { let n, pos = $1 in F.Number (n, pos) }
  | ID                                    { F.Id $1 }
  | IPv6                                  { let i, p, pos = $1 in F.Ip ((Ipset.ip_of_string i, p), pos) }
;
