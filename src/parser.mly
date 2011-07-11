%{
  (* Include commonly used modules *)

  open Frontend
  open Printf
  open Scanf
  open Lexing

  (* Define a function to be called whenever a syntax error is
     encountered. The function prints line number along with a
     description. *)

  let exit_ s =    
    let pos_start = Parsing.symbol_start_pos () in
    let pos_end = Parsing.symbol_end_pos () in
    let c_end = pos_end.pos_cnum - pos_end.pos_bol + 1 in
    let c_start = pos_start.pos_cnum - pos_start.pos_bol + 1 in
      prerr_string (s ^ "\n");
      prerr_string (sprintf "File \"%s\", line %d, character %d-%d:\n" pos_end.pos_fname pos_end.pos_lnum c_start c_end);
      exit 1
  let parse_error s = (* Printf.printf "%s\n" s *) exit_ s

%}
%token ZONE PROCESS RULE IMPORT
%token DEFINE 
%token NETWORK INTERFACE
%token MANGLE FILTER NAT
%token POLICY ALLOW DENY REJECT LOG
%token SOURCE DESTINATION ADDRESS STATE USE 
%token NEW ESTABLISHED RELATED INVALID
%token START EQ ENDL SEMI PROTOCOL
%token TCP_PORT UDP_PORT ICMPTYPE TCPFLAGS
%token EQ NE


%token <int * Lexing.position> INT
%token <string * Lexing.position> ID
%token <int list * int * Lexing.position> IPv6
%token <string * Lexing.position> STRING
%token <char> CHAR

%token LBRACE RBRACE COMMA DOT COLON DCOLON SLASH END

%start main
%type <Frontend.node list> main
%%

/* Scan a list of statements, until the end of the list is encountered. */

main:
  | statement                             { [ $1 ] }
  | statement main                        { $1 :: $2 }
  | END                                   { [] }
;

process:
  | process_type rule_seq action          { ($1, $2, $3) }
  | error                                 { exit_ "Expected process definition" }
;

statement:
  | IMPORT STRING                         { Import($2) }
  | ZONE ID LBRACE zone_stms RBRACE       { Zone($2, $4) }
  | DEFINE ID EQ rule_seq                 { DefineStms($2, $4) }
  | DEFINE ID EQ POLICY policy_seq        { DefinePolicy($2, $5) }
  | DEFINE ID EQ data_list                { DefineList($2, $4) }
  | PROCESS process                       { let a, b, c = $2 in Process(a, b, c) }
;

/* Scan elements within a zone. */

zone_stm:
  | NETWORK EQ IPv6                       { let i, p, pos = $3 in Network(Ip.ip_of_string i, p) }
  | INTERFACE EQ ID                       { Interface($3)}
  | PROCESS process                       { let a, b, c = $2 in ZoneRules(a, b, c) }
;

zone_stms:
  | zone_stm SEMI zone_stms               { $1 :: $3 }
  | zone_stm                              { [ $1 ] }
  |                                       { [] }
;

process_type:
  | MANGLE                                { MANGLE }
  | FILTER                                { FILTER }
  | NAT                                   { NAT }
;

/* Rules statements can be a single rule, or a list 
   of rules enclosed in curly braces, seperated by semicolon. */

rule_stm:
  | RULE rule_seq action                  { Rule ($2, $3) }
  | USE ID                                { Reference ($2) }
  | filter_direction filter_stm           { Filter ($1, fst $2, snd $2) }
  | STATE oper state_list                 { State ($3, $2) }
  | PROTOCOL oper data_list               { Protocol ($3, $2) }
  | ICMPTYPE oper data_list               { IcmpType ($3, $2) }
  | TCPFLAGS oper data_list SLASH data_list { TcpFlags (($3, $5), $2) }
;

rule_stms:
  | rule_seq SEMI rule_stms               { $1 @ $3 }
  | rule_seq                              { $1 }
  |                                       { [] }
;

rule_seq:
  | rule_stm                              { [$1] }
  | LBRACE rule_stms RBRACE               { $2 }
  | error                                 { exit_ "Missing semi colon?" }
;

/* A policy can be a single policy, or a list of policies 
   enclosed in curly braces seperated by semicolon. */

policy_seq:
  | policy                                { [ $1 ] }
  | LBRACE policy_stms RBRACE             { $2 }
  | error                                 { exit_ "Expected policy" }
;

policy_stms:
  | policy SEMI policy_stms               { $1 :: $3 }
  | policy                                { [ $1 ] }
  |                                       { [ ] }
;

string:
  | STRING                                { fst $1 }
  | error                                 { exit_ "Expected string" }
;

policy:
  | ALLOW                                 { ALLOW }
  | DENY                                  { DENY }
  | REJECT                                { REJECT }
  | LOG string                            { LOG($2) }
  | ID                                    { Ref($1) }
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
  | TCP_PORT oper data_list               { (TcpPort $3, $2) }
  | UDP_PORT oper data_list               { (UdpPort $3, $2) }
  | ADDRESS oper data_list                { (Address $3, $2) }
  | ZONE oper data_list                   { (FZone $3, $2) }
  | error                                 { exit_ "Expected filter" }
;

oper:
  | EQ                                    { false }
  | NE                                    { true }
  | error                                 { exit_ "Expected = or '!='" }
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
  | INT                                   { let n, pos = $1 in Number (n, pos) }
  | ID                                    { Id $1 }
  | IPv6                                  { let i, p, pos = $1 in Ip ((Ip.ip_of_string i, p), pos) }
;

