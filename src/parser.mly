%{
  (* Include commonly used modules *)

module F = Frontend
module Ip6 = Ipset.Ip6
open Lexing

(* Define a function to be called whenever a syntax error is
   encountered. The function prints line number along with a
   description. *)
let parse_error pos s =
  Printf.eprintf "File \"%s\", line %d\nError: %s\n" pos.Lexing.pos_fname pos.Lexing.pos_lnum s;
  exit 1
%}
%token ZONE PROCESS RULE IMPORT
%token DEFINE
%token NETWORK INTERFACE
%token MANGLE FILTER NAT
%token ALLOW DENY REJECT LOG
%token POLICY
%token SOURCE DESTINATION ADDRESS STATE USE
%token NEW ESTABLISHED RELATED INVALID
%token SEMI PROTOCOL
%token TCP_PORT UDP_PORT ICMP6TYPE TCPFLAGS
%token EQ NE


%token <int * Lexing.position> INT
%token <int list * int * Lexing.position> IPv6
%token <int * int * int * int * int * Lexing.position> IPv4
%token <string * Lexing.position> QUOTE
%token <string * Lexing.position> IDENT

%token LBRACE RBRACE COMMA SLASH END

%start main
%type <Frontend.node list> main
%%

/* Scan a list of statements, until the end of the list is encountered. */

main:
  | stms = terminated(list(statement), END)            { stms }

statement:
  | IMPORT s=string                                    { F.Import(s) }
  | ZONE id=id LBRACE stms=separated_list_opt(SEMI, zone_stm) RBRACE { F.Zone(id, stms) }
  | DEFINE id=id EQ POLICY policies=policy_seq         { F.DefinePolicy(id, policies) }
  | DEFINE id=id EQ rules=rule_seq                     { F.DefineStms(id, rules) }
  | DEFINE id=id EQ rule=rule_stm                      { F.DefineStms(id, [ rule ] ) }
  | DEFINE id=id EQ data=data_list                     { F.DefineList(id, data) }
  | PROCESS t=process_type r=rule_seq POLICY p=policy_seq { F.Process (t,r,p) }

rule_seq:
  | LBRACE rules=separated_list_opt(SEMI, rule_stm) RBRACE { rules }

(* Scan elements within a zone. *)

zone_stm:
  | NETWORK EQ ip=IPv6                                 { let (i, p, _pos) = ip in F.Network(Ip6.ip_of_string i, p) }
  | INTERFACE EQ id=id                                 { F.Interface(id)}
  | PROCESS t=process_type r=rule_seq p=policy_opt     { F.ZoneRules (t,r,p) }

policy_opt:
  | { [] }
  | POLICY policies=policy_seq { policies }

process_type:
  | MANGLE                                             { F.MANGLE }
  | FILTER                                             { F.FILTER }
  | NAT                                                { F.NAT }

(* Rules statements can be a single rule, or a list
   of rules enclosed in curly braces, seperated by semicolon. *)

rule_stm:
  | RULE r=rule_seq p=policy_opt                       { F.Rule (r, p) }
  | USE id=id                                          { F.Reference (id) }
  | d=filter_direction f=filter_stm                    { F.Filter (d, fst f, snd f) }
  | STATE o=oper states=separated_list(COMMA, state)   { F.State (states, o) }
  | PROTOCOL o=oper d=data_list                        { F.Protocol (d, o) }
  | ICMP6TYPE o=oper d=data_list                       { F.Icmp6Type (d, o) }
  | TCPFLAGS o=oper f=data_list SLASH d=data_list      { F.TcpFlags ((f, d), o) }

(* A policy can be a single policy, or a list of policies
   enclosed in curly braces seperated by semicolon. *)

policy_seq:
  | p=policy                                           { [ p ] }
  | LBRACE p=separated_list_opt(SEMI, policy) RBRACE   { p }

string:
  | s=QUOTE                                            { s }
  | error                                              { parse_error $startpos "Expected string" }

policy:
  | ALLOW                                              { F.ALLOW }
  | DENY                                               { F.DENY }
  | REJECT                                             { F.REJECT }
  | LOG s=string                                       { F.LOG(fst s) }
  | id=id                                              { F.Ref(id) }

(* Rules for a generic filter. *)

filter_direction:
  | SOURCE                                             { Ir.SOURCE }
  | DESTINATION                                        { Ir.DESTINATION }

filter_stm:
  | TCP_PORT o=oper d=data_list                        { (F.TcpPort d, o) }
  | UDP_PORT o=oper d=data_list                        { (F.UdpPort d, o) }
  | ADDRESS o=oper d=data_list                         { (F.Address d, o) }
  | ZONE o=oper d=data_list                            { (F.FZone d, o) }
  | error                                              { parse_error $startpos "Expected filter" }

oper:
  | EQ                                                 { false }
  | NE                                                 { true }
  | error                                              { parse_error $startpos "Expected = or '!='" }

state:
  | NEW                                                { State.NEW }
  | ESTABLISHED                                        { State.ESTABLISHED }
  | RELATED                                            { State.RELATED }
  | INVALID                                            { State.INVALID }

(* Data lists are polymorphic data sets. The types are
   validated when mapping the frontend language to the Ir tree *)

data_list:
  | data=separated_list_opt(COMMA, data)                   { data }
;

data:
  | i=INT                                              { let n, pos = i in F.Number (n, pos) }
  | id=id                                              { F.Id id }
  | ip=IPv6                                            { let i, p, pos = ip in F.Ip ((Ip6.ip_of_string i, p), pos) }

separated_list_opt(SEP, T):
  | { [] }
  | t = T { [t] }
  | t = T SEP ts = separated_list_opt(SEP, T) { t :: ts }

id:
  | s = QUOTE { s }
  | i = IDENT { i }
  | error     { parse_error $startpos "Identifier or quoted string expected" }
