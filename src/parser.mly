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
%token ALLOW DENY REJECT LOG
%token POLICY
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
  | stms = terminated(list(statement), END)            { stms }
;

process:
  | t=process_type r=rule_seq POLICY a=policy_seq      { (t, r, a) }
  | error                                              { parse_error $startpos "Expected process definition" }
;

statement:
  | IMPORT s=STRING                                    { F.Import(s) }
  | ZONE id=ID LBRACE stms=zone_stms RBRACE            { F.Zone(id, stms) }
  | DEFINE id=ID EQ POLICY policies=policy_seq         { F.DefinePolicy(id, policies) }
  | DEFINE id=ID EQ rules=rule_seq                     { F.DefineStms(id, rules) }
  | DEFINE id=ID EQ data=data_list                     { F.DefineList(id, data) }
  | PROCESS p=process                                  { let (a, b, c) = p in F.Process(a, b, c) }
;

/* Scan elements within a zone. */

zone_stm:
  | NETWORK EQ ip=IPv6                                 { let (i, p, _pos) = ip in F.Network(Ipset.ip_of_string i, p) }
  | INTERFACE EQ id=ID                                 { F.Interface(id)}
  | PROCESS p=process                                  { let (a, b, c) = p in F.ZoneRules(a, b, c) }
;

zone_stms:
  | stms = separated_list(SEMI, zone_stm)              { stms }
;

process_type:
  | MANGLE                                             { F.MANGLE }
  | FILTER                                             { F.FILTER }
  | NAT                                                { F.NAT }
;

/* Rules statements can be a single rule, or a list
   of rules enclosed in curly braces, seperated by semicolon. */

rule_stm:
  | RULE r=rule_seq a=action                           { F.Rule (r, a) }
  | USE id=ID                                          { F.Reference (id) }
  | d=filter_direction f=filter_stm                    { F.Filter (d, fst f, snd f) }
  | STATE o=oper s=state_list                          { F.State (s, o) }
  | PROTOCOL o=oper d=data_list                        { F.Protocol (d, o) }
  | ICMPTYPE o=oper d=data_list                        { F.IcmpType (d, o) }
  | TCPFLAGS o=oper f=data_list SLASH d=data_list      { F.TcpFlags ((f, d), o) }
;

rule_seq:
  | rule=rule_stm                                      { [rule] }
  | LBRACE rules=separated_list(SEMI, rule_stm) RBRACE { rules }
  | error                                              { parse_error $startpos "Missing semi colon?" }
;

/* A policy can be a single policy, or a list of policies
   enclosed in curly braces seperated by semicolon. */

policy_seq:
  | p=policy                                           { [ p ] }
  | LBRACE p=separated_list(SEMI, policy) RBRACE       { p }
  | error                                              { parse_error $startpos "Expected policy" }
;

string:
  | s=STRING                                           { fst s }
  | error                                              { parse_error $startpos "Expected string" }
;

policy:
  | ALLOW                                              { F.ALLOW }
  | DENY                                               { F.DENY }
  | REJECT                                             { F.REJECT }
  | LOG s=string                                       { F.LOG(s) }
  | id=ID                                              { F.Ref(id) }
;

action:
  | POLICY policies=policy_seq                         { policies }
  |                                                    { [] }
;

/* Rules for a generic filter. */

filter_direction:
  | SOURCE                                             { Ir.SOURCE }
  | DESTINATION                                        { Ir.DESTINATION }
;

filter_stm:
  | TCP_PORT o=oper d=data_list                        { (F.TcpPort d, o) }
  | UDP_PORT o=oper d=data_list                        { (F.UdpPort d, o) }
  | ADDRESS o=oper d=data_list                         { (F.Address d, o) }
  | ZONE o=oper d=data_list                            { (F.FZone d, o) }
  | error                                              { parse_error $startpos "Expected filter" }
;

oper:
  | EQ                                                 { false }
  | NE                                                 { true }
  | error                                              { parse_error $startpos "Expected = or '!='" }
;

state_list:
  | states=separated_list(COMMA, state)                { states }

;

state:
  | NEW                                                { Ir.NEW }
  | ESTABLISHED                                        { Ir.ESTABLISHED }
  | RELATED                                            { Ir.RELATED }
  | INVALID                                            { Ir.INVALID }
;

/* Data lists are polymorphic data sets. The types are
   validated when mapping the frontend language to the Ir tree */

data_list:
  | data=separated_list(COMMA, data)                   { data }
;

data:
  | i=INT                                              { let n, pos = i in F.Number (n, pos) }
  | id=ID                                              { F.Id id }
  | ip=IPv6                                            { let i, p, pos = ip in F.Ip ((Ipset.ip_of_string i, p), pos) }
;
