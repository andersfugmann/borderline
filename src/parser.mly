%{
    %}
(* Restrict to address family *)
%token ZONE PROCESS RULE IMPORT
%token DEFINE
%token NETWORK INTERFACE GROUP SNAT
%token ALLOW DENY REJECT LOG COUNTER USER_CHAIN
%token POLICY
%token ADDRESS FAMILY STATE USE
%token SEMI IPV4 IPV6 PROTOCOL
%token PORT ICMP6 ICMP4 TCPFLAGS TRUE FALSE HOPLIMIT
%token EQ NE NOT APPEND

%token <int * Lexing.position> INT
%token <string * int * Lexing.position> IPv6
%token <string * int * Lexing.position> IPv4
%token <string * Lexing.position> QUOTE
%token <string * Lexing.position> IDENT

%token LBRACE RBRACE LBRACKET RBRACKET COMMA END SLASH

%start main
%type <Frontend.node list> main
%%

/* Scan a list of statements, until the end of the list is encountered. */

main:
  | stms = terminated(list(statement), END)            { stms }

statement:
  | IMPORT s=string                                          { Frontend.Import(s) }
  | ZONE id=id LBRACE stms=separated_list_opt(SEMI, zone_stm) RBRACE { Frontend.Zone(id, stms) }
  | DEFINE id=id_quote EQ POLICY policies=policy_seq         { Frontend.DefinePolicy(id, policies) }
  | DEFINE id=id_quote EQ rule=rule_seq                      { Frontend.DefineStms(id, rule) }
  | DEFINE id=id_quote EQ b = bool                           { Frontend.DefineStms(id, [ b ]) }
(*  | DEFINE id=id_quote EQ rule=rule_stm                    { Frontend.DefineStms(id, [ rule ]) } *)
  | DEFINE id=id_quote EQ RULE r=rule_seq p=policy_opt       { Frontend.DefineStms(id, [ Frontend.Rule (r, p) ]) }
  | DEFINE id=id_quote EQ data=data_list                     { Frontend.DefineList(id, data) }
  | DEFINE id=id_quote APPEND data=data_list                 { Frontend.AppendList(id, data) }
  | PROCESS t=id r=rule_seq POLICY p=policy_seq              { Frontend.Process (t,r,p) }

rule_seq:
  | LBRACE rules=separated_list_opt(SEMI, rule_stm) RBRACE { rules }

(* Scan elements within a zone. *)

zone_stm:
  | NETWORK EQ data=data_list                          { Frontend.Network (data) }
  | INTERFACE EQ data=data_list                        { Frontend.Interface(data)}
  | GROUP EQ data=data_list                            { Frontend.If_group(data)}
  | PROCESS t=id r=rule_seq p=policy_opt               { Frontend.ZoneRules (t,r,p) }
  | SNAT zones=data_list ip=ipv4                       { Frontend.ZoneSnat(zones, fst ip) }

policy_opt:
  | { [] }
  | POLICY policies=policy_seq { policies }

(* Rules statements can be a single rule, or a list
   of rules enclosed in curly braces, seperated by semicolon. *)

rule_stm:
  | RULE r=rule_seq p=policy_opt                  { Frontend.Rule (r, p) }
  | NOT USE id=id                                 { Frontend.Reference (id, true) }
  | USE id=id                                     { Frontend.Reference (id, false) }
  | d=id f=filter_stm                             { Frontend.Filter (d, fst f, snd f) }
  | STATE o=oper states=data_list                 { Frontend.State (states, o) }
  | PROTOCOL o=oper d=data_list                   { Frontend.Protocol (d, o) }
  | ADDRESS FAMILY o=oper d=address_family_list   { Frontend.Address_family (d, o) }
  | ICMP6 o=oper d=data_list                      { Frontend.Icmp6 (d, o) }
  | ICMP4 o=oper d=data_list                      { Frontend.Icmp4 (d, o) }
  | HOPLIMIT o=oper d=data_list                   { Frontend.Hoplimit (d, o) }
  | TCPFLAGS o=oper f=data_list SLASH m=data_list { Frontend.TcpFlags (f, m, o) }
  | b = bool                                      { b }

(* A policy can be a single policy, or a list of policies
   enclosed in curly braces seperated by semicolon. *)

policy_seq:
  | p=policy                                           { [ p ] }
  | LBRACE p=separated_list_opt(SEMI, policy) RBRACE   { p }

string:
  | s=QUOTE                                            { s }

policy:
  | USER_CHAIN s=string                                { Frontend.User_chain s }
  | COUNTER                                            { Frontend.Counter }
  | ALLOW                                              { Frontend.Allow }
  | DENY                                               { Frontend.Deny }
  | REJECT s=string                                    { Frontend.Reject (Some s) }
  | REJECT                                             { Frontend.Reject (None) }
  | LOG s=string                                       { Frontend.Log(fst s) }
  | id=id                                              { Frontend.Ref(id) }

(* Rules for a generic filter. *)

filter_stm:
  | id=id PORT o=oper d=data_list                      { (Frontend.Ports (id, d), o) }
  | ADDRESS o=oper d=data_list                         { (Frontend.Address d, o) }
  | ZONE o=oper d=data_list                            { (Frontend.FZone d, o) }

oper:
  | EQ                                                 { false }
  | NE                                                 { true }


(* Data lists are polymorphic data sets. The types are
   validated when mapping the frontend language to the Ir tree *)
data_list:
  | LBRACKET data=separated_list_opt(COMMA, data) RBRACKET { data }
  | data=data                                              { [data] }

data:
  | i=INT                                              { let n, pos = i in Frontend.Number (n, pos) }
  | id=id                                              { Frontend.Id id }
  | ip=ip                                              { Frontend.Ip (fst ip, snd ip) }
  | s=QUOTE                                            { let s, pos = s in Frontend.String (s, pos) }

address_family_list:
  | LBRACKET data=separated_list_opt(COMMA, address_family) RBRACKET { data }
  | data=address_family                                              { [ data ] }

address_family:
  | IPV4 { Ir.Ipv4 }
  | IPV6 { Ir.Ipv6 }

bool:
  | TRUE
  | NOT FALSE                                          { Frontend.True }
  | NOT TRUE
  | FALSE                                              { Frontend.False }

(* Separated list, allowing seperator at the end *)
separated_list_opt(SEP, T):
  | { [] }
  | t = T { [t] }
  | t = T SEP ts = separated_list_opt(SEP, T) { t :: ts }

id:
  | i = IDENT { i }

id_quote:
  | i = IDENT { i }
  | q = QUOTE { q }

ip:
  | ip=ipv4 { Frontend.Ipv4 (fst ip), snd ip }
  | ip=ipv6 { Frontend.Ipv6 (fst ip), snd ip }

ipv4:
  | ip=IPv4 { let (i, mask, pos) = ip in
                  let addr = Ipaddr.V4.Prefix.make mask
                    (Ipaddr.V4.of_string_exn i)
                  in
                  addr, pos
            }

ipv6:
  | ip=IPv6 { let (i, mask, pos) = ip in
              let addr = Ipaddr.V6.Prefix.make mask
                (Ipaddr.V6.of_string_exn i)
              in
              addr, pos
            }
