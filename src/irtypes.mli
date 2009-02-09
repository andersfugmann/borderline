type filterdirection = SOURCE | DESTINATION ;;
type processtype = MANGLE | INPUT | FORWARD | OUTPUT | NAT;;
type statetype = NEW | RELATED | ESTABLISHED | INVALID ;;
type policytype = ALLOW | DENY | REJECT ;;

type node = Import of string list
          | Zone of string * node list
          | Define of string * node list
          | Set of  processtype * node list
          | Rule of node list
          | Interface of string
          | Filter of filterdirection * node
          | State of statetype
          | Policy of policytype
          | Port of int list
          | Ip of int * int * int * int * int;;





