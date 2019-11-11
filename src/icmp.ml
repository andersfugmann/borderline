open Core

module V4 = struct
  type t = EchoReply
         | DestinationUnreachable
         | SourceQuench
         | Redirect
         | EchoRequest
         | TimeExceeded
         | ParameterProblem
         | TimestampRequest
         | TimestampReply
         | InfoRequest
         | InfoReply
         | RouterAdvertisement
         | RouterSolicitation
         | AddressMaskRequest
         | AddressMaskReply

  let of_string (s, pos) =
    match String.lowercase s with
    | "echo-reply" -> EchoReply
    | "destination-unreachable" -> DestinationUnreachable
    | "source-quench" -> SourceQuench
    | "redirect" -> Redirect
    | "echo-request" -> EchoRequest
    | "time-exceeded" -> TimeExceeded
    | "parameter-problem" -> ParameterProblem
    | "timestamp-request" -> TimestampRequest
    | "timestamp-reply" -> TimestampReply
    | "info-request" -> InfoRequest
    | "info-reply" -> InfoReply
    | "router-advertisement" -> RouterAdvertisement
    | "router-solicitation" -> RouterSolicitation
    | "address-mask-request" -> AddressMaskRequest
    | "address-mask-reply" -> AddressMaskReply
    | _ -> Common.parse_error ~id:s ~pos "Unknown icmpv4 type"
end

module V6 = struct
  type t = DestinationUnreachable
         | PacketTooBig
         | TimeExceeded
         | EchoRequest
         | EchoReply
         | ListenerQuery
         | ListenerReport
         | ListenerReduction
         | RouterSolicitation
         | RouterAdvertisement
         | NeighborSolicitation
         | NeighborAdvertisement
         | Redirect
         | ParameterProblem
         | RouterRenumbering

  let of_string (s, pos) =
    match String.lowercase s with
    | "destination-unreachable" -> DestinationUnreachable
    | "packet-too-big" -> PacketTooBig
    | "time-exceeded" -> TimeExceeded
    | "echo-request" -> EchoRequest
    | "echo-reply" -> EchoReply
    | "listener-query" -> ListenerQuery
    | "listener-report" -> ListenerReport
    | "listener-reduction" -> ListenerReduction
    | "router-solicitation" -> RouterSolicitation
    | "router-advertisement" -> RouterAdvertisement
    | "neighbor-solicitation" -> NeighborSolicitation
    | "neighbor-advertisement" -> NeighborAdvertisement
    | "redirect" -> Redirect
    | "parameter-problem" -> ParameterProblem
    | "router-renumbering" -> RouterRenumbering
    | _ -> Common.parse_error ~id:s ~pos "Unknown icmpv6 type"
end
