# Wave specification

## Definition

Wave is the Fluxor-native home for portable application-protocol capabilities —
HTTP, WebSocket, gRPC, RTP, SIP, SMTP and S3 — in both client and server roles. It
exists so applications consume bounded protocol modules without Fluxor becoming
the owner of application or session protocol semantics.

Wave is not a network stack, proxy product, API gateway, message broker, media
session product, identity provider, or service mesh.

## Ownership

Wave owns:

- HTTP/1.1 message parsing, serialization, routing mechanics, connection state,
  client and server behaviour, and bounded body handling — including the shared
  method vocabulary both generations resolve against, request-body framing
  (`Content-Length`, chunked transfer coding, `Expect: 100-continue`) and the
  refusal of a message that carries contradictory framing headers;
- the HTTP application fan-out contract — the `HttpRequest` / `HttpResponse`
  envelopes, their `(conn_id, stream_id)` correlation, and the backpressure and
  streaming rules that carry them — which is how a graph node OUTSIDE Wave holds
  the resources and business handlers listed below as not Wave's;
- HTTP/2 framing, stream state, flow control, and HPACK;
- HTTP/3 request/response semantics, QPACK, and request-stream multiplexing
  above QUIC;
- RFC 6455 upgrade validation and generation, accept-proof verification, frame
  parsing and serialization, client-side masking, fragmentation, control-frame
  handling, and `WsFrame` stream adaptation, in both client and server roles;
- gRPC-over-HTTP/2 transport composition — `application/grpc` content typing,
  `te: trailers`, and `grpc-status` trailer handling;
- RTP header parsing, serialization, sequence and timestamp tracking,
  packetization, depacketization, and bounded session state;
- RFC 3261 subset dialog transaction mechanics and receive-side jitter recovery;
- RFC 5321 submission-client mechanics;
- S3 object-request mechanics — SigV4 canonical-form construction, the signing
  key chain, and the request/response records that carry one operation;
- protocol feature/variant declarations and target constraints;
- the shared I/O-free codec cores in `modules/common`, `include!`d verbatim so
  host and device compile identical bytes;
- protocol conformance vectors, malformed-input tests, and interoperability
  harnesses; and
- signed `.fmod` packaging and OCI publication for Wave modules.

Wave does not own:

- the Fluxor ABI, graph, scheduler, channels, content-type registry, timers,
  capability resolver, target descriptors, or provider contracts;
- Ethernet, IP, ICMP, TCP, UDP, DNS, or socket and endpoint allocation;
- TLS, DTLS, certificate validation, Kagi identity, or cryptographic key
  custody;
- QUIC transport, congestion control, recovery, packet protection, streams, or
  endpoint lifecycle;
- browser or native WebSocket host APIs and platform network shims;
- HTTP application resources, tenant routing policy, authorization, CDN policy,
  webhook meaning, or business handlers;
- Grove media-session semantics or Spectra codecs; or
- Quantum topic and session semantics, or durable message delivery.

## Fluxor contract

Fluxor is authoritative for `NetProto`, `WsFrame`, `OctetStream`, `AudioEncoded`,
telemetry surfaces, rate classes, and every on-wire content-type identifier. Wave
consumes those names and their public SDK layouts without assigning replacements.

Wave modules are ordinary position-independent Fluxor modules: bounded channels,
explicit backpressure, target capability matching, declared timers, normal graph
activation. They must not add a second socket, scheduler, module, or provider
ABI.

`http` and `rtp` reach transports through `NetProto` and never call a host socket
API. WebSocket protocol logic consumes an HTTP upgrade and exposes `WsFrame`;
`ws_stream` adapts between `WsFrame` and application `OctetStream`.

## Modules

Roles are not uniform. `http` is server and client; `websocket`, `smtp` and `s3`
are clients only; `ws_stream` is an adapter; `rtp` and `sip` are peer user
agents. Nothing in this document promises a server for every protocol that has a
client, or the reverse.

### `http`

A combined client and server carrying HTTP/1.1, HTTP/2 and HTTP/3, the WebSocket
upgrade, routing, file and provider bindings, connection limits, and the gRPC
client path. Three variants — `web` (h1 + ws), `h2`, and `full` (adds h3) — let a
target take only the generations it serves.

gRPC is a composition, not a module: the `grpc` parameter sets
`content-type: application/grpc` and `te: trailers` on the HTTP/2 client and
surfaces the `grpc-status` trailer. Service definitions, method dispatch,
protobuf schemas and reflection are application concerns.

### `websocket`

An RFC 6455 HTTP/1.1 client — upgrade request, verified accept proof, masked
frames. Fluxor ships the server-side `ws_stream` path and a WS-over-HTTP/2 client
(RFC 8441) but no HTTP/1.1 WebSocket client, so this closes a substrate
reachability gap. `Ready` is reachable only through a cryptographically verified
`Sec-WebSocket-Accept`.

Permessage-deflate, subprotocol negotiation, reconnect policy, and
multi-connection session routing are not implemented.

### `ws_stream`

The `WsFrame` ⇄ `OctetStream` adapter: framing envelope, single-active-connection
policy, retry buffers, telemetry, and lossless steady-state backpressure.

### `rtp`

A combined transmitter and receiver: RFC 3550 packet handling, PCMU/G.711 input,
UDP `NetProto` binding, and endpoint controls. It declares rp2350 and bcm2712, so
the media path builds for the same targets as `sip`, which drives it. Broader
payload formats, RTCP, SRTP, and multi-party session policy are not implemented.

Transmit and receive bounds are deliberately different numbers. Wave transmits at
most 40 ms per packet, a policy choice; it accepts up to one Ethernet MTU,
because packet duration is the sender's choice and RFC 3551 sets no ceiling on
it. A packet too large to accept is refused and counted, never delivered as the
fraction that happened to fit. Both directions are verified against ffmpeg rather
than against Wave's own reading of the RFC.

### `sip`

An RFC 3261 subset UAC/UAS for a two-party PCMU call: INVITE/ACK/BYE/200-OK, a
bounded transaction FSM, and receive-side reorder with loss-concealing playout.
It owns protocol facts only — call policy is Conclave's, the G.711 codec is
Spectra's, and transmission is the separate `rtp` module, driven over a control
port. `wall_clock` timer class, because the T1 retransmit timer and the `ptime`
playout cadence both read real time; playout must, or a relaxed scheduler tick
would stretch the audio.

Registration, authentication, TLS/SIPS, re-INVITE, transfer, hold, forking,
multi-party mixing, RTCP and SRTP are not implemented.

### `smtp`

An RFC 5321 mail submission client: the lockstep ESMTP conversation from the
server's 220 greeting through a dot-stuffed DATA body to QUIT, with delivery
reported on a status port only when end-of-data (250) *and* QUIT (221) are both
accepted. `wall_clock` timer class for the connect and reply deadlines. Message
meaning belongs to Conclave; Wave owns the wire mechanics.

Scope is unauthenticated submission — no STARTTLS, no AUTH, no pipelining, one
recipient per instance — which suits a trusted relay or sink behind a security
boundary and does not suit a public MX. As everywhere in Wave, TLS is a Fluxor
module wired in front.

### `s3`

A SigV4-signed client for S3-compatible object endpoints: GET, PUT, HEAD and
DELETE on `/bucket/key`, each signed with the payload hashed in. It earns a
compiled module for a reason none of the others share — not round-trip count,
which is one, but crypto: the `Authorization` header is an HMAC chain over a
canonical form of the request, and a bytecode codec cannot compute it. SHA-256
is SDK-owned, as `websocket`'s SHA-1 is.

Two modes, chosen by whether `request_in` is wired: driven, one operation per
`S3Request` record answered with an `S3Response`; and probe, which signs a
ListBuckets on boot and reports the status, as the cheapest proof that
credentials work against a real endpoint. Which bucket backs which namespace,
and what a key denotes, are the consumer's — Wave owns the wire mechanics and
the signature.

## HTTP/3 status

Every module must declare where a listed surface is not yet a working path, since
a reader is otherwise entitled to assume everything under "Wave owns" is
delivered. HTTP/3 is the one surface with such a gap.

**HTTP/3 is served end to end**, by Wave's `http` over Fluxor's `quic`.
`tools/e2e/h3_server.sh` boots `examples/linux/wave_h3.yaml` and drives it with
**aioquic**, an independent implementation: configured routes serve their own
bodies, an unmatched path gets a Wave-rendered 404, connections are served
repeatedly, and two requests multiplexed on one connection are both answered.

The boundary is the one drawn above — Wave owns HTTP/3 request/response semantics
and QPACK, Fluxor owns QUIC transport, streams and packet protection — and the
seam is Fluxor's `mux` contract, which names QUIC as its canonical provider.
An h3 ALPN is the whole configuration: `quic` surfaces the request streams and
`http` consumes them with `h3 = 1`. No new content type, no new ports, no ABI
change. `quic` no longer carries an HTTP/3 implementation of its own, so QPACK
exists once in the stack rather than twice. See [`architecture/http3-ownership.md`](architecture/http3-ownership.md).

Implemented and tested: the RFC 9114 frame layer; QPACK including Huffman-coded
names and values; the request header decoder with the §4.3 message rules; RFC
9220 extended CONNECT recognition; the response encoder and framing; dispatch
against the real route table; and a stream-multiplexed pump with per-stream
buffers, round-robin emission and bounded refusal when the slot table is full.

Served over h3: static and template routes, and WebSocket tunnels via RFC 9220
extended CONNECT — answered with a bare 200, since `Sec-WebSocket-Accept` is an
HTTP/1 header, with RFC 6455 frames riding h3 DATA frames through the unchanged,
transport-agnostic `wire::ws`. Templates use the same renderer h1 and h2 do, with
the route and body cursor lifted into parameters so each generation supplies its
own — a connection slot for h1 and h2, a stream slot for h3.

**Not shared with h3**: file and proxy routes, which thread more than a cursor
through `server::cur_slot_mut` — file handles, relay connection state. Dispatch
reports `HandlerNotShared(id)` for those rather than serving one concurrent
request correctly and the rest wrongly.

**Client and server both.** Wave's h3 client rides the same `mux` contract the
server does, so the transport stays protocol-free in both directions.

The duplicate HTTP/3 in Fluxor's `quic` is therefore now scheduled for removal
rather than kept: the boundary is *all HTTP logic here, QUIC below*, and the two
arguments that previously held the copy in place have both lapsed — the client
one because Wave has a client, and the self-test one because proving a transport
is a job for a `mux`-level fixture rather than for a second HTTP server. The
sequencing constraint is that the replacement self-test lands FIRST: Fluxor must
stay able to prove its own transport using only Fluxor, and the dependency
direction forbids reaching through Wave to do it.

## Transport and security boundary

HTTP/1 and HTTP/2 run over a Fluxor TCP or TLS provider. HTTP/3 runs over the
Fluxor QUIC provider. RTP runs over a Fluxor UDP provider; secure RTP requires an
explicit future capability and must never be implied by an RTP binding.

Wave parses authenticated transport output but does not decide peer identity or
authorization. Applications receive verified identity and route policy through
separate explicit inputs. A protocol path must never infer trust from connection
presence.

## Correctness and bounds

Every module declares:

- supported RFC versions, extensions, roles, and deviations;
- maximum connections, streams, headers, frames, bodies, payloads, and working
  memory;
- timer class and timeout semantics;
- incremental parsing, fragmentation, reset, close, and half-close behaviour;
- flow-control and backpressure behaviour;
- malformed-input, peer-failure, and resource-exhaustion errors; and
- interoperability peers, fixtures, fuzz targets, and target builds.

Malformed or adversarial input must produce a bounded protocol error. It must
never panic, overrun, allocate without a declared ceiling, cross a connection or
session boundary, or silently discard authoritative application data. Wave runs
bare-metal with no allocator and no unwinding: a panic is not a caught exception,
it is the device.

## Consumers

- Nanocloud uses the HTTP and WebSocket modules for bounded API and streaming
  paths while retaining API and resource semantics.
- Quantum may expose broker and session protocols through Wave transports while
  retaining messaging authority.
- Truffle, Grove and Zedex may use HTTP, WebSocket or RTP capabilities without
  owning their wire implementations.

Consumers depend on public Fluxor transport and content contracts, and on
immutable Wave module identity — never on Wave-private connection state.
