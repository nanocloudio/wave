# Wave specification

## Definition

Wave is the Fluxor-native home for portable application-protocol capabilities —
HTTP, WebSocket, gRPC, RTP, SIP and SMTP — in both client and server roles. It
exists so applications consume bounded protocol modules without Fluxor becoming
the owner of application or session protocol semantics.

Wave is not a network stack, proxy product, API gateway, message broker, media
session product, identity provider, or service mesh.

## Ownership

Wave owns:

- HTTP/1.1 message parsing, serialization, routing mechanics, connection state,
  client and server behaviour, and bounded body handling;
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

Roles are not uniform. `http` is server and client; `websocket` and `smtp` are
clients only; `ws_stream` is an adapter; `rtp` and `sip` are peer user agents.
Nothing in this document promises a server for every protocol that has a client,
or the reverse.

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
`quic` gained one parameter (`h3_app`) to let an h3 connection use it; `http`
gained one (`h3`) to consume it. No new content type, no new ports, no ABI
change. See [`architecture/http3-ownership.md`](architecture/http3-ownership.md).

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

**Deliberately duplicated**: Fluxor's `quic` keeps its own `h3.rs`, `qpack.rs` and
`ws.rs`. That is not a copy awaiting deletion — it carries an h3 *client*, which
Wave does not have, and it is how Fluxor self-tests its transport without
depending on Wave. Wave's h3 is the server applications use; `quic`'s is a
transport self-test and a client. The RFC 7541 Huffman table is the part worth
sharing, and it has to travel through the Fluxor SDK to point the right way down
the dependency graph.

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
