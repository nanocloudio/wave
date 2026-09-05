# Wave specification

## Definition

Wave is the fluxor-native home for reusable, bounded application-wire
mechanics above fluxor transports. It began with HTTP-based
protocols, but its boundary is the mechanism rather than HTTP
ancestry:

- message parsing and serialisation;
- framing and header compression;
- bounded connection, stream and transaction state machines;
- protocol-defined acknowledgement, retry, close and error
  behaviour;
- wire-level authentication and canonicalisation mechanics using
  fluxor-owned cryptographic operations; and
- portable conformance-tested adapters between a transport surface
  and an application/domain record surface.

It exists so applications consume bounded protocol modules without
fluxor becoming the owner of application or session protocol
semantics.

Wave is not an unrestricted protocol collection. It does not own the
meaning of a request, conversation, message, call, media session,
route, identity, topic, database operation or network-reachability
decision. It is not a network stack, proxy product, API gateway,
message broker, media session product, identity provider, or service
mesh.

## Protocol families

Wave's capabilities group into four families. These are catalogue and
ownership families, not source directories or separately versioned
packages: every fmod remains independently built, admitted, packaged
and loaded, and a target pays only for the modules its graph selects.

| Family | Mechanics |
| --- | --- |
| Web | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC transport composition, the ordered-ack exchange provider role, and the S3 HTTP/SigV4 profile |
| Mail | SMTP submission, RFC 5322 parsing, MIME structure and bounded inbound mail records |
| Realtime | SIP signalling, RTP media and the RTCP control plane, SRTP/SRTCP framing and replay mechanics, SFrame framing, and WebRTC session-description facts |
| Traversal | STUN Binding in both roles, TURN wire, and bounded transaction mechanics |

Each capability is stated at one of five maturity levels, and the
catalogue below names the level rather than letting a lower one read
as a higher:

1. an I/O-free codec core;
2. a bounded transaction/state-machine core;
3. a deployable fmod;
4. a complete client, server or peer role; and
5. an end-to-end composition with independent-peer and target
   evidence.

A core mounted for tests is not a deployable protocol role. Framing
is not encryption, a TURN codec is not a relay, and WebRTC SDP
attributes are not a WebRTC implementation.

## Admission and rejection

A future protocol belongs in Wave only when every rule below holds:

1. It operates above a fluxor transport or generic stream/datagram
   surface.
2. Its mechanics can exist without owning application policy,
   product meaning or durable domain state.
3. It contains reusable bounded parsing, serialisation, framing or
   transaction behaviour rather than only application-specific
   request handling.
4. It serves more than one application, connector profile or
   independently useful composition.
5. No sibling already owns state that is inseparable from its wire
   behaviour.
6. It can be tested against normative vectors and, where an
   implementation exists, an independent peer.
7. Its maximum memory, records, connections, streams, transactions,
   work per step, timer behaviour, backpressure and failure outcomes
   can be declared honestly for every target it names.
8. It can consume current fluxor SDK contracts without creating a
   private transport, security, scheduler or content-type surface.

Admission is an architectural decision recorded in context history
before a new public module identity is introduced. Reuse of a small
codec by only one module is not by itself a reason to create another
module or repository.

The following are insufficient reasons to place work in Wave: the
mechanism is described by an RFC; it travels over HTTP; it has a
network-shaped name; its current consumer already depends on Wave; or
its policy engine happens to drive a Wave codec. Application
conventions over HTTP remain application compositions unless they
contain independently reusable bounded wire mechanics. This
explicitly keeps REST, GraphQL, webhooks, OCI registry lifecycle,
PromQL and identity-provider behaviour in their application or
Chronicle compositions; TCP, UDP, DNS, TLS, DTLS, QUIC, crypto
operations and opaque key handles in fluxor; MQTT, AMQP and Kafka in
Quantum; database protocols and their operation adapters in Lattice;
codec algorithms in Spectra; and reachability, conversation and
media-topology policy with the owners in the table below.

## Ecosystem ownership

| Project | Responsibility |
| --- | --- |
| Fluxor | ABI, scheduling, channels, content contracts, TCP/UDP, endpoint allocation, DNS, TLS, DTLS, QUIC, cryptographic operations and opaque key handles |
| Wave | Reusable wire encoding, decoding, framing, protocol facts and bounded application-protocol transaction mechanics |
| Wormhole | Candidate gathering policy, ICE pair formation, check scheduling and nomination, relay selection, allocation policy and relay operation |
| Conclave | Conversation identity, participants, call/message intent, connector policy and authorisation |
| Grove | Media topology, clocks, routing, advanced jitter/adaptation, mixing and distributed media-session execution |
| Spectra | Audio, image and video codec algorithms and media-container mechanics |
| Quantum | MQTT, AMQP and Kafka broker/session protocols, topics, queues, retained/offline state, routing and durability |
| Lattice | Database and key/value protocol adapters coupled to database operations and consistency semantics |

Where a composition crosses this table, the seam is an explicit
fluxor content contract or a documented bounded record carried over
an existing surface. A shared concept is not permission for private
cross-repository state. Conclave's WebRTC profile records the same
assignments from its side; the masterplan places SDP in Wave and ICE
policy in Wormhole for the same reason integrity computation is here
and "whether to send" is not.

## Ownership

Wave owns:

- HTTP/1.1 message parsing, serialisation, routing mechanics,
  connection state, client and server behaviour, and bounded body
  handling — including the shared method vocabulary both generations
  resolve against, request-body framing (`Content-Length`, chunked
  transfer coding, `Expect: 100-continue`) and the refusal of a
  message that carries contradictory framing headers;
- the HTTP application fan-out contract — the `HttpRequest` /
  `HttpResponse` envelopes, their `(conn_id, stream_id)` correlation,
  and the backpressure and streaming rules that carry them — which is
  how a graph node outside Wave holds the resources and business
  handlers listed below as not Wave's;
- HTTP/2 framing, stream state, flow control, and HPACK;
- HTTP/3 request/response semantics, QPACK, and request-stream
  multiplexing above QUIC;
- RFC 6455 upgrade validation and generation, accept-proof
  verification, frame parsing and serialisation, client-side masking,
  fragmentation, control-frame handling, and `WsFrame` stream
  adaptation, in both client and server roles;
- gRPC-over-HTTP/2 transport composition — `application/grpc`
  content typing, `te: trailers`, and `grpc-status` trailer handling;
- RTP header parsing, serialisation, sequence and timestamp tracking,
  packetisation, depacketisation, and bounded session state;
- RFC 3261 subset dialog transaction mechanics and receive-side
  jitter recovery;
- RFC 5321 submission-client mechanics;
- S3 object-request mechanics — SigV4 canonical-form construction,
  the signing key chain, and the request/response records that carry
  one operation;
- protocol feature/variant declarations and target constraints;
- the shared I/O-free codec cores in `modules/common`, `include!`d
  verbatim so every consumer compiles identical bytes; and
- signed `.fmod` packaging and OCI publication for Wave modules.

Wave does not own:

- the fluxor ABI, graph, scheduler, channels, content-type registry,
  timers, capability resolver, target descriptors, or provider
  contracts;
- Ethernet, IP, ICMP, TCP, UDP, DNS, or socket and endpoint
  allocation;
- TLS, DTLS, certificate validation, Kagi identity, or cryptographic
  key custody;
- QUIC transport, congestion control, recovery, packet protection,
  streams, or endpoint lifecycle;
- browser or native WebSocket host APIs and platform network shims;
- HTTP application resources, tenant routing policy, authorisation,
  CDN policy, webhook meaning, or business handlers;
- Grove media-session semantics or Spectra codecs; or
- Quantum topic and session semantics, or durable message delivery.

## Fluxor contract

Fluxor is authoritative for `NetProto`, `WsFrame`, `OctetStream`,
`AudioEncoded`, telemetry surfaces, rate classes, and every on-wire
content-type identifier. Wave consumes those names and their public
SDK layouts without assigning replacements.

Wave modules are ordinary position-independent fluxor modules:
bounded channels, explicit backpressure, target capability matching,
declared timers, normal graph activation. They must not add a second
socket, scheduler, module, or provider ABI.

`http`, `rtp` and `s3` reach transports through `NetProto` and never
call a host socket API. WebSocket protocol logic consumes an HTTP
upgrade and exposes `WsFrame`; `ws_stream` adapts between `WsFrame`
and application `OctetStream`.

## Modules

Roles are not uniform. `http` is server and client; `websocket`,
`smtp` and `s3` are clients only; `ws_stream`, `mail` and `jitter`
are adapters; `rtp` and `sip` are peer user agents; `stun` is a
Binding server. Nothing in this document promises a server for every
protocol that has a client, or the reverse.

### `http`

A combined client and server carrying HTTP/1.1, HTTP/2 and HTTP/3,
the WebSocket upgrade, routing, file and provider bindings,
connection limits, and the gRPC client path. Five variants — `web`
(h1 + ws), `app` (h1 + the application fan-out), `h2` (adds HTTP/2),
`full` (the default, adds HTTP/3) and `exchange` (adds the
graph-driven client) — let a target take only what it serves.
Source: `modules/foundation/http/manifest.toml`.

When a `tls` module in front supplies verified peer identities, a
request forwarded to an application carries the peer's key
fingerprint as a typed trailer. Wave owns the join — matching an
identity to the connection it belongs to, and releasing it when that
connection ends — and nothing else: whether a given peer may perform
a given request is the application's decision, and the checks behind
the identity are the TLS module's. An identity binds only for a
handshake that succeeded, whose chain validated, and whose peer
proved possession of the key; a certificate that was merely presented
is a different fact from a peer that was authenticated.

gRPC is a composition, not a module: the `grpc` parameter sets
`content-type: application/grpc` and `te: trailers` on the HTTP/2
client and surfaces the `grpc-status` trailer. Service definitions,
method dispatch, protobuf schemas and reflection are application
concerns.

The `exchange` variant carries the graph-driven client: requests
arrive as records at run time instead of being fixed by params, which
makes `http` a provider of fluxor's `stream.ordered_ack.exchange`
surface — the role a producer binds to reach a destination that
ANSWERS, as opposed to a sink that only accepts. A request record is
`[method:u8][path_len:u16][body_len:u16][path…][body…]` on
`publish_in`; the response body returns on `reply_out`, correlated by
`corr` and echoing the publish's `msg_key` so a downstream stage
rejoins it without holding state.

What Wave owns here is only the mapping between that surface and an
HTTP request: the verb vocabulary, the head, and which reply status a
failure earns. The surface itself, its frames and its correlation
rules are fluxor's, and what a payload MEANS stays with the producer.

The declared terms are `ack = "transport"` (a 2xx is the origin
accepting the request, not a durability claim HTTP has no way to
make), `ordering = "single"` (one connection per exchange and one
request in flight, so there is never a second record to reorder
against), `broadcast = "unsupported"` (refused rather than ignored —
this client dials one origin, and acking a fan-out that reached one
destination would report a delivery that did not happen) and
`max_payload = 8192`. Credentials, retry policy and the meaning of a
refusal belong to the producer.

What an upstream failure looks like is a deployment choice. By default
a response is a completed exchange whatever its status, and an error
body is the answer — which is what a consumer reading a problem
document wants. A graph may instead ask for a status of 400 or above
to answer as a typed refusal carrying the code, so a producer can
retry a 503 and discard a 404 without parsing a payload whose shape it
does not know. Wave classifies; what to do about a class stays with
the producer.

`capabilities` is declared per module rather than per variant, so the
manifest states this surface for artefacts that do not compile it.
That is a property of the variant split — the `app` fan-out ports have
it too — and it means a deployment wiring `publish_in`/`reply_out`
must ship `http-exchange.fmod`.

### `websocket`

An RFC 6455 HTTP/1.1 client — upgrade request, verified accept
proof, masked frames. The ecosystem's server-side WebSocket path is
`http` plus `ws_stream`, and a WS-over-HTTP/2 client (RFC 8441)
lives in fluxor, so this module closes the remaining reachability
gap: dialling an HTTP/1.1 WebSocket. `Ready` is reachable only
through a cryptographically verified `Sec-WebSocket-Accept`.

Permessage-deflate, subprotocol negotiation, reconnect policy, and
multi-connection session routing are not implemented.

### `ws_stream`

The `WsFrame` ⇄ `OctetStream` adapter: framing envelope,
single-active-connection policy, retry buffers, telemetry, and
lossless steady-state backpressure.

### `rtp`

The media endpoint: RFC 3550 packet handling both ways on one
symmetric port — G.711 in, packets out; datagrams in, validated
`[seq][payload]` records out for the `jitter` adapter. It declares
rp2350 and bcm2712, so the media path builds for the same targets as
`sip`, which drives it over control records. Broader payload
formats, RTCP, SRTP, and multi-party session policy are not
implemented.

Transmit and receive bounds are deliberately different numbers. Wave
transmits at most 40 ms per packet, a policy choice; it accepts up
to one Ethernet MTU, because packet duration is the sender's choice
and RFC 3551 sets no ceiling on it. A packet too large to accept is
refused and counted, never delivered as the fraction that happened
to fit.

### `rtcp`

The control plane RTP does not have. RTP carries media and says
nothing about how it arrived; RTCP is the only channel on which a
receiver tells a sender what it actually got — loss, jitter, round
trip — and the only one on which a sender publishes the mapping
between its RTP timestamp and real time. A media path without it
cannot adapt and cannot synchronise, and neither failure is visible
from the media itself.

A module rather than a role inside `rtp`, on grounds recorded before
the identity was introduced: RTCP has its own endpoint, its own
wall-clock deadline where `rtp` attests `agnostic`, and a cost the
smallest artefact in the tree should not carry unasked. This is the
split `jitter` already uses.

Statistics reach it over `rtp`'s appended `rtcp_stats` output as two
tagged records: one per accepted packet, and the transmit counters
after each packet sent. Which arrive decides which report goes out.
Neither carries a wall-clock time, because `rtp` reads no clock;
`rtcp` stamps time from its own, which is exact for the reception
record and an approximation of simultaneity for the transmit one.
The module README works through why.

It decides nothing: rate adaptation, teardown on a BYE and quality
policy read these numbers and act. Not implemented: SDES items beyond
CNAME, RFC 4585 feedback, and the full §6.3 membership and
reconsideration algorithm; the interval assumes the two-party session
`rtp` and `sip` compose.

### `sip`

An RFC 3261 subset UAC/UAS for a two-party PCMU call, signalling
only: INVITE/ACK/BYE/200-OK, a bounded transaction FSM, and SDP
negotiation facts. It owns protocol facts and no media path — call
policy is Conclave's, the G.711 codec is Spectra's, and the media
endpoint and reorder/playout are the separate `rtp` and `jitter`
modules, driven over shared control records. `wall_clock` timer
class for the T1 retransmit timer.

### `jitter`

The realtime family's reorder/playout adapter: validated
`[seq][payload]` records from `rtp` in, loss-concealed µ-law playout
out at `ptime` cadence, obeying the same START/STOP records `sip`
drives the transmitter with. The ring is the host-vectored
`jitter_core`; `wall_clock` timer class, because playout must track
real time or a relaxed scheduler tick would stretch the audio.
Adaptive playout, clock recovery and topology-aware buffering are
Grove's, not Wave's.

Registration, authentication, TLS/SIPS, re-INVITE, transfer, hold,
forking, multi-party mixing, RTCP and SRTP are not implemented.

### `smtp`

An RFC 5321 mail submission client: the lockstep ESMTP conversation
from the server's 220 greeting, through an optional SASL PLAIN
authentication step, then a dot-stuffed DATA body to
QUIT, with delivery reported on a status port only when end-of-data
(250) and QUIT (221) are both accepted. `wall_clock` timer class for
the connect and reply deadlines. Message meaning belongs to
Conclave; Wave owns the wire mechanics.

Submission may be authenticated: `AUTH PLAIN` (RFC 4616) only, and
only on a channel the graph has declared confidential, since the
module cannot see whether `tls` sits in front of it. Neither an
undeclared channel nor a server offering no mechanism falls back to
an unauthenticated submission; both fail, because a message meant to
carry credentials that did not is one nobody can attribute.

Scope otherwise is narrow — no STARTTLS, no pipelining, one recipient
per instance. Unauthenticated and untrusted, that suits a relay or
sink behind a security boundary and does not suit a public MX. As
everywhere in Wave, TLS is a fluxor module wired in front.

### `mail`

An RFC 5322 inbound message parser: spans of a message in, one
bounded facts record and a streamed body out, correlated by a
caller-chosen id. The format mechanics live in the host-tested
`rfc5322` and `mime` cores; the module is the pump around them,
holding only the header block until it is complete and forwarding
the body as it arrives. `timer_class = "agnostic"` — no clock is
read.

The facts state the addresses that parsed, the subject and date as
written, and the `Message-ID` / `In-Reply-To` / `References`
identifiers verbatim, as evidence only. Which conversation a message
belongs to, whether an attachment is retained, and what an address
means are Conclave's; a parser that picked a thread would be deciding
conversation membership from a header the sender chose. `mail` owns
no network endpoint — ingress is whatever the graph wires in front.

### `stun`

STUN Binding in both roles over one datagram endpoint.

The **responder** tells a peer the address its packets arrived from —
the one fact a peer behind a NAT cannot learn any other way, and the
first thing an ICE agent gathers. The **client** asks that question of
a server and reports the answer as
`[status:u8][ip:4 BE][port:u16 LE][code:u16 LE]` on `result_out`.
Setting `server_ip` arms the client; leaving it zero is the
responder-only module.

One module rather than two because it is one protocol over one
socket: a Binding request and its response differ by two bits of the
message type, and separating them would duplicate the parse, the
FINGERPRINT check and the endpoint pump to no end.

The client retransmits on the RFC 5389 §7.2.1 schedule — seven
transmissions, 500 ms doubling, 39.5 s total — because over UDP an
unanswered request is indistinguishable from an undelivered one. A
response is accepted only when its source address AND its transaction
id both match: being told your own address by a stranger is the one
thing this exchange must not allow, since a reflexive address becomes
an ICE candidate and a forged one points a media path wherever the
forger likes. Every transaction produces exactly one result, timeouts
included — a client that reported nothing would leave whatever wired
it waiting forever.

It is not an ICE agent and not a TURN relay: it gathers no
candidates, forms no pairs, schedules no connectivity checks and
nominates nothing. Those are reachability decisions, and reachability
policy belongs to Wormhole. It asks a question and answers one; it
does not decide what to do with either.

### `s3`

A SigV4-signed client for S3-compatible object endpoints: GET, PUT,
HEAD and DELETE on `/bucket/key`, each signed with the payload
hashed in. It earns a compiled module for a reason none of the
others share — not round-trip count, which is one, but crypto: the
`Authorization` header is an HMAC chain over a canonical form of the
request, and a bytecode codec cannot compute it. SHA-256 is
SDK-owned, as `websocket`'s SHA-1 is.

Two modes, chosen by whether `request_in` is wired: driven, one
operation per `S3Request` record answered with an `S3Response`; and
probe, which signs a ListBuckets on boot and reports the status, as
the cheapest proof that credentials work against a real endpoint.
Which bucket backs which namespace, and what a key denotes, are the
consumer's — Wave owns the wire mechanics and the signature.

## Family catalogue and maturity

Every module and core has one family and one maturity level. The
modules above are all deployable fmods (level 3) or better; the
cores in `modules/common/` are level 1 or 2 and are stated as such —
none of them is a protocol role, however complete its vectors.

| Capability | Family | Maturity |
| --- | --- | --- |
| `http` (h1/h2/h3, WS upgrade, gRPC client path) | Web | End-to-end composition: independent-peer interop and Pi 5 load evidence for h1/TLS and h3 |
| `http` as `stream.ordered_ack.exchange` provider (`exchange` variant) | Web | Complete provider role, end-to-end from an independent consumer: chronicle's `../chronicle/tools/e2e/http-exchange.sh` drives a request through it and asserts the reply is correlated and the `msg_key` echoed |
| `websocket` | Web | Complete client role; server-path interop against Python `websockets`, an independent RFC 6455 peer |
| `ws_stream` | Web | Deployable adapter fmod |
| `s3` | Web | Complete client role; SigV4 host-tested, with probe mode as the live-endpoint credential check — no recorded independent-endpoint run is claimed here |
| gRPC | Web | Composition of the HTTP/2 client, not a module |
| `smtp` | Mail | Complete submission-client role with independent-peer evidence (Exim) |
| `mail` | Mail | Deployable adapter fmod over the `rfc5322`/`mime` cores |
| `rfc5322`, `mime`, `smtp_core`/`smtp_wire`, `mail_wire` | Mail | I/O-free codec and transaction cores |
| `sip` | Realtime | Peer-UA role: end-to-end composition — Linux L4 and the Pi 5 rig scenario both pass (2026-08-26) |
| `rtp` | Realtime | The symmetric media endpoint, transmit and receive; end-to-end with `sip` on the Pi 5 rig |
| `rtcp` | Realtime | Deployable fmod, both report directions: RFC 3550 §6 compound framing, SR and RR with SDES, the §A.3/§A.8 receiver statistics, the §6.2 interval, and the round trip closed against a peer's echo of our own Sender Report |
| `rtcp_core` | Realtime | I/O-free codec and arithmetic core: compound framing, SR/RR/SDES/BYE, report blocks, the receiver statistics and the interval, pinned to the RFC's own formulas |
| `jitter` | Realtime | Deployable adapter fmod over `jitter_core` |
| `jitter_core` | Realtime | Bounded reorder/playout core, mounted by `jitter` |
| `sframe_core` | Realtime | I/O-free framing core, RFC 9605 header layout pinned to all 289 published vectors. Framing only: no composition yet encrypts, authenticates, handles replay or rotates keys, so this is not SFrame end-to-end encryption |
| `webrtc_sdp` | Realtime | I/O-free codec core for the SDP attributes that make a description a WebRTC one — bounded session-description facts, not a WebRTC stack |
| `sip_core`, `sip_dialog`, `sip_wire`, `rtp_core` | Realtime | Codec and transaction cores mounted by `sip`/`rtp` |
| `stun` | Traversal | Deployable fmod, BOTH Binding roles: the responder is RFC 5769-pinned, and the client is a complete role — RFC 5389 §7.2.1 retransmission, source- and transaction-matched responses, one result per transaction |
| `stun_txn` | Traversal | Bounded transaction core: the §7.2.1 schedule and the response-matching rule, mounted by `stun` |
| `stun_core` | Traversal | I/O-free codec core shared by `stun` and `turn_core` |
| `turn_core` | Traversal | I/O-free codec core: TURN methods, relay attributes, long-term credential key and ChannelData framing, tested directly against its own vectors. There is no TURN module, client, server or relay; a TURN module identity would need a concrete bounded transaction role and an admission decision first |

RTCP is implemented as the `rtcp` module above, in both report
directions. A participant that has received media reports what it
got; one that has transmitted sends a Sender Report carrying the
NTP/RTP pair and its packet and octet counts; one that has done both
sends a Sender Report with reception blocks in it. A peer's reports
about this participant are decoded back out, and the round trip
closes against the peer's echo of an NTP timestamp we published.

The NTP field is a LOCAL timebase unless a graph supplies
`ntp_epoch_offset_s`. That is exact for round-trip calculation, which
subtracts only values the same participant issued, and NOT sufficient
for synchronising two sources against each other, which needs a
shared epoch.

SRTP and SRTCP appear in the Realtime family as planned mechanics;
nothing in this checkout implements them, and no capability above may
be cited as if it did. `rtcp` sends and receives in the clear.

## HTTP/3

HTTP/3 is served end to end by Wave's `http` over fluxor's `quic`.
The boundary is the one drawn above — Wave owns HTTP/3
request/response semantics and QPACK, fluxor owns QUIC transport,
streams and packet protection — and the seam is fluxor's `mux`
stream-record contract, which names QUIC as its canonical provider.
An h3 ALPN is the whole configuration: `quic` surfaces the request
streams and `http` consumes them with `h3 = 1`. No new content type,
no new ports, no ABI change, and QPACK exists once in the stack.
[architecture/http3-ownership.md](architecture/http3-ownership.md)
describes the seam in full.

Served over h3, client and server both: static and template routes,
the application fan-out, and WebSocket tunnels via RFC 9220 extended
CONNECT — answered with a bare 200, since `Sec-WebSocket-Accept` is
an HTTP/1 header, with RFC 6455 frames riding h3 DATA frames through
the same transport-agnostic frame codec h1 and h2 use.

Not shared with h3: file and proxy routes, which hold per-connection
state (file handles, relay connections) that the stream-multiplexed
pump cannot yet carry per stream. Dispatch answers those with a 501
naming the situation rather than serving one concurrent request
correctly and the rest wrongly.

Deployment limits, all failing closed: eight concurrent sessions
(matching the QUIC engine's connection table — a ninth connection
receives a stateless CONNECTION_REFUSED from the transport, and a
session the table cannot hold is closed with H3_REQUEST_REJECTED,
never left unanswered), sixteen concurrent request streams, and a
2 KiB per-stream response buffer. A response that does not fit is
refused whole with a tested refusal rather than truncated;
incremental DATA framing for larger bodies is deliberately deferred
until load evidence establishes its shape.

## Transport and security boundary

HTTP/1 and HTTP/2 run over a fluxor TCP or TLS provider. HTTP/3 runs
over the fluxor QUIC provider. RTP runs over a fluxor UDP provider;
secure RTP requires an explicit future capability and must never be
implied by an RTP binding.

Wave parses authenticated transport output but does not decide peer
identity or authorisation. Applications receive verified identity
and route policy through separate explicit inputs. A protocol path
must never infer trust from connection presence.

## Correctness and bounds

Every module declares:

- supported RFC versions, extensions, roles, and deviations;
- maximum connections, streams, headers, frames, bodies, payloads,
  and working memory;
- timer class and timeout semantics;
- incremental parsing, fragmentation, reset, close, and half-close
  behaviour;
- flow-control and backpressure behaviour; and
- malformed-input, peer-failure, and resource-exhaustion errors.

Malformed or adversarial input must produce a bounded protocol
error. It must never panic, overrun, allocate without a declared
ceiling, cross a connection or session boundary, or silently discard
authoritative application data. Wave runs bare-metal with no
allocator and no unwinding: a panic is not a caught exception, it is
the device.

Conformance is established against the RFC's own vectors, and against
an independent implementation wherever one exists. Grading Wave
against Wave's reading of a specification proves only that the
reading is self-consistent, which is the failure mode a wire protocol
is most prone to: both ends of a test agreeing on the same
misinterpretation.

## Consumers

- Nanocloud uses the HTTP and WebSocket modules for bounded API and
  streaming paths while retaining API and resource semantics.
- Quantum may expose broker and session protocols through Wave
  transports while retaining messaging authority.
- Truffle, Grove and Zedex may use HTTP, WebSocket or RTP
  capabilities without owning their wire implementations.

Consumers depend on public fluxor transport and content contracts,
and on immutable Wave module identity — never on Wave-private
connection state.
