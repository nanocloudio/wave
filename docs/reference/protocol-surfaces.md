# Protocol surface boundary

Fluxor owns these canonical transport and content surfaces. Wave
consumes them without assigning replacement identifiers. The
"declared by" column lists the Wave modules whose manifests carry the
surface as a port content type.

| Surface | Meaning | Declared by |
| --- | --- | --- |
| `NetProto` | Network endpoint and framed transport commands/events | `http` (`net_in`/`net_out`), `rtp`, `websocket`, `s3` |
| `OctetStream` | Unstructured application bytes | every module — HTTP bodies, `ws_stream` payloads, RTP PCMU audio, SIP datagrams, SMTP session bytes, S3 operation records |
| `WsFrame` | Connection-addressed WebSocket frame envelope | `http` (`ws_in`/`ws_out`), `ws_stream` |
| `FmpMessage` | Structured control records | `http` (`variables`), `sip` (`call`) |
| `Telemetry` | Observability records | `ws_stream` |
| `AudioEncoded` | Codec-domain audio access units | not consumed — see below |
| `HttpRequest` / `HttpResponse` | The application fan-out envelopes | `http` (`req_out`/`resp_in`) |
| `TextPlain` | Human-readable status lines | `s3` (`status_out`) |

Two surfaces are carried over ports rather than declared as port
types. The `mux` contract (opcodes `0xB0..0xCF`, disjoint from
`NetProto`) delivers QUIC request streams to `http` in h3 mode on
the same `net_in`/`net_out` it uses for h1 and h2. Datagram framing
(`DG_AF_INET`) is how `rtp` and `sip` address UDP peers through
their transport ports.

The `S3Request` and `S3Response` operation records are Wave-local
layouts, not fluxor content types: `s3`'s `request_in` and
`response_out` ports declare `OctetStream` and document the record
framing in the module manifest. The `SmtpRequest` and `SmtpResult`
records on `smtp`'s `request_in` and `result_out` ports are the same
kind of layout, and `smtp`'s `status_out` is likewise `OctetStream`.

`stun` speaks the datagram surface directly rather than a local
record layout: a Binding request arrives as one datagram and is
answered with another. Note the datagram surface's own split — the
address is big-endian so the IP module can memcpy it into a header,
while the port is little-endian. Reading the port the same way as the
address yields a byte-swapped port that still looks like a port.

The module answers Binding requests and nothing else. Candidate
gathering, pair formation, connectivity checks and nomination are an
ICE agent's work, and an agent's decisions are NAT-traversal policy
rather than protocol mechanics — a different concern, in Wormhole.

`sip`'s `command_in` and `event_out` carry the same kind of layout.
A command names one call and what to do about it — dial, accept,
reject, hang up, cancel — with the peer and media endpoints travelling
with it rather than fixed at construction. An event reports what
happened to that call: offered, provisional, established with the
negotiated remote media endpoint and payload type, and exactly one
terminal outcome. While `command_in` is wired an incoming call is held
until a decision names it, and `auto_answer` does not apply.

`http`'s `ws_admit_out`, `ws_admit_in` and `ws_event_out` are also
Wave-local layouts on `OctetStream`. A route using the admission
handler reports its upgrade — connection id, path, headers and
requested subprotocols — and composes no 101 until a decision names
that connection. Nothing downstream sees a frame from a connection the
application did not admit, and a refusal reaches the browser as an
HTTP status rather than a socket that opens and goes quiet. The event
port carries what happened rather than what was asked for: `opened`
once the upgrade is on the wire, `closed` once the connection has
actually ended, with its origin and close code.

The admission request carries no transport facts. The accept event
below carries a connection id and a local port and no peer address, and
`http` sits above whatever terminated TLS rather than inside it, so a
"secure" or "peer address" field would be invented at that seam. Where
a deployment terminates TLS through `tls`, that module publishes the
peer identity it verified on its own port.

`mail`'s `message_in`, `facts_out` and `body_out` carry the same kind
of Wave-local layout. An inbound message arrives as spans under one
correlation id; what leaves is a bounded facts record and the body,
forwarded as it arrives. The facts state the addresses that parsed and
the `Message-ID` / `In-Reply-To` / `References` identifiers verbatim.
Which conversation a message belongs to is decided above Wave, from
those identifiers and the conversation's own bindings.

A submission record carries a caller-chosen correlation id, an
envelope sender, one recipient and a span of the message; a message
larger than one record continues over further records under that id.
Each accepted submission is answered with exactly one result carrying
the correlation id, an outcome classification, the phase the
conversation reached, the final reply code with its enhanced status
and bounded text, and the peer address submitted to. The reply
answering end-of-data is what the acceptance rests on; the QUIT that
follows is cleanup and cannot withdraw it.

Wave must not depend on private IP/TCP/UDP state or on platform
socket handles. `NetProto` endpoint and connection identifiers are
transport identities, not authenticated principals or tenant
authorisations.

`rtp` carries PCMU/G.711 as `OctetStream` rather than
`AudioEncoded`. Moving it needs an explicit fluxor contract change
and a graph migration, so it is a decision to take deliberately
rather than a substitution to make in passing.
