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
framing in the module manifest. `smtp`'s `status_out` is likewise
`OctetStream`.

Wave must not depend on private IP/TCP/UDP state or on platform
socket handles. `NetProto` endpoint and connection identifiers are
transport identities, not authenticated principals or tenant
authorisations.

`rtp` carries PCMU/G.711 as `OctetStream` rather than
`AudioEncoded`. Moving it needs an explicit fluxor contract change
and a graph migration, so it is a decision to take deliberately
rather than a substitution to make in passing.
