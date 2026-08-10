# Protocol surface boundary

Fluxor owns these canonical transport and content surfaces. Wave consumes them
without assigning replacement identifiers.

| Surface | Meaning | Declared by |
| --- | --- | --- |
| `NetProto` | Network endpoint and framed transport commands/events | `http` (`net_in`/`net_out`), `rtp`, `websocket` |
| `OctetStream` | Unstructured application bytes | every module — HTTP bodies, `ws_stream` payloads, RTP PCMU audio, SIP datagrams, SMTP session bytes |
| `WsFrame` | Connection-addressed WebSocket frame envelope | `http` (`ws_in`/`ws_out`), `ws_stream` |
| `FmpMessage` | Structured control records | `http` (`variables`), `sip` (`call`) |
| `Telemetry` | Observability records | `ws_stream` |
| `AudioEncoded` | Codec-domain audio access units | not consumed — see below |

Two surfaces are carried *over* ports rather than declared as port types. The
`mux` contract (`0xB0..0xCF`, disjoint from `NetProto`) delivers QUIC request
streams to `http` in h3 mode on the same `net_in`/`net_out` it uses for h1 and h2.
Datagram framing (`DG_AF_INET`) is how `rtp` and `sip` address UDP peers through
their transport ports.

Wave must not depend on private IP/TCP/UDP state or on platform socket handles.
`NetProto` endpoint and connection identifiers are transport identities, not
authenticated principals or tenant authorizations.

`rtp` carries PCMU/G.711 as `OctetStream` rather than `AudioEncoded`. Moving it
needs an explicit Fluxor contract change and a graph migration, so it is a
decision to take deliberately rather than a substitution to make in passing.
