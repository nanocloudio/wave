# `websocket` — RFC 6455 HTTP/1.1 client

The client half of RFC 6455. It duplicates nothing: Fluxor provides the
server-side `ws_stream` path, and Wave's `http` provides a WS-over-HTTP/2 client
(`client_h2.rs`, RFC 8441), but neither is an HTTP/1.1 WebSocket client. This
module is that, and it is why RFC 6455 byte semantics consolidate in Wave.

## Behaviour

The connection starts as HTTP. The client sends an `Upgrade` request carrying a
random `Sec-WebSocket-Key` and **cryptographically verifies** the server's
`Sec-WebSocket-Accept` (`base64(SHA1(key ++ magic))`) before switching. After the
101, both sides exchange frames; client frames are masked (payload XOR a
per-frame key). PING is answered with PONG.

On boot it upgrades, sends a masked text `message`, and emits every server
frame's payload on `message_out`.

`Ready` is reachable only through a verified upgrade — see
`ws_transition` in `modules/common/ws_core.rs` and the
`client_state_machine_gates_ready_on_the_upgrade` vector.

## Ports

| Port | Direction | Content type | Meaning |
| --- | --- | --- | --- |
| `net_in` | input | `NetProto` | Transport events from the bound TCP/TLS provider |
| `request_in` | input | `OctetStream` | Application payload to frame outbound |
| `net_out` | output | `NetProto` | Transport commands |
| `message_out` | output | `OctetStream` | Received frame payloads |

## Parameters

| Name | Meaning |
| --- | --- |
| `endpoint` | Hex `[ip:4][port:2 LE]` — a config carries text, so bytes arrive hex-encoded |
| `host` | `Host:` header value |
| `path` | Request path |
| `message` | Text payload sent once the upgrade completes |

## Shared cores

Protocol lives in `modules/common` and crypto in the Fluxor SDK, `include!`d
verbatim so the device and the host harness compile identical bytes:

- `ws_core.rs` — upgrade request/verify and the masked frame codec;
- `sha1_core.rs` — SHA-1 for the accept proof;
- `b64_core.rs` — Base64 for the key nonce and proof;
- `hex_core.rs` — hex decode for the `endpoint` parameter.

Conformance vectors: `tests/harness/tests/websocket_ws_core_conformance.rs`.

## Boundary

TLS is not this module's concern. Wire the Fluxor `tls` module between the
transport and `net_in`/`net_out` for `wss://` — see `examples/README.md`.

## Not claimed

Permessage-deflate, continuation-fragment reassembly above the frame codec,
subprotocol negotiation, reconnect policy, and multi-connection session routing
are future features, not migration claims.
