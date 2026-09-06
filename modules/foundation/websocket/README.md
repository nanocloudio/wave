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

On boot it upgrades and sends a masked text `message`. It then reads
`request_in` in chunks of at most 504 bytes and sends each chunk as one message.
`request_opcode` selects text (1, default) or binary (2). This port is an octet
stream: producers needing application record boundaries must frame their own
records inside it. Pending frames survive network backpressure, and drain sends
already staged bytes before sending CLOSE. Drain waits up to five seconds for
its peer's close before releasing the transport. Received payloads leave on
`message_out` as complete messages, reassembled across continuation frames, up
to 2048 bytes. Invalid UTF-8, masking direction, control framing and continuation
ordering close the session; oversized messages close with 1009. PING payloads up
to 125 bytes are echoed exactly. Transport and application backpressure retain
accepted bytes rather than truncating them.

The nonce and every mask use Fluxor's CSPRNG. An entropy error fails the session;
there is no predictable fallback. Input text chunks must contain valid UTF-8;
use binary for arbitrary octet streams.

`Ready` is reachable only through a verified upgrade — see
`ws_transition` in `modules/common/ws_core.rs`.

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
verbatim, so each core has a single source of truth wherever it is compiled:

- `ws_core.rs` — upgrade request/verify and the masked frame codec;
- `sha1_core.rs` — SHA-1 for the accept proof;
- `b64_core.rs` — Base64 for the key nonce and proof;
- `hex_core.rs` — hex decode for the `endpoint` parameter.

## Boundary

TLS is not this module's concern. Wire the Fluxor `tls` module between the
transport and `net_in`/`net_out` for `wss://`; the wiring shape is the one the
repository README gives for `https://`.

## Not claimed

Permessage-deflate, subprotocol negotiation, application reconnect policy and
multi-connection session routing are outside this connector profile. An
unsolicited extension or subprotocol in the upgrade response is refused.
