# `ws_stream` — `WsFrame` ⇄ `OctetStream` adapter

Bridges the WebSocket-frame envelope used by `http`'s `ws_in` / `ws_out` ports
and a raw byte stream, so an application module can ride a WebSocket without
touching WS framing.

Bytes only. A consumer that needs *connections* — one that binds a peer
identity to a session, Fluxor's `remote_channel` above all — takes `net_proto`
from [`ws_net`](../ws_net/README.md) instead: a byte stream says nothing about
when a session begins or ends, and a carrier must not assume it.

Wire layout (mirrors `http`'s `server::ws::ws_emit_fanout_frame`):

```text
[conn_id u32 LE][opcode u8][fin u8][payload_len u16 LE][payload]
```

Flow:

```text
tx_in  (OctetStream)  →  tx_out (WsFrame)  →  http.ws_in   → browser
browser → http.ws_out →  rx_in  (WsFrame)  →  rx_out (OctetStream)
```

The adapter tracks the active client connection's `conn_id` from the most
recently observed inbound frame and stamps it on outbound frames. **One
connection at a time:** a second client replaces the first. Multi-connection
routing is a session-layer concern above this module.

## Ports

| Port | Direction | Content type |
| --- | --- | --- |
| `tx_in` | input | `OctetStream` |
| `rx_in` | input | `WsFrame` |
| `tx_out` | output | `WsFrame` |
| `rx_out` | output | `OctetStream` |
| `telemetry` | output (index 2, optional) | `Telemetry` |

`bytes_in` counts payload delivered inbound to `rx_out`; `bytes_out` counts
`WsFrame` bytes sent to `tx_out`.

## Boundary

`WsFrame` itself remains a **Fluxor** content-type contract — Wave consumes the
name and its layout without assigning a replacement identifier
(`docs/reference/protocol-surfaces.md`). Browser and native `WebSocket` host APIs
remain Fluxor platform providers.
