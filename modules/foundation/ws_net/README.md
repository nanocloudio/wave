# `ws_net` — `net_proto` over a server-side WebSocket

A WebSocket route is a place connections arrive, so what sits above one is a
`net_proto` provider: the same contract `linux_net` implements for TCP and
`tls` speaks on its clear side. That is what lets a connection-bearing
consumer — Fluxor's `remote_channel` above all — ride a WebSocket with its
session semantics intact.

`ws_stream` is the adapter for consumers that want bytes and nothing more. The
difference is not framing but whether connections exist: this module reports
when one opens and when it closes, and a carrier that binds an authenticated
peer to a session needs exactly that. Handed a bare byte stream it would have
to assume a session around it, which is the one assumption such a carrier must
not make.

```text
browser → http.ws_out → rx_in  (WsFrame)  → net_out (NetProto) → consumer
consumer → net_in (NetProto) → tx_out (WsFrame) → http.ws_in  → browser
```

## Connection ids pass through

The `ws_frame` envelope's `conn` is the transport connection id widened to u32,
and `http` stamps it from the `MSG_ACCEPTED` its own slot was opened with. An
id here is therefore the same id `tls` reported on `peer_identity` for that
connection, and a consumer can join the two. Renumbering would break exactly
that join, so this module allocates nothing: every id it reports is one it was
given.

`http` owns the id space, so `net_proto`'s release rule — a transport holding a
closed id back from the next accept — is not this module's to enforce, and it
needs nothing from it. `CMD_CLOSE` for an id no longer live is a no-op, which
the contract already allows, and a data frame for an id that is not live is a
new connection whatever that id was used for before.

## What it answers

| From the consumer | Effect |
| --- | --- |
| `CMD_BIND [port]` | The route is the bind, so it has already succeeded: answered `MSG_BOUND [0][port]`. The port is remembered and echoed on every accept, so a consumer fanned alongside others claims only its own connections. |
| `CMD_SEND [conn][data]` | One binary `WsFrame` to that connection. |
| `CMD_CLOSE [conn]` | A close `WsFrame`, and the connection is forgotten. |
| `CMD_CONNECT` / `CMD_CONNECT_TO` | `MSG_ERROR` `ENOSYS` on the requester tag. A served route has no outbound side, and a provider that dropped a dial silently would leave its consumer waiting out a deadline for a connection nothing attempted. |

| From the browser | Effect |
| --- | --- |
| First data frame of a connection | `MSG_ACCEPTED [conn][port]`, then the payload as `MSG_DATA`. |
| Data frame (text, binary, continuation) | `MSG_DATA [conn][data]`, split across frames when longer than `MAX_DATA_FRAGMENT`. |
| Close | `MSG_CLOSED [conn]`. |
| Ping, pong | Ignored; they are the HTTP server's business. |

## Ports

| Port | Direction | Content type |
| --- | --- | --- |
| `net_in` | input | `NetProto` |
| `rx_in` | input (index 1) | `WsFrame` |
| `net_out` | output | `NetProto` |
| `tx_out` | output (index 1) | `WsFrame` |
| `telemetry` | output (index 2, optional) | `Telemetry` |

`bytes_in` counts payload delivered inbound as `MSG_DATA`; `bytes_out` counts
payload sent outbound from `CMD_SEND`.

## Backpressure

Each direction holds at most one frame in flight, and new input is read only
once both are clear. A write that cannot land consumes nothing, so the buffer
is left as it was and offered again on the next step. Nothing is dropped.
