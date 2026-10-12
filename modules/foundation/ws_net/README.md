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
the contract already allows.

A frame is only ever sent to the connection it names. One for a connection this
module no longer holds is dropped rather than handed to `http`'s fan-out
sentinel, which resolves to whichever connection is active — and that is how a
consumer tidying up one session would close the session that replaced it.

## Connections come from the lifecycle

A connection is reported when `http` commits it — its `opened` event on
`event_in` — not when it first sends a frame. A carrier greets its peer before
the peer says anything, so a module that learned of connections only from their
traffic would wait on a greeting the peer is waiting on too.

## Sessions are numbered by the stage below

`http`'s `opened` event carries the session generation the stage beneath it
numbered the connection's session with: `tls` numbers each session it opens,
and names it by the same number on its `peer_identity` records. This module
appends that generation to the `MSG_ACCEPTED` it gives the consumer — at the
place `net_proto::session_generation` reads it — which is what lets a consumer
that binds a session to an authenticated peer (`remote_channel` under
`require_peer: 1`) join the two. With nothing below `http` numbering sessions
the generation is 0 and nothing is appended: a consumer is never told a session
was numbered when it was not.

## What it answers

| From the consumer | Effect |
| --- | --- |
| `CMD_BIND [port]` | The route is the bind, so it has already succeeded: answered `MSG_BOUND [0][port]`. The port is remembered and echoed on every accept, so a consumer fanned alongside others claims only its own connections. |
| `CMD_SEND [conn][data]` | One binary `WsFrame` to that connection. |
| `CMD_CLOSE [conn]` | A close `WsFrame`, and the connection is forgotten. |
| `CMD_CONNECT` / `CMD_CONNECT_TO` | `MSG_ERROR` `ENOSYS` on the requester tag. A served route has no outbound side, and a provider that dropped a dial silently would leave its consumer waiting out a deadline for a connection nothing attempted. |

| From the browser | Effect |
| --- | --- |
| Data frame for a connection `event_in` never reported | `MSG_ACCEPTED [conn][port]` with no generation, then the payload as `MSG_DATA`. A consumer that binds sessions to peers refuses it. |
| Data frame (text, binary, continuation) | `MSG_DATA [conn][data]`, split across frames when longer than `MAX_DATA_FRAGMENT`. |
| Close | `MSG_CLOSED [conn]`. |
| Ping, pong | Ignored; they are the HTTP server's business. |

| From `http`'s `event_in` | Effect |
| --- | --- |
| `opened` | `MSG_ACCEPTED [conn][port]`, followed by `[generation]` when the session is numbered. |
| `closed` | `MSG_CLOSED [conn]`, and the connection is forgotten. |

## Ports

| Port | Direction | Content type |
| --- | --- | --- |
| `net_in` | input | `NetProto` |
| `rx_in` | input (index 1) | `WsFrame` |
| `event_in` | input (index 2) | `OctetStream` — `http`'s `ws_event_out` |
| `net_out` | output | `NetProto` |
| `tx_out` | output (index 1) | `WsFrame` |
| `telemetry` | output (index 2, optional) | `Telemetry` |

`bytes_in` counts payload delivered inbound as `MSG_DATA`; `bytes_out` counts
payload sent outbound from `CMD_SEND`.

## Backpressure

Each direction holds at most one frame in flight, and new input is read only
once both are clear. A write that cannot land consumes nothing, so the buffer
is left as it was and offered again on the next step. Nothing is dropped.
