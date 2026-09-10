# Session continuity: `http` as a session anchor

Fluxor owns session continuity — the continuity classes, the
SessionCtrlV1 control plane, the anchor/worker split, the opaque
handoff and its delivery cursors (`../fluxor/docs/architecture/protocol_surfaces.md`).
Wave owns the application protocols that compose on top, and one of
them holds long-lived, application-owned state behind a client
connection: a server-side WebSocket. This document describes how
`http` acts as a Fluxor **transport anchor** for those sessions, so the
worker behind the connection can be replaced during maintenance while
the client sees nothing but a bounded pause.

Source: `modules/foundation/http/server/session.rs` (the anchor),
`modules/common/ws_session_worker.rs` (the worker-side core),
`modules/fixtures/ws_echo_worker/` (the far side of the seam for the
gates).

## What moves and what does not

`http` already hands every frame of a fan-out WebSocket across the
connection-addressed `WsFrame` seam (`ws_out` / `ws_in`) to whatever
module owns the application protocol. That module is a Fluxor *session
worker*; what it accumulates for a connection is the state a swap
moves, and it is opaque to `http`, which relays it byte for byte.

Nothing `http` holds for the connection moves. Close state, ping/pong
timing, outbound fragmentation and the admission outcome are anchor
state, and under the `edge_anchored` class the anchor never moves. The
HTTP/2 and HTTP/3 stream tables are the same kind of thing. They matter
for a different class, `transport_migratable`, where the transport
association itself changes attachment point — that is `ip`, `tls` and
`quic` business, composed with a directory, a reservation and a fence
from outside the module, and a stream anchor like this one is admitted
for it only on a bare-metal target. Wave's contribution to that class is
narrower and worth stating: it keeps a connection's own state
checkpointable, which is a property a codec can destroy in one commit.
See [HPACK and QPACK](#hpack-and-qpack) below.

## Ports, feature and variants

The anchor is the `session` feature of the `http` module, carried by
the server-class variants (`full`, `h2`, `exchange`) and omitted from
the embedded ones (`web`, `app`, `h1_exchange`), whose ports below are
omitted with it. Every port is inert until wired: an instance with
`ctrl_out` unwired anchors nothing and serves a plain fan-out.

| Port | Index | Content | Role |
| --- | --- | --- | --- |
| `ws_out` / `ws_in` | out[2] / in[3] | `WsFrame` | Worker 0's data plane. |
| `ctrl_out` / `ctrl_in` | out[3] / in[10] | `OctetStream` | SessionCtrlV1 to and from worker 0. |
| `ws2_out` / `ws2_in` | out[11] / in[12] | `WsFrame` | The standby worker's data plane. |
| `ctrl2_out` / `ctrl2_in` | out[10] / in[11] | `OctetStream` | SessionCtrlV1 to and from the standby. |
| `sessions_sink` / `sessions_changes` | out[12] / in[13] | `OctetStream` | The operator's swap trigger: a store subscription self-edge. |

The `WsFrame` edges are mailbox channels (`buffer_group` in the
graph), one envelope per record, as every `WsFrame` edge must be. The
control edges are ordinary byte streams; the frames carry their own
lengths. Two workers follow the `ctrl2` / `data2` shape of Fluxor's
`echo_anchor`: channels are static, and the anchor's forwarding flip
is the activation.

Parameters: `anchor_id` (sixteen hex characters naming the anchor on
every session id and `MON_SESSION` line), `session_drain_ms` (the swap
window and the deadline every `DRAIN` carries; default 500),
`handoff_after_frames` (swap the workers every N forwarded envelopes;
the gates' trigger, 0 = never), `sessions_prefix` (the store prefix
whose `active = <0|1>` row names the worker new sessions attach to; a
change away from the current one requests a swap).

## The session's life

A connection upgraded on a fan-out route — the `websocket_fanout:
true, retain_replay: false` session variant on HTTP/1.1, and the RFC
8441 / RFC 9220 tunnels on HTTP/2 and HTTP/3 — is minted a session id
`[anchor_id:8][conn_id:4 BE][generation:4 BE]` and attached to the
active worker with `CMD_SC_ATTACH` at class `edge_anchored`. Its frames
are held until `MSG_SC_ATTACHED`. A worker that refuses leaves nothing
to serve, so the connection is closed `1011` — the h1 connection, or the
h2 or h3 tunnel's stream, each from its own step. The generation counter
is server-wide, so an id is never reused even though a `conn_id` is;
its layout lets a worker recover the connection it serves from the
identity alone, which `CMD_SC_ATTACH` does not otherwise carry.

A swap drains every established session on the active worker under one
window — one still waiting on its own attach is not yet the old worker's
to hand over:
`DRAIN` to each, the export relayed verbatim to the standby, `RESUME`
at epoch + 1, forwarding flipped on `RESUMED`, `DETACH` to the old
worker. New sessions attach to the standby from the moment the swap
starts. Each step emits `MON_SESSION` with the session, epoch and
status, so a swap is diagnosable from telemetry alone
(`../fluxor/docs/architecture/monitor-protocol.md`).

## Delivery cursors

The one part of the export the anchor reads. `CMD_SC_EXPORT_BEGIN`
carries what the blob accounts for inbound and what it has emitted
outbound; the anchor keeps the same pair per session. The unit is this
binding's choice — whole `WsFrame` envelope bytes, framing included,
because an envelope is what crosses the seam — and the contract asks
only that both sides count the same thing. The forwarded cursor advances when an envelope is accepted
onto the worker's channel; the relayed cursor when an envelope from the
worker is *queued* onto the connection's send path — never when it is
read, because an envelope read and written back for a busy target is
read again. At export both pairs must agree (`cursors_admit`), or the
blob and the client have seen different prefixes of the session and
the handoff is refused.

Before the exporting worker's control channel is read during a swap,
its data channel must poll empty, so everything it emitted before
`DRAINED` has been queued toward the client and counted; after
`DRAINED` it emits nothing more, and the new worker cannot emit until
`RESUME`. That ordering is what keeps old output ahead of new.

## Refusal and the way back

Cursors that disagree, an import the standby rejects, a worker error
mid-swap, or a window that closes all leave the session on the
exporting worker. The anchor detaches the standby and sends the old
worker `CMD_SC_RESUME` at the session's *current* epoch — nothing was
committed anywhere, so nothing advanced — and releases the hold on
`MSG_SC_RESUMED`. Fluxor's contract documents this return path
(`session_ctrl.rs` §Delivery cursors) and its `echo_worker` honours it.
A cursor mismatch refuses that session alone; a closed window abandons
the swap for every session still short of `RESUMED`. A return path
that itself goes quiet fails the session (`1011`) three windows after
the drain began.

## The hold

A session being swapped forwards nothing: its frames stay in the slot's
receive buffer and the transport window closes behind them. Nothing is
dropped, and on HTTP/1.1 there is no second buffer at all. The cost is
real: a full receive buffer stops the inbound demultiplex loop for every
connection on the instance (`http.demux.stalls`), which is why a
worker's sessions are swapped under one window, the window is bounded by
`session_drain_ms`, and the deadline should be short — a worker's blob
is small.

A held session is exempt from the idle policy for as long as the hold
lasts, and the time it took is credited to the clock when the hold
lifts, so the silence a swap caused is never counted against the client.
`session_drain_ms` must sit under half `ws_idle_ms`, so a swap that
completes cannot expire either side's keepalive; an instance that breaks
that rule refuses to load, as does one in single-client fan-out mode,
one with a retention-replay route, and one whose `anchor_id` is not
sixteen hex characters. A refused frame's mask is put back before it is
offered again.

The tunnels do hold a second buffer, and it is what bounds a hold there.
On HTTP/2 a
DATA frame that will not fit the 512-byte accumulator is left in the
receive buffer and offered again, rather than answered `1009`; the
exception is a single frame too large for an empty accumulator, which no
amount of waiting would make deliverable and which closes `1009` as it
would on an unheld tunnel. On HTTP/3 the tunnel's 1 KiB accumulator is
the whole of what a held tunnel can absorb, and past it the tunnel
closes `1009`. Both are bounded by the window.

## HTTP/2 and HTTP/3 tunnels

An RFC 8441 tunnel's frames arrive inside h2 DATA frames and leave the
same way; the RFC 6455 bytes are the same, so the fan-out and its
fragmentation serve both generations from one place
(`ws::ws_queue_frame_fin`). The tunnel is a session on the connection's
slot exactly as an h1 upgrade is, and ending the tunnel detaches the
session while the connection carries on.

An RFC 9220 tunnel over HTTP/3 has no connection slot of its own —
`h3` runs on Fluxor's mux surface — so a fan-out tunnel is *seated*: a
connection-table slot (`Phase::H3Tunnel`) whose `conn_id` is the
tunnel's stream slot index, the identity `WsFrame` envelopes name.
Inbound frames cross the seam from the mux step, where the module
state is held mutably; outbound envelopes are wrapped in h3 DATA
frames on the tunnel's stream. Ending the tunnel frees the seat and
detaches the session. Admission-gated routes are not served as tunnels
over h2 or h3 — the admission exchange belongs to the h1 upgrade — and a
CONNECT naming one is answered `501` rather than upgraded.

## The worker's half

`modules/common/ws_session_worker.rs` is what a `WsFrame` consumer
mounts to be an anchored worker: attach and detach by session id, the
map from a connection id to its session, the delivery cursors, the
drain-to-dry rule, export gated on a message boundary, import into a
caller-sized blob, the resume that follows an import and the one that
returns a refused session to service. Control frames are consumed
through `handle_ctrl` and produced through `next_out`; the module moves
the bytes and owns the blob. A worker holding half a message (a
`fin = 0` fragment) declares nothing until the other half arrives.
Timers are the module's: Fluxor's `protocol_timer.rs` is plain data a
module may carry in its blob and rebase with `shift` after import.

`modules/fixtures/ws_echo_worker/` wraps the core around the least
state that makes a swap observable — a per-session message count and
the partial message — and answers `<tag>:<count>:<message>`. Wave
ships no product worker: the application that owns a WebSocket's state
lives outside Wave.

Consumers behind `ws_stream` get no continuity from this. That adapter
is not a session worker — it has no control ports to attach through —
and it strips the connection id the envelopes carry, so downstream of it
there is nothing left for a session to be keyed on.

## HPACK and QPACK

Neither codec keeps a dynamic table. That absence is load-bearing for
continuity: a dynamic table is a compression context both endpoints
evolve with every header block and cannot be reconstructed on another
host without replaying the connection, so a connection carrying one
could never be migrated. With none, an HTTP/2 or HTTP/3 connection's
header state is nothing and the rest is a record of integers.
`modules/foundation/http/wire/hpack.rs` and
`modules/foundation/http/wire/qpack.rs` record the invariant, and
`tests/harness/tests/header_compression_invariant.rs` holds it: the
advertised table size is zero, the encoder never emits the
incremental-indexing form, and the HPACK decoder handed that form takes
it as a plain literal and then refuses the index the peer believes it
created. QPACK carries the same rule on the other side of the block: the
prefix this module emits pins Required Insert Count at zero, and its
decoder refuses a field line that names the dynamic table.

## Evidence

- `tests/harness/tests/ws_session_anchor.rs` — the anchor against
  scripted workers: attach and hold, the swap, cursor refusal, the
  deadline, the held idle clock, and every composition an anchored
  instance refuses to load, a mistyped `anchor_id` among them.
- `tests/harness/tests/ws_session_worker.rs` — the fixture against a
  scripted anchor: boundary-gated export, cursors, import with the count
  carried, resume-from-drained, detach mid-import, and a detach reply
  that survives the attach that reuses its slot.
- `tests/harness/tests/ws_session_h2.rs` — the h2 tunnel on the seam in
  both directions, held across a full swap without a `1009`, refused at
  the attach and closed `1011`, and ended without taking its connection
  with it.
- `tests/harness/tests/ws_session_h3.rs` — the h3 tunnel on the seam,
  swapped with its stream open, refused at the attach, and closed with
  its seat released.
- `tests/harness/tests/ws_session_handoff.rs` — the real graph
  (`examples/linux/wave_ws_handoff.yaml`) on `fluxor-linux`, swapped
  every three frames under an independent `websockets` peer that
  watches one connection stay open while the replies change worker and
  the count carries; the `MON_SESSION` relocations are checked in the
  runtime log. The same file gates the declaration: a `continuity` block
  naming a module that is not a session worker is refused at build.
- `tests/hardware/pi5_wave_ws_handoff.toml` — the Pi 5 rig, keyed on
  the relocation beat recurring on the telemetry channel under the
  probe's WebSocket load (`examples/rig/pi5_ws_handoff.yaml`).
