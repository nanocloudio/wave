# HTTP multi-connection architecture

A single `http` module instance serves many concurrent HTTP/1,
HTTP/2, and WebSocket connections within one process tick. Each
in-flight connection gets its own slot, its own phase, and a tick of
work per `step()` — comparable to Linux's per-process behaviour,
with no FIFO-induced head-of-line blocking and no idle peer starving
the queue.

Source: `modules/foundation/http/server/mod.rs`; the fan-out paths
are `modules/foundation/http/server/ws.rs` and
`modules/foundation/http/server/app.rs`.

## State layout

`ServerState` holds the server-wide configuration: channel handles,
routes, the body cache and arena, telemetry variables, the
per-connection slot table, and the step iterator's bookkeeping.
Per-connection state lives in `ConnSlot`, one entry per slot.

A `ConnSlot` carries the conn id, phase, route match, request path
buffer, recv/send buffers (heap-allocated lazily on accept and
released on close), file/template/streaming state, WebSocket
fragmentation state, and an optional `H2State` (allocated only when
the conn upgrades to HTTP/2 — h1-only conns never pay the cost).

The active slot is identified by `ServerState::cur_slot`. Phase
handlers and their helpers (`cur_slot`, `cur_slot_mut`,
`cur_send_buf_mut_ptr`, `cur_conn_id`, …) read or mutate that slot.

## Per-target sizing

The capacity tunables live in the `abi::config::http` profile of the
SDK the modules build against, one profile per target class:

| Profile | `MAX_CONCURRENT_CONNS` | `ARENA_WORKING_SET_CONNS` | `RECV_BUF_SIZE` | `SEND_BUF_SIZE` |
|---|---|---|---|---|
| aarch64 (bcm2712, Linux host) | 256 | 256 | 8192 | 4100 |
| wasm32 | 256 | 64 | 4096 | 4100 |
| embedded (rp2350) | 1 | 1 | 2048 | 4100 |

`MAX_CONCURRENT_CONNS` matches fluxor's IP-module TCP connection
ceiling on host platforms. The slot table is the parallelism bound;
an idle slot costs only its table entry, because its heap
allocations are released on close. Per-slot `recv_buf`, `send_buf`,
and `H2State` (h2 only) all live on the module heap arena.

`alloc_free_slot` allocates `recv_buf` + `send_buf` on
`MSG_ACCEPTED`; `slot_release_buffers` returns them on close.
`H2State` is allocated lazily by `ensure_h2_state()` from
`h2::enter()`. `body_pool` grows via `heap_realloc` doubling each
time `parse_route_body` would overflow; `body_offset`, `body_len`,
`body_pool_cap`, and `body_pool_used` are all u32 so the pool can
exceed 64 KiB if app templates demand it.

`module_arena_size()` reports
`2 × DEFAULT_BODY_POOL_SIZE +
ARENA_WORKING_SET_CONNS × (RECV_BUF_SIZE + SEND_BUF_SIZE +
size_of::<H2State>()) + per-alloc-overhead + slack`, so the kernel
allocates the right peak envelope at module-init time. Memory
scales with active connections, not with the slot table size.

## Step iterator

`step()` is O(active) via a `ready_bits: [u64; N]` bitmap on
`ServerState`. `alloc_free_slot` sets the slot's bit;
`slot_release_buffers` clears it. Each tick snapshots the bitmap,
starts at `step_cursor`, walks set bits via `trailing_zeros`, and
ticks each marked slot's phase. After the tick, `step_cursor`
advances by one so no slot starves the others.

A server-level `bound: u8` flag (set on `MSG_BOUND`) gates
`demux_inbound` so it stays dormant during the bind sequence and
runs every tick afterwards — even when slot 0 is reused for a
connection after bind completes.

## Inbound demux

`demux_inbound` runs once per `step()` at the top, before any
per-slot work. It reads `NetProto` frames from `net_in_chan`, looks
up the target slot by `conn_id`, and routes:

- `MSG_ACCEPTED` → `alloc_free_slot(s, conn_id)` → mark phase
  `RecvRequest`. If the slot table is full, actively close the new
  conn so the IP layer doesn't leak a TCP slot waiting for our
  timeout.
- `MSG_DATA` → `find_slot_by_conn_id(s, conn_id)` → append payload
  to that slot's `recv_buf`. The frame is peeked first; if the
  target's `recv_buf` is too full to hold the payload, the frame
  is left on `net_in_chan` so the IP module's atomic-FIFO write
  rejection triggers TCP backpressure (closes `rcv_wnd` for the
  affected conn until we drain).
- `MSG_CLOSED` → set the target slot's `peer_closed` flag.
- `MSG_BOUND` → set the server-wide `bound` flag.

The demux processes up to 16 frames per tick; anything left over
rolls into the next call.

## Outbound

Per-slot phase handlers write into the active slot's `send_buf` and
call `net_send` to push CMD_SEND envelopes to `net_out_chan`.
`net_send` is atomic-FIFO: the channel either accepts the whole
envelope or rejects it, and rejection counts as backpressure rather
than partial delivery.

The h1 phase machine (`Phase::SendHeaders` → `SendBody` →
`DrainSend`) emits headers and body chunks for static, template,
file, FS, stream, and proxy handlers. h2 emits `HEADERS` + `DATA`
frames via the round-robin emitter in `step_sending_body`, capped
by per-stream and per-connection send windows.

## File-channel serialisation

`file_chan` is shared across slots — `HANDLER_FILE`,
`HANDLER_STREAM`, and `HANDLER_TEMPLATE`'s cache-fill path all
issue `IOCTL_FLUSH` + `IOCTL_NOTIFY` against it. To prevent two
concurrent slots racing on the channel state, `ServerState` carries
a `file_chan_owner: i16` slot-index lock:

- `try_acquire_file_chan` claims it. If another slot holds it,
  callers stall in `DispatchRoute` and retry on the next tick (or,
  for h2, mark the stream `Fetching` and let `drive_cache_fetch`
  retry).
- Released on transition to `DrainSend` and in
  `slot_release_buffers` (any close path).

`HANDLER_FS_FILE` (handler 7) bypasses this entirely via a per-slot
`fs_fd` through the FS contract, and is the recommended path for
new deployments.

## Body cache retention

Cache entries carry a `retain: u8` reader refcount. A cache hit
bumps it on the way in (in `cache_try_or_fetch` and the inline h1
hit path); end-of-emission (`Phase::DrainSend` for h1, h2's
`free_slot`) decrements via `cache_release_for_route`.
`cache_alloc` refuses to evict any entry with `retain > 0`, so
another cache miss can't trample the body_pool region a stream is
still rendering from. `cache_lookup` also requires `CACHE_COMPLETE`
so an in-progress fill doesn't masquerade as a hit. Source:
`modules/foundation/http/server/cache.rs`.

## WebSocket fan-out

When a route's handler is `HANDLER_WEBSOCKET_FANOUT`, the slot's
`ws_fan_out` flag is set and outbound WS bytes flow through a pair
of typed channels:

- `ws_in` (in[3], `WsFrame`): the http server reads `WsFrame`
  envelopes here and queues them on the active slot's `send_buf`
  as wire frames.
- `ws_out` (out[2], `WsFrame`): inbound browser WS frames are
  emitted as `WsFrame` records for downstream consumers.

`ws_drain_fanout_input` routes envelopes by their `conn_id` field
to the target slot. The `WsFrame` envelope carries its conn id as a
u32, and `ws_stream` stamps a `u32::MAX` "unclaimed" sentinel on
outbound envelopes until it observes a real inbound frame; the
sentinel routes to the first available fan-out slot. If the
target's `send_buf` is non-empty (or it's mid-fragmentation), the
envelope is written back to `ws_in_chan` so the next tick retries
delivery.

Fragmentation: when a `WsFrame` envelope's payload exceeds
`SEND_BUF_SIZE - WS_FRAG_HDR_RESERVE`, the message is split into a
`BINARY/fin=0` first fragment + N `CONTINUATION/fin=0` fragments +
a final `CONTINUATION/fin=1` (RFC 6455 §5.4). The source payload
is heap-allocated per-slot for the duration of fragmentation and
freed when the final fragment is queued (or on slot close).

## HTTP application fan-out

When a route's handler is `HANDLER_APP` (11), the request is handed
to a downstream module and its answer is served back. The symmetric
counterpart to WebSocket fan-out above: there the module owns the WS
envelope and something else owns the protocol inside it; here it
owns HTTP framing, connection state and bounded body handling, and
something else owns what the request means.

- `req_out` (out[6], `HttpRequest`): the matched request, as
  `[conn_id u16][stream_id u16][method u8][flags u8][path_len u16]
  [hdr_len u16][body_len u16]` followed by the path, the raw header
  block and the decoded body. Header fields are forwarded verbatim
  rather than filtered — an application's API is defined in terms of
  headers a gateway cannot know in advance. Pseudo-headers are
  excluded on h2: `:method` is that generation's encoding of the
  request line, not a field.
- `resp_in` (in[6], `HttpResponse`):
  `[conn_id u16][stream_id u16][status u16][flags u8][ct_len u8]
  [hdr_len u16][body_len u16]` then the content type, the
  application's own headers and the body.

**Peer identity.** `flags` bit 1 marks a request whose connection
completed a handshake that verified the peer. The fingerprint follows
the body as `[svid_len u16 LE][svid]`, past every length in the fixed
head, so a consumer that does not read the bit sees exactly what it
saw before. The three section lengths are the envelope's ABI — every
consumer reads path, headers and body by them — which is why the
identity is a trailer rather than a fourth field.

It is not a synthetic header such as `X-Forwarded-Client-Cert`
either. A header is forgeable by the client unless the server strips
every copy of it first, and one missed strip promotes an anonymous
caller to whoever it claims to be; a trailer sits in a structure the
client cannot reach at all.

The identity belongs to the connection, not the request. It arrives
once per handshake on `peer_identity` (in[9]) — often before the
accept it belongs to — and is released when the connection ends,
because connection ids are recycled and a stale entry would
authenticate the next holder as the previous one.

`drain_responses` routes an envelope by `(conn_id, stream_id)` —
never `conn_id` alone, because h2 multiplexes many requests over one
connection and an application is entitled to answer them out of
order. Under h1 `stream_id` carries a request generation instead: a
connection released with a request still outstanding can be followed
by a new peer holding the same recycled id, and the generation keeps
the late answer from matching the new peer's request. Applications
echo the field back in both cases. If the target slot's `send_buf`
is busy, the envelope is written back to `resp_in` and retried next
tick, the same backpressure the WS fan-out uses; unlike WS fan-out
there is no retention, since replaying a previous response to a new
request would answer request N with response N-1.

`Content-Length`, `Connection` and `Transfer-Encoding` are dropped
from the application's header block and emitted by the module: they
describe this connection's framing, which only the module knows. Two
`Content-Length` values on the wire is the ambiguity RFC 9112 §6.3
refuses on the request side.

**Streaming.** `flags` bit 0 (`MORE_BODY`) marks a body arriving
across several envelopes — the only way a response can exceed
`SEND_BUF_SIZE`, which is what serving artefacts requires. On h1 the
first envelope's `Content-Length` header (if the application
declared one) frames the whole transfer and keep-alive survives;
without one the response is close-delimited. On h2 no length is
needed at all: END_STREAM on the final DATA frame delimits it.

**Timeout.** A request unanswered for `APP_TIMEOUT_MS` (30 s) is
answered 504 by the module, per stream under h2, so one hung request
does not exhaust the slot table. Mid-stream the connection is closed
instead — a 504 appended to a body already on the wire would be read
as content.

**Graph wiring.** Both edges need a non-zero `buffer_group:`, which
puts the channel in mailbox mode so one write is one whole envelope.
The default is a byte-streaming FIFO, which fragments structured
records — so omitting the group does not fail loudly, it delivers
half an envelope.

```yaml
- from: http.req_out
  to: app.request_in
  buffer_group: 1
- from: app.response_out
  to: http.resp_in
  buffer_group: 2
```

The groups differ because the two directions are independent channels
carrying different types; sharing a group would alias their buffers.
The auto-assign pass cannot infer either group, because "this edge
needs transport atomicity" is not visible from the graph shape.

## Limitations

- **Single-conn `legacy_mode`** — the routeless file-server
  fallback (`legacy_mode == 2`) serialises all requests through
  the slot phase machine. Multi-conn parallelism applies; the file
  channel is the bottleneck.
- **`MAX_CONCURRENT_CONNS` set to 256** — not a wire limit.
  `conn_id` is a u16 on the net-protocol surface, so the id space
  allows 65,535; the 256 is a memory decision (slot table plus
  `ARENA_WORKING_SET_CONNS` of buffers) and raising it is a sizing
  question. The two are worth keeping distinct: the shed counters
  report slot exhaustion and arena exhaustion separately precisely
  because they are different ceilings.
- **Per-instance `H2State`** is large (`MAX_STREAMS` ×
  `StreamSlot`). On embedded targets only one slot exists, so the
  cost is bounded; on host targets it scales with
  `ARENA_WORKING_SET_CONNS`.
