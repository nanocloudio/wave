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
| embedded (rp2350) | 4 | 4 | 2048 | 4100 |
| embedded (rp2040) | 1 | 1 | 2048 | 4100 |

The two embedded rows are one profile that reads the silicon it is
building for: four slots cost about 24 KiB, which is a tenth of the
RP2350's arena and over a third of the RP2040's, so the smaller die
serves one connection — a single-page local UI rather than a browser
opening parallel sockets.

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
owns HTTP framing, connection state and bounded bodies, and
something else owns what the request means.

Source: `modules/foundation/http/server/app.rs`. The records are fluxor's
exchange contract (`abi::contracts::exchange`), in which this server is the
REQUESTER and the application the provider; its port pair is `request_out`
(`ExchangeRequest`) and `response_in` (`ExchangeResponse`).

### Records

Every record is `[kind u8][flags u8][id: 14 bytes]` then its payload. The id
names the exchange; this server packs it as `[origin u8][0][conn u32 LE]
[stream u64 LE]`, and the application treats it as opaque and echoes it.

| Direction | Kind | Payload |
|---|---|---|
| `request_out` | HEAD | `[method u8][target_len u16][hdr_len u16][peer_len u16][resp_credit u32]` target, header lines, peer fingerprint, then the first body bytes |
| both | BODY | body bytes; `MORE` unless it ends the body |
| both | ABORT | `[reason u8]` |
| both | CREDIT | `[bytes u32]` — response credit on `request_out`, request credit on `response_in` |
| both | DATAGRAM | `[context u64]` payload, an HTTP/3 datagram |
| `response_in` | HEAD | `[status u16][ct_len u8][hdr_len u16]` content type, header lines, body |
| `response_in` | LINK | `[state u8]`, id all zero — the application's link to whatever backs it |

`origin` is 1 for a TCP connection (h1, whose `stream` is a request
generation, and h2, whose `stream` is the stream id) and 2 for a QUIC session
(h3, whose `stream` is the transport's stream handle). The target is the
request target as received, path and query; header lines are `name: value\r\n`,
and h2 and h3 add `host` from `:authority`. Header fields are forwarded
verbatim rather than filtered — an application's API is defined in terms of
headers a gateway cannot know in advance — and a block past
`MAX_FWD_HEADERS` is refused 431 rather than forwarded short.

### Bodies in the HEAD

A request body already received whole that fits the record rides inline in
the HEAD, with no `MORE`, and the application grants nothing for it. One whose
declared length (`Content-Length`) fits the record and `recv_buf` but which is
still arriving is waited for — under the stall deadline — and then sent the
same way; a chunked body goes inline only if it is already whole. A client
that asked for `100 Continue`, a tunnel (`CONNECT`), and a body longer than
one record get a HEAD with `MORE` at once, and their body follows on the
application's credit.

### Correlation

`drain_responses` reads `response_in` once per step and hands each record to the
exchange its id names — never by connection alone, because h2 multiplexes
many requests over one connection and an application may answer them in any
order. Under h1 the `stream` half is a request generation: a connection
released with an exchange open can be followed by a new peer holding the same
recycled id, and the generation keeps a late answer from reaching it. A record
for an exchange that is no longer open is dropped and counted
(`app_records_stale`).

### Credit

One channel carries every exchange, so no exchange may be held back by
leaving the channel unread. Each direction runs on credit instead:

- request-body bytes go to the application only as far as it has granted
  CREDIT. Until it does, bytes stay in the connection's `recv_buf` (h1) or
  the stream's receive buffer inside its flow-control window (h2, h3), which
  is refilled only as bytes are forwarded — so a held body closes the
  client's window and nothing else;
- response-body bytes are accepted from the application up to the HEAD's
  `resp_credit` plus the CREDIT records sent back as bytes leave for the peer.
  What the application sent ahead of the connection is held in the exchange's
  record queue, never past its credit; a record past it is a violation, and
  the exchange is aborted (`app_violations`).

`100 Continue` is sent on the application's first request credit: credit is
the application's consent to receive the body.

### Ending

An exchange ends when both directions have, or when either side sends ABORT.
The module aborts toward the application when the peer goes, a body passes its
route ceiling or does not parse, the application lets its progress deadline
lapse (`APP_TIMEOUT_MS`, `HOLD_TIMEOUT_MS` for a held stream), or the server
drains; aborts that `request_out` cannot take yet are queued, no new exchange is
opened while one waits, and a drain is not complete until they are delivered.
A response that ends before the request ends the exchange, and the module
stops reading the request body.

A LINK DOWN from the application says every exchange it holds without a
complete response is unknowable. The server cannot issue a request whose body
it has already streamed a second time, so it answers each for the application:
502 before the response began, a cut-off response after.

**Graph wiring.** The two edges are framed, and the build gives each a mailbox
of its own, so one write is one whole record; a graph names the ports and
nothing else.

```yaml
- from: http.request_out
  to: app.request_in
- from: app.response_out
  to: http.response_in
```

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
