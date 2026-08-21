# `http` — HTTP/1.1, HTTP/2 and HTTP/3 server and client

One module carrying the server, the HTTP/1 and HTTP/2 clients, the WebSocket
upgrade path, and the gRPC-over-HTTP/2 composition.

## Roles

| Role | Generation | State |
| --- | --- | --- |
| Server | HTTP/1.1 | Implemented, on silicon, curl-verified |
| Server | HTTP/2 (h2c + ALPN) | Implemented, on silicon, load-tested |
| Server | WebSocket (RFC 6455 upgrade + fan-out) | Implemented, on silicon |
| Server | gRPC (HEADERS/DATA/trailers) | Implemented, verified against `grpcio` |
| Server | Application fan-out (`HANDLER_APP`) | Implemented on h1 + h2 |
| Client | HTTP/1 | Implemented — speaks **HTTP/1.0** (see deviations) |
| Client | HTTP/2, incl. gRPC and WS-over-h2 (RFC 8441) | Implemented |
| Server | HTTP/3 | Implemented — served end to end over `quic`, verified against aioquic |

## Variants

`[[variant]]` in `manifest.toml` selects the feature set. A target takes only the
generations it serves:

| Variant | Artefact | Features |
| --- | --- | --- |
| `full` (default) | `http.fmod` | h1, h2, ws, h3 |
| `h2` | `http-h2.fmod` | h1, h2, ws |
| `web` | `http-web.fmod` | h1, ws |

The point is flash. `web` is roughly 45% smaller than `full`, which is what makes
the h1-only path viable on rp2350. Each artefact is held to a byte ceiling and to
the subset relation — `http-web` strictly smaller than `http-h2`, which is
strictly smaller than `http` — so a variant cannot quietly stop paying for
itself. Current sizes are not repeated here, because a number in prose is a
number that rots.

`h1` and `ws` are declared markers, always compiled. A `min` (h1-only) variant
would need the WebSocket seams gated first. Most of that code is now one file
(`server/ws.rs`), but the call sites are not: ~145 `ws` references remain
scattered across the core, `h1`, `h2` and `h3`, because a WS tunnel is reachable
from every generation. The prize is small either way — the ws-attributable
*named* symbols in `http-web.elf` are ~1.2 KiB, the rest being inlined into the
shared request path — so it is worth doing against a specific flash target the
`web` variant misses, not on principle.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `net_in` / `net_out` | 0 | in / out | `NetProto` | Transport events and commands |
| `variables` | 1 | input | `FmpMessage` | Template variable updates |
| `file_data` | 2 | input | `OctetStream` | Body bytes for file-backed routes |
| `file_ctrl` | 1 | output | `OctetStream` | File request control |
| `ws_out` / `ws_in` | 2 / 3 | out / in | `WsFrame` | WebSocket fan-out (handler 5) |
| `routes_sink` / `routes_changes` | 4 | out / in | `OctetStream` | Compiled-route subscription self-edge |
| `listeners_sink` / `listeners_changes` | 5 | out / in | `OctetStream` | Dynamic-listener subscription self-edge |

## Parameters

`mode` (0 server / 1 client), `port`, `body`, `path`, `host_ip`, `protocol`,
`request_body`, `websocket`, `host_tcp`, `grpc`, then eight route blocks of
`route_N_{path,body,handler,proxy_ip,proxy_port,source,content_type,fs_path,fs_list,fs_filter}`.
Tags are wire positions: append, never renumber.

## Timing

`timer_class = "wall_clock"` — the client connect timeout and the proxy dial and
retry deadlines all read `dev_millis`. Nothing counts scheduler passes as time.

## Draining

Asked to shut down, the server stops answering and reports itself finished only
once nothing it accepted is still outstanding — a request mid-parse, one waiting
on an application, and a response still flushing all hold the drain open until
they end.

Connections themselves are not outstanding work, and the distinction is what
makes the drain terminate at all: a keep-alive connection between requests is
closed, an HTTP/2 connection with no open stream is sent GOAWAY naming the last
stream it served, and a WebSocket tunnel is sent a `1001 going away` close. Each
of those is an ending the peer can act on, where waiting for the peer to close
first would simply never finish.

## Methods and request bodies

The server recognises `GET HEAD POST PUT PATCH DELETE OPTIONS CONNECT` on both
h1 and h2, from one table (`wire/method.rs`). A well-formed request naming
anything else is **501**, not 400 — the bytes were fine, the method is not
implemented. One table for both generations is what makes a request mean the
same thing whichever carried it.

Request bodies are read and bounded: `Content-Length`, `Transfer-Encoding:
chunked`, and `Expect: 100-continue` (which `docker push` and `curl -T` send and
then WAIT for). A message carrying BOTH framing headers is refused with 400
rather than resolved in favour of one — RFC 9112 §6.3, and the reason is request
smuggling, not tidiness. Over `max_body_kib` is 413 on h1 and RST_STREAM on h2.

A body is consumed even when the matched route has no use for it: bytes left in
the receive buffer are read as the beginning of the next request on a keep-alive
connection.

## Application fan-out

`HANDLER_APP` (route key `app: true`) forwards a matched request to a downstream
graph node on `req_out` and serves its `resp_in` answer. The module keeps HTTP;
the application keeps what the request means — the split
`docs/specification.md` draws.

Envelope layouts, correlation, backpressure, streaming and the required
`buffer_group:` on both edges are documented in
[`docs/architecture/http_multiconn.md`](../../../docs/architecture/http_multiconn.md),
which shows the two edges alongside them.

Behind the `app` feature, so the `web` variant does not carry it — an rp2350
serving h1 from config should not pay for a handler that forwards to a module it
does not run.

## Declared deviations

- **The HTTP/1 client speaks HTTP/1.0**, with a `Host` header. Legal, and
  deliberate, but it means no keep-alive: one connection per request.
- **`bytes=500-499` returns 416** where RFC 7233 §3.1 says an unsatisfiable-looking
  range whose first-byte-pos exceeds last-byte-pos should be ignored (→ 200).
  Preserved from the origin rather than corrected.
- **An unterminated header block after a valid request line does not 400.** The
  `>= RECV_BUF_SIZE → 400` guard only fires when no request line has arrived; the
  slot is held and reaped by the transport's per-connection timeout instead.

## HTTP/3 — what exists and what does not

**What exists:**

- the frame layer — varint type/length framing, truncation, grease types, and
  request-stream frame legality (RFC 9114 §7.1);
- QPACK — the static table, the prefixed-integer codec, block prefix, and field
  lines including **Huffman-coded names and values** (RFC 9204 §4.1.2 reuses the
  RFC 7541 table, shared with HPACK as `modules/common/huffman_core.rs`);
- the **request header section decoder** — pseudo-header extraction with the
  RFC 9114 §4.3 message rules enforced (mandatory pseudo-headers, no repeats, no
  pseudo after a regular field, lowercase field names), a bounded path, and
  `content-length`;
- RFC 9220 extended CONNECT recognition (`:protocol: websocket`);
- the **response encoder** — QPACK field section plus HEADERS/DATA framing, all
  or nothing;
- per-frame request-stream ingest returning headers, a DATA payload range, or an
  RFC 9114 §8.1 error code;
- **dispatch** — a decoded request matched against the module's real route table
  and a `HANDLER_STATIC` route rendered from the same body pool h1 and h2 serve
  from, with the route's own content type, and a self-rendered 404 on a miss.

- the **stream-multiplexed pump** — `pump_stream_in` / `pump_next_out` over
  `[stream_id u64][flags][len u16][payload]` records, the same envelope
  `ws_stream` uses to multiplex WebSocket frames. Four concurrent request slots,
  each with its own accumulator and response buffer, round-robin emission, and
  refusal rather than overwriting when the table is full. Two requests can be
  served concurrently over one connection.

**How it is wired:** Fluxor's `quic` surfaces h3 request streams over the `mux`
contract — an `h3` ALPN is all it takes, since the transport has no responder of
its own to displace; `http` with `h3 = 1` consumes them on its
ordinary `net_in`/`net_out` (mux opcodes are disjoint from net_proto's, so one
channel pair carries both). The full path interoperates with **aioquic**.

**Handlers served over h3:** `HANDLER_STATIC` and `HANDLER_TEMPLATE`. Templates
go through the *same* renderer h1 and h2 use — `render_template_route_into`,
which is `render_template_into` with its two connection-scoped dependencies
(which route, how far through the body) lifted into parameters. HTTP/1 and
HTTP/2 pass their per-connection slot; HTTP/3 passes its per-STREAM slot,
because it multiplexes and a connection-scoped cursor would interleave two
responses into each other. A template that does not fit the scratch is refused,
never truncated — a truncated page renders, looks complete, and is missing
whatever came after the cut.

**WebSocket over HTTP/3 (RFC 9220)** is served too. An extended CONNECT
(`:method CONNECT`, `:protocol websocket`) on a `HANDLER_WEBSOCKET` route is
answered with a bare 200 — no `Sec-WebSocket-Accept`, which is an HTTP/1
handshake header with no meaning here (RFC 8441 §5.1) — and the stream becomes a
tunnel carrying RFC 6455 frames inside h3 DATA frames. The frame layer is
`wire::ws`, unchanged: it is transport-agnostic, which is why WebSocket did not
have to be written a third time.

What *was* new is the lifecycle, and it is the reason this took a separate
piece of work: a request slot is released the moment its response drains, and a
tunnel must outlive the 200 that opened it. Client frames must be masked
(RFC 6455 §5.3), PING draws a PONG, and CLOSE ends the tunnel.

**Not served over h3:** file and proxy routes. Those thread more than a cursor
through `server::cur_slot_mut` — file handles, relay connection state — so
dispatch answers **501** and names the handler: not a 404 (the route exists),
not a 500 (nothing failed), not a stream reset (nothing is wrong with the
connection), and not a path that happens to work for exactly one concurrent
request. `http.h3.handler_unavailable` counts it, so the mismatch is visible to
whoever configured the route and not only to the client that hit it.

There is no longer a second implementation to reconcile with: Fluxor's `quic`
has shed its own `qpack.rs` and `h3.rs` responder, so QPACK exists once in the
stack, here. See `docs/architecture/http3-ownership.md`.
