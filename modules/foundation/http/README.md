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
| `full` (default) | `http.fmod` | h1, h2, ws, h3, app |
| `exchange` | `http-exchange.fmod` | `full` plus the graph-driven client |
| `h2` | `http-h2.fmod` | h1, h2, ws, app |
| `app` | `http-app.fmod` | h1, app |
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
| `req_out` / `resp_in` | 6 | out / in | `HttpRequest` / `HttpResponse` | Application fan-out (handler 11) |
| `ws_admit_out` / `ws_admit_in` | 7 | out / in | `OctetStream` | WebSocket admission request and decision |
| `ws_event_out` | 8 | output | `OctetStream` | Committed WebSocket lifecycle facts |
| `publish_in` | 8 | input | `OctetStream` | Graph-driven client requests (`exchange` variant) |
| `reply_out` | 9 | output | `OctetStream` | Graph-driven client responses (`exchange` variant) |
| `peer_identity` | 9 | input | `OctetStream` | Verified peer from a mutual-TLS handshake |

Indices are per direction, so an input and an output may share a number
without sharing an edge. Every port past the first is optional: a graph wires
what its deployment uses, and an unwired port is silent rather than an error.

## Parameters

`mode` (0 server / 1 client), `port`, `body`, `path`, `host_ip`, `protocol`,
`request_body`, `websocket`, `host_tcp`, `grpc`, then eight route blocks of
`route_N_{path,body,handler,proxy_ip,proxy_port,source,content_type,fs_path,fs_list,fs_filter}`,
and the high-tag set: `routes_prefix`, `listeners_prefix`, `max_body_kib`,
`content_type`, `surface_status`, then the connection-lifetime set
`header_timeout_ms`, `keepalive_idle_ms`, `pressure_idle_ms`, `stall_ms`,
`ws_idle_ms`.
Tags are wire positions: append, never renumber.

Two shape the client's requests and its answers:

- `content_type` labels a composed request body, or is left empty to send no
  `Content-Type` at all. A server that accepts a typed body may refuse one that
  arrives unlabelled.
- `surface_status` decides what an upstream failure looks like on the exchange
  surface. Left at zero, a response is a successful exchange whatever its
  status, and an error body is the answer — which is what most consumers want.
  Set, a status of 400 or above answers as a typed refusal carrying the code,
  so a producer can retry a 503 and discard a 404 without parsing a payload
  whose shape it does not know.

## Connection lifetime

Nothing else on the path closes an established connection that stops
talking — not `tls`, and not `ip`, whose timers cover SYN retransmit and
unacknowledged data only. So the server keeps one wall-clock stamp per
connection, moved by every byte the peer sends, every byte the transport
takes, and every response completed, and closes a connection whose stamp is
older than the limit for its phase. The header limit is the exception: it is
measured from the moment the wait for a head began, not from the last byte,
so a head trickled one byte at a time is bounded in total. Milliseconds; 0
disables a limit.

| Waiting for | Limit | Default | Counter |
|---|---|---|---|
| a complete request head, from accept or from the first byte of the next request | `header_timeout_ms` | 10 000 | `conns_timeout_header` |
| the next request on a keepalive | `keepalive_idle_ms`, or `pressure_idle_ms` once the slot table is three quarters full | 60 000 / 2 000 | `conns_timeout_idle` |
| a body still arriving, a response still draining, a proxy relay, a cache stream to the client | `stall_ms` | 15 000 | `conns_timeout_stall` |
| a WebSocket frame (ping at half, close 1001 at full) | `ws_idle_ms` | 0 (off) | `conns_timeout_idle` |
| an HTTP/2 or HTTP/3 request on an open session | the keepalive limit; GOAWAY then close | | `conns_timeout_idle` |

The application fan-out keeps its own 30 s deadline (`app_timeouts`), and a
phase that is waiting on this server rather than on the peer — the file
provider, the admission decision — is not measured.

An accept that finds no free slot closes the longest-idle keepalive
connection and takes its slot, counted as `conns_evicted_idle`; a new caller
is never refused in favour of a silent one. That, and the pressure limit, are
what let the table empty again when load falls. The `[http] state` heartbeat
reports `act=` (slots allocated now) and `hw=` (the peak since boot), so a
capture shows both.

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
stream it served, an HTTP/3 session with no open stream is sent GOAWAY naming
the first request it will not process and then closed, and a WebSocket tunnel —
over either generation — is sent a `1001 going away` close. Each of those is an
ending the peer can act on, where waiting for the peer to close first would
simply never finish.

Admission stops the moment the drain begins. A connection accepted afterwards is
closed rather than served, and a new HTTP/3 stream is refused; the GOAWAY
identifier tells the peer which requests it may re-issue elsewhere. Bytes for
work already accepted keep flowing, because that work still has to finish.

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

### Who is calling

A TLS handshake establishes who the peer is. The request that follows is where
an application decides what that peer may do, and the two facts arrive on
different channels: the identity on `peer_identity`, the request on the
transport. Joining them is this module's job.

When `peer_identity` is wired and a handshake verified the peer, the request
envelope sets flag bit 1 and carries the peer's key fingerprint as a trailer
after the body — `[svid_len u16 LE][svid]`, past every length in the fixed
head. A consumer that does not read the flag sees exactly what it saw before.

A trailer rather than a synthetic header such as `X-Forwarded-Client-Cert`: a
header is forgeable by the client unless the server strips every copy of it
first, and one missed strip promotes an anonymous caller to whoever it claims
to be. A trailer sits in a structure the client cannot reach.

An identity binds only for a handshake that succeeded, whose certificate chain
validated, and whose peer proved possession of the key. A certificate that was
merely presented is a different fact from a peer that was authenticated. The
identity is held against the CONNECTION rather than the request, because it
arrives once per handshake — often before the accept it belongs to — and it is
released the moment the connection ends, since connection ids are recycled and
a stale entry would authenticate the next holder as the previous one.

Wire nothing and every request is anonymous, with no trailer and no flag. The
`peers_unbound` counter is the signal that something in between is wrong:
non-zero on a listener configured for mutual TLS means callers are reaching the
application anonymous, which nothing at request level shows — the request
succeeds, and the application simply never learns who made it.

## Exchange delivery

A terminal reply and its correlation remain resident until `reply_out` accepts
that exact frame. Backpressure prevents the next request from being admitted.
Drain refuses an in-flight request, preserves an already completed reply, closes
the transport, and reports quiescence only after the reply is delivered. An
unread reply holds a bounded amount of state; the module does not report a
successful drain while discarding it. Applications still need idempotency for
retries after transport or process failure.

## HTTP/1 client response framing

Response heads are bounded to 2048 bytes. The client accepts up to 16
informational responses before a final response, streams Content-Length and
chunked bodies, and completes an unframed body only at EOF. Truncated bodies,
malformed or conflicting framing, unsupported transfer codings and malformed
trailers fail the exchange. HEAD, 204 and 304 complete at their bodyless framing
boundary. A full output channel retains both decoded and unread transport bytes.

The client uses separate wall-clock deadlines: `client_header_ms` (15000) is
absolute from request transmission to a final response head, `client_stall_ms`
(15000) bounds lack of byte progress, and `client_total_ms` (60000) bounds the
whole request including connect and blocked output. Zero disables an individual
limit. A trickled header does not restart its head deadline.

## HTTP/1 client connections

The client speaks HTTP/1.1. `authority` (parameter 112, up to 128 bytes,
default `localhost`) selects the Host header, falling back to the configured
IP. `method` (parameter 113) takes the same verb codes the request envelope
carries, and defaults to GET.

`client_keep_alive` (parameter 114, default 0) lets one connection to an origin
serve exchanges in sequence. Only a complete, reusable response returns its
connection to that bounded pool; a peer close, an idle expiry
(`client_stall_ms`), a failure and a drain each retire it. A request is never
replayed automatically, so a connection that dies mid-exchange fails that
exchange rather than repeating a side effect. With keep-alive off, the client
closes at completion.

## HTTP/3 client requests

An HTTP/3 request is composed from the same `path`, `body`, `content_type`,
`authority` and `method` parameters, and the head/stall/total deadlines apply
unchanged. A configured field too large for its buffer fails the request rather
than being truncated.

HEADERS and DATA are split to the mux provider's send bound and retained across
a refusal, with FIN following the complete body. Response DATA streams through
bounded staging independently of frame length, while a response header block
stays capped at 1024 encoded bytes. Status, Content-Length, informational
responses, trailers, stream identity, FIN, reset and session closure are all
validated before an exchange completes. CONNECT is rejected: a tunnel needs an
interface of its own, and answering it on the request path would give a caller
a tunnel that silently is not one.

## Declared deviations

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

There is no second implementation to reconcile with: Fluxor's `quic` carries
no QPACK and no HTTP/3 responder of its own, so QPACK exists once in the
stack, here. See `docs/architecture/http3-ownership.md`.

## WebSocket admission

A route using the admission handler does not grant its own upgrade. The
request is reported on `ws_admit_out` — connection id, path, headers and
requested subprotocols — and the 101 is composed only when a decision naming
that connection arrives on `ws_admit_in`. An accept may name the subprotocol to
echo; a refusal carries an HTTP status and a bounded reason.

The distinction that matters is when. A gate downstream of a completed upgrade
can refuse to act on frames, but the socket is already open and the peer already
believes it is talking to the application. Here nothing downstream ever sees a
frame from a connection it did not admit.

`ws_event_out` carries what happened rather than what was asked for: `opened`
once the upgrade is on the wire, and `closed` once the connection has actually
ended, with its origin and close code. A connection that never opened owes no
closure.

A decision that never arrives is refused on the module's own deadline with a
503, so a browser is never left holding an upgrade forever. Any decision byte
that is not an explicit accept refuses.
