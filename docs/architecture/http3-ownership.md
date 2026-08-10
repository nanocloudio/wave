# HTTP/3: who owns what, and how the seam works

**Decision.** Wave owns the HTTP/3 protocol — framing, QPACK, request and
response semantics, and stream multiplexing. Fluxor's `quic` owns the transport —
packets, keys, loss recovery, congestion control, stream lifecycle — and exposes
accepted streams as **stream-addressed records** on its existing application
ports. Wave's `http` consumes those records in h3 mode.

This is not a new boundary. It is the one
[`../specification.md`](../specification.md) states: Wave owns "HTTP/3
request/response semantics, QPACK, and request-stream multiplexing above QUIC",
and does not own "QUIC transport, congestion control, recovery, packet
protection, streams, or endpoint lifecycle".

## The seam: Fluxor's `mux` contract, not a new one

Fluxor's `mux` contract is public and stable, and already describes exactly this
surface (`../fluxor/modules/sdk/contracts/net/mux.rs`, synced into `target/fluxor/`):

> The multiplexed session surface is a channel contract for transports that
> expose many logical streams or message channels over one transport
> association. Intended consumers: QUIC engines (the canonical case)…

It carries `MSG_MUX_STREAM_ACCEPTED` / `_RX` / `_CLOSED` and
`CMD_MUX_STREAM_SEND` with `[session_id u32][stream_id u32][data]`, and `quic`
already implements it for non-h3 ALPN — where, in its own words, "the app, e.g.
an mqtt codec, owns the protocol". So HTTP/3 needs **no new envelope**: the h3
path is another app on a surface Fluxor defines and `quic` already speaks. The
only change is that an h3-negotiated connection may use it.

Two consequences, and they are why this costs so little:

- **No new content type.** Fluxor owns the registry; Wave consumes those names
  without assigning replacements.
- **No new ports.** The mux opcode range (0xB0..0xCF) is disjoint from
  net_proto's, and the contract states that "a single channel pair may carry
  multiple contracts unambiguously". `http` consumes h3 on the same
  `net_in`/`net_out` it uses for h1 and h2, and leaves frames that are not its
  own alone.

It also matches how TLS is wired — a module placed *between* the transport and
the protocol, so the same protocol code serves both schemes. The h3 analogue is
that shape with a different contract on the seam:

```text
linux_net  <--UDP-->  quic (h3_app=1)  <--mux stream records-->  http (h3=1)
```

## What each side does

**Fluxor `quic`** takes one parameter, `h3_app`. With it set, an ALPN-negotiated
h3 connection surfaces its REQUEST streams over `mux` instead of answering them
from its own table. The connection preamble — the h3 control and QPACK
unidirectional streams, and SETTINGS — stays in `quic`: stream-type plumbing is
transport-adjacent, and the client mode needs it regardless. Only request streams
cross the seam.

**Wave `http`** takes `h3 = 1`, which routes `module_step` to the mux pump instead
of the net_proto server loop. Decode, dispatch and response framing are I/O-free
— no syscalls, no channels, no clock — so the protocol is testable without a
socket, which is why the concurrency tests can exist at all.

## Why the protocol does not belong in the transport

Not because the transport is incapable. `quic`'s own HTTP/3 responder handles
concurrent bidi streams and accumulates POST bodies. The reason is what it
serves:

> `/// Server-side: hardcoded route table.` `GET /` returns "hello h3"; anything
> else returns 404.

Three entries, compiled in. That is a **transport self-test** — the right thing
to have when bringing up QUIC, and not an HTTP server. Serving real content needs
routes, static/template/file/proxy handlers, dynamic route updates, content
types, request spans, range requests, and documented deviations against all of
it. That exists in Wave's `http`, which already owns HTTP/1.1 and HTTP/2. So the
question is not who *could* implement HTTP/3, but whether the protocol should be
implemented twice — about 2,500 lines across `h3.rs`, `qpack.rs` and `ws.rs` are
carried in both places today, and a fix to either QPACK does not reach the other.

## Status: served end to end

`tools/e2e/h3_server.sh` boots `examples/linux/wave_h3.yaml` and drives it with
**aioquic**, an independent HTTP/3 implementation sharing no lineage with either
repository. It asserts routed bodies (not a fixture), a Wave-rendered 404,
repeated connections, and two requests multiplexed on one connection:

```
   ok  / -> 200 wave h3 ok
   ok  /health -> 200 ok
   ok  /nowhere -> 404 Not Found
   ok  4 further connections served
   ok  both streams served on one connection
```

Not curl: this host's curl is built against OpenSSL 3.5, whose QUIC client fails
before sending a packet (`error:0A0003E7:SSL routines::invalid session id`). The
server never sees the connection, so it says nothing about the server.

The end-to-end gate is load-bearing rather than ceremonial. Three defects reached
it that every unit test had passed — the class that only appears when real bytes
cross a real seam, where the fault is in the wiring between correct components
rather than in either component.

## WebSocket over HTTP/3 (RFC 9220)

Wave serves it. Extended CONNECT on a `HANDLER_WEBSOCKET` route is answered with
a bare 200 — no `Sec-WebSocket-Accept`, which is an HTTP/1 handshake header (RFC
8441 §5.1) — and the stream becomes a tunnel carrying RFC 6455 frames inside h3
DATA frames. `wire::ws` is unchanged and transport-agnostic, so one frame
implementation serves h1, h2 and h3.

The lifecycle is the substance: a request slot is released when its response
drains, but a tunnel must outlive the 200 that opened it, so `pump_next_out`
rewinds a tunnel's cursor instead of releasing its slot. Mutation-verified —
releasing the slot on drain, accepting unmasked client frames, answering PING
with PING, and upgrading a non-WebSocket route each fail exactly the test that
names them.

## Proven on silicon

`tests/hardware/pi5_wave_h3.toml` — three consecutive passes on the pi5 rig, each
from its own power cycle and each a fresh boot by evidence: the probe polls QUIC,
finds nothing, and reports the board answering ~14 s later rather than replying
from the previous kernel. The kernel side is clean — no PANIC, no `rc=-110`, no
dropped frames, `bna=0 ovr=0`.

The scenario is also proven able to **fail**, which matters more than the pass.
Flipping the graph to `h3_app: 0` + `enable_h3: 1` leaves the board serving
HTTP/3 perfectly well — from `quic`'s hardcoded fixture — and the run fails with
`body=b'hello h3\n' lacks 'wave h3 on pi5'`. A scenario asserting only "200 OK"
would have passed that, while measuring the wrong implementation.

## The duplication stays, and the boundary is narrower than it looks

`quic`'s HTTP/3 is not a copy awaiting deletion. Two reasons:

1. **It has a client side.** `h3_encode_request_headers`, the client request path
   and `quic_h3_client.yaml` have no counterpart in Wave, whose h3 is server-only.
   Removing them would delete a capability nothing replaces.
2. **It is Fluxor's QUIC self-test, and the dependency direction forbids the
   alternative.** Six paired example graphs (server/client, ws, concurrent) let
   Fluxor prove its transport carries an HTTP/3 exchange using only Fluxor. Wave
   depends on Fluxor, never the reverse, so Fluxor cannot test `quic` through
   Wave's `http`. Deleting the responder would leave the transport testable only
   from another repository.

So the split is:

- **Wave's h3 is the server** applications use — routes, handlers, spans,
  everything an HTTP server is. `h3_app = 1` selects it.
- **`quic`'s h3 is a transport self-test and an h3 client.** Its hardcoded
  three-entry table is the right size for that job.

What is worth deduplicating is the RFC 7541 Huffman table, which exists in Wave's
`modules/common/huffman_core.rs` and again in `quic`'s `qpack.rs`. Sharing it has
to go through Fluxor's SDK, because that is the one source both sides already
`include!` and it points the right way down the dependency graph.

## Open

- **File and proxy routes are not shared with h3.** They thread more than a
  cursor through `server::cur_slot_mut` — file handles, relay connection state —
  so dispatch reports `HandlerNotShared(id)` rather than serving one concurrent
  request correctly and the rest wrongly.
- **Client-side h3 is untouched.** `quic`'s client path owns it.
