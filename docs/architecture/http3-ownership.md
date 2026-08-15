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
linux_net  <--UDP-->  quic (alpn=h3)  <--mux stream records-->  http (h3=1)
```

## What each side does

**Fluxor `quic`** surfaces every REQUEST stream on an ALPN-negotiated h3
connection over `mux`. This is not a mode — it is what the transport does, and
there is no alternative path, because there is no longer a responder to take.
The connection preamble — the h3 control and QPACK unidirectional streams, and
SETTINGS — stays in `quic`: stream-type plumbing is connection-scoped and no
request can flow before it. Only request streams cross the seam.

**Wave `http`** takes `h3 = 1`, which routes `module_step` to the mux pump instead
of the net_proto server loop. The same pump carries the h3 CLIENT: a client
request opens a mux stream and rides the identical contract, so the transport
stays protocol-free in both directions. Decode, dispatch and response framing are I/O-free
— no syscalls, no channels, no clock — so the protocol is testable without a
socket, which is why the concurrency tests can exist at all.

## Why the protocol did not belong in the transport

Not because the transport was incapable. `quic`'s HTTP/3 responder handled
concurrent bidi streams and accumulated POST bodies. The reason was what it
served:

> `/// Server-side: hardcoded route table.` `GET /` returns "hello h3"; anything
> else returns 404.

Three entries, compiled in. That is a **transport self-test** — the right thing
to have when bringing up QUIC, and not an HTTP server. Serving real content needs
routes, static/template/file/proxy handlers, dynamic route updates, content
types, request spans, range requests, and documented deviations against all of
it. That exists in Wave's `http`, which already owns HTTP/1.1 and HTTP/2. So the
question was never who *could* implement HTTP/3, but whether the protocol should
be implemented twice — about 2,500 lines across `h3.rs`, `qpack.rs` and `ws.rs`
were carried in both places, and a fix to either QPACK did not reach the other.

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

The scenario was also proven able to **fail**, which matters more than the pass.
While `quic` still had its responder, flipping the graph to `h3_app: 0` +
`enable_h3: 1` left the board serving HTTP/3 perfectly well — from the hardcoded
fixture — and the run failed with `body=b'hello h3\n' lacks 'wave h3 on pi5'`. A
scenario asserting only "200 OK" would have passed that, while measuring the
wrong implementation. That particular substitution is no longer constructible,
which is the point of removing the fixture, but the assertion stays as written:
it is what distinguishes serving content from answering a request.

## The duplication is gone

**Decision, now carried out: all HTTP logic is Wave's, QUIC is Fluxor's.** `quic`
has shed `qpack.rs` and `ws.rs` entirely, its hardcoded three-entry route table,
its client request path, and the `h3.request` span — roughly 2,500 lines. `h3.rs`
survives at a fifth of its former size, holding the connection preamble alone:
frame header build/parse and the control-stream SETTINGS / GOAWAY /
PRIORITY_UPDATE codecs. What `quic` keeps is packets, keys, recovery, congestion
control and stream lifecycle. The seam did not move; it was already the right
one.

This reversed what this document previously concluded, and it is worth being
explicit about why, because the earlier reasoning was sound on the facts it had:

1. **"It has a client side."** It did, and Wave did not. Wave now does —
   `step_mux_client` rides the same mux contract the server does — so keeping a
   second HTTP/3 to preserve a capability no longer preserves anything.
2. **"It is Fluxor's QUIC self-test, and the dependency direction forbids the
   alternative."** The dependency direction is unchanged and still forbids
   testing `quic` through Wave. What changed is the recognition that this is a
   *testing* requirement, not an ownership one, and it is satisfied by a
   fixture at the `mux` layer — the surface `quic` actually exposes — rather
   than by a second HTTP server maintained for the purpose.

**The replacement self-test landed before the deletion, not after.** That was
the one hard ordering constraint: Fluxor must remain able to prove its own
transport carries a multiplexed exchange using only Fluxor, and a window where
that is untrue is a window where a QUIC regression has nothing to catch it. The
replacement is `mux_echo` driven by `quic_mux_loopback.yaml` and gated by
`../fluxor/tests/harness/tests/quic_mux_selftest.rs` — a real loopback handshake, a real
multiplexed exchange, asserted on the property a transport actually owes its
application: bytes come back on the stream they were sent on, byte for byte, and
the exchange repeats rather than working once and wedging.

The peer's own limits cross the seam too, in the other direction. They arrive
on the h3 control stream, which only the transport reads, but every one of them
constrains how a REQUEST is encoded — so `quic` forwards them as
`MSG_MUX_PEER_SETTINGS` and Wave enforces them. Two details decide whether that
is safe: an ABSENT `SETTINGS_MAX_FIELD_SECTION_SIZE` means unlimited while an
advertised `0` forbids header sections outright, so the unset state is a
`u32::MAX` sentinel rather than a zero that would silently refuse every
response; and the wire type is a varint up to 2^62 against a `u32` field, where
truncating `2^32` yields `0` and wedges the connection, so it saturates. Both
are gated, and both gates were verified by mutation.

Two further gates hold the line now that the code is out.
`../fluxor/tests/harness/tests/quic_telemetry.rs` asserts `quic.connection` is the ONLY
span the transport emits, so a protocol span cannot reappear below Wave's and
start double-counting requests. And the retired parameter tags — 8
(`enable_ws`), 10 (`enable_concurrent_bidi`), 13 (`h3_app`) — are recorded as
retired rather than reused, so a graph still carrying one gets a clean
"unknown param" from the composer instead of silently binding to whatever
took the tag.

With `quic` carrying no QPACK, the RFC 7541 Huffman table has one home and the
"share it through the SDK to point the right way down the dependency graph"
workaround is unnecessary.

## Open

- **File and proxy routes are not shared with h3.** They thread more than a
  cursor through `server::cur_slot_mut` — file handles, relay connection state —
  so dispatch reports `HandlerNotShared(id)` rather than serving one concurrent
  request correctly and the rest wrongly.
- **File and proxy routes answer 501 over h3, and that is the end state for
  now.** They are single-in-flight by construction — `render_file_into` pulls
  from ONE module-scoped `file_chan`, and the proxy threads a relay connection —
  so "sharing" them with h3 would serialise every stream on a connection behind
  one file, which is worse than not offering them. Per-stream file channels are
  a storage-contract change, not an h3 one. Until then the answer is a 501 with
  a body naming the situation, plus `http.h3.handler_unavailable`, so it reads
  as the configuration fact it is.
