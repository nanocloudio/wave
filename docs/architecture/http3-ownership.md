# HTTP/3: who owns what, and how the seam works

Wave owns the HTTP/3 protocol — framing, QPACK, request and response
semantics, and stream multiplexing. Fluxor's `quic` owns the
transport — packets, keys, loss recovery, congestion control, stream
lifecycle — and exposes accepted streams as stream-addressed records
on its application ports. Wave's `http` consumes those records in h3
mode, as client and as server.

This is the boundary [`../specification.md`](../specification.md)
states: Wave owns "HTTP/3 request/response semantics, QPACK, and
request-stream multiplexing above QUIC", and does not own "QUIC
transport, congestion control, recovery, packet protection, streams,
or endpoint lifecycle".

Source: `modules/foundation/http/server/h3.rs`,
`modules/foundation/http/client/h3.rs`,
`modules/foundation/http/wire/`.

## The seam: fluxor's `mux` contract, not a new one

Fluxor's `mux` contract is the multiplexed session surface for
transports that expose many logical streams over one association,
and it names QUIC as its canonical provider. It carries
`MSG_MUX_STREAM_ACCEPTED` / `_RX` / `_CLOSED` and
`CMD_MUX_STREAM_SEND` with `[session_id u32][stream_id u32][data]`;
the client side adds `CMD_MUX_STREAM_OPEN` / `MSG_MUX_STREAM_OPENED`
and `CMD_MUX_STREAM_CLOSE`. HTTP/3 needs no new envelope: the h3
path is another application on a surface fluxor defines. Two
consequences:

- **No new content type.** Fluxor owns the registry; Wave consumes
  those names without assigning replacements.
- **No new ports.** The mux opcode range (`0xB0..0xCF`) is disjoint
  from `NetProto`'s, and a single channel pair may carry multiple
  contracts unambiguously. `http` consumes h3 on the same
  `net_in`/`net_out` it uses for h1 and h2, and leaves frames that
  are not its own alone.

It also matches how TLS is wired — a module placed between the
transport and the protocol, so the same protocol code serves both
schemes. The h3 analogue is that shape with a different contract on
the seam:

```yaml
- { from: linux_net.net_out, to: quic.net_in }
- { from: quic.net_out,      to: linux_net.net_in }
- { from: quic.app_out,      to: http.net_in }
- { from: http.net_out,      to: quic.app_in }
```

## What each side does

**Fluxor's `quic`** surfaces every request stream on an
ALPN-negotiated h3 connection over `mux`. The connection preamble —
the h3 control and QPACK unidirectional streams, and SETTINGS —
stays in `quic`: stream-type plumbing is connection-scoped and no
request can flow before it. Only request streams cross the seam.

**Wave's `http`** takes `h3 = 1`, which routes `module_step` to the
mux pump instead of the `NetProto` server loop. The same pump
carries the h3 client: `step_mux_client` opens a mux stream per
request and rides the identical contract, so the transport stays
protocol-free in both directions. Decode, dispatch and response
framing are I/O-free — no syscalls, no channels, no clock.

The pump multiplexes per-stream buffers with round-robin emission
and bounded refusal when the slot table is full. Implemented in
full: the RFC 9114 frame layer; QPACK including Huffman-coded names
and values; the request header decoder with RFC 9114 §4.3 message
rules; RFC 9220 extended CONNECT recognition; the response encoder
and framing; and dispatch against the real route table. Templates
use the same renderer h1 and h2 do, with the route and body cursor
lifted into parameters so each generation supplies its own — a
connection slot for h1 and h2, a stream slot for h3.

## Peer settings cross the seam too

The peer's limits arrive on the h3 control stream, which only the
transport reads, but every one of them constrains how a request or
response is encoded — so `quic` forwards them as
`MSG_MUX_PEER_SETTINGS` and Wave enforces them. Two details decide
whether that is safe. An absent `SETTINGS_MAX_FIELD_SECTION_SIZE`
means unlimited while an advertised `0` forbids header sections
outright, so the unset state is a `u32::MAX` sentinel rather than a
zero that would silently refuse every response. And the wire type is
a varint up to 2^62 against a `u32` field, where truncating `2^32`
yields `0` and wedges the connection, so the decode saturates.

The same message carries the extended-CONNECT sideband: the
`PEER_SETTINGS_FLAG_ENABLE_CONNECT` bit tells Wave whether the peer
advertised RFC 9220 support.

## WebSocket over HTTP/3 (RFC 9220)

Wave serves it. Extended CONNECT on a WebSocket route is answered
with a bare 200 — no `Sec-WebSocket-Accept`, which is an HTTP/1
handshake header (RFC 8441 §5.1) — and the stream becomes a tunnel
carrying RFC 6455 frames inside h3 DATA frames. The frame codec
(`modules/foundation/http/wire/ws.rs`) is transport-agnostic, so one
frame implementation serves h1, h2 and h3.

The lifecycle is the substance: a request slot is released when its
response drains, but a tunnel must outlive the 200 that opened it,
so the pump rewinds a tunnel's cursor instead of releasing its slot.

## Limitations

File and proxy routes are not shared with h3, and answer 501. They
are single-in-flight by construction — the file path pulls from one
module-scoped file channel, and the proxy threads a relay
connection — so sharing them with h3 would serialise every stream on
a connection behind one file, which is worse than not offering them.
Per-stream file channels are a storage-contract change, not an h3
one. The 501 carries a body naming the situation, and the
`http.h3.handler_unavailable` telemetry counter names the handler,
so it reads as the configuration fact it is.
