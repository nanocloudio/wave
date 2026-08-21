# `rtp` — RFC 3550 transmitter and receiver

A combined transmitter and receiver for PCMU/G.711 over a UDP `NetProto`
binding. It builds for rp2350 and bcm2712 — the same targets as `sip`, which
drives it over a control port.

`timer_class = "agnostic"`: this module reads no clock at all. Packet cadence is
the graph's, not its own.

Header decode is shared with `sip` in `modules/common/rtp_core.rs`, so the module
that sends packets and the module that plays them agree on which bytes are
payload — the fixed header, the CSRC list, a §5.3.1 extension and §5.1 padding
all move that boundary.

## Ports

| Port | Direction | Content | Carries |
| --- | --- | --- | --- |
| `net_in` / `net_out` | in / out | `NetProto` | UDP datagrams to and from the bound endpoint |
| `g711` | in (1) | `OctetStream` | µ-law audio to packetize and send |
| `packets` | out (1) | `OctetStream` | µ-law audio recovered from received packets |
| `endpoint` | ctrl in | `OctetStream` | peer address and start/stop control |

Parameters: `local_port`, `peer_ip`, `peer_port`, `ptime`, `ssrc`.

## Bounds

Transmit and receive ceilings are deliberately different numbers.

- **Transmit: 320 bytes** (`MAX_PAYLOAD`) — 40 ms of PCMU at 8 kHz. This is a
  policy choice about packet duration, which is the sender's to make.
- **Receive: 1472 bytes** less the RTP header (`RX_MAX_PAYLOAD`) — one Ethernet
  MTU of UDP payload. RFC 3551 sets no ceiling on packet duration, so a receiver
  that assumed its own transmit bound would reject conforming senders: ffmpeg's
  RTP muxer defaults to 1024-byte PCMU payloads, or 128 ms.

A packet too large to accept is refused and counted, never delivered as the
fraction that happened to fit. Both directions interoperate with ffmpeg's RTP
muxer, not only with Wave's own reading of the RFC.

## Not implemented

RTCP, SRTP, jitter buffering, payload formats other than PCMU, and multi-party
session policy. Receive-side reorder and loss-concealing playout live in `sip`,
which owns the media recovery for a call. Secure RTP requires an explicit future
capability and is never implied by an RTP binding.

## Observability

This module carries no metrics of its own: byte throughput is observed at the
foundation transport it rides, not recounted here.
