# `rtp` — RFC 3550 transmitter and receiver

A combined transmitter and receiver for negotiated RTP over a UDP `NetProto`
binding. The `g711` port carries raw PCMU for the smallest voice graph, and
encoded access units arrive as bounded `rtp_media_wire` records that the
mounted `rtp_media` boundary packetizes as H.264 or VP8. The shared media cores also provide
route validation, pacing, congestion control, and RTP-to-wall-clock
synchronization for higher-level media graphs.
It builds for rp2350 and bcm2712 — the same targets as `sip`, which drives it
over a control port.

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

Parameters include `local_port`, `peer_ip`, `peer_port`, `ptime`, `ssrc`,
negotiated payload/SSRC/MID routes, DTLS-SRTP exporter material, and TURN relay
and ChannelData settings.

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

## Composition boundaries

RTCP report generation and jitter-buffer playout remain separate modules so a
minimal voice graph does not pay for them. `rtp` emits bounded metadata records
with sequence, timestamp, SSRC, payload type, marker, and MID; `rtcp` consumes
those records for reports. SRTP/SRTCP are explicit profiles configured by
parameters or DTLS-SRTP exporter material and are never enabled implicitly.

Video codecs remain in shared zero-copy packetizers (`rtp_h264` and `rtp_vp8`)
so Spectra or another source can choose the negotiated codec. The fixed record
header carries codec, marker, and RTP timestamp; the higher-level media graph
owns the bounded access-unit buffer and feeds packet plans into the transport
and encryption seam.

## Observability

This module carries no metrics of its own: byte throughput is observed at the
foundation transport it rides, not recounted here.
