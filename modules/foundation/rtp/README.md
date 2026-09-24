# `rtp` — RFC 3550 transmitter and receiver

A combined transmitter and receiver for one negotiated RTP stream over a UDP
`NetProto` binding. Media to send arrives as the fluxor encoded-media record
stream (`abi::contracts::encoded`) on `audio_in` or `video_in`; each access unit
is packetized in the negotiated payload format by the shared `rtp_payload` core
— RFC 3551 PCMU, RFC 7587 Opus, RFC 6184 H.264, RFC 7741 VP8. The shared media
cores also provide route validation, pacing, congestion control, and
RTP-to-wall-clock synchronization for higher-level media graphs.
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
| `audio_in` | in (1) | `AudioEncoded` | PCMU or Opus access units to send |
| `video_in` | in (2) | `VideoEncoded` | H.264 or VP8 access units to send |
| `packets` | out (1) | `OctetStream` | receive records for `jitter` (`rtp_wire.rs`) |
| `rtcp_stats` | out (2) | `OctetStream` | per-packet statistics for `rtcp` |
| `endpoint` | ctrl in | `OctetStream` | peer address and start/stop control |

One instance is one RTP stream — one SSRC, one payload type — so a graph wires
`audio_in` or `video_in`, never both; `module_new` refuses the second.

Parameters include `authority`, `local_port`, `ssrc`, `payload_type`, `codec`
(the negotiated payload format), negotiated payload/SSRC/MID routes, DTLS-SRTP
exporter material, and TURN relay and ChannelData settings.

## What the stream must say

The media input's `STREAM` record must name the negotiated `codec` at that
payload format's RTP clock (8 kHz PCMU, 48 kHz Opus, 90 kHz video). A stream
that does not is refused and counted until the next `STREAM`: the unit's `pts`
becomes the RTP timestamp directly, which is only right at the payload clock.
Codec identity and clock are facts the stream states, not ones this module
guesses — and SDP, fmtp and payload-type negotiation stay with the signalling
that configured `codec` and `payload_type`.

## Bounds

Transmit and receive ceilings are deliberately different numbers.

- **Transmit: 1200 bytes** (`TX_MTU`) of payload per packet, leaving room under
  a 1500-byte MTU for IP, UDP, SRTP and a TURN envelope. Video access units are
  fragmented to fit (FU-A, VP8 continuation); an audio unit is one packet, and
  one that does not fit is dropped and counted.
- **Receive: 1472 bytes** less the RTP header (`RX_MAX_PAYLOAD`) — one Ethernet
  MTU of UDP payload. RFC 3551 sets no ceiling on packet duration, so a receiver
  that assumed its own transmit bound would reject conforming senders: ffmpeg's
  RTP muxer defaults to 1024-byte PCMU payloads, or 128 ms.
- **Media input: 4096-byte fragments** (`max_payload` on both media ports). An
  access unit larger than that arrives as several `UNIT` fragments and is
  packetized as it arrives, so no whole-unit buffer exists anywhere.

A packet too large to accept is refused and counted, never delivered as the
fraction that happened to fit.

## Composition boundaries

Reordering, depacketizing and loss signalling are `jitter`'s; RTCP report
generation is `rtcp`'s, so a minimal graph does not pay for either. `rtp` emits
bounded receive records carrying sequence, timestamp, SSRC, payload type,
marker, the negotiated codec and MID. SRTP/SRTCP are explicit profiles
configured by parameters or DTLS-SRTP exporter material and are never enabled
implicitly.

## Observability

This module carries no metrics of its own: byte throughput is observed at the
foundation transport it rides, not recounted here.
