# `jitter` — RTP reorder and depacketize

The receive-side buffering the realtime family owns: validated RTP payloads in,
the fluxor encoded-media record stream (`abi::contracts::encoded`) out, in
order. The reorder window is the host-tested `modules/common/jitter_core.rs`;
the payload formats — RFC 3551 PCMU, RFC 7587 Opus, RFC 6184 H.264, RFC 7741
VP8 — are `modules/common/rtp_payload.rs`. This module is the pump around them.

It exists so `sip` does not privately own a media path: signalling decides
when media starts and stops, and says so on control records; this module
obeys them and owns nothing about the call.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `rx_in` | in 0 | input | `OctetStream` | Receive records from `rtp.packets`: sequence, timestamp, SSRC, payload type, marker, codec, payload (`rtp_wire.rs`) |
| `media_ctrl` | in 1 | input | `OctetStream` | The shared media-control records: START arms release and resets the window, STOP closes the stream with `END` and clears, SET_ENDPOINT addresses the transmitter and is ignored |
| `audio_out` | out 0 | output | `AudioEncoded` | The received stream, for PCMU or Opus |
| `video_out` | out 1 | output | `VideoEncoded` | The received stream, for H.264 (Annex B) or VP8 |

The codec comes from the receive records, which `rtp` tags with the codec it
negotiated; the stream opens with a `STREAM` record naming it. A stream whose
medium has no wired output is dropped and counted.

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 3 | `max_hold_ms` | 60 | How long a missing packet is waited for before it is declared lost |

Ids 1 and 2 are closed — the ids are wire positions, so a gap stays a gap
rather than being reused.

## Loss

A hole in the sequence holds release until the packet arrives or
`max_hold_ms` passes; then it is skipped and the next unit carries
`DISCONTINUITY`. A video unit that lost a packet mid-way is closed with a
`TRUNCATED` fragment and its remaining packets are dropped, so a decoder never
decodes a damaged picture as a whole one. Concealment is the decoder's.

## Timing

`timer_class = "wall_clock"`: the hold is real time, and a relaxed scheduler
tick must stretch scheduling, never the hold. Release itself is not paced —
presenting media on time belongs to the sink that owns the clock.

## What it is not

Not adaptive playout, not clock recovery, not topology-aware buffering, not
mixing — those are Grove's. Not an RTP parser — `rtp` validates packets and
hands over receive records; an unknown frame or a runt is consumed whole and
dropped, never partially read.
