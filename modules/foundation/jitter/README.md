# `jitter` — RTP reorder and loss-concealing playout

The minimum receive-side buffering the realtime family owns
(`.context/rfc_hardening.md` §9.6): validated RTP payloads in, loss-concealed
µ-law playout out at the codec's frame cadence. The ring and both of its
operations live in the host-tested `modules/common/jitter_core.rs`; this
module is the pump around them.

It exists so `sip` does not privately own a media path: signalling decides
when media starts and stops, and says so on control records; this module
obeys them and owns nothing about the call.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `rx_in` | in 0 | input | `OctetStream` | `[seq: u16 LE][payload…]` — one validated RTP payload per record (`rtp.packets`) |
| `media_ctrl` | in 1 | input | `OctetStream` | The shared media-control records: START arms playout and resets the ring, STOP disarms and clears, SET_ENDPOINT addresses the transmitter and is ignored |
| `ulaw_out` | out 0 | output | `OctetStream` | Loss-concealed µ-law playout at `ptime` cadence |

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `ptime` | 20 | Frame cadence in ms (0 reads as 20) |
| 2 | `target_fill` | 3 | Packets buffered before first playout |

## Timing

`timer_class = "wall_clock"`. Playout paces on real time and must: a relaxed
scheduler tick that stretched the interval would stretch the audio.

## What it is not

Not adaptive playout, not clock recovery, not topology-aware buffering, not
mixing — those are Grove's. Not an RTP parser — `rtp` validates packets and
hands over `[seq][payload]`; a record too short to carry a sequence number is
dropped by bound, never partially read.
