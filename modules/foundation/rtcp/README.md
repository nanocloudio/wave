# `rtcp` — the control plane RTP does not have

RTP carries media and says nothing about how it arrived. This module is the
channel on which a receiver tells a sender what it actually got — how much was
lost, how much arrival times jittered, and how long the round trip is — and on
which a sender publishes the RTP-timestamp-to-real-time mapping that makes
lip-sync possible. A media path with no RTCP cannot adapt and cannot
synchronise, and neither failure is visible from the media itself.

The protocol mechanics live in the host-tested `modules/common/rtcp_core.rs`;
this module is the pump around them.

## Why a module and not a role inside `rtp`

Three reasons, recorded with the admission decision in `.context/backlog.md`:

- **Its own endpoint.** RFC 3550 §11 puts RTCP on the odd port one above RTP's.
  It is not the same socket, so it is not `rtp` wearing a second hat.
- **Its own clock.** The §6.2 interval is a wall-clock deadline. `rtp` attests
  `timer_class = "agnostic"` and its manifest carries an explicit warning that
  pacing must revisit that — folding RTCP in would downgrade the attestation
  for every graph that locks `rtp` today, and cost it admission to a
  variable-cadence domain it currently qualifies for.
- **Its own cost.** `rtp.fmod` on rp2350 is the smallest artefact in the tree.
  An always-on control plane roughly doubles it, on the target least able to
  pay, for something an embedded transmitter may not want at all.

This is the split `jitter` already uses: a separate realtime adapter over
`rtp`'s validated records.

## How the statistics get here

`rtp` gained one appended output, `rtcp_stats` (out[2]), carrying two tagged
record kinds:

| Tag | Record | Emitted |
| --- | --- | --- |
| 1 `RX` | `[seq: u16 LE][rtp_ts: u32 LE]` | Once per accepted packet |
| 2 `TX` | `[packets: u32 LE][octets: u32 LE][rtp_ts: u32 LE]` | After each packet sent |

Neither carries a wall-clock time, because `rtp` reads no clock; this module
stamps time from its own.

For the RX record that is **exact**. RFC 3550 §A.8 estimates jitter from a
*difference of differences* — `D(i,j) = (Rj - Ri) - (Sj - Si)` — so a constant
offset between `rtp` seeing a packet and this module reading the record cancels
completely. What would not cancel is a *varying* offset, which is why the
records are drained every step rather than in batches on a timer.

For the TX record it is an **approximation, and a stated one**: a Sender
Report's NTP/RTP pair is read as "these two were simultaneous", and here they
are simultaneous to within one scheduler pass rather than exactly.

The link is best-effort on `rtp`'s side: a record the channel cannot take is
dropped and counted, never retried. Media must not stall because a report
consumer fell behind. A dropped RX record perturbs a smoothed estimate; a
dropped TX record costs nothing at all, because it is a latest-value that the
next packet supersedes.

A record whose tag this module does not know **stops the drain** rather than
being skipped. Its length is unknown, so skipping it would misalign every
record behind it — which reads as plausible sequence numbers beside nonsense
jitter, the failure mode hardest to notice.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `net_in` | 0 | input | `OctetStream` | `MSG_DG_BOUND` / `MSG_DG_RX_FROM` |
| `net_out` | 0 | output | `OctetStream` | `CMD_DG_BIND` / `CMD_DG_SEND_TO` |
| `rtp_stats` | 1 | input | `OctetStream` | `[seq: u16 LE][rtp_ts: u32 LE]` from `rtp`'s out[2] |
| `reports_out` | 1 | output | `OctetStream` | What the peer reported about **our** stream |

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `port` | 5005 | Local RTCP port (RFC 3550 §11: RTP's port + 1) |
| 2 | `peer_ip` | 0 | u32 LE of the peer's IPv4 address; zero sends nothing |
| 3 | `peer_port` | 5005 | The peer's RTCP port |
| 4 | `ssrc` | `0x46585254` | This participant's synchronisation source |
| 5 | `cname` | `wave@rt` | Canonical name carried in every compound |
| 6 | `bandwidth_bps` | 64000 | Session bandwidth the §6.2 interval divides |

## What it sends

One compound per interval: a report, then `SDES(CNAME)` — the minimum §6.1
admits.

**Which report depends on whether this participant has sent media.** A TX
record makes it a Sender Report, carrying the NTP/RTP pair and the packet and
octet counts §6.4.1 defines; without one it is a Receiver Report. That is the
whole of §6.4's split: only a participant that has transmitted has a timestamp
mapping to publish, and publishing one for a stream never sent would hand a
receiver a mapping for nothing. A sender's report still carries its own
reception blocks — a participant is usually both.

A participant that has heard nothing sends an **empty** report: presence,
without a claim about a stream it never saw. That is what §6.4.2 asks for.

`we_sent` in the §6.2 interval means the same thing: a sender draws from the
senders' quarter of the RTCP bandwidth, a receiver from the other three
quarters.

### The NTP timestamp

`ntp_epoch_offset_s` lifts the local millisecond clock into the NTP epoch.
Left at zero the field is a **local timebase**, and the distinction matters
differently for the two things it is used for:

- **Round trip** subtracts only values this participant issued, so a local
  timebase is exact for it. This is what closes the loop: we publish an NTP
  timestamp, the peer echoes its middle 32 bits with the delay it held it for,
  and `now - delay - echo` is the round trip.
- **Synchronising two sources** compares timestamps from *different*
  participants and needs a shared epoch. With a zero offset it will be
  confidently wrong — which is why the offset is a parameter rather than an
  assumption.

The interval is §6.2's — it scales with the session so total RTCP traffic stays
a fixed fraction of the bandwidth however many participants join — randomised
over [0.5, 1.5] per §6.3.1 and corrected by e−1.5. The randomisation is not
decoration: without it every participant reports in lockstep and the session
sees a periodic burst instead of a trickle. The PRNG is seeded from the SSRC so
two instances in one graph draw different intervals.

## What it reads

A compound from the configured peer only. An RTCP endpoint is reachable by
anyone, and a report from a stranger would otherwise be read as this session's
loss and jitter.

A report is staged in one slot and drained on the next step, so an ordinary
consumer sees every measurement the peer sends. When the channel is refusing,
the slot is **overwritten rather than held**: loss, jitter and round trip
describe the link as it is now, and a consumer more than a reporting interval
behind — five seconds at the RFC's floor — is better served by the current
measurement than by the one it missed.

From that compound it keeps two things. An SR's NTP timestamp and the local
time it arrived, so the next report can tell the peer how long we sat on it —
which is what makes *their* round-trip calculation possible at all. And any
report block addressed to our own SSRC, which is the peer telling us how our
stream arrived: the only channel that carries that fact.

A second SSRC is a third participant, which is a session this module does not
model. Counted, never silently folded into the first one's numbers.

## Timing

`timer_class = "wall_clock"`. The reporting interval and the arrival stamps
that feed the jitter estimate are both real time. An interval counted in
scheduler passes would stretch and compress with the cadence, which is the
drift `adaptive_tick` §8 rule 2 forbids.

## Scope — read this before wiring it

**It decides nothing.** Rate adaptation, call teardown on a BYE, and quality
policy read these numbers and act; this module produces them.

Not implemented: SDES items beyond CNAME, APP packets beyond being skipped, RFC 4585 feedback,
and the full §6.3 membership/reconsideration algorithm — the interval here
assumes the two-party session `rtp` and `sip` compose.

**Nothing here encrypts.** SRTCP is a separate mechanism and its absence is
stated, not implied.
