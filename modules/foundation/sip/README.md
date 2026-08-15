# `sip` — RFC 3261 subset UAC/UAS for two-party PCMU voice

Voice is split three ways and this module holds the middle: **Spectra** owns the
G.711 codec, **Wave** owns the signalling and the receive-side recovery, and
**Conclave** owns the call semantics above both. This module is a UDP endpoint
wrapper around three cores in `modules/common` — `sip_core` (message formatters
and response/SDP parsers), `sip_dialog` (the transaction FSM), and `jitter_core`
(reorder window and playout).

## What it owns, and what it does not

It owns **protocol facts**: when an INVITE is legal, what an ACK answers, when a
transaction has timed out, and how a reordered RTP stream is played back. It owns
no **call policy** — who may call whom, what a busy answer means, how a call is
recorded — that is Conclave's, above this module. It owns neither transport (the
datagram endpoints are Fluxor's) nor codec (µ-law is Spectra's `g711`).

It is a **two-party** user agent. Multi-party mixing, transfer, hold, forking,
registration, and authentication are not implemented and are not claimed.

## Shape

Two datagram endpoints and two media edges:

```text
  peer UA  <--- sip_net_in/out (SIP signalling, 5060) --->  sip_dialog FSM
  peer RTP  ---> rtp_net_in ---> jitter_core ---> ulaw_out ---> g711 decoder
                                                  rtp_ctrl ---> `rtp` module (TX)
```

Receive and transmit are deliberately asymmetric in ownership: this module holds
the **receive** path (reorder + loss-concealing playout) because that is
recovery, which is protocol work; transmission is the separate `rtp` module,
driven over `rtp_ctrl` with `SET_ENDPOINT` / `START` / `STOP`.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `sip_net_in` | 0 | input | `OctetStream` | Inbound SIP datagrams |
| `sip_net_out` | 0 | output | `OctetStream` | Outbound SIP datagrams |
| `rtp_net_in` | 1 | input | `OctetStream` | Inbound RTP for the jitter buffer |
| `rtp_net_out` | 1 | output | `OctetStream` | RTP receive endpoint commands |
| `ulaw_out` | 2 | output | `OctetStream` | Playout µ-law at `ptime` cadence |
| `rtp_ctrl` | 3 | output | `OctetStream` | 8-byte control frames to the `rtp` transmitter |
| `call` | — | ctrl_input | `FmpMessage` | Any byte: place a call from `Ready`, hang up from `Active` |

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `local_ip` | 0 | Local address, used in Via/Contact and SDP |
| 2 | `local_sip_port` | 5060 | Local signalling port |
| 3 | `peer_ip` | 0 | Peer address |
| 4 | `peer_sip_port` | 5060 | Peer signalling port |
| 5 | `rtp_port` | 5004 | Local RTP receive port, advertised in SDP |
| 6 | `auto_answer` | 1 | Answer an inbound INVITE without asking above |
| 8 | `ptime` | 20 | Packet time in ms; also the playout cadence |

Id 7 is unused — the ids are wire positions, so the gap is preserved rather than
closed.

## Timing

`timer_class = "wall_clock"`. Two clocks, both `dev_millis`: the T1 retransmit
timer (500 ms, in the `Inviting` / `WaitAck` / `ByeSent` states) and the `ptime`
playout cadence. Playout must track real time — a scheduler-pass proxy would
stretch the audio whenever the tick relaxed.

## Shared cores

Mounted by `#[path]` from `modules/common`, so the device build and the host
vectors compile identical bytes:

- `sip_core.rs` — INVITE/ACK/BYE/200-OK formatters, response and SDP parsers;
- `sip_dialog.rs` — the bounded UAC/UAS transaction FSM, protocol facts only;
- `jitter_core.rs` — bounded reorder window and loss-concealing playout;
- `hex_core.rs` — hex for byte-valued parameters.

## Not claimed

TLS/SIPS, digest authentication, REGISTER, re-INVITE, transfer, hold, forking,
multi-party mixing, RTCP, SRTP, and any codec other than PCMU. Secure RTP
requires an explicit future capability and is never implied by an RTP binding
(`docs/specification.md`).

## Coverage

- **L0** — the cores are vector-tested in the host harness:
  `tests/harness/tests/sip_vectors.rs`, `tests/harness/tests/sip_dialog_vectors.rs`,
  `tests/harness/tests/sip_jitter_vectors.rs`, plus the hostile-input sweep in
  `tests/harness/tests/codec_bounds_sweep_cores.rs`.
- **L1** — `tests/harness/tests/sip.rs` drives the wrapper through
  `sip_harness`, which plays both the peer UA and the far-end media source:
  both endpoints bound at the configured ports; silence until a bind is
  answered; an inbound INVITE answered with a 200 OK advertising our own media
  port; the ACK starting media at the endpoint the peer's SDP named, with
  SET_ENDPOINT strictly before START; an outbound call ACKing its answer; the
  T1 retransmit being byte-identical to the original request; BYE answered and
  media stopped; local hangup; playout at the `ptime` cadence; reordered packets
  played in sequence order; malformed RTP concealed as silence rather than
  played; no audio before a call is up; and an unconfigured module staying
  inert.

**No rig scenario.** The media path has never run on real silicon. That needs a
graph and an independent RTP peer on the host, and it is the remaining gap for
this module.

Two behaviours worth knowing before reading the tests. Playout is
loss-**concealing**: once a call is up the channel emits one `ptime` frame per
cadence tick whether or not a packet arrived, writing µ-law silence when it did
not — a voice path that stopped emitting would starve the codec downstream. And
`jitter_core` takes its playout base from the *first* packet it sees, so a
sequence number below that one is out of window and dropped by design.
