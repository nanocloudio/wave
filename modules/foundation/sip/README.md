# `sip` — RFC 3261 subset UAC/UAS for two-party PCMU voice

Voice is split three ways and this module holds the middle: **Spectra** owns the
G.711 codec, **Wave** owns the wire mechanics, and **Conclave** owns the call
semantics above both. This module is SIGNALLING ONLY: a
UDP endpoint wrapper around two cores in `modules/common` — `sip_core` (message
formatters and response/SDP parsers) and `sip_dialog` (the transaction FSM).
The media path is the separate `rtp` (endpoint, packetise/depacketise) and
`jitter` (reorder/playout) modules, driven over control records.

## What it owns, and what it does not

It owns **protocol facts**: when an INVITE is legal, what an ACK answers, and
when a transaction has timed out. It owns
no **call policy** — who may call whom, what a busy answer means, how a call is
recorded — that is Conclave's, above this module. It owns neither transport (the
datagram endpoints are Fluxor's) nor codec (µ-law is Spectra's `g711`).

It is a **two-party** user agent. Multi-party mixing, transfer, hold, forking,
registration, and authentication are not implemented and are not claimed.

## Shape

One datagram endpoint, and control records fanned to the media modules:

```text
  peer UA  <--- sip_net_in/out (SIP signalling) --->  sip_dialog FSM
                                    rtp_ctrl ---> `rtp` (endpoint) + `jitter` (ctrl)
```

The dialog decides when media runs; the media modules do the running. On
establishment this module emits `SET_ENDPOINT` (the negotiated peer) and
`START`; on BYE, `STOP` — the same records to both consumers, fanned by the
graph.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `sip_net_in` | 0 | input | `OctetStream` | Inbound SIP datagrams |
| `sip_net_out` | 0 | output | `OctetStream` | Outbound SIP datagrams |
| `rtp_ctrl` | 1 | output | `OctetStream` | 8-byte control records to `rtp.endpoint` and `jitter.media_ctrl` |
| `command_in` | 1 | input | `OctetStream` | `SipCommand` records: dial, accept, reject, hang up, cancel |
| `event_out` | 2 | output | `OctetStream` | `SipEvent` records: one per call transition |
| `call` | — | ctrl_input | `FmpMessage` | Any byte: place a call from `Ready`, hang up from `Active` |

### Commands and events

A `SipCommand` names one call and what to do about it, carrying the peer and
media endpoints with it rather than taking them from construction-time
parameters: a connector that can only ever call one address is not a connector.

`SipEvent` reports what happened to that call — offered, provisional,
established with the negotiated remote media endpoint and payload type, and
exactly one terminal outcome: rejected with its status, timed out, failed,
hung up by the peer, closed locally, or declined by this end. Every call
reaches exactly one terminal event, which is what lets a caller free what it
was holding without guessing.

**An incoming call is not answered until a decision names it.** While
`command_in` is wired the module holds the `INVITE`, reports it as offered, and
answers only on an accept — or refuses with the status a reject chose. Ringing
a caller and then having nobody able to accept is a worse outcome than a
refusal, so the decision comes first.

When `command_in` is wired, `auto_answer` does not apply. A graph that wired a
decision port and also let the module answer on its own would answer twice, and
the first answer would be the one nobody authorised.

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `local_ip` | 0 | Local address, used in Via/Contact and SDP |
| 2 | `local_sip_port` | 5060 | Local signalling port |
| 3 | `peer_ip` | 0 | Peer address |
| 4 | `peer_sip_port` | 5060 | Peer signalling port |
| 5 | `rtp_port` | 5004 | Local RTP receive port, advertised in SDP |
| 6 | `auto_answer` | 1 | Answer an inbound INVITE without asking above. Ignored while `command_in` is wired |
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

## Status

The wrapper's behavioural contract: silence until its endpoints are bound and a
call is up, media started at the endpoint the peer's SDP named with
`SET_ENDPOINT` strictly before `START`, T1 retransmits byte-identical to the
original request, and an unconfigured module staying inert.

**No rig scenario.** The media path has never run on real silicon. That needs a
graph and an independent RTP peer on the host, and it is the remaining gap for
this module.

Two behaviours worth knowing. Playout is
loss-**concealing**: once a call is up the channel emits one `ptime` frame per
cadence tick whether or not a packet arrived, writing µ-law silence when it did
not — a voice path that stopped emitting would starve the codec downstream. And
`jitter_core` takes its playout base from the *first* packet it sees, so a
sequence number below that one is out of window and dropped by design.
