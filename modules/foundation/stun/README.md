# `stun` — STUN Binding server

Tells a peer the address its packets arrived from. That one fact is what a peer
behind a NAT cannot learn any other way, and it is the first thing an ICE agent
gathers. The message mechanics live in the host-tested
`modules/common/stun_core.rs`; this module is the pump around them.

## Why it is a compiled module and not a codec

The codec is not: `stun_core.rs` is a stateless transform and is exactly that.
This module exists because answering a request means owning a datagram
endpoint — binding it, learning its id, and holding a reply until the transport
takes it. That is connection-shaped state, which a codec does not have.

## What it is not

**Not an ICE agent.** It gathers no candidates, forms no pairs, schedules no
connectivity checks and nominates nothing. Those are decisions about
reachability, and reachability policy is Wormhole's; this module answers a
question and does not decide what to do with the answer.

**Not a TURN server.** It relays nothing.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `net_in` | 0 | input | `OctetStream` | `MSG_DG_BOUND` / `MSG_DG_RX_FROM` |
| `net_out` | 0 | output | `OctetStream` | `CMD_DG_BIND` / `CMD_DG_SEND_TO` |

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `port` | 3478 | UDP port to bind |

## Timing

`timer_class = "agnostic"`. No clock is read. A request is answered from the
datagram it arrived in, with no transaction table and no retransmission of its
own.

## Scope — read this before wiring it

A Binding request gets a success response carrying `XOR-MAPPED-ADDRESS` and
`FINGERPRINT`. Anything else gets an answer that says why, or nothing at all:

- a datagram that is not STUN is dropped silently, because this endpoint may
  carry other traffic and a datagram never addressed to this protocol deserves
  no reply;
- a response or an indication is dropped: it belongs to a transaction this
  module did not start;
- a method other than Binding is refused with 400;
- a comprehension-required attribute this responder does not understand is
  refused with 420, rather than ignored — answering a request whose terms were
  not understood claims an agreement that was not reached;
- a `FINGERPRINT` that is present and wrong means the bytes are not what the
  sender sent, so the message is dropped.

No long-term credentials, no `REALM`/`NONCE` challenge, and no `ALTERNATE-SERVER`
redirection. `MESSAGE-INTEGRITY` is understood by the core and is not required
by this responder: a public Binding server that demanded it could not answer
the requests it exists to answer.

## Status

One reply is owed per request and is retained until the transport takes it: a
reply dropped because the channel was briefly full leaves a peer retransmitting
against a responder that already decided.

Known gaps, stated rather than implied:

- **IPv4 only.** The core parses and builds IPv6 addresses; this module binds
  and answers over IPv4 because that is what the datagram provider emits today.
- **No credential mechanism.** Short-term credentials are what ICE uses, and
  the agent that needs them lives elsewhere.
