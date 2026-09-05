# `stun` — STUN Binding, both roles

Tells a peer the address its packets arrived from, and asks a server the same
question. That one fact is what a peer behind a NAT cannot learn any other way,
and it is the first thing an ICE agent gathers. The message mechanics live in
the host-tested `modules/common/stun_core.rs` and the client's transaction
schedule in `modules/common/stun_txn.rs`; this module is the pump around them.

## Two roles, one module

A Binding request and its response differ by two bits of the message type, and
both travel over the same socket. Splitting the roles would duplicate the
parse, the FINGERPRINT check and the endpoint pump and buy nothing. Setting
`server_ip` arms the client; leaving it zero is the responder-only module this
was before, which sends nothing and reports nothing.

## Why it is a compiled module and not a codec

The codec is not: `stun_core.rs` is a stateless transform and is exactly that.
This module exists because answering a request means owning a datagram
endpoint — binding it, learning its id, and holding a reply until the transport
takes it. That is connection-shaped state, which a codec does not have. The
client adds a second kind: a transaction with a deadline, which is why the
manifest attests `wall_clock` even though the responder still reads no clock.

## The client

Over UDP an unanswered request is indistinguishable from an undelivered one, so
the client retransmits on the RFC 5389 §7.2.1 schedule — seven transmissions,
500 ms doubling, 39.5 s in total — and only then gives up. Only a CONFIRMED
write advances that schedule: counting a refused one would burn a transmission
the server never had a chance to see.

**A response is accepted only when its source address and its transaction id
both match.** Anyone can send a STUN response to an open UDP port, and being
told your own address by a stranger is the one thing this exchange must not
allow — the reflexive address becomes an ICE candidate, and a forged one points
a media path wherever the forger likes. A present-but-wrong FINGERPRINT is
refused for the same reason.

`XOR-MAPPED-ADDRESS` is preferred and `MAPPED-ADDRESS` accepted as the RFC 3489
fallback — a server old enough to send only the latter is still telling the
truth about what it saw. A success carrying neither is reported as
`STUN_RES_NO_ADDRESS` rather than as an address of zeroes, because zeroes where
a candidate goes is worse than a stated failure.

**Every transaction produces exactly one result**, timeouts included, and the
record is held until `result_out` takes it. A client that reported nothing when
a server went away would leave whatever wired it waiting forever, with no other
way to learn the address was never learned.

One transaction at a time, and one per instance: this client asks one server
for one address. Asking repeatedly would be a keepalive and asking several
servers at once would be candidate gathering — both are ICE, and both are
policy this module has no standing to decide.

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
| `result_out` | 1 | output | `OctetStream` | One client result per transaction; silent in responder-only mode |

## Parameters

| Id | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `port` | 3478 | UDP port to bind |
| 2 | `server_ip` | 0 | u32 LE of the server's IPv4 address, big-endian within. Non-zero ARMS the client |
| 3 | `server_port` | 3478 | The server's UDP port |
| 4 | `txn_seed` | 0 | Varies the transaction-id sequence between instances counting from the same place |

## The result record

`[status:u8][ip:4 BE][port:u16 LE][code:u16 LE]` — 9 bytes.

| Status | Meaning |
| --- | --- |
| 0 `OK` | `ip`/`port` are the reflexive address the server saw |
| 1 `TIMEOUT` | Every transmission went unanswered |
| 2 `ERROR` | The server answered with an error; `code` is its STUN error code |
| 3 `NO_ADDRESS` | A success carrying no address this client could read |

The address is big-endian because that is how it travels in STUN and on this
repo's datagram surface; the two integers are little-endian because that is how
records are read here. The mix is deliberate — re-encoding the address would
mean a consumer that logs it has to undo the tidying.

## Timing

`timer_class = "wall_clock"`. The responder still reads no clock — a request is
answered from the datagram it arrived in — but the client holds the RFC 5389
§7.2.1 deadline, and a module attests once for everything it compiles.
A schedule counted in scheduler passes would stretch with the cadence, which is
the drift a module attested `agnostic` promises not to have.

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
