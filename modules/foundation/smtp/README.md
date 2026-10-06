# `smtp` — RFC 5321 mail submission client

A connector for outbound mail **submission** only. The protocol logic lives in
the host-tested `modules/common/smtp_core.rs` and the result layout in
`modules/common/smtp_wire.rs`; this module is the I/O pump around them. Message
meaning — who sends, what is in the body, what a bounce means — is Conclave's;
the wire mechanics are Wave's.

Submissions arrive as exchange requests and are answered one for one — the
module is a PROVIDER of fluxor's exchange contract — so a single long-running
instance submits many messages without its graph being rebuilt.

## Why it is a compiled module and not a codec

The conversation is lockstep and server-led:

```text
  connect -> 220 greeting -> EHLO/250 -> [AUTH PLAIN/235] -> MAIL FROM/250
          -> RCPT TO/250 -> DATA/354 -> <dot-stuffed message>.CRLF/250
          -> QUIT/221
```

Every command waits on the 3-digit code of the previous — possibly multi-line —
reply, and the first thing that happens is the *server* speaking. A reply-driven,
multi-round-trip session over a server-chosen greeting is not a stateless
transform, so it is a module rather than a shared-core codec called by someone
else: it must own the connection lifecycle and drive the transport itself.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `net_in` | 0 | input | `OctetStream` | `NET_MSG_*` transport events |
| `net_out` | 0 | output | `OctetStream` | `NET_CMD_CONNECT_TO` / `SEND` / `CLOSE` |
| `status_out` | 1 | output | `OctetStream` | One human-readable status line per submission |
| `request_in` | 1 | input | `ExchangeRequest` | Submissions |
| `response_out` | 2 | output | `ExchangeResponse` | Exactly one answer per submission, its body an `SmtpResult` |

### Submissions and results

A submission is an exchange request:

- **HEAD** — method `POST`; `target` the one recipient mailbox
  (`rcpt@example.test`, at most 256 bytes); a `mail-from: <sender>` header
  naming the envelope sender (at most 256 bytes); the message — its header
  block and body, as they go after `DATA` — as the body. The body rides inline
  when it fits; MORE says BODY records follow.
- **BODY** — more of the message, never past the credit this module grants:
  the rest of its 8176-byte chunk at once, then each chunk's worth again as it
  reaches the wire. Neither this module nor its caller holds a whole message.
- **CREDIT** — response credit for the answer's body.
- **ABORT** — the caller gives up the submission: the conversation is closed
  where it stands and nothing more is written for it.

One request carries one recipient: a message to several recipients is several
submissions, which keeps every result recipient-scoped, since a server refusing
one recipient says nothing about another. One submission is performed at a
time; a second arriving meanwhile is answered `503`, and may be repeated.

Every submission is answered exactly once, under the requester's exchange id.
The answer's status says who decided: `200` when the relay gave its verdict —
accepted, or refused permanently or for now, or a reply out of sequence, or
credentials that could not be sent; `502` when the relay could not be reached
or dropped the connection before deciding; `504` when it stopped answering. A
request this module will not perform is answered `400` (not POST, no
recipient or no `mail-from`) or `413` (a recipient or sender past 256 bytes)
with no body, before any connection opens.

The body of every other answer is an `SmtpResult` (multi-byte fields
little-endian; offsets in bytes):

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 1 | `op`, always `0x6F` |
| 1 | 1 | `outcome` (below) |
| 2 | 1 | `phase`: how far the conversation got (`smtp_core::smtp_phase_code`) |
| 3 | 2 | `code`: the final reply code |
| 5 | 1 | enhanced status class (`0` when the reply carried none) |
| 6 | 2 | enhanced status subject |
| 8 | 2 | enhanced status detail |
| 10 | 4 | `peer_ip`: the relay's v4 address, zero when the authority is a name |
| 14 | 2 | `peer_port` |
| 16 | 2 | `text_len` |
| 18 | `text_len` | the reply text, at most 256 bytes |

`outcome` is `0` accepted, `1` refused permanently (5xx), `2` refused for now
(4xx), `3` a protocol error, `4` the connection could not be opened, `5` a
deadline passed, `6` the connection closed before a terminal reply, `9`
credentials configured but not sendable. The answer's body goes only as far
as the requester's response credit: whole in the HEAD when the credit covers
it, and otherwise the HEAD first with MORE and the result once credit arrives.
An answer the channel cannot take yet is retained and offered again, so
transient output pressure never loses one.

The outcome classification states what the protocol showed and stops there:
none of its values claims a person received or read anything.

**The 250 answering end-of-data is the acceptance.** From that moment the server
holds the message, and the QUIT that follows is graceful cleanup. A QUIT that
fails, times out, or never completes does not un-accept it — reporting otherwise
would have a caller submit the message again and deliver it twice.

`status_out` carries a short human-readable line. It cannot express a reply
code or an enhanced status, so anything driving submissions consumes
`response_out` instead; `status_out` suits a graph whose outcome a person
reads.

## Parameters

| Id | Name | Meaning |
| --- | --- | --- |
| 1 | — | retired |
| 2 | `helo` | EHLO domain |
| 3 | `mail_from` | Envelope sender |
| 4 | `rcpt_to` | Envelope recipient (one) |
| 5 | `body` | Message headers and body; dot-stuffed on the way out |
| 6 | `auth_user` | SASL PLAIN username; its presence is what configures authentication |
| 7 | `auth_pass` | SASL PLAIN password |
| 8 | `channel_confidential` | u32 LE; non-zero asserts a `tls` node sits in front. Anything else, including absent, reads as zero |
| 9 | `authority` | `host[:port]`, port 25 when it names none: the relay to dial. A name goes to the network provider as a name, for it to resolve. At most 128 bytes; absent, longer, or not `host[:port]` refuses construction |

Params describe a single submission. When an envelope is configured, that
submission is performed once at startup as if its request had arrived — with
nobody to answer, so its outcome is the status line alone, which is all a
graph whose only job is one message needs. A connector leaves them unset and
drives `request_in` instead.

## Timing

`timer_class = "wall_clock"`. Two deadlines, both `dev_millis`:
`CONNECT_TIMEOUT_MS` (10 s) and `REPLY_TIMEOUT_MS` (15 s). A stalled server
produces `smtp: timeout` and a closed connection, never an indefinite wait.

## Authentication

`AUTH PLAIN` (RFC 4616) only, sent with an empty authzid and an initial
response, so authentication costs one round trip and no continuation state.
Setting `auth_user` is what turns it on; a password with no username is not a
credential and is ignored.

**A credential is only ever sent on a channel the graph has declared
confidential.** `AUTH PLAIN` is cleartext, and this module cannot see whether a
`tls` node sits in front of it — that is what composing transports means. So the
deployment says, with `channel_confidential`, and the default is to refuse.

Two things refuse: an undeclared channel, and a server that offered no mechanism
this module speaks. Both fail the submission rather than quietly falling back to
an unauthenticated one, and both report `SMTP_OUT_AUTH_UNAVAILABLE` rather than a
refusal code — the server never saw a credential, so nothing about the message or
the account is in question, only the graph. Falling back is the tempting
behaviour and the wrong one: the relay may well accept the message, attribute it
to nobody, and the operator who configured a username would never learn their
credentials did not travel.

LOGIN and CRAM-MD5 are not implemented. LOGIN puts the same secret in the same
clear over two extra round trips; CRAM-MD5 needs challenge/response state for a
mechanism whose hash is long past recommending. A mechanism this module does not
recognise is one it will not use.

## Scope — read this before wiring it

**No STARTTLS, no pipelining, one recipient per submission.** STARTTLS is absent
on purpose, not for want of effort: it asks a module to renegotiate its own
transport mid-stream, which is the thing a dataflow graph expresses by composing
nodes instead. Wire Fluxor's `tls` module in client mode between the transport
and `net_in`/`net_out` for an implicit-TLS submission port — the port 465 shape —
exactly as `websocket` does for `wss://`, and set `channel_confidential`.

Without that, the envelope and body cross the wire in the clear, which suits a
trusted relay or sink behind a security boundary and does *not* suit a public MX
over the open internet.

No MX resolution, no queue, no retry, no DSN parsing, no 8BITMIME/SMTPUTF8
negotiation. Queuing, the retry schedule and idempotency belong to the caller,
which is why the result classifies a refusal rather than acting on it.

One submission is performed at a time and each opens its own connection.
Connection reuse across submissions is a later profile: it multiplies the
failure modes a result has to describe, and nothing needs it yet.

## Status

The module's behavioural contract: silence until the 220 greeting; the
conversation advanced exactly once per reply however the bytes are split across
transport reads; exactly one answer per submission, retained until the channel
takes it; acceptance decided at end-of-data and never revisited;
transparency encoding correct across a record boundary; and commands that a real
MTA (Exim) parses as byte-legal.

Known gaps, stated rather than implied:

- **`bcm2712` only.** Same as `websocket`, and for no stronger reason than that
  nothing has needed it from `rp2350` yet.
- **Peer identity is an address.** The result carries the address the message
  was submitted to. Stronger identity comes from the `tls` module's peer
  identity when a TLS submission profile is selected, and is not restated here.
