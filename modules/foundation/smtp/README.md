# `smtp` — RFC 5321 mail submission client

A connector for outbound mail **submission** only. The protocol logic lives in
the host-tested `modules/common/smtp_core.rs` and the record layouts in
`modules/common/smtp_wire.rs`; this module is the I/O pump around them. Message
meaning — who sends, what is in the body, what a bounce means — is Conclave's;
the wire mechanics are Wave's.

Submissions arrive as records and are answered one for one, so a single
long-running instance submits many messages without its graph being rebuilt.

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
| `net_out` | 0 | output | `OctetStream` | `NET_CMD_CONNECT` / `SEND` / `CLOSE` |
| `status_out` | 1 | output | `OctetStream` | One human-readable status line per submission |
| `request_in` | 1 | input | `OctetStream` | `SmtpRequest` submissions |
| `result_out` | 2 | output | `OctetStream` | Exactly one `SmtpResult` per submission |

### Submissions and results

An `SmtpRequest` carries a caller-chosen correlation id, the envelope sender,
one recipient, and a span of the message. A message larger than one record
continues over further records under the same id, and neither this module nor
its caller holds the whole message in a buffer. One request carries one
recipient: a message to several recipients is several submissions, which keeps
every result recipient-scoped, since a server refusing one recipient says
nothing about another.

Every accepted submission is answered with exactly one `SmtpResult`, carrying
the correlation id, an outcome classification a retry policy can act on, the
phase the conversation reached, the final reply code with its RFC 3463 enhanced
status and bounded text, and the peer address the message was submitted to. A
result the channel cannot take yet is retained and offered again, so transient
output pressure never loses one.

The outcome classification distinguishes acceptance, a permanent refusal (5xx),
a transient refusal (4xx), a protocol error, a failed connect, a timeout, a
connection lost mid-conversation, a cancelled submission, a request that could
not be used, and credentials that were configured but could not be sent. It states what the protocol showed and stops there: none of
those values claims a person received or read anything.

**The 250 answering end-of-data is the acceptance.** From that moment the server
holds the message, and the QUIT that follows is graceful cleanup. A QUIT that
fails, times out, or never completes does not un-accept it — reporting otherwise
would have a caller submit the message again and deliver it twice.

`status_out` carries a short human-readable line. It cannot express a
correlation id, a reply code, or an enhanced status, so anything driving
submissions consumes `result_out` instead; `status_out` suits a graph whose
outcome a person reads.

## Parameters

| Id | Name | Meaning |
| --- | --- | --- |
| 1 | `endpoint` | Hex `[ip:4][port:2 LE]` — configs carry text, so bytes arrive hex-encoded |
| 2 | `helo` | EHLO domain |
| 3 | `mail_from` | Envelope sender |
| 4 | `rcpt_to` | Envelope recipient (one) |
| 5 | `body` | Message headers and body; dot-stuffed on the way out |
| 6 | `auth_user` | SASL PLAIN username; its presence is what configures authentication |
| 7 | `auth_pass` | SASL PLAIN password |
| 8 | `channel_confidential` | u32 LE; non-zero asserts a `tls` node sits in front. Anything else, including absent, reads as zero |

Params describe a single submission. When an envelope is configured, that
submission is performed once at startup as if its record had arrived — which is
all a graph whose only job is one message needs. A connector leaves them unset
and drives `request_in` instead.

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
transport reads; exactly one result per accepted submission, retained until the
channel takes it; acceptance decided at end-of-data and never revisited;
transparency encoding correct across a record boundary; and commands that a real
MTA (Exim) parses as byte-legal.

Known gaps, stated rather than implied:

- **`bcm2712` only.** Same as `websocket`, and for no stronger reason than that
  nothing has needed it from `rp2350` yet.
- **Peer identity is an address.** The result carries the address the message
  was submitted to. Stronger identity comes from the `tls` module's peer
  identity when a TLS submission profile is selected, and is not restated here.
