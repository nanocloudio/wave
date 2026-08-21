# `smtp` — RFC 5321 mail submission client

A connector for outbound mail **submission** only. The protocol logic lives in
the host-tested `modules/common/smtp_core.rs`; this module is the I/O
pump around it. Message meaning — who sends, what is in the body, what a bounce
means — is Conclave's; the wire mechanics are Wave's.

## Why it is a compiled module and not a codec

The conversation is lockstep and server-led:

```text
  connect -> 220 greeting -> EHLO/250 -> MAIL FROM/250 -> RCPT TO/250
          -> DATA/354 -> <dot-stuffed message>.CRLF/250 -> QUIT/221
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
| `status_out` | 1 | output | `OctetStream` | One human-readable delivery result line |

`status_out` emits exactly one of `smtp: delivered`, `smtp: rejected`,
`smtp: connection closed`, `smtp: network error`, or `smtp: timeout`. Delivery is
`delivered` only after the server accepts end-of-data (250) **and** the QUIT is
answered (221) — an accepted DATA with a dropped connection is not a delivery.

## Parameters

| Id | Name | Meaning |
| --- | --- | --- |
| 1 | `endpoint` | Hex `[ip:4][port:2 LE]` — configs carry text, so bytes arrive hex-encoded |
| 2 | `helo` | EHLO domain |
| 3 | `mail_from` | Envelope sender |
| 4 | `rcpt_to` | Envelope recipient (one) |
| 5 | `body` | Message headers and body; dot-stuffed on the way out |

## Timing

`timer_class = "wall_clock"`. Two deadlines, both `dev_millis`:
`CONNECT_TIMEOUT_MS` (10 s) and `REPLY_TIMEOUT_MS` (15 s). A stalled server
produces `smtp: timeout` and a closed connection, never an indefinite wait.

## Scope — read this before wiring it

**Unauthenticated submission only: no STARTTLS, no AUTH, no pipelining, one
recipient, one message per module instance.** That is the class of deployment
that submits to a trusted relay or sink behind a security boundary. It is *not*
safe to point at a public MX over the open internet: the envelope and body cross
the wire in the clear. TLS is not this module's concern either way — wire
Fluxor's `tls` module between the transport and `net_in`/`net_out` for an
implicit-TLS submission port, exactly as `websocket` does for `wss://`.

No MX resolution, no queue, no retry, no DSN parsing, no 8BITMIME/SMTPUTF8
negotiation.

## Status

The module's behavioural contract: silence until the 220 greeting, the
conversation advanced exactly once per reply however the bytes are split across
transport reads, `delivered` never reported on rejection, deferral, or a dropped
connection, and commands that a real MTA (Exim) parses as byte-legal.

Known gaps, stated rather than implied:

- **`bcm2712` only.** Same as `websocket`, and for no stronger reason than that
  nothing has needed it from `rp2350` yet.
