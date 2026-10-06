# `s3` — SigV4-signed S3 connector

A client for S3-compatible object endpoints. Signing lives in the shared
`modules/common/sigv4_core.rs`; the signed request head, `aws-chunked` body
framing and response framing in `modules/common/s3_core.rs`; the records it
answers are fluxor's exchange contract (`abi::contracts::exchange`), in which
it is a PROVIDER. This module is the I/O pump around them. Object meaning — which bucket backs which namespace, what a key maps to —
is the consumer's; the wire mechanics are Wave's.

## Why it is a compiled module and not a codec

An S3 operation is a single round trip — but every request carries an
`Authorization: AWS4-HMAC-SHA256 …` header whose signature is an HMAC chain
(`derive_key(secret, date, region, service)` over a canonical form of
method/URI/headers/payload-hash), and a streamed body signs every chunk. It is
not the round-trip count that forces a module here, it is the crypto: a
bytecode codec cannot compute an HMAC/SHA-256 signature. SHA-256 itself is
SDK-owned (`target/fluxor/fluxor-abi/sdk/crypto/sha256.rs`), per the same rule
as `websocket`'s SHA-1.

## Two modes, chosen by whether `request_in` is wired

- **Driven** — one exchange at a time, as an exchange provider: GET / PUT /
  HEAD / DELETE / POST on `/bucket/key[?query]`, with request and response
  bodies of any size streamed under credit.
- **Probe** (`request_in` unwired) — on boot, sign a `GET /` (ListBuckets)
  and report the HTTP status on `status_out` (200 = signature accepted,
  403 = SignatureDoesNotMatch). The cheapest proof of credentials against a
  real endpoint.

## Records

Both record ports are framed, so the build gives each edge a mailbox of its
own: one write is one whole record and one read takes one.

A caller writes, on `request_in`:

- **HEAD** — `id` (caller-chosen, echoed verbatim on every record of the
  exchange), `method` (the exchange contract's vocabulary), `target`
  (`/bucket/key[?query]`, percent-encoded as it goes on the wire), `headers`
  (extra `name: value\r\n` lines to send, such as `range`, `content-type`,
  `content-length`; never `host`, which the connector signs as its own
  `authority`), `peer` empty, `resp_credit`, the response-body credit it
  grants up front, and the body's first bytes. A body that fits rides whole in
  the HEAD with no MORE, and then needs no `content-length`: its length is the
  bytes it carries. MORE says BODY records follow, and then `content-length`
  must declare the whole body, inline bytes included.
- **BODY** — request body bytes, MORE on every record but the last, never
  more than the credit the connector has granted.
- **CREDIT** — more response-body credit.
- **ABORT** — the caller ends the exchange: the connection is closed and no
  further record is sent for it.

The connector writes, on `response_out`:

- **HEAD** — the endpoint's status, `Content-Type`, every other response
  header line except the connection's own framing (`Connection`,
  `Keep-Alive`, `Transfer-Encoding`; `Content-Length` is forwarded so a caller
  sees an object's size), and the first body bytes. MORE while body follows.
- **BODY** — response body bytes as they arrive, decoded from
  `Content-Length`, chunked or close-delimited framing, never more than the
  caller's credit. MORE on every record but the last.
- **CREDIT** — request-body credit, granted as the body's bytes leave for the
  transport.
- **ABORT** — the exchange failed after its response began.

## What driven mode guarantees

One HEAD in, one terminal outcome out. Every request HEAD the connector takes
off `request_in` ends in exactly one terminal record: the endpoint's response
ending (a HEAD or BODY without MORE), or an ABORT. A failure before any
response record has gone out is answered with a HEAD carrying the connector's
own status:

| Status | Meaning |
| --- | --- |
| `400` | the request is malformed: a target that cannot be signed (not absolute path form, a broken `%` escape, more than 64 query parameters), extra headers that are not `name: value\r\n` lines or name a header the connector writes itself (`host`, `authorization`, `connection`, `transfer-encoding`, `content-encoding`, `expect`, `x-amz-*` signing fields), or a `content-length` that is not one decimal number |
| `400` | a method other than GET, PUT, HEAD, DELETE or POST; a body that follows its HEAD with no `content-length`, since S3 needs a body's length before its first byte; a `content-length` the inline body disagrees with |
| `413` | a target past 2048 bytes or extra headers past 2048 |
| `500` | the request could not be built at all — this connector is the failing party |
| `502` | the path to the endpoint failed before it answered: a failed dial, a transport error, a close before the response head, or a response head that is malformed or larger than 4096 bytes |
| `503` | a drain arrived before the exchange was attempted |
| `504` | the endpoint stayed silent past its budget (10 s to connect, 15 s without progress) |

After the response has begun, a failure is an ABORT: `PEER_GONE` when the
transport closes or fails mid-body, `MALFORMED` when the response's chunk
framing is broken, `STALLED` when the endpoint goes silent. A caller that
breaks the exchange's contract is answered with ABORT whether or not a
response has begun: `MALFORMED` for a body longer or shorter than its
`content-length`,
`CREDIT_OVERRUN` for body bytes past the credit granted, `STALLED` for a
caller that neither sends the body nor reads the response for 30 s. Every
ABORT closes the connection.

## Bodies, credit and signing

A body of at most one chunk (8192 bytes) is taken whole into the chunk buffer
— whatever the HEAD did not carry inline is granted as credit once the
connection is up — and its SHA-256 is the payload hash, as
`x-amz-content-sha256`. A larger body goes out
`aws-chunked`: `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
`Content-Encoding: aws-chunked`, `x-amz-decoded-content-length`, and a wire
`Content-Length` that is the encoded length, computed before the first byte
from the declared length and the fixed chunk size. Each 8192-byte chunk is
signed in a chain from the head's own signature, and the connector holds at
most one: the caller is granted one chunk's credit once the head has left, and
the next only once that chunk's bytes have left for the transport. Signed
headers are `host`, `x-amz-content-sha256`, `x-amz-date` and, when streaming,
`x-amz-decoded-content-length`; the signature binds the wall-clock time at the
moment the request is built, after the connection is up.

The response body moves on the caller's credit in the same way. The connector
holds at most one transport segment of it, and does not read `net_in` again
until that segment has been forwarded — a caller that stops granting credit
holds the endpoint back through TCP, not through a buffer here.

## One at a time, and the drain

The connector performs one exchange at a time on its own connection
(`Connection: close`). With no connection held between exchanges there is no
backend link to report: an endpoint that cannot be reached is that exchange's
502, and the connector writes no LINK. A HEAD written while one is in flight is read and held;
it begins when the exchange ahead of it has ended and its terminal record has
been taken, and the caller may grant it credit or abort it while it waits.

Every boundary is held to the same rule. A full `response_out` holds a record
until the caller reads it, and no further exchange starts until then. A dial,
a request frame or a close the transport refuses is offered again unchanged on
a later step, so a signed request never goes out with a hole in it and a
connection is never left open because its close could not be written.

Draining closes the connector to new work without abandoning work it took:
`request_in` is read only while an exchange is in flight (it may still need its
caller's body and credit to finish); a HEAD taken behind it is answered `503`;
and the connector reports itself finished only once nothing it took is
unanswered and the transport has taken every command it owes. A HEAD still on
the channel was never taken and is owed nothing.

## Ports

| Port | Direction | Content type | Meaning |
| --- | --- | --- | --- |
| `net_in` | input | NetProto | transport events from `ip`/`linux_net` |
| `net_out` | output | NetProto | transport commands |
| `status_out` | output | TextPlain | probe mode: HTTP status of the ListBuckets probe |
| `request_in` | input | ExchangeRequest | request-direction records (driven mode) |
| `response_out` | output | ExchangeResponse | response-direction records |

## Parameters

`authority` (`host[:port]`, port 80 when it names none: where the connector
dials — a name goes to the network provider as a name, for it to resolve —
and, verbatim, the `Host` SigV4 signs), `access_key`, `secret`, `region` — see
`define_params!` in `mod.rs`. The authority is at most 128 bytes; absent,
longer, or not `host[:port]` refuses construction. `access_key`, `secret` and
`region` are each at most 128 bytes, and a longer one refuses construction
rather than signing with a prefix of it; `region` defaults to `us-east-1`.
