# Limit register

The ceilings this project chose, why each is where it is, and what a caller
meets on the far side of it.

A ceiling found in one of the source files named below but absent from this
document is a bug. That is a claim about the code, and an unchecked claim
about code decays into a claim about whoever last edited the register — so
`fluxor ci`'s `limit-register` phase checks it. Every row in the fenced block
at the end must still be declared, with the value quoted, in the file it
names; every name in that block must also appear in the prose here; and any
ceiling-shaped constant in a named file that is neither registered nor
exempted fails the gate.

Scope is deliberate. A file named here is one the register vouches for
entirely, so adding a file means accounting for every ceiling in it. The set
starts at the ceilings already published to readers in
[docs/reference/envelope.md](../reference/envelope.md) and owned by Wave rather
than by a Fluxor profile constant. Growing it is an act of ownership, not
bookkeeping.

## HTTP/2

| Ceiling | Value | What one past it meets |
|---|---|---|
| `MAX_STREAMS` | 4 | `REFUSED_STREAM`, counted as `h2_streams_refused` |

Four concurrent streams per connection, the same on every target. A browser
opening a fifth is told to retry it rather than queued, because a queue here
is indistinguishable from a slow server and costs the memory the refusal
exists to protect.

## HTTP/3

| Ceiling | aarch64 | elsewhere | What one past it meets |
|---|---|---|---|
| `MAX_H3_SESSIONS` | 8 | 2 | session closed, `H3_REQUEST_REJECTED` |
| `MAX_H3_STREAMS` | 16 | 4 | stream refused |
| `MAX_PEER_UNI` | 4 | 4 | `H3_STREAM_CREATION_ERROR` |

The session and stream tables split by architecture because HTTP/3 rides
Fluxor's `quic`, which targets bcm2712 only: on every other target this state
is structurally idle and sized to pay for nothing beyond existing. The stream
table is shared across sessions, so it is the total in flight rather than a
per-session allowance.

`MAX_PEER_UNI` is four because HTTP/3 defines three peer-initiated
unidirectional streams — control, QPACK encoder, QPACK decoder — and the
fourth is the spare that lets a push or a greased stream arrive without
costing the peer an error it did not earn.

| Ceiling | Value | What one past it meets |
|---|---|---|
| `H3_WS_PAYLOAD_MAX` | 512 | oversized frame refused |
| `TUNNEL_FRAME_MAX` | `H3_SEND_BUF - 24` | frame split to fit |

`H3_WS_PAYLOAD_MAX` bounds one WebSocket payload carried over an HTTP/3
extended-CONNECT stream. `TUNNEL_FRAME_MAX` is not an independent choice: it
is the send buffer less the largest frame header the tunnel can prepend, and
it is registered as that expression so the derivation stays visible and a
change to the buffer cannot silently outgrow the header allowance.

## HTTP application records

| Ceiling | Value | What one past it meets |
|---|---|---|
| `APP_RECORD_MAX` | 8192 | the record is not written; nothing larger is ever composed |
| `APP_BODY_MAX` | `APP_RECORD_MAX - APP_HDR` | a body is split across records |
| `MAX_FWD_HEADERS` | 4096 | `431`, the request never reaches the application |
| `MAX_TARGET` (`app.rs`) | 2048 | `414` |
| `MAX_H3_FIELDS` | `MAX_FWD_HEADERS`, 0 without applications | `431` on HTTP/3 |
| `MAX_EXCHANGES` (`app.rs`) | one per connection, h2 stream and h3 stream | `503`, the request is not opened |
| `QUEUE_LIMIT` | `RESP_WINDOW` plus two records | `ABORT(CREDIT_OVERRUN)`, counted as `app_violations` |

An application exchange travels in records of `APP_RECORD_MAX` bytes — one
mailbox write, small enough for every target's channel — so a body moves as
many records, never one buffer. The request head that opens an exchange must
fit one record, which is why its header block and target are bounded where
the head is composed rather than wherever they happen to overflow. `MAX_H3_FIELDS`
is the same header bound reached through QPACK, and does not exist on a build
that forwards to no application.

`MAX_EXCHANGES` is not chosen: it is the number of requests the transport
tables can have open, so an exchange can only be refused when the connection
or stream that carries it could not exist either. `QUEUE_LIMIT` is what one
exchange may have queued toward the peer — the response credit it was given
plus a head record and one record of slack. An application inside its credit
never reaches it, so reaching it is a broken contract and is answered as one.

## Request bodies

| Ceiling | Value | What one past it meets |
|---|---|---|
| `DEFAULT_MAX_BODY` | 64 KiB | `413`, before the body is read when the length is declared |
| `MAX_BODY_KIB_CEILING` | `1 << 30` KiB | construction refused |
| `H3_RX_HOLD` | 256 KiB | the peer is not given credit past it |

A route's body ceiling is the route's to declare (`route_N_max_body_kib`);
`DEFAULT_MAX_BODY` is what a route that declares nothing accepts. A body is
streamed under credit and never held whole, so the ceiling bounds what a
route accepts rather than memory. `MAX_BODY_KIB_CEILING` bounds the
declaration, 1 TiB, so a saturated parameter is refused rather than read as a
choice. `H3_RX_HOLD` is the request body an HTTP/3 stream holds between QUIC
and the application; credit returns to the peer only as bytes are forwarded.

## SigV4

| Ceiling | Value | What one past it meets |
|---|---|---|
| `SV4_SKEW_MAX` | 900 s | `RequestTimeTooSkewed` |
| `SV4_EXPIRES_MAX` | 7 days | `AuthorizationQueryParametersError` |
| `SV4_QUERY_PARAMS_MAX` | 64 | `InvalidArgument` (server); `400` (connector) |
| `SV4_SIGNED_HEADERS_MAX` | 32 | `InvalidArgument` |

The skew and presign lifetime are S3's own. The two counts bound the
canonical request, which is built in fixed scratch: 64 query parameters and
32 signed headers are past anything an S3 client sends.

## S3 server

| Ceiling | Value | What one past it meets |
|---|---|---|
| `OBJECT_CEILING_MIB` | 5 TiB | `max_object_mib` past it refuses construction |
| `PART_SIZE_MAX` | 5 GiB | `EntityTooLarge` |
| `S3_PART_NUMBER_MAX` | 10000 | `InvalidArgument` |
| `S3_BUCKET_MAX` | 63 | `InvalidBucketName` |
| `NAME_MAX` | `STORAGE_KEY_MAX` | `KeyTooLongError` |
| `CT_MAX` (`s3_serve`) | 128 | `InvalidArgument` |
| `READ_RANGE_MAX` | 64 | the `Range` is not a single range, and the object is served whole |
| `READ_COND_MAX` | 200 | `InvalidArgument` |
| `S3_CHUNK_LINE_MAX` | `16 + 17 + 64 + 2` | `IncompleteBody` |
| `MAX_EXCHANGES` (`s3_serve`) | 32 | `503 SlowDown` |
| `MAX_UPLOADS` | 64 | `503 SlowDown` |
| `MAX_COMPLETIONS` | 4 | `503 SlowDown` |
| `ETAG_MAX` | 32 | `InternalError`; a listed part's longer tag is `InvalidPart` |
| `UPLOAD_TTL_S` | 24 h | the upload's staging is reclaimed |
| `LIST_RENDER_CAP` | `(LIST_PAGE_BUF - LIST_DOC_RESERVE) / LIST_EXPANSION` | a listing page is asked for no more entries |
| `MAX_CREDENTIALS` | 16 | the module serves nothing; every request `503` |
| `CREDS_FILE_MAX` | 16 KiB | the module serves nothing |
| `S3_ACCESS_KEY_MAX` | 128 | the module serves nothing |
| `S3_SECRET_MAX` | 128 | the module serves nothing |
| `S3_PEER_MAX` | 128 | the module serves nothing |

The object and part ceilings are S3's; a deployment narrows the object one
with `max_object_mib`. A key is bounded by the storage name it becomes, so
the bound is the storage contract's, not a separate choice. The exchange and
upload tables are what the module holds at once; past them a client is told
to slow down rather than queued. A completion holds every listed part's number
and entity tag, up to 10000 of them, so completions in progress have their
own, smaller table. The heap is sized from the exchange and completion
tables, so it cannot run out before they do. `ETAG_MAX` is the longest entity
tag a provider may answer — Fluxor's stores answer 32 bytes — and a longer
one is an error rather than a prefix, since a prefix names nothing.

`LIST_RENDER_CAP` is derived: the most entries a page may hold such that
every one, escaped, still renders beside the document's head and tail.

A credentials file the module cannot hold whole, a credential it cannot
store, or more credentials than the table leaves the module serving nothing:
loading part of a file would hand out an authority nobody wrote down.

## S3 connector

| Ceiling | Value | What one past it meets |
|---|---|---|
| `MAX_TARGET` (`s3`) | 2048 | `400` |
| `MAX_CALLER_HEADERS` | 2048 | `400` |
| `RESP_HEAD_MAX` | 4096 | `502`, the connection closed |
| `CT_MAX` (`s3`) | 255 | the content type is forwarded among the headers |
| `SEND_MAX` | `net_proto::MAX_DATA_FRAGMENT` | the request is split across frames |

The target and caller headers bound what the connector signs, in the fixed
scratch the canonical request is built in. `RESP_HEAD_MAX` bounds what it
parses of an endpoint's answer, and also guarantees the response head fits one
record. `CT_MAX` is the record's one-byte content-type length. `SEND_MAX` keeps
each frame within `net_out`'s record.

## Not ceilings

Two constants in the named files match the naming convention without being
policy. They are exempted in the second block below, each with its reason:
`WS_BUF_SIZE` is per-stream reassembly scratch, and `H3_VARINT_MAX` is the
width RFC 9000 gives a QUIC varint — a wire fact, not a decision this project
made.

## Elsewhere

Ceilings this register does not yet cover, and where they are enforced today:

- **The connection envelope** — the transport, TLS and HTTP slot tables are
  Fluxor profile constants, not Wave's. They are generated into
  [docs/reference/envelope.md](../reference/envelope.md) straight from the
  compiled constants by `tools/ci/envelope_table.sh`, which fails when the
  document and the profile disagree.
- **Flash budgets** — every artefact's ceiling lives in
  `tools/ci/fmod_size_budget.sh`, which also enforces that a variant stays
  smaller than the superset it is a subset of.

```limit-register
MAX_STREAMS | modules/foundation/http/server/h2.rs | 4
MAX_H3_SESSIONS | modules/foundation/http/server/h3.rs | 8
MAX_H3_SESSIONS | modules/foundation/http/server/h3.rs | 2
MAX_H3_STREAMS | modules/foundation/http/server/h3.rs | 16
MAX_H3_STREAMS | modules/foundation/http/server/h3.rs | 4
MAX_PEER_UNI | modules/foundation/http/server/h3.rs | 4
H3_WS_PAYLOAD_MAX | modules/foundation/http/server/h3.rs | 512
TUNNEL_FRAME_MAX | modules/foundation/http/server/h3.rs | H3_SEND_BUF - 24
MAX_FWD_HEADERS | modules/foundation/http/server/app.rs | 4096
MAX_TARGET | modules/foundation/http/server/app.rs | 2048
MAX_EXCHANGES | modules/foundation/http/server/app.rs | MAX_CONCURRENT_CONNS + H2_EXCHANGES + H3_EXCHANGES
QUEUE_LIMIT | modules/foundation/http/server/app.rs | RESP_WINDOW + 2 * (RECORD_MAX as u32 + 4)
MAX_H3_FIELDS | modules/foundation/http/server/h3.rs | super::app::MAX_FWD_HEADERS
MAX_H3_FIELDS | modules/foundation/http/server/h3.rs | 0
H3_RX_HOLD | modules/foundation/http/server/h3.rs | 256 * 1024
DEFAULT_MAX_BODY | modules/foundation/http/server/reqbody.rs | 64 * 1024
MAX_BODY_KIB_CEILING | modules/foundation/http/server/reqbody.rs | 1 << 30
SV4_EXPIRES_MAX | modules/common/sigv4_core.rs | 7 * 24 * 3600
SV4_SKEW_MAX | modules/common/sigv4_core.rs | 15 * 60
SV4_QUERY_PARAMS_MAX | modules/common/sigv4_core.rs | 64
SV4_SIGNED_HEADERS_MAX | modules/common/sigv4_core.rs | 32
S3_BUCKET_MAX | modules/common/s3_serve_core.rs | 63
S3_PART_NUMBER_MAX | modules/common/s3_serve_core.rs | 10_000
S3_CHUNK_LINE_MAX | modules/common/s3_serve_core.rs | 16 + 17 + 64 + 2
S3_ACCESS_KEY_MAX | modules/common/s3_serve_core.rs | 128
S3_SECRET_MAX | modules/common/s3_serve_core.rs | 128
S3_PEER_MAX | modules/common/s3_serve_core.rs | 128
OBJECT_CEILING_MIB | modules/foundation/s3_serve/mod.rs | 5 * 1024 * 1024
PART_SIZE_MAX | modules/foundation/s3_serve/mod.rs | 5 << 30
NAME_MAX | modules/foundation/s3_serve/mod.rs | STORAGE_KEY_MAX
CT_MAX | modules/foundation/s3_serve/mod.rs | 128
READ_RANGE_MAX | modules/foundation/s3_serve/mod.rs | 64
READ_COND_MAX | modules/foundation/s3_serve/mod.rs | 200
MAX_EXCHANGES | modules/foundation/s3_serve/mod.rs | 32
MAX_UPLOADS | modules/foundation/s3_serve/mod.rs | 64
MAX_COMPLETIONS | modules/foundation/s3_serve/mod.rs | 4
ETAG_MAX | modules/foundation/s3_serve/mod.rs | 32
UPLOAD_TTL_S | modules/foundation/s3_serve/mod.rs | 24 * 3600
LIST_RENDER_CAP | modules/foundation/s3_serve/mod.rs | (LIST_PAGE_BUF - LIST_DOC_RESERVE) / LIST_EXPANSION
MAX_CREDENTIALS | modules/foundation/s3_serve/mod.rs | 16
CREDS_FILE_MAX | modules/foundation/s3_serve/mod.rs | 16 * 1024
MAX_TARGET | modules/foundation/s3/mod.rs | 2048
MAX_CALLER_HEADERS | modules/foundation/s3/mod.rs | 2048
RESP_HEAD_MAX | modules/foundation/s3/mod.rs | 4096
CT_MAX | modules/foundation/s3/mod.rs | 255
SEND_MAX | modules/foundation/s3/mod.rs | net_proto::MAX_DATA_FRAGMENT
```

```limit-register-exempt
WS_BUF_SIZE | modules/foundation/http/server/h2.rs | per-stream WebSocket reassembly scratch, sized to the frame codec rather than chosen as a limit
H3_VARINT_MAX | modules/foundation/http/server/h3.rs | the width RFC 9000 gives a QUIC varint, not a choice this project makes
```
