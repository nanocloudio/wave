# `s3` — SigV4-signed S3 connector

A connector for S3-compatible object endpoints. The signing and canonical-form
construction live in the shared `modules/common/s3_core.rs`, the
request/response records in `modules/common/s3_wire.rs`; this module is the
I/O pump around them. Object meaning — which bucket backs which namespace,
what a key maps to — is the consumer's (loam's gateway makes that mapping);
the wire mechanics are Wave's. Relocated from loam.

## Why it is a compiled module and not a codec

S3 GET/PUT is a single round trip — but every request carries an
`Authorization: AWS4-HMAC-SHA256 …` header whose signature is an HMAC chain
(`derive_key(secret, date, region, service)` over a canonical form of
method/URI/headers/payload-hash). It is not the round-trip count that forces a
module here, it is the crypto: a bytecode codec cannot compute an HMAC/SHA-256
signature. SHA-256 itself is SDK-owned
(`target/fluxor/fluxor-abi/sdk/crypto/sha256.rs`), per the same rule as
`websocket`'s SHA-1.

## Two modes, chosen by whether `request_in` is wired

- **Driven** — one S3 operation per `S3Request` record, answered with an
  `S3Response`: GET / PUT / HEAD / DELETE on `/bucket/key`, each signed with
  the payload hashed in. What lets a graph store what it computes.
- **Probe** (`request_in` unwired) — on boot, sign a `GET /` (ListBuckets)
  and report the HTTP status on `status_out` (200 = signature accepted,
  403 = SignatureDoesNotMatch). The cheapest proof of credentials against a
  real endpoint.

## What driven mode guarantees

One record in, one record out. Every `S3Request` the connector understands is
answered with exactly one `S3Response` carrying the same correlation id — the
endpoint's status when it replied, `501` for an operation this connector does
not perform, `413` for an object larger than one record can carry, `500` when
the request could not be built at all, `502` when the transport failed before
the endpoint could answer, and `504` when it stayed silent past the reply
budget. The three 5xx name the failing party: `500` is this connector, `502` the
path to the endpoint, `504` the endpoint itself. A record whose own header is
truncated is dropped rather than answered, because the correlation id is inside
the part that could not be trusted; the drop is logged, since it is the only
signal a caller gets for a record nothing is owed for.

The connector performs one operation at a time, and the answer is what releases
it: a full `response_out` holds the finished record until the caller reads it,
and no further request is taken until then. Draining follows the same rule — the
connector reports itself finished only once nothing it accepted is still
unanswered.

## Ports

| Port | Direction | Content type | Meaning |
| --- | --- | --- | --- |
| `net_in` | input | NetProto | transport events from `ip`/`linux_net` |
| `net_out` | output | NetProto | transport commands |
| `status_out` | output | OctetStream | HTTP status of the last operation |
| `request_in` | input | OctetStream | `S3Request` records (driven mode) |
| `response_out` | output | OctetStream | `S3Response` records |

## Parameters

`endpoint` (hex `[ip:4][port:2 LE]`), `host` (the Host header), `access_key`,
`secret`, `region` — see `define_params!` in `mod.rs`.

The request/response records are deliberately `OctetStream`, not a registered
content type: a `CONTENT_TYPES` entry moves the ABI-surface digest and
re-stamps every fmod in every workspace member, which a two-party record
layout does not earn.
