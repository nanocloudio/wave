# `s3` — SigV4-signed S3 connector

A connector for S3-compatible object endpoints. The signing and canonical-form
construction live in the host-tested `modules/common/s3_core.rs`, the
request/response records in `modules/common/s3_wire.rs`; this module is the
I/O pump around them. Object meaning — which bucket backs which namespace,
what a key maps to — is the consumer's (loam's gateway makes that mapping);
the wire mechanics are Wave's. Relocated from loam per
`../fluxor/.context/rfc_storage_capability_symmetry.md` §7.

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
