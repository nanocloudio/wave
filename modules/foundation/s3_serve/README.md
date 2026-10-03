# `s3_serve` — an S3 server over `storage.object`

`s3_serve` answers S3 requests that `http` hands it on an application route,
and stores objects through whichever `storage.object` provider the graph binds.
It never names a provider and never holds a body whole: request bodies move to
the provider's streamed put record by record, and objects move to the peer
through ranged reads, each side paced by credit.

Source: `mod.rs` (exchanges and provider calls), `../../common/s3_serve_core.rs`
(operations, naming, errors, XML, ranges, `aws-chunked`, credentials,
listings, part lists), `../../common/sigv4_core.rs` (signatures).

## Wiring

| Port | Direction | Content type | Edge |
|---|---|---|---|
| `request_in` | input | `HttpRequest` | from `http.req_out`, `buffer_group` set |
| `response_out` | output | `HttpResponse` | to `http.resp_in`, `buffer_group` set |

`http` routes the S3 namespace to the application with an `app: true` route
whose ceiling covers the largest object (`route_N_max_body_kib`).

Resources: `storage.object` (write), `fs` (read, for the credentials file).

The module's heap holds a response record and a listing page for each of its
32 exchanges, and a part list for each of its 4 completions; a request the
heap cannot serve is answered `503 SlowDown`.

## Parameters

| Tag | Name | Default | Meaning |
|---|---|---|---|
| 1 | `credentials` | required | Path of the credentials file, read through `fs`; at most 256 bytes |
| 2 | `region` | `us-east-1` | The region signatures must be scoped to; at most 32 bytes |
| 3 | `mesh_roots` | required | One or two 64-hex Ed25519 mesh root keys, comma-separated |
| 4 | `max_object_mib` | 5120 | Largest object, MiB; at most 5 TiB |
| 5 | `part_min_kib` | 5120 | Smallest multipart part but the last, KiB |

A missing credentials path or roots, a path past 256 bytes, roots that do not
parse, a region past 32 bytes and an object ceiling of 0 or past 5 TiB refuse
construction.

## Credentials

One credential per line; `#` starts a comment:

```text
<access-key> <secret> <scope> <fxcap1 chain> [peer=<fingerprint hex>]
```

The scope is `bucket/`, granting a bucket's objects and its uploads, or
`bucket/o/<prefix>/`, granting only the keys under a prefix. The chain is a
mesh capability whose leaf names the scope's object (`fluxor modules cap mint
--scope <scope>`). At most 16 credentials; access keys and secrets at most
128 bytes.

When the file is loaded, every chain is verified against `mesh_roots` and the
trusted clock, and must name its scope's object. Any line that does not parse
and any chain that does not verify leaves the module serving nothing: every
request is answered `503`. Loading waits for a trusted clock.

Each chain is then presented to the provider (`PRESENT`) once, and every
operation made with that access key runs under the grant the provider answered.
Whether a key reaches a bucket is the provider's decision on each operation;
the module keeps no list of what a key may touch. A provider that keeps no
authority (`PRESENT` answers `ENOSYS`) is refused for the same reason: the
scope would be enforced by nothing.

`peer=` binds a key to the mutual-TLS identity `http` reports for the
connection. A bound key is refused (`AccessDenied`) on a connection that
verified no peer or a different one; an unbound key is accepted whatever the
channel. The binding is opt-in per key because the signature already proves the
caller holds the secret; binding adds that it must also hold the client key,
which a deployment chooses where secrets travel further than certificates.

## Authentication

Every request must carry a SigV4 signature, in the `Authorization` header or
as presigned query parameters. Unsigned requests are refused `403
AccessDenied`. The credential scope must name this server's region and the
`s3` service; the request time must be within 15 minutes of the trusted clock,
counting the clock's uncertainty against the request; a presigned URL is
refused once its lifetime (at most seven days) has passed, by the same
conservative reading. Without a trusted clock requests are answered `503`.

Payload forms:

| `x-amz-content-sha256` | Checked |
|---|---|
| hex SHA-256 | as the body streams; a mismatch aborts the write (`XAmzContentSHA256Mismatch`) |
| `UNSIGNED-PAYLOAD` | not hashed |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | each `aws-chunked` chunk's signature, chained from the request's |

Trailer forms, `x-amz-checksum-*`, `Content-MD5` and `x-amz-copy-source` are
refused `501 NotImplemented` rather than accepted unchecked.

## Operations

| Request | Operation |
|---|---|
| `GET /` | ListBuckets — the bucket of the key's scope |
| `HEAD`/`PUT /b` | HeadBucket / CreateBucket — 200 when the grant reaches the bucket |
| `GET /b?location` | GetBucketLocation |
| `GET /b`, `GET /b?list-type=2` | ListObjects, ListObjectsV2 — `prefix`, `delimiter`, `max-keys` (1-1000), `continuation-token`, `start-after`/`marker`, `encoding-type=url` |
| `PUT /b/k` | PutObject, streamed; `If-None-Match: *` and `If-Match` are conditions on the commit |
| `GET`/`HEAD /b/k` | GetObject / HeadObject — `Range`, `If-Match`, `If-None-Match` |
| `DELETE /b/k` | DeleteObject — 204, also for a missing key |
| `POST /b/k?uploads` | CreateMultipartUpload |
| `PUT /b/k?partNumber&uploadId` | UploadPart, streamed |
| `POST /b/k?uploadId` | CompleteMultipartUpload |
| `DELETE /b/k?uploadId` | AbortMultipartUpload |

Anything else is `501 NotImplemented`; a method S3 does not define for the
resource is `405 MethodNotAllowed`.

Every write is acknowledged only once the provider has decided it — a pending
answer is asked again with the same request — and the fence it reported is
returned as `x-fluxor-fence`: `volatile`, `local-durable`,
`replicated-durable`, `content-hashed`, `revision-monotone` or
`view-consistent`.

## Errors

S3 errors are XML `<Error>` documents (`Code`, `Message`, `Resource`,
`RequestId`). A provider answer maps to one:

| Provider | S3 | Status |
|---|---|---|
| `ENXIO`, `ENOENT` | `NoSuchKey` (`NoSuchUpload` for an upload) | 404 |
| `EACCES` | `AccessDenied` | 403 |
| `EEXIST`, `EAGAIN` on a write | `PreconditionFailed` | 412 |
| `EINVAL` | `InvalidArgument` | 400 |
| `EOVERFLOW` | `KeyTooLongError` | 400 |
| `ENOSPC` | `InsufficientStorage` | 507 |
| `ENOMEM`, `EBUSY` | `SlowDown` | 503 |
| `ENOSYS` | `NotImplemented` | 501 |
| anything else | `InternalError` | 500 |

`EINPROGRESS` on a write and `EAGAIN` on a read are not errors: the request is
asked again. An error after the response has begun ends it with an abort, which
`http` turns into a reset or a closed connection; a failed completion, whose
`200` goes out early, carries its `<Error>` in the body as S3 does.

## Naming

Bucket `B` and key `K` name the object `B/o/K`; multipart uploads are staged
under `B/u/`. The full contract is
[docs/reference/storage-object-naming.md](../../../docs/reference/storage-object-naming.md).

## Multipart uploads

An upload is recorded at `B/u/<id>` and each part staged at
`B/u/<id>/<NNNNN>` through the streamed put. Completion checks the listed
parts (ascending, each staged under the ETag listed for it, each but the last
at least `part_min_kib`),
answers `200` at once, copies the parts into the final object through one
streamed put while sending whitespace every few seconds, commits, and removes
the staging. An abort removes the staging.

Uploads do not survive a restart: everything under each bucket's `u/` is
removed when the module starts. An upload untouched for 24 hours is reclaimed
the same way.

## Limits

Each refuses rather than clamps:

| Limit | Value | Refusal |
|---|---|---|
| Object size | `max_object_mib` | `EntityTooLarge` |
| Part size | 5 GiB | `EntityTooLarge` |
| Part number | 1-10000 | `InvalidArgument` |
| Key | object name within `STORAGE_KEY_MAX` | `KeyTooLongError` |
| `max-keys` | 1000 | `InvalidArgument` |
| `Content-Type` stored | 128 bytes | `InvalidArgument` |
| `If-Match`, `If-None-Match` | 200 bytes | `InvalidArgument` |
| Exchanges in flight | 32 | `503 SlowDown` |
| Uploads open | 64 | `503 SlowDown` |
| Completions in progress | 4 | `503 SlowDown` |
| Provider entity tag | 32 bytes | `500 InternalError` |
| Credentials | 16 | refuses to serve |
| Credentials file | 16 KiB | refuses to serve |
