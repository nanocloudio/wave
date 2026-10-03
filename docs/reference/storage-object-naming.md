# S3 names on `storage.object`

How an S3 bucket and key name a `storage.object` object. Every provider an S3
server stores through holds its objects under these names, and every capability
that grants S3 access is minted over a scope of them, so the mapping is a
contract between the server, the providers and whoever issues capabilities.

Source: `modules/common/s3_serve_core.rs` (`s3_object_name`, `s3_upload_name`,
`s3_bucket_valid`), served by `modules/foundation/s3_serve`.

## Objects

Bucket `B` and key `K` name the object

```text
B/o/K
```

- `B` follows S3's bucket naming rules: 3 to 63 bytes of lowercase letters,
  digits, `.` and `-`; starting and ending with a letter or digit; no `..`;
  not shaped like an IPv4 address.
- `K` is the key's bytes, percent-decoded from the request target exactly
  once, and must be non-empty UTF-8.
- The whole name is at most the storage contract's `STORAGE_KEY_MAX` (255)
  bytes. A key that would take it past is refused, never shortened.

A request whose bucket or key breaks a rule is refused before any provider is
asked:

| Broken | S3 error | Status |
|---|---|---|
| bucket naming rules | `InvalidBucketName` | 400 |
| empty key, or not UTF-8 | `InvalidArgument` | 400 |
| name past `STORAGE_KEY_MAX` | `KeyTooLongError` | 400 |

## Multipart staging

An upload `U` (32 lowercase hex digits) of bucket `B` is recorded at `B/u/U`,
and its part `N` (1-10000) is staged at `B/u/U/NNNNN`, five decimal digits.
Staging names never collide with object names, because objects live under
`B/o/` and staging under `B/u/`; a listing of a bucket's objects never sees
an upload.

## Scopes

A capability over S3 names a storage scope — a key prefix ending `/` —
through `fluxor modules cap mint --scope`:

| Scope | Grants |
|---|---|
| `B/` | every object of bucket `B`, and its multipart staging |
| `B/o/P/` | the objects whose keys start `P/` |

A scope narrower than its bucket does not cover `B/u/`, so multipart uploads
with such a key are refused by the provider.

## Listings

A listing of bucket `B` with prefix `P` is a `storage.object` `LIST` of
`B/o/P`. The keys it returns have `B/o/` removed before they reach the client.
