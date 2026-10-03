// The protocol half of an S3 server: everything `s3_serve` decides from bytes
// alone. Bounded, no_std, no allocation, no I/O. Mounted after `sha256.rs`
// (SDK) and `sigv4_core.rs`, whose items it names by bare name.
//
// What lives here: which S3 operation a request is; how a bucket and key name
// a `storage.object` object; the S3 error vocabulary and its statuses; the XML
// a response carries; byte ranges; the `aws-chunked` body decoder that checks
// each chunk's signature; the credentials file; list continuation tokens; the
// `CompleteMultipartUpload` part list.
//
// ## Object naming
//
// A bucket `B` and key `K` name the `storage.object` object `B/o/K`, where `K`
// is the key's bytes (percent-decoded from the request target) and must be
// UTF-8. Multipart staging lives beside the objects, under `B/u/`: the upload
// `U` is recorded at `B/u/U` and its part `N` staged at `B/u/U/NNNNN`. A
// capability over the scope `B/` therefore covers a bucket's objects and its
// uploads; one over `B/o/P/` covers the keys under `P/` alone.
//
// Refused explicitly, never adjusted: a bucket outside S3's naming rules
// (`InvalidBucketName`), an empty key or one that is not UTF-8
// (`InvalidArgument`), and a key whose object name would pass the storage
// contract's `STORAGE_KEY_MAX` (`KeyTooLongError`).

/// Shortest and longest bucket names S3 allows.
pub const S3_BUCKET_MIN: usize = 3;
pub const S3_BUCKET_MAX: usize = 63;
/// The separator between a bucket and its objects.
pub const S3_OBJECTS: &[u8] = b"/o/";
/// The separator between a bucket and its multipart staging.
pub const S3_UPLOADS: &[u8] = b"/u/";
/// Bytes of an upload id: 16 random bytes in hex.
pub const S3_UPLOAD_ID_LEN: usize = 32;
/// Highest part number S3 allows.
pub const S3_PART_NUMBER_MAX: u32 = 10_000;
/// Longest chunk-size line of an `aws-chunked` body:
/// `hex(size);chunk-signature=<64 hex>\r\n`.
pub const S3_CHUNK_LINE_MAX: usize = 16 + 17 + 64 + 2;

// ── Operations ───────────────────────────────────────────────────────────

/// What a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3Op {
    ListBuckets,
    HeadBucket,
    CreateBucket,
    DeleteBucket,
    GetBucketLocation,
    ListObjects,
    ListObjectsV2,
    PutObject,
    GetObject,
    HeadObject,
    DeleteObject,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    /// A bucket or object operation this server does not perform.
    NotImplemented,
    /// A method S3 does not define for the resource.
    MethodNotAllowed,
}

/// A request's resource, as spans of the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S3Resource<'a> {
    /// The bucket, as sent (bucket names have nothing to decode).
    pub bucket: &'a [u8],
    /// The key, still percent-encoded; empty for a bucket or service request.
    pub key: &'a [u8],
    /// The raw query.
    pub query: &'a [u8],
}

/// Split a path-style target into bucket, key and query.
pub fn s3_resource(target: &[u8]) -> S3Resource<'_> {
    let (path, query) = sv4_split_target(target);
    let path = path.strip_prefix(b"/").unwrap_or(path);
    let (bucket, key) = match path.iter().position(|&c| c == b'/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path, &path[path.len()..]),
    };
    S3Resource { bucket, key, query }
}

/// Classify a request by method (the `http_exchange` vocabulary's names, as
/// bytes) and resource.
pub fn s3_classify(method: &[u8], r: &S3Resource<'_>) -> S3Op {
    let q = r.query;
    if r.bucket.is_empty() {
        return if method == b"GET" {
            S3Op::ListBuckets
        } else {
            S3Op::MethodNotAllowed
        };
    }
    if r.key.is_empty() {
        // Bucket subresources this server does not keep (policies, ACLs,
        // versioning, …) are refused, not answered as a listing.
        let sub = s3_bucket_subresource(q);
        return match (method, sub) {
            (b"GET", Sub::None) => {
                if sv4_query_param(q, b"list-type") == Some(b"2") {
                    S3Op::ListObjectsV2
                } else {
                    S3Op::ListObjects
                }
            }
            (b"GET", Sub::Location) => S3Op::GetBucketLocation,
            (b"HEAD", Sub::None) => S3Op::HeadBucket,
            (b"PUT", Sub::None) => S3Op::CreateBucket,
            (b"DELETE", Sub::None) => S3Op::DeleteBucket,
            (_, Sub::Other) | (_, Sub::Location) => S3Op::NotImplemented,
            _ => S3Op::MethodNotAllowed,
        };
    }
    let has_upload = sv4_query_param(q, b"uploadId").is_some();
    if sv4_query_has(q, b"uploads") {
        return if method == b"POST" {
            S3Op::CreateMultipartUpload
        } else {
            S3Op::NotImplemented
        };
    }
    if has_upload {
        return match method {
            b"PUT" => S3Op::UploadPart,
            b"POST" => S3Op::CompleteMultipartUpload,
            b"DELETE" => S3Op::AbortMultipartUpload,
            b"GET" => S3Op::NotImplemented,
            _ => S3Op::MethodNotAllowed,
        };
    }
    if s3_object_subresource(q) {
        return S3Op::NotImplemented;
    }
    match method {
        b"PUT" => S3Op::PutObject,
        b"GET" => S3Op::GetObject,
        b"HEAD" => S3Op::HeadObject,
        b"DELETE" => S3Op::DeleteObject,
        _ => S3Op::MethodNotAllowed,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sub {
    None,
    Location,
    Other,
}

/// Query parameters that only carry the request, never select a subresource.
fn s3_plain_param(k: &[u8]) -> bool {
    k.starts_with(b"X-Amz-")
        || k.starts_with(b"x-amz-")
        || matches!(
            k,
            b"list-type"
                | b"prefix"
                | b"delimiter"
                | b"continuation-token"
                | b"max-keys"
                | b"start-after"
                | b"encoding-type"
                | b"fetch-owner"
                | b"marker"
                | b"partNumber"
                | b"uploadId"
                | b"response-content-type"
                | b"response-content-disposition"
                | b"response-cache-control"
        )
}

fn s3_bucket_subresource(q: &[u8]) -> Sub {
    let mut sub = Sub::None;
    for part in q.split(|&c| c == b'&') {
        if part.is_empty() {
            continue;
        }
        let k = match part.iter().position(|&c| c == b'=') {
            Some(e) => &part[..e],
            None => part,
        };
        if k == b"location" {
            if sub == Sub::None {
                sub = Sub::Location;
            }
        } else if !s3_plain_param(k) {
            sub = Sub::Other;
        }
    }
    sub
}

fn s3_object_subresource(q: &[u8]) -> bool {
    q.split(|&c| c == b'&').any(|part| {
        let k = match part.iter().position(|&c| c == b'=') {
            Some(e) => &part[..e],
            None => part,
        };
        !part.is_empty() && !s3_plain_param(k)
    })
}

// ── Naming ───────────────────────────────────────────────────────────────

/// Whether a bucket name follows S3's rules: 3-63 bytes of lowercase
/// letters, digits, `.` and `-`, starting and ending with a letter or digit,
/// no `..`, and not shaped like an IPv4 address.
pub fn s3_bucket_valid(b: &[u8]) -> bool {
    if b.len() < S3_BUCKET_MIN || b.len() > S3_BUCKET_MAX {
        return false;
    }
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !edge(b[0]) || !edge(b[b.len() - 1]) {
        return false;
    }
    let mut prev = 0u8;
    for &c in b {
        if !(edge(c) || c == b'.' || c == b'-') || (c == b'.' && prev == b'.') {
            return false;
        }
        prev = c;
    }
    let ip_shaped = b.split(|&c| c == b'.').count() == 4
        && b.split(|&c| c == b'.')
            .all(|p| !p.is_empty() && p.len() <= 3 && p.iter().all(u8::is_ascii_digit));
    !ip_shaped
}

/// Write the object name for `bucket` and the decoded `key` into `out`.
pub fn s3_object_name(bucket: &[u8], key: &[u8], out: &mut [u8]) -> Result<usize, S3Err> {
    if !s3_bucket_valid(bucket) {
        return Err(S3Err::InvalidBucketName);
    }
    if key.is_empty() || !s3_utf8(key) {
        return Err(S3Err::InvalidArgument);
    }
    s3_join(out, &[bucket, S3_OBJECTS, key]).ok_or(S3Err::KeyTooLong)
}

/// Write `bucket/o/` + `prefix` into `out`: the `LIST` prefix of a listing.
pub fn s3_list_prefix(bucket: &[u8], prefix: &[u8], out: &mut [u8]) -> Result<usize, S3Err> {
    if !s3_bucket_valid(bucket) {
        return Err(S3Err::InvalidBucketName);
    }
    s3_join(out, &[bucket, S3_OBJECTS, prefix]).ok_or(S3Err::KeyTooLong)
}

/// Write the staging name of an upload (`part` 0) or of one of its parts.
///
/// A part is five decimal digits, so one past [`S3_PART_NUMBER_MAX`] has no
/// name here rather than a name it would share with a smaller part.
pub fn s3_upload_name(bucket: &[u8], upload: &[u8], part: u32, out: &mut [u8]) -> Option<usize> {
    if part == 0 {
        return s3_join(out, &[bucket, S3_UPLOADS, upload]);
    }
    if part > S3_PART_NUMBER_MAX {
        return None;
    }
    let mut digits = [b'0'; 5];
    let mut v = part;
    for d in digits.iter_mut().rev() {
        *d = b'0' + (v % 10) as u8;
        v /= 10;
    }
    s3_join(out, &[bucket, S3_UPLOADS, upload, b"/", &digits])
}

/// The key of an object name under `bucket/o/`, or `None`.
pub fn s3_key_of<'a>(name: &'a [u8], bucket: &[u8]) -> Option<&'a [u8]> {
    name.strip_prefix(bucket)?.strip_prefix(S3_OBJECTS)
}

/// Whether `b` is well-formed UTF-8 (RFC 3629: no overlongs, no surrogates,
/// nothing past U+10FFFF).
pub fn s3_utf8(b: &[u8]) -> bool {
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        let (len, min) = match c {
            0x00..=0x7f => {
                i += 1;
                continue;
            }
            0xc2..=0xdf => (2, 0x80u32),
            0xe0..=0xef => (3, 0x800),
            0xf0..=0xf4 => (4, 0x1_0000),
            _ => return false,
        };
        if i + len > b.len() {
            return false;
        }
        let mut cp = (c as u32) & (0x7f >> len);
        for k in 1..len {
            let cc = b[i + k];
            if cc & 0xc0 != 0x80 {
                return false;
            }
            cp = (cp << 6) | (cc & 0x3f) as u32;
        }
        if cp < min || cp > 0x10_ffff || (0xd800..=0xdfff).contains(&cp) {
            return false;
        }
        i += len;
    }
    true
}

fn s3_join(out: &mut [u8], parts: &[&[u8]]) -> Option<usize> {
    let mut n = 0usize;
    for p in parts {
        let end = n.checked_add(p.len())?;
        if end > out.len() {
            return None;
        }
        out[n..end].copy_from_slice(p);
        n = end;
    }
    Some(n)
}

// ── Errors ───────────────────────────────────────────────────────────────

/// The S3 errors this server answers. Closed: every refusal is one of these,
/// each with one status and one `<Code>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum S3Err {
    AccessDenied = 0,
    SignatureDoesNotMatch,
    InvalidAccessKeyId,
    RequestTimeTooSkewed,
    AuthorizationHeaderMalformed,
    AuthorizationQueryParametersError,
    MissingSecurityHeader,
    XAmzContentSha256Mismatch,
    InvalidBucketName,
    InvalidArgument,
    KeyTooLong,
    NoSuchKey,
    NoSuchBucket,
    NoSuchUpload,
    InvalidPart,
    InvalidPartOrder,
    EntityTooSmall,
    EntityTooLarge,
    MalformedXml,
    InvalidRange,
    PreconditionFailed,
    MissingContentLength,
    IncompleteBody,
    MethodNotAllowed,
    NotImplemented,
    SlowDown,
    ServiceUnavailable,
    InsufficientStorage,
    InternalError,
}

/// `(code offset, code length, status)` per error, in declaration order: the
/// codes are spans of one literal rather than a table of slices, which the
/// flat module image could not relocate.
const S3_CODES: &[u8] = b"AccessDeniedSignatureDoesNotMatchInvalidAccessKeyIdRequestTimeTooSkewedAuthorizationHeaderMalformedAuthorizationQueryParametersErrorMissingSecurityHeaderXAmzContentSHA256MismatchInvalidBucketNameInvalidArgumentKeyTooLongErrorNoSuchKeyNoSuchBucketNoSuchUploadInvalidPartInvalidPartOrderEntityTooSmallEntityTooLargeMalformedXMLInvalidRangePreconditionFailedMissingContentLengthIncompleteBodyMethodNotAllowedNotImplementedSlowDownServiceUnavailableInsufficientStorageInternalError";

const S3_CODE_SPAN: [(u16, u8, u16); 29] = [
    (0, 12, 403),
    (12, 21, 403),
    (33, 18, 403),
    (51, 20, 403),
    (71, 28, 400),
    (99, 33, 400),
    (132, 21, 400),
    (153, 25, 400),
    (178, 17, 400),
    (195, 15, 400),
    (210, 15, 400),
    (225, 9, 404),
    (234, 12, 404),
    (246, 12, 404),
    (258, 11, 400),
    (269, 16, 400),
    (285, 14, 400),
    (299, 14, 400),
    (313, 12, 400),
    (325, 12, 416),
    (337, 18, 412),
    (355, 20, 411),
    (375, 14, 400),
    (389, 16, 405),
    (405, 14, 501),
    (419, 8, 503),
    (427, 18, 503),
    (445, 19, 507),
    (464, 13, 500),
];

impl S3Err {
    /// The `<Code>` S3 answers with.
    pub fn code(self) -> &'static [u8] {
        let (at, len, _) = S3_CODE_SPAN[self as usize];
        match S3_CODES.get(at as usize..at as usize + len as usize) {
            Some(c) => c,
            None => &[],
        }
    }

    /// The HTTP status.
    pub fn status(self) -> u16 {
        S3_CODE_SPAN[self as usize].2
    }
}

/// The S3 error a `storage.object` errno stands for, when the operation
/// addresses an object (`NoSuchKey`) or an upload (`NoSuchUpload`).
/// `EINPROGRESS` and a read's `EAGAIN` are not errors and never reach here.
pub fn s3_errno(rc: i32, upload: bool) -> S3Err {
    use errno::*;
    match rc {
        ENXIO | ENOENT => {
            if upload {
                S3Err::NoSuchUpload
            } else {
                S3Err::NoSuchKey
            }
        }
        // The grant does not cover the name, lacks the permission, or has
        // expired.
        EACCES => S3Err::AccessDenied,
        // An ABSENT precondition lost (EEXIST) or an ETAG one did (EAGAIN).
        EEXIST | EAGAIN => S3Err::PreconditionFailed,
        EINVAL => S3Err::InvalidArgument,
        // A name past the provider's key bound.
        EOVERFLOW => S3Err::KeyTooLong,
        ENOSPC => S3Err::InsufficientStorage,
        // The provider has no room right now.
        ENOMEM | EBUSY => S3Err::SlowDown,
        ENOSYS => S3Err::NotImplemented,
        _ => S3Err::InternalError,
    }
}

// ── Writing responses ─────────────────────────────────────────────────────

/// A bounded byte writer. Overflow is recorded rather than truncated into a
/// short document: a caller that finds `over` set refuses the whole.
pub struct S3Out<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
    pub over: bool,
}

impl<'a> S3Out<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            len: 0,
            over: false,
        }
    }

    pub fn put(&mut self, b: &[u8]) {
        let end = self.len + b.len();
        if end > self.buf.len() {
            self.over = true;
            return;
        }
        self.buf[self.len..end].copy_from_slice(b);
        self.len = end;
    }

    pub fn dec(&mut self, mut v: u64) {
        let mut d = [0u8; 20];
        let mut n = 0;
        loop {
            d[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.put(&d[n..n + 1]);
        }
    }

    pub fn hex(&mut self, b: &[u8]) {
        for &c in b {
            let mut h = [0u8; 2];
            sv4_hex(&[c], &mut h);
            self.put(&h);
        }
    }

    /// Text content, XML-escaped.
    pub fn xml_text(&mut self, b: &[u8]) {
        for &c in b {
            match c {
                b'&' => self.put(b"&amp;"),
                b'<' => self.put(b"&lt;"),
                b'>' => self.put(b"&gt;"),
                b'"' => self.put(b"&quot;"),
                b'\'' => self.put(b"&apos;"),
                // Control bytes are not valid XML 1.0 text; S3 escapes them
                // numerically.
                0..=0x1f if !matches!(c, b'\t' | b'\n' | b'\r') => {
                    self.put(b"&#");
                    self.dec(c as u64);
                    self.put(b";");
                }
                _ => self.put(core::slice::from_ref(&c)),
            }
        }
    }

    /// Text content percent-encoded (`encoding-type=url`), `/` kept.
    pub fn url_text(&mut self, b: &[u8]) {
        for &c in b {
            if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'/') {
                self.put(core::slice::from_ref(&c));
            } else {
                const UP: &[u8; 16] = b"0123456789ABCDEF";
                self.put(&[b'%', UP[(c >> 4) as usize], UP[(c & 0xf) as usize]]);
            }
        }
    }

    /// `<tag>text</tag>`, text escaped.
    pub fn elem(&mut self, tag: &[u8], text: &[u8]) {
        self.put(b"<");
        self.put(tag);
        self.put(b">");
        self.xml_text(text);
        self.put(b"</");
        self.put(tag);
        self.put(b">");
    }

    /// `<tag>n</tag>`.
    pub fn elem_dec(&mut self, tag: &[u8], v: u64) {
        self.put(b"<");
        self.put(tag);
        self.put(b">");
        self.dec(v);
        self.put(b"</");
        self.put(tag);
        self.put(b">");
    }
}

/// The XML declaration every S3 document starts with.
pub const S3_XML_DECL: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
/// The S3 document namespace.
pub const S3_XMLNS: &[u8] = b" xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";

/// An `<Error>` document.
pub fn s3_error_xml(
    err: S3Err,
    message: &[u8],
    resource: &[u8],
    request_id: &[u8],
    out: &mut S3Out<'_>,
) {
    out.put(S3_XML_DECL);
    out.put(b"<Error>");
    out.elem(b"Code", err.code());
    out.elem(b"Message", message);
    out.elem(b"Resource", resource);
    out.elem(b"RequestId", request_id);
    out.put(b"</Error>");
}

/// An entity tag as S3 quotes it: `"<hex>"`.
pub fn s3_etag(etag: &[u8], out: &mut S3Out<'_>) {
    out.put(b"\"");
    out.hex(etag);
    out.put(b"\"");
}

/// An RFC 7231 HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`) for Unix seconds.
pub fn s3_http_date(secs: u64, out: &mut S3Out<'_>) {
    let mut ts = [0u8; 16];
    let mut date = [0u8; 8];
    sv4_format_amz_date(secs, &mut ts, &mut date);
    let days = secs / 86_400;
    // 1970-01-01 was a Thursday.
    const DAYS: &[u8] = b"ThuFriSatSunMonTueWed";
    const MONTHS: &[u8] = b"JanFebMarAprMayJunJulAugSepOctNovDec";
    let wd = (days % 7) as usize;
    let month = ((date[4] - b'0') * 10 + (date[5] - b'0')) as usize;
    out.put(&DAYS[wd * 3..wd * 3 + 3]);
    out.put(b", ");
    out.put(&date[6..8]);
    out.put(b" ");
    let m = month.clamp(1, 12) - 1;
    out.put(&MONTHS[m * 3..m * 3 + 3]);
    out.put(b" ");
    out.put(&date[0..4]);
    out.put(b" ");
    out.put(&ts[9..11]);
    out.put(b":");
    out.put(&ts[11..13]);
    out.put(b":");
    out.put(&ts[13..15]);
    out.put(b" GMT");
}

/// An ISO 8601 timestamp (`2009-10-12T17:50:30.000Z`) for Unix seconds, as
/// listings carry it.
pub fn s3_iso_date(secs: u64, out: &mut S3Out<'_>) {
    let mut ts = [0u8; 16];
    let mut date = [0u8; 8];
    sv4_format_amz_date(secs, &mut ts, &mut date);
    out.put(&date[0..4]);
    out.put(b"-");
    out.put(&date[4..6]);
    out.put(b"-");
    out.put(&date[6..8]);
    out.put(b"T");
    out.put(&ts[9..11]);
    out.put(b":");
    out.put(&ts[11..13]);
    out.put(b":");
    out.put(&ts[13..15]);
    out.put(b".000Z");
}

// ── Ranges ───────────────────────────────────────────────────────────────

/// What a `Range` header asks of an object of known size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3Range {
    /// The whole object (no header, or one this server serves whole: a
    /// multi-range or unit other than bytes).
    Whole,
    /// Bytes `start..=end`, answered 206.
    Part { start: u64, end: u64 },
    /// No byte of the object is in range: 416 `InvalidRange`.
    Unsatisfiable,
}

/// Resolve a `Range` header value (`bytes=a-b`, `bytes=a-`, `bytes=-n`).
pub fn s3_range(value: Option<&[u8]>, size: u64) -> S3Range {
    let Some(v) = value else {
        return S3Range::Whole;
    };
    let Some(spec) = v.strip_prefix(b"bytes=") else {
        return S3Range::Whole;
    };
    // More than one range is answered whole, as S3 does.
    if spec.split(|&c| c == b',').nth(1).is_some() {
        return S3Range::Whole;
    }
    let Some(dash) = spec.iter().position(|&c| c == b'-') else {
        return S3Range::Whole;
    };
    let (a, b) = (&spec[..dash], &spec[dash + 1..]);
    let num = |s: &[u8]| -> Option<u64> {
        if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut v: u64 = 0;
        for &c in s {
            v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
        }
        Some(v)
    };
    match (num(a), num(b)) {
        (Some(start), Some(end)) => {
            if start > end {
                S3Range::Whole
            } else if start >= size {
                S3Range::Unsatisfiable
            } else {
                S3Range::Part {
                    start,
                    end: end.min(size - 1),
                }
            }
        }
        (Some(start), None) if b.is_empty() => {
            if start >= size {
                S3Range::Unsatisfiable
            } else {
                S3Range::Part {
                    start,
                    end: size - 1,
                }
            }
        }
        (None, Some(n)) if a.is_empty() => {
            if n == 0 || size == 0 {
                S3Range::Unsatisfiable
            } else {
                S3Range::Part {
                    start: size.saturating_sub(n),
                    end: size - 1,
                }
            }
        }
        _ => S3Range::Whole,
    }
}

// ── aws-chunked bodies ───────────────────────────────────────────────────

/// Where an `aws-chunked` decoder stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3ChunkState {
    /// Reading a `hex;chunk-signature=sig\r\n` line.
    Line,
    /// Inside a chunk's data.
    Data,
    /// The CRLF after a chunk's data.
    DataEnd,
    /// The final zero-length chunk has been read and verified.
    Done,
}

/// An `aws-chunked` body decoder that verifies each chunk's signature,
/// chained from the request's seed signature. Fed in arbitrary slices; holds
/// a partial chunk line in a small carry.
pub struct S3Chunked {
    pub state: S3ChunkState,
    line: [u8; S3_CHUNK_LINE_MAX],
    line_len: usize,
    remaining: u64,
    expect_sig: [u8; 64],
    prev_sig: [u8; 64],
    hash: Sha256,
    /// The chunk being read is the zero-length final one.
    last: bool,
    /// Decoded bytes produced.
    pub decoded: u64,
}

/// What feeding an `aws-chunked` decoder came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3ChunkErr {
    /// The framing does not parse.
    Malformed,
    /// A chunk's signature does not match.
    Signature,
}

/// The inputs a chunk signature is computed from.
pub struct S3ChunkKey<'a> {
    pub signing_key: &'a [u8; 32],
    pub amz_date: &'a [u8],
    pub scope_date: &'a [u8],
    pub region: &'a [u8],
    pub service: &'a [u8],
}

impl S3Chunked {
    pub fn new(seed_signature: &[u8; 64]) -> Self {
        Self {
            state: S3ChunkState::Line,
            line: [0; S3_CHUNK_LINE_MAX],
            line_len: 0,
            remaining: 0,
            expect_sig: [0; 64],
            prev_sig: *seed_signature,
            hash: Sha256::new(),
            last: false,
            decoded: 0,
        }
    }

    fn close_chunk(&mut self, key: &S3ChunkKey<'_>) -> Result<(), S3ChunkErr> {
        let h = core::mem::take(&mut self.hash).finalize();
        let sig = sv4_chunk_signature(
            key.signing_key,
            key.amz_date,
            key.scope_date,
            key.region,
            key.service,
            &self.prev_sig,
            &h,
        );
        if !sv4_eq(&sig, &self.expect_sig) {
            return Err(S3ChunkErr::Signature);
        }
        self.prev_sig = sig;
        Ok(())
    }

    /// Feed `input`; each decoded data slice is handed to `sink` once its
    /// framing has been read. A chunk's signature is checked when its data
    /// ends, so `sink` may have received data of a chunk that then fails:
    /// the caller discards what it wrote on `Err`.
    pub fn feed<F: FnMut(&[u8])>(
        &mut self,
        mut input: &[u8],
        key: &S3ChunkKey<'_>,
        mut sink: F,
    ) -> Result<(), S3ChunkErr> {
        while !input.is_empty() {
            match self.state {
                S3ChunkState::Done => return Err(S3ChunkErr::Malformed),
                S3ChunkState::Line => {
                    let nl = input.iter().position(|&c| c == b'\n');
                    let take = nl.map_or(input.len(), |i| i + 1);
                    if self.line_len + take > S3_CHUNK_LINE_MAX {
                        return Err(S3ChunkErr::Malformed);
                    }
                    self.line[self.line_len..self.line_len + take].copy_from_slice(&input[..take]);
                    self.line_len += take;
                    input = &input[take..];
                    if nl.is_none() {
                        continue;
                    }
                    let line = &self.line[..self.line_len];
                    let line = line.strip_suffix(b"\r\n").ok_or(S3ChunkErr::Malformed)?;
                    let semi = line
                        .iter()
                        .position(|&c| c == b';')
                        .ok_or(S3ChunkErr::Malformed)?;
                    let sig = line[semi + 1..]
                        .strip_prefix(b"chunk-signature=")
                        .ok_or(S3ChunkErr::Malformed)?;
                    if sig.len() != 64 {
                        return Err(S3ChunkErr::Malformed);
                    }
                    let mut size: u64 = 0;
                    if semi == 0 || semi > 16 {
                        return Err(S3ChunkErr::Malformed);
                    }
                    for &c in &line[..semi] {
                        let d = sv4_hexval(c).ok_or(S3ChunkErr::Malformed)?;
                        size = (size << 4) | d as u64;
                    }
                    self.expect_sig.copy_from_slice(sig);
                    self.line_len = 0;
                    self.remaining = size;
                    if size == 0 {
                        // The final chunk signs the empty string; its CRLF
                        // ends the body.
                        self.last = true;
                        self.state = S3ChunkState::DataEnd;
                    } else {
                        self.state = S3ChunkState::Data;
                    }
                }
                S3ChunkState::Data => {
                    let take = (self.remaining.min(input.len() as u64)) as usize;
                    self.hash.update(&input[..take]);
                    sink(&input[..take]);
                    self.decoded += take as u64;
                    self.remaining -= take as u64;
                    input = &input[take..];
                    if self.remaining == 0 {
                        self.state = S3ChunkState::DataEnd;
                    }
                }
                S3ChunkState::DataEnd => {
                    // Both CRLF bytes must be seen; a single one carries over.
                    let need = 2 - self.line_len;
                    let take = need.min(input.len());
                    self.line[self.line_len..self.line_len + take].copy_from_slice(&input[..take]);
                    self.line_len += take;
                    input = &input[take..];
                    if self.line_len < 2 {
                        continue;
                    }
                    if &self.line[..2] != b"\r\n" {
                        return Err(S3ChunkErr::Malformed);
                    }
                    self.line_len = 0;
                    let last = self.last;
                    self.close_chunk(key)?;
                    self.state = if last {
                        S3ChunkState::Done
                    } else {
                        S3ChunkState::Line
                    };
                }
            }
        }
        Ok(())
    }

    pub fn done(&self) -> bool {
        self.state == S3ChunkState::Done
    }
}

// ── Credentials ───────────────────────────────────────────────────────────

/// Longest access key, secret and peer fingerprint (hex) a credential holds.
pub const S3_ACCESS_KEY_MAX: usize = 128;
pub const S3_SECRET_MAX: usize = 128;
pub const S3_PEER_MAX: usize = 128;

/// One line of the credentials file, as spans of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S3CredLine<'a> {
    pub access_key: &'a [u8],
    pub secret: &'a [u8],
    /// The capability's scope: `bucket/` or `bucket/o/prefix/`.
    pub scope: &'a [u8],
    /// The capability chain, `fxcap1.` text.
    pub chain: &'a [u8],
    /// The mTLS peer fingerprint (hex) requests with this key must arrive
    /// from; empty when unbound.
    pub peer: &'a [u8],
}

/// Why a credentials line was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3CredErr {
    /// Not `access_key secret scope chain [peer=hex]`.
    Shape,
    /// A field longer than its bound.
    TooLong,
    /// The scope is not `bucket/` or `bucket/o/…/` with a valid bucket.
    Scope,
}

/// Parse one non-comment line of the credentials file. `None` for a blank
/// line or a `#` comment.
pub fn s3_cred_line(line: &[u8]) -> Option<Result<S3CredLine<'_>, S3CredErr>> {
    let start = line
        .iter()
        .position(|&c| c != b' ' && c != b'\t' && c != b'\r')?;
    let line = &line[start..];
    if line[0] == b'#' {
        return None;
    }
    let mut it = line
        .split(|&c| c == b' ' || c == b'\t' || c == b'\r')
        .filter(|f| !f.is_empty());
    let (Some(ak), Some(secret), Some(scope), Some(chain)) =
        (it.next(), it.next(), it.next(), it.next())
    else {
        return Some(Err(S3CredErr::Shape));
    };
    let peer = match it.next() {
        None => &line[..0],
        Some(f) => match f.strip_prefix(b"peer=") {
            Some(p) if !p.is_empty() && p.iter().all(|c| c.is_ascii_hexdigit()) => p,
            _ => return Some(Err(S3CredErr::Shape)),
        },
    };
    if it.next().is_some() {
        return Some(Err(S3CredErr::Shape));
    }
    if ak.len() > S3_ACCESS_KEY_MAX || secret.len() > S3_SECRET_MAX || peer.len() > S3_PEER_MAX {
        return Some(Err(S3CredErr::TooLong));
    }
    if s3_scope_bucket(scope).is_none() {
        return Some(Err(S3CredErr::Scope));
    }
    Some(Ok(S3CredLine {
        access_key: ak,
        secret,
        scope,
        chain,
        peer,
    }))
}

/// The bucket a scope names, when it is `bucket/` or `bucket/o/<prefix>/`.
pub fn s3_scope_bucket(scope: &[u8]) -> Option<&[u8]> {
    if scope.last() != Some(&b'/') {
        return None;
    }
    let slash = scope.iter().position(|&c| c == b'/')?;
    let bucket = &scope[..slash];
    if !s3_bucket_valid(bucket) {
        return None;
    }
    let rest = &scope[slash..];
    if rest == b"/" || (rest.starts_with(S3_OBJECTS) && rest.len() > S3_OBJECTS.len()) {
        Some(bucket)
    } else {
        None
    }
}

// ── Listing ──────────────────────────────────────────────────────────────

/// A continuation token: the provider's cursor and the last common prefix
/// already returned, each hex-encoded, `.`-joined. Opaque to clients.
pub fn s3_token_encode(cursor: &[u8], last_prefix: &[u8], out: &mut S3Out<'_>) {
    out.hex(cursor);
    out.put(b".");
    out.hex(last_prefix);
}

/// Decode a continuation token into its cursor and last common prefix.
pub fn s3_token_decode<'a>(
    token: &[u8],
    cursor: &'a mut [u8],
    last_prefix: &'a mut [u8],
) -> Option<(&'a [u8], &'a [u8])> {
    let dot = token.iter().position(|&c| c == b'.')?;
    let unhex = |src: &[u8], out: &mut [u8]| -> Option<usize> {
        if !src.len().is_multiple_of(2) || src.len() / 2 > out.len() {
            return None;
        }
        for (i, p) in src.chunks(2).enumerate() {
            out[i] = (sv4_hexval(p[0])? << 4) | sv4_hexval(p[1])?;
        }
        Some(src.len() / 2)
    };
    let c = unhex(&token[..dot], cursor)?;
    let p = unhex(&token[dot + 1..], last_prefix)?;
    Some((&cursor[..c], &last_prefix[..p]))
}

/// The common prefix a key rolls up to under `prefix` with `delimiter`, if
/// any: the key's bytes through the first delimiter after the prefix.
pub fn s3_common_prefix<'a>(key: &'a [u8], prefix: &[u8], delimiter: &[u8]) -> Option<&'a [u8]> {
    if delimiter.is_empty() || !key.starts_with(prefix) {
        return None;
    }
    let rest = &key[prefix.len()..];
    let at = rest.windows(delimiter.len()).position(|w| w == delimiter)?;
    Some(&key[..prefix.len() + at + delimiter.len()])
}

// ── CompleteMultipartUpload ───────────────────────────────────────────────

/// Longest tag-and-text span the part-list reader carries across records.
pub const S3_PARTS_CARRY: usize = 256;

/// One `<Part>` of a completion request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S3Part {
    pub number: u32,
    /// The ETag as listed, hex digits only (quotes dropped); empty when the
    /// client listed none.
    pub etag: [u8; 64],
    pub etag_len: u8,
}

/// An incremental reader of a `CompleteMultipartUpload` body. Elements other
/// than `<Part>`, `<PartNumber>` and `<ETag>` are passed over. A record
/// boundary may fall anywhere, inside a tag or inside the text of an element
/// read: the reader carries what it has gathered and resumes where it was.
pub struct S3PartsReader {
    carry: [u8; S3_PARTS_CARRY],
    carry_len: usize,
    /// Which element's text is being read: [`S3_TEXT_NONE`],
    /// [`S3_TEXT_NUMBER`] or [`S3_TEXT_ETAG`]. While one is, `carry` holds
    /// its text and as much of its closing tag as has arrived.
    text: u8,
    in_part: bool,
    number: Option<u32>,
    etag: [u8; 64],
    etag_len: usize,
    /// The highest part number accepted so far; parts must ascend.
    pub last: u32,
    pub count: u32,
}

const S3_TEXT_NONE: u8 = 0;
const S3_TEXT_NUMBER: u8 = 1;
const S3_TEXT_ETAG: u8 = 2;

/// What the part-list reader refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3PartsErr {
    Malformed,
    Order,
    TooMany,
}

/// Strip one leading and one trailing `quote` from `t`.
fn s3_unquote<'a>(t: &'a [u8], quote: &[u8]) -> &'a [u8] {
    let t = t.strip_prefix(quote).unwrap_or(t);
    t.strip_suffix(quote).unwrap_or(t)
}

impl Default for S3PartsReader {
    fn default() -> Self {
        Self::new()
    }
}

impl S3PartsReader {
    /// A reader at the start of a part list.
    pub const fn new() -> Self {
        Self {
            carry: [0; S3_PARTS_CARRY],
            carry_len: 0,
            text: S3_TEXT_NONE,
            in_part: false,
            number: None,
            etag: [0; 64],
            etag_len: 0,
            last: 0,
            count: 0,
        }
    }

    /// The length of the closing tag the carried text ends with, once the
    /// whole of it has arrived.
    fn text_closed(&self) -> Option<usize> {
        let have = &self.carry[..self.carry_len];
        if self.text == S3_TEXT_NUMBER {
            have.ends_with(b"</PartNumber>").then_some(13)
        } else {
            have.ends_with(b"</ETag>").then_some(7)
        }
    }

    /// The text of a `<PartNumber>` or `<ETag>` element, read whole.
    fn take_text(&mut self, close_len: usize) -> Result<(), S3PartsErr> {
        let text = &self.carry[..self.carry_len - close_len];
        if self.text == S3_TEXT_NUMBER {
            if text.is_empty() || text.len() > 5 {
                return Err(S3PartsErr::Malformed);
            }
            let mut n: u32 = 0;
            for &c in text {
                if !c.is_ascii_digit() {
                    return Err(S3PartsErr::Malformed);
                }
                n = n * 10 + (c - b'0') as u32;
            }
            self.number = Some(n);
        } else {
            // `"hex"`, `&quot;hex&quot;` or bare hex.
            let t = s3_unquote(s3_unquote(text, b"&quot;"), b"\"");
            if t.len() > self.etag.len() {
                return Err(S3PartsErr::Malformed);
            }
            self.etag[..t.len()].copy_from_slice(t);
            self.etag_len = t.len();
        }
        Ok(())
    }

    /// Feed body bytes; each completed `<Part>` is handed to `sink`.
    pub fn feed<F: FnMut(&S3Part)>(
        &mut self,
        mut input: &[u8],
        mut sink: F,
    ) -> Result<(), S3PartsErr> {
        loop {
            if self.text != S3_TEXT_NONE {
                // Gather the element's text up to its closing tag.
                let close_len = loop {
                    if let Some(n) = self.text_closed() {
                        break n;
                    }
                    let Some((&b, rest)) = input.split_first() else {
                        return Ok(());
                    };
                    if self.carry_len == S3_PARTS_CARRY {
                        return Err(S3PartsErr::Malformed);
                    }
                    self.carry[self.carry_len] = b;
                    self.carry_len += 1;
                    input = rest;
                };
                self.take_text(close_len)?;
                self.text = S3_TEXT_NONE;
                self.carry_len = 0;
                continue;
            }
            // Text between tags is passed over until a `<` begins one.
            if self.carry_len == 0 {
                match input.iter().position(|&c| c == b'<') {
                    None => return Ok(()),
                    Some(i) => input = &input[i..],
                }
            }
            // Accumulate one tag, `<…>`.
            let room = S3_PARTS_CARRY - self.carry_len;
            let avail = &input[..input.len().min(room)];
            let gt = avail.iter().position(|&c| c == b'>');
            let take = gt.map_or(avail.len(), |i| i + 1);
            self.carry[self.carry_len..self.carry_len + take].copy_from_slice(&avail[..take]);
            self.carry_len += take;
            input = &input[take..];
            if gt.is_none() {
                if self.carry_len == S3_PARTS_CARRY {
                    return Err(S3PartsErr::Malformed);
                }
                return Ok(());
            }
            let tag = &self.carry[..self.carry_len];
            if tag == b"<PartNumber>" || tag == b"<ETag>" {
                if !self.in_part {
                    return Err(S3PartsErr::Malformed);
                }
                self.text = if tag == b"<PartNumber>" {
                    S3_TEXT_NUMBER
                } else {
                    S3_TEXT_ETAG
                };
            } else if tag == b"<Part>" {
                self.in_part = true;
                self.number = None;
                self.etag_len = 0;
            } else if tag == b"</Part>" {
                if !self.in_part {
                    return Err(S3PartsErr::Malformed);
                }
                let n = self.number.ok_or(S3PartsErr::Malformed)?;
                if n == 0 || n > S3_PART_NUMBER_MAX {
                    return Err(S3PartsErr::Malformed);
                }
                if n <= self.last {
                    return Err(S3PartsErr::Order);
                }
                self.count += 1;
                if self.count > S3_PART_NUMBER_MAX {
                    return Err(S3PartsErr::TooMany);
                }
                self.last = n;
                self.in_part = false;
                let mut p = S3Part {
                    number: n,
                    etag: [0; 64],
                    etag_len: self.etag_len as u8,
                };
                p.etag[..self.etag_len].copy_from_slice(&self.etag[..self.etag_len]);
                sink(&p);
            }
            self.carry_len = 0;
        }
    }
}
