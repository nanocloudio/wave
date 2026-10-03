// AWS Signature Version 4: one core for the side that signs and the side that
// verifies. Bounded, no_std, no allocation. SHA-256 is SDK-owned: the mounting
// module `include!`s `target/fluxor/fluxor-abi/sdk/crypto/sha256.rs` before
// this file, which supplies `sha256` and `Sha256`. HMAC (RFC 2104) is
// construction glue over it, not a primitive.
//
// A signature is HMAC(signing key, string to sign), where the signing key is
// derived from the secret, the date, the region and the service, and the
// string to sign carries the SHA-256 of a canonical form of the request:
//
//   method \n canonical URI \n canonical query \n canonical headers \n
//   signed header names \n payload hash
//
// The canonical form is hashed as it is produced rather than assembled in a
// buffer, so the request target and header block are bounded only by what the
// caller holds. The query is the exception: its parameters are sorted, so
// they are canonicalised into a caller-held scratch first.
//
// Canonical URI: the path, percent-decoded and re-encoded with every byte
// outside the unreserved set (A-Z a-z 0-9 - . _ ~) as %XX and `/` kept. S3
// encodes once, so a path a client sent encoded and one it sent raw
// canonicalise alike. Canonical query: each `name=value` decoded and
// re-encoded the same way (`/` encoded too), a bare `name` taken as
// `name=`, sorted by name and then by value. Canonical headers: each signed
// header's values, trimmed, inner runs of spaces collapsed, several
// occurrences joined with `,`.

/// SHA-256 of nothing: the payload hash of a request without a body.
pub const SV4_EMPTY_SHA256: &[u8; 64] =
    b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Payload hash declaring the body is not signed.
pub const SV4_UNSIGNED: &[u8] = b"UNSIGNED-PAYLOAD";
/// Payload hash declaring an `aws-chunked` body whose chunks are each signed.
pub const SV4_STREAMING: &[u8] = b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// The only algorithm.
pub const SV4_ALGORITHM: &[u8] = b"AWS4-HMAC-SHA256";
/// The longest a presigned URL may live, in seconds: seven days.
pub const SV4_EXPIRES_MAX: u64 = 7 * 24 * 3600;
/// How far a request's timestamp may sit from the server's clock, in seconds.
pub const SV4_SKEW_MAX: u64 = 15 * 60;
/// Most query parameters canonicalised. A request with more is refused as
/// malformed rather than signed over a subset.
pub const SV4_QUERY_PARAMS_MAX: usize = 64;
/// Bytes of canonical query held while sorting: a target is at most 2048
/// bytes and re-encoding at most triples it.
pub const SV4_QUERY_SCRATCH: usize = 3 * 2048;
/// Most signed header names.
pub const SV4_SIGNED_HEADERS_MAX: usize = 32;

/// Why a request's signature was refused. Closed: every refusal is one of
/// these, and the S3 error a server answers is chosen from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sv4Error {
    /// No signature at all: neither an `Authorization` header nor presigned
    /// query parameters.
    Missing,
    /// The `Authorization` header or a presigned parameter does not parse.
    Malformed,
    /// An algorithm other than `AWS4-HMAC-SHA256`.
    Algorithm,
    /// The credential scope names another region or service, or a date that
    /// is not the request's.
    Scope,
    /// A header the signature needs is absent (`x-amz-date`,
    /// `x-amz-content-sha256`), or `host` is not among the signed headers.
    HeaderMissing,
    /// The request's time is outside the allowed skew of the server's clock.
    Skew,
    /// A presigned URL past its expiry, or one claiming more than seven days.
    Expired,
    /// The access key is not one this server knows.
    UnknownKey,
    /// The signature does not match.
    Mismatch,
    /// A payload hash form this core does not verify.
    PayloadForm,
    /// More query parameters or signed headers than this core holds.
    TooLarge,
}

/// HMAC-SHA-256.
pub fn sv4_hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finalize()
}

const SV4_HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `data` into `out`; the bytes written.
pub fn sv4_hex(data: &[u8], out: &mut [u8]) -> usize {
    let mut o = 0;
    for &b in data {
        if o + 2 > out.len() {
            break;
        }
        out[o] = SV4_HEX[(b >> 4) as usize];
        out[o + 1] = SV4_HEX[(b & 0xf) as usize];
        o += 2;
    }
    o
}

/// Lowercase hex of a 32-byte digest.
pub fn sv4_hex32(d: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    sv4_hex(d, &mut out);
    out
}

/// Lowercase hex of `SHA256(data)`.
pub fn sv4_sha256_hex(data: &[u8]) -> [u8; 64] {
    sv4_hex32(&sha256(data))
}

/// The signing key:
/// `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service), "aws4_request")`.
pub fn sv4_signing_key(secret: &[u8], date: &[u8], region: &[u8], service: &[u8]) -> [u8; 32] {
    // The secret is keyed in two parts so a secret of any length is used
    // whole: HMAC hashes a key longer than its block, which is exactly what
    // a concatenation buffer would have had to bound.
    let mut k = Sha256::new();
    let key_len = 4 + secret.len();
    let k_date = if key_len > 64 {
        k.update(b"AWS4");
        k.update(secret);
        let hashed = k.finalize();
        sv4_hmac(&hashed, date)
    } else {
        let mut buf = [0u8; 64];
        buf[..4].copy_from_slice(b"AWS4");
        buf[4..key_len].copy_from_slice(secret);
        sv4_hmac(&buf[..key_len], date)
    };
    let k_region = sv4_hmac(&k_date, region);
    let k_service = sv4_hmac(&k_region, service);
    sv4_hmac(&k_service, b"aws4_request")
}

/// Constant-time equality.
pub fn sv4_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Parse a decimal number of bytes. `None` for an empty or non-digit field,
/// or one past `u64`.
pub fn sv4_digits(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn sv4_days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYYMMDDTHHMMSSZ` to Unix seconds.
pub fn sv4_parse_amz_date(s: &[u8]) -> Option<u64> {
    if s.len() != 16 || s[8] != b'T' || s[15] != b'Z' {
        return None;
    }
    let year = sv4_digits(&s[0..4])? as i64;
    let month = sv4_digits(&s[4..6])? as i64;
    let day = sv4_digits(&s[6..8])? as i64;
    let hour = sv4_digits(&s[9..11])?;
    let min = sv4_digits(&s[11..13])?;
    let sec = sv4_digits(&s[13..15])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = sv4_days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Format Unix seconds as `YYYYMMDDTHHMMSSZ` and `YYYYMMDD`.
pub fn sv4_format_amz_date(secs: u64, ts: &mut [u8; 16], date: &mut [u8; 8]) {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u64;
    let y = (yoe + era * 400 + if m <= 2 { 1 } else { 0 }) as u64;
    let put = |out: &mut [u8], mut v: u64| {
        for i in (0..out.len()).rev() {
            out[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    };
    put(&mut date[0..4], y);
    put(&mut date[4..6], m);
    put(&mut date[6..8], d);
    ts[..8].copy_from_slice(date);
    ts[8] = b'T';
    put(&mut ts[9..11], sod / 3600);
    put(&mut ts[11..13], (sod % 3600) / 60);
    put(&mut ts[13..15], sod % 60);
    ts[15] = b'Z';
}

fn sv4_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

fn sv4_hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `src`, handing each byte to `f`. `None` on a malformed
/// escape.
fn sv4_decode_each<F: FnMut(u8)>(src: &[u8], mut f: F) -> Option<()> {
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' {
            let hi = sv4_hexval(*src.get(i + 1)?)?;
            let lo = sv4_hexval(*src.get(i + 2)?)?;
            f((hi << 4) | lo);
            i += 3;
        } else {
            f(src[i]);
            i += 1;
        }
    }
    Some(())
}

/// Percent-decode `src` into `out`; the length, or `None` on a malformed
/// escape or when `out` is short.
pub fn sv4_decode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut n = 0usize;
    let mut over = false;
    sv4_decode_each(src, |b| {
        if n < out.len() {
            out[n] = b;
            n += 1;
        } else {
            over = true;
        }
    })?;
    if over {
        None
    } else {
        Some(n)
    }
}

/// Write `b` canonically encoded: unreserved bytes as they are, `/` kept when
/// `keep_slash`, everything else as uppercase `%XX`.
fn sv4_encode_byte(b: u8, keep_slash: bool, out: &mut [u8; 3]) -> usize {
    if sv4_unreserved(b) || (keep_slash && b == b'/') {
        out[0] = b;
        1
    } else {
        const UP: &[u8; 16] = b"0123456789ABCDEF";
        out[0] = b'%';
        out[1] = UP[(b >> 4) as usize];
        out[2] = UP[(b & 0xf) as usize];
        3
    }
}

/// Canonically encode (decoding first) `src` into the hash.
fn sv4_hash_encoded(h: &mut Sha256, src: &[u8], keep_slash: bool) -> Option<()> {
    sv4_decode_each(src, |b| {
        let mut e = [0u8; 3];
        let n = sv4_encode_byte(b, keep_slash, &mut e);
        h.update(&e[..n]);
    })
}

/// Canonically encode (decoding first) `src` into `out` at `at`; the new
/// offset.
fn sv4_put_encoded(out: &mut [u8], mut at: usize, src: &[u8], keep_slash: bool) -> Option<usize> {
    let mut over = false;
    sv4_decode_each(src, |b| {
        let mut e = [0u8; 3];
        let n = sv4_encode_byte(b, keep_slash, &mut e);
        if at + n <= out.len() {
            out[at..at + n].copy_from_slice(&e[..n]);
            at += n;
        } else {
            over = true;
        }
    })?;
    if over {
        None
    } else {
        Some(at)
    }
}

/// Split a request target into path and query.
pub fn sv4_split_target(target: &[u8]) -> (&[u8], &[u8]) {
    match target.iter().position(|&c| c == b'?') {
        Some(q) => (&target[..q], &target[q + 1..]),
        None => (target, &[]),
    }
}

/// The raw value of the first query parameter named `name`, still encoded.
pub fn sv4_query_param<'a>(query: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for part in query.split(|&c| c == b'&') {
        let (k, v) = match part.iter().position(|&c| c == b'=') {
            Some(e) => (&part[..e], &part[e + 1..]),
            None => (part, &part[part.len()..]),
        };
        if k == name {
            return Some(v);
        }
    }
    None
}

/// Whether a parameter named `name` is present, with or without a value.
pub fn sv4_query_has(query: &[u8], name: &[u8]) -> bool {
    sv4_query_param(query, name).is_some()
}

/// The values of a header named `name` (ASCII case-insensitive) in a
/// `name: value\r\n` block, each trimmed with inner space runs collapsed, joined
/// with `,`, fed to `f`. False when the header is absent.
fn sv4_header_canonical<F: FnMut(&[u8])>(headers: &[u8], name: &[u8], mut f: F) -> bool {
    let mut found = false;
    for line in headers.split(|&c| c == b'\n') {
        let line = match line.last() {
            Some(b'\r') => &line[..line.len() - 1],
            _ => line,
        };
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        if !line[..colon].eq_ignore_ascii_case(name) {
            continue;
        }
        if found {
            f(b",");
        }
        found = true;
        let v = &line[colon + 1..];
        let start = v
            .iter()
            .position(|&c| c != b' ' && c != b'\t')
            .unwrap_or(v.len());
        let end = v
            .iter()
            .rposition(|&c| c != b' ' && c != b'\t')
            .map_or(start, |e| e + 1);
        let mut space = false;
        for &c in &v[start..end] {
            if c == b' ' || c == b'\t' {
                space = true;
                continue;
            }
            if space {
                f(b" ");
                space = false;
            }
            f(core::slice::from_ref(&c));
        }
    }
    found
}

/// The first value of header `name`, trimmed.
pub fn sv4_header<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in headers.split(|&c| c == b'\n') {
        let line = match line.last() {
            Some(b'\r') => &line[..line.len() - 1],
            _ => line,
        };
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(name) {
            let v = &line[colon + 1..];
            let start = v
                .iter()
                .position(|&c| c != b' ' && c != b'\t')
                .unwrap_or(v.len());
            let end = v
                .iter()
                .rposition(|&c| c != b' ' && c != b'\t')
                .map_or(start, |e| e + 1);
            return Some(&v[start..end]);
        }
    }
    None
}

/// The credential scope and signature of a request, in either form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sv4Auth<'a> {
    pub access_key: &'a [u8],
    /// `YYYYMMDD` of the credential scope.
    pub scope_date: &'a [u8],
    pub region: &'a [u8],
    pub service: &'a [u8],
    /// Signed header names, `;`-separated, lowercase, as the client listed
    /// them (presigned: still percent-encoded as sent).
    pub signed_headers: &'a [u8],
    /// Hex signature as sent.
    pub signature: &'a [u8],
    /// `YYYYMMDDTHHMMSSZ` of the request.
    pub amz_date: &'a [u8],
    /// Presigned lifetime in seconds; `None` for the header form.
    pub expires: Option<u64>,
}

/// A credential's access key, date, region and service.
type Sv4Credential<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

/// Parse an `X-Amz-Credential` / `Credential=` value:
/// `AK/YYYYMMDD/region/service/aws4_request`.
fn sv4_credential(c: &[u8]) -> Option<Sv4Credential<'_>> {
    let mut it = c.split(|&b| b == b'/');
    let ak = it.next()?;
    let date = it.next()?;
    let region = it.next()?;
    let service = it.next()?;
    let term = it.next()?;
    if it.next().is_some() || term != b"aws4_request" || ak.is_empty() || date.len() != 8 {
        return None;
    }
    Some((ak, date, region, service))
}

/// Parse the header form: `Authorization: AWS4-HMAC-SHA256 Credential=…,
/// SignedHeaders=…, Signature=…` with `x-amz-date` from the headers.
pub fn sv4_parse_header_auth<'a>(headers: &'a [u8]) -> Result<Sv4Auth<'a>, Sv4Error> {
    let auth = sv4_header(headers, b"authorization").ok_or(Sv4Error::Missing)?;
    let Some(rest) = auth.strip_prefix(SV4_ALGORITHM) else {
        // A word before the first space names some other algorithm.
        return Err(if auth.split(|&c| c == b' ').nth(1).is_some() {
            Sv4Error::Algorithm
        } else {
            Sv4Error::Malformed
        });
    };
    let mut cred = None;
    let mut signed = None;
    let mut sig = None;
    for part in rest.split(|&c| c == b',') {
        let start = part.iter().position(|&c| c != b' ').unwrap_or(part.len());
        let part = &part[start..];
        if let Some(v) = part.strip_prefix(b"Credential=") {
            cred = Some(v);
        } else if let Some(v) = part.strip_prefix(b"SignedHeaders=") {
            signed = Some(v);
        } else if let Some(v) = part.strip_prefix(b"Signature=") {
            sig = Some(v);
        }
    }
    let (Some(cred), Some(signed), Some(sig)) = (cred, signed, sig) else {
        return Err(Sv4Error::Malformed);
    };
    let (access_key, scope_date, region, service) =
        sv4_credential(cred).ok_or(Sv4Error::Malformed)?;
    let amz_date = sv4_header(headers, b"x-amz-date").ok_or(Sv4Error::HeaderMissing)?;
    Ok(Sv4Auth {
        access_key,
        scope_date,
        region,
        service,
        signed_headers: signed,
        signature: sig,
        amz_date,
        expires: None,
    })
}

/// Parse the presigned form from the query. `credential_buf` receives the
/// decoded credential, which the returned scope borrows.
pub fn sv4_parse_presigned<'a>(
    query: &'a [u8],
    credential_buf: &'a mut [u8; 256],
) -> Result<Sv4Auth<'a>, Sv4Error> {
    let alg = sv4_query_param(query, b"X-Amz-Algorithm").ok_or(Sv4Error::Missing)?;
    if alg != SV4_ALGORITHM {
        return Err(Sv4Error::Algorithm);
    }
    let cred_raw = sv4_query_param(query, b"X-Amz-Credential").ok_or(Sv4Error::Malformed)?;
    let n = sv4_decode(cred_raw, credential_buf).ok_or(Sv4Error::Malformed)?;
    let cred: &'a [u8] = &credential_buf[..n];
    let (access_key, scope_date, region, service) =
        sv4_credential(cred).ok_or(Sv4Error::Malformed)?;
    let signed = sv4_query_param(query, b"X-Amz-SignedHeaders").ok_or(Sv4Error::Malformed)?;
    let sig = sv4_query_param(query, b"X-Amz-Signature").ok_or(Sv4Error::Malformed)?;
    let amz_date = sv4_query_param(query, b"X-Amz-Date").ok_or(Sv4Error::Malformed)?;
    let expires = sv4_query_param(query, b"X-Amz-Expires")
        .and_then(sv4_digits)
        .ok_or(Sv4Error::Malformed)?;
    if expires == 0 || expires > SV4_EXPIRES_MAX {
        return Err(Sv4Error::Malformed);
    }
    Ok(Sv4Auth {
        access_key,
        scope_date,
        region,
        service,
        signed_headers: signed,
        signature: sig,
        amz_date,
        expires: Some(expires),
    })
}

/// The canonical query, sorted: `(name, value)` spans into `scratch`.
struct Sv4Query {
    entries: [(u16, u16, u16, u16); SV4_QUERY_PARAMS_MAX],
    count: usize,
}

fn sv4_canonical_query(
    query: &[u8],
    skip_signature: bool,
    scratch: &mut [u8; SV4_QUERY_SCRATCH],
) -> Result<Sv4Query, Sv4Error> {
    let mut q = Sv4Query {
        entries: [(0, 0, 0, 0); SV4_QUERY_PARAMS_MAX],
        count: 0,
    };
    let mut at = 0usize;
    if query.is_empty() {
        return Ok(q);
    }
    for part in query.split(|&c| c == b'&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.iter().position(|&c| c == b'=') {
            Some(e) => (&part[..e], &part[e + 1..]),
            None => (part, &part[part.len()..]),
        };
        if skip_signature && k == b"X-Amz-Signature" {
            continue;
        }
        if q.count == SV4_QUERY_PARAMS_MAX {
            return Err(Sv4Error::TooLarge);
        }
        let k_at = at;
        at = sv4_put_encoded(scratch, at, k, false).ok_or(Sv4Error::Malformed)?;
        let v_at = at;
        at = sv4_put_encoded(scratch, at, v, false).ok_or(Sv4Error::Malformed)?;
        q.entries[q.count] = (
            k_at as u16,
            (v_at - k_at) as u16,
            v_at as u16,
            (at - v_at) as u16,
        );
        q.count += 1;
    }
    // Insertion sort by name, then value: bounded and allocation-free.
    for i in 1..q.count {
        let mut j = i;
        while j > 0 {
            let a = q.entries[j - 1];
            let b = q.entries[j];
            let ka = &scratch[a.0 as usize..(a.0 + a.1) as usize];
            let kb = &scratch[b.0 as usize..(b.0 + b.1) as usize];
            let va = &scratch[a.2 as usize..(a.2 + a.3) as usize];
            let vb = &scratch[b.2 as usize..(b.2 + b.3) as usize];
            if (ka, va) <= (kb, vb) {
                break;
            }
            q.entries.swap(j - 1, j);
            j -= 1;
        }
    }
    Ok(q)
}

/// SHA-256 of the canonical request.
///
/// `target` is the request target as received (path and query);
/// `headers` the request's `name: value\r\n` block; `signed_headers` the
/// `;`-separated names (lowercase, as listed); `payload_hash` what the
/// canonical form ends with. For a presigned request `X-Amz-Signature` is left
/// out of the canonical query.
pub fn sv4_canonical_request_hash(
    method: &[u8],
    target: &[u8],
    headers: &[u8],
    signed_headers: &[u8],
    payload_hash: &[u8],
    presigned: bool,
    scratch: &mut [u8; SV4_QUERY_SCRATCH],
) -> Result<[u8; 32], Sv4Error> {
    let (path, query) = sv4_split_target(target);
    let mut h = Sha256::new();
    h.update(method);
    h.update(b"\n");
    if path.is_empty() {
        h.update(b"/");
    } else {
        sv4_hash_encoded(&mut h, path, true).ok_or(Sv4Error::Malformed)?;
    }
    h.update(b"\n");
    let q = sv4_canonical_query(query, presigned, scratch)?;
    for i in 0..q.count {
        let (ka, kl, va, vl) = q.entries[i];
        if i > 0 {
            h.update(b"&");
        }
        h.update(&scratch[ka as usize..(ka + kl) as usize]);
        h.update(b"=");
        h.update(&scratch[va as usize..(va + vl) as usize]);
    }
    h.update(b"\n");
    let mut names = 0usize;
    let mut has_host = false;
    for name in signed_headers.split(|&c| c == b';') {
        if name.is_empty() {
            return Err(Sv4Error::Malformed);
        }
        names += 1;
        if names > SV4_SIGNED_HEADERS_MAX {
            return Err(Sv4Error::TooLarge);
        }
        if name == b"host" {
            has_host = true;
        }
        h.update(name);
        h.update(b":");
        if !sv4_header_canonical(headers, name, |b| h.update(b)) {
            return Err(Sv4Error::HeaderMissing);
        }
        h.update(b"\n");
    }
    if !has_host {
        return Err(Sv4Error::HeaderMissing);
    }
    h.update(b"\n");
    h.update(signed_headers);
    h.update(b"\n");
    h.update(payload_hash);
    Ok(h.finalize())
}

/// The hex signature over a canonical request hash.
pub fn sv4_signature(
    signing_key: &[u8; 32],
    amz_date: &[u8],
    scope_date: &[u8],
    region: &[u8],
    service: &[u8],
    canonical_hash: &[u8; 32],
) -> [u8; 64] {
    let mut sts = [0u8; 256];
    let mut n = 0usize;
    for part in [
        SV4_ALGORITHM,
        b"\n",
        amz_date,
        b"\n",
        scope_date,
        b"/",
        region,
        b"/",
        service,
        b"/aws4_request\n",
    ] {
        let m = part.len().min(sts.len() - n);
        sts[n..n + m].copy_from_slice(&part[..m]);
        n += m;
    }
    let ch = sv4_hex32(canonical_hash);
    let m = 64.min(sts.len() - n);
    sts[n..n + m].copy_from_slice(&ch[..m]);
    n += m;
    sv4_hex32(&sv4_hmac(signing_key, &sts[..n]))
}

/// The signature of one `aws-chunked` chunk, chained from the previous one
/// (the request's own signature for the first).
pub fn sv4_chunk_signature(
    signing_key: &[u8; 32],
    amz_date: &[u8],
    scope_date: &[u8],
    region: &[u8],
    service: &[u8],
    previous: &[u8],
    chunk_hash: &[u8; 32],
) -> [u8; 64] {
    // The string to sign is short and bounded, so it is built whole: HMAC
    // needs its message in one piece.
    let mut msg = [0u8; 512];
    let mut n = 0usize;
    for part in [
        &b"AWS4-HMAC-SHA256-PAYLOAD\n"[..],
        amz_date,
        b"\n",
        scope_date,
        b"/",
        region,
        b"/",
        service,
        b"/aws4_request\n",
        previous,
        b"\n",
        SV4_EMPTY_SHA256,
        b"\n",
    ] {
        let m = part.len().min(msg.len() - n);
        msg[n..n + m].copy_from_slice(&part[..m]);
        n += m;
    }
    let ch = sv4_hex32(chunk_hash);
    let m = 64.min(msg.len() - n);
    msg[n..n + m].copy_from_slice(&ch[..m]);
    n += m;
    sv4_hex32(&sv4_hmac(signing_key, &msg[..n]))
}

/// Whether `t` (a request's Unix time) lies within the allowed skew of a
/// clock reading `now ± uncertainty`. Conservative: the whole uncertainty is
/// counted against the request.
pub fn sv4_within_skew(t: u64, now: u64, uncertainty: u64) -> bool {
    t.saturating_add(SV4_SKEW_MAX) >= now.saturating_add(uncertainty)
        && t <= now.saturating_sub(uncertainty).saturating_add(SV4_SKEW_MAX)
}

/// Whether a presigned URL signed at `t` for `expires` seconds is still
/// valid at `now ± uncertainty`. Conservative, as the skew check is.
pub fn sv4_presign_live(t: u64, expires: u64, now: u64, uncertainty: u64) -> bool {
    now.saturating_add(uncertainty) <= t.saturating_add(expires)
}
