// Bounded, no_std, no-alloc AWS Signature V4 request signing for S3-compatible
// endpoints. Crypto primitives are SDK-owned: the consuming module must
// include! `../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs` (module-relative) before this file; the RFC 2104
// `hmac_sha256` below is the only local glue (construction, not primitives). `include!`d by the `s3` .fmod.
//
// This connector makes a point the others don't: even a STATELESS request/reply
// protocol needs a compiled module when each request must be cryptographically
// SIGNED. S3 GET/PUT is a single round trip — but the request carries an
// `Authorization: AWS4-HMAC-SHA256 …` header whose signature is
//   HMAC( derive_key(secret,date,region,service), string_to_sign )
// over a canonical form of the method/URI/headers/payload-hash. So it is not the
// multi-round-trip that forces a module here, it is the crypto: a bytecode codec
// cannot compute an HMAC/SHA-256 signature. (Depends on `sha256`/`hmac_sha256`
// from scram_core — the safe, oracle-pinned SHA-256; see scram_core's header for
// why this crate carries its own rather than the SDK's unsafe NEON one.)

/// HMAC-SHA-256 (RFC 2104) over the SDK's streaming `Sha256` — construction
/// glue only; the compression function is SDK-owned.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    let mut i = 0;
    while i < 64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
        i += 1;
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

const HEXD: &[u8; 16] = b"0123456789abcdef";

/// Lowercase-hex encode `data` into `out`; returns the byte length written.
pub fn hex_lower(data: &[u8], out: &mut [u8]) -> usize {
    let mut o = 0;
    for &b in data {
        if o + 2 > out.len() {
            break;
        }
        out[o] = HEXD[(b >> 4) as usize];
        out[o + 1] = HEXD[(b & 0xf) as usize];
        o += 2;
    }
    o
}

/// Lowercase hex of `SHA256(data)` (64 bytes).
pub fn sha256_hex(data: &[u8]) -> [u8; 64] {
    let h = sha256(data);
    let mut out = [0u8; 64];
    hex_lower(&h, &mut out);
    out
}

/// The empty-payload hash (`SHA256("")`), used as `x-amz-content-sha256` for
/// bodyless requests.
pub const EMPTY_PAYLOAD_SHA256: &[u8; 64] =
    b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Derive the SigV4 signing key:
/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
pub fn sigv4_signing_key(secret: &[u8], date: &[u8], region: &[u8], service: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 4 + 128];
    k0[..4].copy_from_slice(b"AWS4");
    let sl = secret.len().min(128);
    k0[4..4 + sl].copy_from_slice(&secret[..sl]);
    let k_date = hmac_sha256(&k0[..4 + sl], date);
    let k_region = hmac_sha256(&k_date, region);
    let k_service = hmac_sha256(&k_region, service);
    hmac_sha256(&k_service, b"aws4_request")
}

fn sput(out: &mut [u8], pos: &mut usize, b: &[u8]) -> Option<()> {
    if *pos + b.len() > out.len() {
        return None;
    }
    out[*pos..*pos + b.len()].copy_from_slice(b);
    *pos += b.len();
    Some(())
}

/// Decimal-encode `v` into `out` at `pos`. Used for `Content-Length`, the one
/// header whose value is a number rather than a copied byte string.
fn sput_dec(out: &mut [u8], pos: &mut usize, v: usize) -> Option<()> {
    let mut d = [0u8; 20];
    let mut n = 0usize;
    let mut x = v;
    if x == 0 {
        d[0] = b'0';
        n = 1;
    } else {
        while x > 0 {
            d[n] = b'0' + (x % 10) as u8;
            x /= 10;
            n += 1;
        }
    }
    while n > 0 {
        n -= 1;
        if *pos >= out.len() {
            return None;
        }
        out[*pos] = d[n];
        *pos += 1;
    }
    Some(())
}

/// Build a fully-signed HTTP/1.1 request for an S3-compatible endpoint —
/// `GET`, `PUT`, `HEAD` or `DELETE`.
///
/// `timestamp` is `YYYYMMDDTHHMMSSZ` (16 bytes), `date` is `YYYYMMDD` (8).
/// Signs `host;x-amz-content-sha256;x-amz-date`. Returns the request length.
///
/// The payload is hashed, not merely attached: SigV4 binds
/// `x-amz-content-sha256` into the canonical request, so a PUT whose body was
/// altered in flight fails the signature rather than storing corrupted bytes.
/// That is the property that makes this worth a compiled module — a bytecode
/// codec cannot compute the hash or the HMAC.
///
/// `Content-Length` is emitted for a payload-bearing request but deliberately
/// NOT added to `SignedHeaders`: SigV4 signs exactly the headers it lists, and
/// widening the set would break compatibility with the canonical form every
/// other S3 client produces.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct SigV4 input (credential, endpoint, request-time, payload); grouping them into a struct only relocates the arity"
)]
pub fn s3_sign_request(
    method: &[u8],
    access_key: &[u8],
    secret: &[u8],
    region: &[u8],
    host: &[u8],
    path: &[u8],
    payload: &[u8],
    timestamp: &[u8],
    date: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    // The payload hash appears three times — canonical request, request header,
    // and (as the empty-payload constant) for bodyless verbs — so it is
    // computed once here.
    let mut payload_hash = [0u8; 64];
    if payload.is_empty() {
        payload_hash.copy_from_slice(EMPTY_PAYLOAD_SHA256);
    } else {
        payload_hash = sha256_hex(payload);
    }

    // ---- canonical request ----
    let mut cr = [0u8; 512];
    let mut c = 0;
    sput(&mut cr, &mut c, method)?;
    sput(&mut cr, &mut c, b"\n")?;
    sput(&mut cr, &mut c, path)?;
    sput(&mut cr, &mut c, b"\n\n")?; // canonical URI, then empty canonical query
    sput(&mut cr, &mut c, b"host:")?;
    sput(&mut cr, &mut c, host)?;
    sput(&mut cr, &mut c, b"\nx-amz-content-sha256:")?;
    sput(&mut cr, &mut c, &payload_hash)?;
    sput(&mut cr, &mut c, b"\nx-amz-date:")?;
    sput(&mut cr, &mut c, timestamp)?;
    sput(
        &mut cr,
        &mut c,
        b"\n\nhost;x-amz-content-sha256;x-amz-date\n",
    )?;
    sput(&mut cr, &mut c, &payload_hash)?;
    let cr_hash = sha256_hex(&cr[..c]);

    // ---- string to sign ----
    let mut sts = [0u8; 256];
    let mut s = 0;
    sput(&mut sts, &mut s, b"AWS4-HMAC-SHA256\n")?;
    sput(&mut sts, &mut s, timestamp)?;
    sput(&mut sts, &mut s, b"\n")?;
    sput(&mut sts, &mut s, date)?;
    sput(&mut sts, &mut s, b"/")?;
    sput(&mut sts, &mut s, region)?;
    sput(&mut sts, &mut s, b"/s3/aws4_request\n")?;
    sput(&mut sts, &mut s, &cr_hash)?;

    // ---- signature ----
    let key = sigv4_signing_key(secret, date, region, b"s3");
    let sig = hmac_sha256(&key, &sts[..s]);
    let mut sig_hex = [0u8; 64];
    hex_lower(&sig, &mut sig_hex);

    // ---- HTTP request ----
    let mut p = 0;
    sput(out, &mut p, method)?;
    sput(out, &mut p, b" ")?;
    sput(out, &mut p, path)?;
    sput(out, &mut p, b" HTTP/1.1\r\nHost: ")?;
    sput(out, &mut p, host)?;
    sput(out, &mut p, b"\r\nx-amz-date: ")?;
    sput(out, &mut p, timestamp)?;
    sput(out, &mut p, b"\r\nx-amz-content-sha256: ")?;
    sput(out, &mut p, &payload_hash)?;
    if !payload.is_empty() {
        sput(out, &mut p, b"\r\nContent-Length: ")?;
        sput_dec(out, &mut p, payload.len())?;
    }
    sput(
        out,
        &mut p,
        b"\r\nAuthorization: AWS4-HMAC-SHA256 Credential=",
    )?;
    sput(out, &mut p, access_key)?;
    sput(out, &mut p, b"/")?;
    sput(out, &mut p, date)?;
    sput(out, &mut p, b"/")?;
    sput(out, &mut p, region)?;
    sput(
        out,
        &mut p,
        b"/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=",
    )?;
    sput(out, &mut p, &sig_hex)?;
    sput(out, &mut p, b"\r\nConnection: close\r\n\r\n")?;
    if !payload.is_empty() {
        sput(out, &mut p, payload)?;
    }
    Some(p)
}

/// `s3_sign_request` for the bodyless `GET` this connector booted with. Kept
/// so the standalone ListBuckets probe (`examples/s3_client/`) reads as what it
/// is — one call, no method or payload to choose.
#[allow(
    clippy::too_many_arguments,
    reason = "delegates to s3_sign_request; the arity is that function's"
)]
pub fn s3_sign_get(
    access_key: &[u8],
    secret: &[u8],
    region: &[u8],
    host: &[u8],
    path: &[u8],
    timestamp: &[u8],
    date: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    s3_sign_request(
        b"GET", access_key, secret, region, host, path, b"", timestamp, date, out,
    )
}

/// Parse an HTTP response status code from `HTTP/1.1 <code> ...`. `None` if the
/// status line is not yet present.
pub fn http_status_code(buf: &[u8]) -> Option<u16> {
    // find first space, then 3 digits
    let mut i = 0;
    while i < buf.len() && buf[i] != b' ' {
        i += 1;
    }
    i += 1;
    let d = buf.get(i..i + 3)?;
    if !d.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((d[0] - b'0') as u16 * 100 + (d[1] - b'0') as u16 * 10 + (d[2] - b'0') as u16)
}

/// Format a UTC epoch (milliseconds) as SigV4's `YYYYMMDDTHHMMSSZ` (into
/// `ts`, 16 bytes) and `YYYYMMDD` (into `date`, 8 bytes). Uses Howard Hinnant's
/// days-from-civil inverse; valid for all dates after 1970.
pub fn sigv4_time(millis: u64, ts: &mut [u8; 16], date: &mut [u8; 8]) {
    let secs = millis / 1000;
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let (hh, mm, ss) = (
        (sod / 3600) as u32,
        ((sod % 3600) / 60) as u32,
        (sod % 60) as u32,
    );
    // civil_from_days
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (if m <= 2 { y + 1 } else { y }) as u32;

    let w2 = |v: u32, o: &mut [u8]| {
        o[0] = b'0' + ((v / 10) % 10) as u8;
        o[1] = b'0' + (v % 10) as u8;
    };
    date[0] = b'0' + ((year / 1000) % 10) as u8;
    date[1] = b'0' + ((year / 100) % 10) as u8;
    date[2] = b'0' + ((year / 10) % 10) as u8;
    date[3] = b'0' + (year % 10) as u8;
    w2(m, &mut date[4..6]);
    w2(d, &mut date[6..8]);
    ts[..8].copy_from_slice(date);
    ts[8] = b'T';
    w2(hh, &mut ts[9..11]);
    w2(mm, &mut ts[11..13]);
    w2(ss, &mut ts[13..15]);
    ts[15] = b'Z';
}
