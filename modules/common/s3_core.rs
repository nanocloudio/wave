// S3 client mechanics over HTTP/1.1: the signed request head the `s3`
// connector writes, the `aws-chunked` framing of a streamed request body, and
// the response head and body framing it reads back. Bounded, no_std, no
// allocation.
//
// Signing is `sigv4_core.rs`. The mounting module `include!`s the SDK's
// `target/fluxor/fluxor-abi/sdk/crypto/sha256.rs`, then `sigv4_core.rs`, then
// this file, so `Sha256`, `sha256` and every `sv4_*` item are in scope by bare
// name. This file holds only what a client needs on top of them.
//
// A request head is laid out with the signed fields first, as one block, so
// the block the canonical request is computed over is exactly the bytes that
// go on the wire:
//
//   METHOD target HTTP/1.1
//   Host: <authority>
//   x-amz-content-sha256: <payload hash>
//   x-amz-date: <YYYYMMDDTHHMMSSZ>
//   x-amz-decoded-content-length: <len>        streamed body only
//   Content-Encoding: aws-chunked              streamed body only
//   Content-Length: <wire length>              any request with a body
//   <caller's header lines>
//   Authorization: AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…
//   Connection: close
//
// A streamed body is `aws-chunked`: fixed-size chunks, each
// `hex(size);chunk-signature=<sig>\r\n<data>\r\n`, then
// `0;chunk-signature=<sig>\r\n\r\n`. Every chunk signature is chained from the
// one before it, the first from the head's own signature.

/// Decoded body bytes per `aws-chunked` chunk. S3 requires every chunk but the
/// last to carry at least 8 KiB; a fixed size makes the encoded length
/// computable before the first byte is sent.
pub const S3_CHUNK: usize = 8192;

/// The chunk-extension that carries a chunk's signature.
const S3_CHUNK_SIG: &[u8] = b";chunk-signature=";

/// The service SigV4 scopes an S3 signature to.
pub const S3_SERVICE: &[u8] = b"s3";

/// Bounded byte writer: every write either fits whole or marks the writer
/// over, and an over writer is refused by [`S3Put::done`].
pub struct S3Put<'a> {
    out: &'a mut [u8],
    at: usize,
    over: bool,
}

impl<'a> S3Put<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self {
            out,
            at: 0,
            over: false,
        }
    }

    pub fn at(&self) -> usize {
        self.at
    }

    pub fn put(&mut self, b: &[u8]) {
        let end = match self.at.checked_add(b.len()) {
            Some(e) => e,
            None => {
                self.over = true;
                return;
            }
        };
        match self.out.get_mut(self.at..end) {
            Some(dst) => {
                dst.copy_from_slice(b);
                self.at = end;
            }
            None => self.over = true,
        }
    }

    pub fn dec(&mut self, v: u64) {
        let mut d = [0u8; 20];
        let n = s3_dec(v, &mut d);
        self.put(d.get(..n).unwrap_or(&[]));
    }

    pub fn hex(&mut self, v: u64) {
        let mut d = [0u8; 16];
        let n = s3_hex(v, &mut d);
        self.put(d.get(..n).unwrap_or(&[]));
    }

    /// The length written, or `None` when anything did not fit.
    pub fn done(&self) -> Option<usize> {
        if self.over {
            None
        } else {
            Some(self.at)
        }
    }
}

/// `v` in decimal; the digits written.
pub fn s3_dec(mut v: u64, out: &mut [u8; 20]) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    loop {
        if let Some(t) = tmp.get_mut(n) {
            *t = b'0' + (v % 10) as u8;
        }
        n += 1;
        v /= 10;
        if v == 0 || n == tmp.len() {
            break;
        }
    }
    for i in 0..n {
        if let (Some(o), Some(t)) = (out.get_mut(i), tmp.get(n - 1 - i)) {
            *o = *t;
        }
    }
    n
}

/// `v` in lowercase hex without leading zeros (`0` for zero); the digits
/// written.
pub fn s3_hex(v: u64, out: &mut [u8; 16]) -> usize {
    let mut n = 1usize;
    while n < 16 && (v >> (4 * n)) != 0 {
        n += 1;
    }
    for i in 0..n {
        let nib = ((v >> (4 * (n - 1 - i))) & 0xf) as u8;
        if let Some(o) = out.get_mut(i) {
            *o = if nib < 10 {
                b'0' + nib
            } else {
                b'a' + nib - 10
            };
        }
    }
    n
}

/// Hex digits of `v` as a chunk size.
fn s3_hex_len(v: u64) -> u64 {
    let mut d = [0u8; 16];
    s3_hex(v, &mut d) as u64
}

/// Wire bytes of one `aws-chunked` chunk carrying `size` decoded bytes,
/// framing included. `size == 0` is the final chunk, whose data is the empty
/// line that ends the body.
pub fn s3_chunk_wire_len(size: u64) -> Option<u64> {
    s3_hex_len(size)
        .checked_add(S3_CHUNK_SIG.len() as u64)?
        .checked_add(64 + 2)?
        .checked_add(size)?
        .checked_add(2)
}

/// The `Content-Length` of an `aws-chunked` body of `decoded` bytes cut into
/// `chunk`-byte chunks: every chunk's framing, the short last chunk if any,
/// and the final empty chunk. `None` on overflow.
pub fn s3_aws_chunked_len(decoded: u64, chunk: u64) -> Option<u64> {
    if chunk == 0 {
        return None;
    }
    let full = decoded / chunk;
    let rest = decoded % chunk;
    let mut total = full.checked_mul(s3_chunk_wire_len(chunk)?)?;
    if rest > 0 {
        total = total.checked_add(s3_chunk_wire_len(rest)?)?;
    }
    total.checked_add(s3_chunk_wire_len(0)?)
}

/// The framing line before a chunk's data: `hex(size);chunk-signature=<sig>\r\n`.
/// The final chunk (`size == 0`) also carries the blank line that ends the
/// body. The bytes written, or `None` when `out` is short.
pub fn s3_chunk_header(size: u64, sig: &[u8; 64], out: &mut [u8]) -> Option<usize> {
    let mut w = S3Put::new(out);
    w.hex(size);
    w.put(S3_CHUNK_SIG);
    w.put(sig);
    w.put(b"\r\n");
    if size == 0 {
        w.put(b"\r\n");
    }
    w.done()
}

/// Whether `target` is a request target the connector can sign and send:
/// absolute path form, visible ASCII only, every `%` a whole escape, and a
/// query the canonical form can hold. `scratch` is the canonical query's
/// working space.
pub fn s3_target_ok(target: &[u8], scratch: &mut [u8; SV4_QUERY_SCRATCH]) -> bool {
    if target.first() != Some(&b'/') {
        return false;
    }
    if target.iter().any(|&c| c <= 0x20 || c >= 0x7F) {
        return false;
    }
    sv4_canonical_request_hash(
        b"GET",
        target,
        b"host: h\r\n",
        b"host",
        SV4_UNSIGNED,
        false,
        scratch,
    )
    .is_ok()
}

fn s3_digits(v: &[u8]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in v {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
}

/// A header the connector writes itself, which a caller may not supply:
/// framing, the signed fields, and the credential.
fn s3_reserved(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"authorization")
        || name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"content-encoding")
        || name.eq_ignore_ascii_case(b"expect")
        || name.eq_ignore_ascii_case(b"x-amz-date")
        || name.eq_ignore_ascii_case(b"x-amz-content-sha256")
        || name.eq_ignore_ascii_case(b"x-amz-decoded-content-length")
}

/// One `name: value\r\n` line of a header block: the name, the trimmed value,
/// and the offset after the line. `None` when the line is not well formed.
fn s3_line(b: &[u8], at: usize) -> Option<(&[u8], &[u8], usize)> {
    let rest = b.get(at..)?;
    let end = rest.windows(2).position(|w| w == b"\r\n")?;
    let line = rest.get(..end)?;
    let colon = line.iter().position(|&c| c == b':')?;
    let name = line.get(..colon)?;
    if name.is_empty() || name.iter().any(|&c| c <= 0x20 || c >= 0x7F) {
        return None;
    }
    let mut v = line.get(colon + 1..)?;
    if v.iter().any(|&c| (c < 0x20 && c != b'\t') || c == 0x7F) {
        return None;
    }
    while let [b' ' | b'\t', tail @ ..] = v {
        v = tail;
    }
    while let [head @ .., b' ' | b'\t'] = v {
        v = head;
    }
    Some((name, v, at + end + 2))
}

/// Why a caller's header block is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3HeaderError {
    /// A line that is not `name: value\r\n`, or a `content-length` that is
    /// not one decimal number.
    Malformed,
    /// A header the connector writes itself.
    Reserved,
}

/// Check a caller's header block and return its `content-length`, if it
/// names one. Every line must be `name: value\r\n` with visible-ASCII names;
/// a header the connector writes itself is refused rather than sent twice.
pub fn s3_caller_headers(block: &[u8]) -> Result<Option<u64>, S3HeaderError> {
    let mut at = 0usize;
    let mut length = None;
    while at < block.len() {
        let (name, value, next) = s3_line(block, at).ok_or(S3HeaderError::Malformed)?;
        if s3_reserved(name) {
            return Err(S3HeaderError::Reserved);
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            let v = s3_digits(value).ok_or(S3HeaderError::Malformed)?;
            if length.is_some() {
                return Err(S3HeaderError::Malformed);
            }
            length = Some(v);
        }
        at = next;
    }
    Ok(length)
}

/// Copy a checked caller header block, minus its `content-length` (the
/// connector writes the wire length itself).
fn s3_put_caller_headers(block: &[u8], w: &mut S3Put<'_>) {
    let mut at = 0usize;
    while let Some((name, _, next)) = s3_line(block, at) {
        if !name.eq_ignore_ascii_case(b"content-length") {
            w.put(block.get(at..next).unwrap_or(&[]));
        }
        at = next;
    }
}

/// Everything a signed request head is made from.
pub struct S3HeadParams<'a> {
    /// The method token.
    pub method: &'a [u8],
    /// Path and query, percent-encoded as they go on the wire.
    pub target: &'a [u8],
    /// The authority: dialled, and signed as `Host`.
    pub host: &'a [u8],
    pub access_key: &'a [u8],
    pub region: &'a [u8],
    pub signing_key: &'a [u8; 32],
    pub amz_date: &'a [u8; 16],
    pub scope_date: &'a [u8; 8],
    /// `x-amz-content-sha256`: the body's hex SHA-256, or [`SV4_STREAMING`].
    pub payload_hash: &'a [u8],
    /// The decoded body length of an `aws-chunked` body; `None` otherwise.
    pub decoded_len: Option<u64>,
    /// The `Content-Length` on the wire; `None` for a request without one.
    pub content_length: Option<u64>,
    /// The caller's extra header lines, already checked.
    pub caller_headers: &'a [u8],
}

/// Write the signed request head into `out`. Returns the head's length and
/// the signature, which seeds the chunk signatures of a streamed body.
pub fn s3_compose_head(
    p: &S3HeadParams<'_>,
    out: &mut [u8],
    scratch: &mut [u8; SV4_QUERY_SCRATCH],
) -> Result<(usize, [u8; 64]), Sv4Error> {
    let mut w = S3Put::new(out);
    w.put(p.method);
    w.put(b" ");
    w.put(p.target);
    w.put(b" HTTP/1.1\r\n");
    let signed_at = w.at();
    w.put(b"Host: ");
    w.put(p.host);
    w.put(b"\r\nx-amz-content-sha256: ");
    w.put(p.payload_hash);
    w.put(b"\r\nx-amz-date: ");
    w.put(p.amz_date);
    w.put(b"\r\n");
    if let Some(n) = p.decoded_len {
        w.put(b"x-amz-decoded-content-length: ");
        w.dec(n);
        w.put(b"\r\n");
    }
    let signed_end = w.done().ok_or(Sv4Error::TooLarge)?;
    let signed_names: &[u8] = if p.decoded_len.is_some() {
        b"host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length"
    } else {
        b"host;x-amz-content-sha256;x-amz-date"
    };
    if p.decoded_len.is_some() {
        w.put(b"Content-Encoding: aws-chunked\r\n");
    }
    if let Some(n) = p.content_length {
        w.put(b"Content-Length: ");
        w.dec(n);
        w.put(b"\r\n");
    }
    s3_put_caller_headers(p.caller_headers, &mut w);
    let tail_at = w.done().ok_or(Sv4Error::TooLarge)?;

    // The signed block is complete on the wire bytes; the canonical request
    // is computed over it in place.
    let block = out.get(signed_at..signed_end).ok_or(Sv4Error::TooLarge)?;
    let hash = sv4_canonical_request_hash(
        p.method,
        p.target,
        block,
        signed_names,
        p.payload_hash,
        false,
        scratch,
    )?;
    let sig = sv4_signature(
        p.signing_key,
        p.amz_date,
        p.scope_date,
        p.region,
        S3_SERVICE,
        &hash,
    );

    let rest = out.get_mut(tail_at..).ok_or(Sv4Error::TooLarge)?;
    let mut w = S3Put::new(rest);
    w.put(b"Authorization: AWS4-HMAC-SHA256 Credential=");
    w.put(p.access_key);
    w.put(b"/");
    w.put(p.scope_date);
    w.put(b"/");
    w.put(p.region);
    w.put(b"/s3/aws4_request, SignedHeaders=");
    w.put(signed_names);
    w.put(b", Signature=");
    w.put(&sig);
    w.put(b"\r\nConnection: close\r\n\r\n");
    let n = w.done().ok_or(Sv4Error::TooLarge)?;
    Ok((tail_at + n, sig))
}

/// Where a response head ends: the offset just past `\r\n\r\n`.
pub fn s3_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The status code of an `HTTP/1.x DDD` status line, which need not yet be
/// complete. `None` until the three digits have arrived, or when the line is
/// not an HTTP/1 status line.
pub fn s3_status_code(buf: &[u8]) -> Option<u16> {
    let prefix = buf.get(..9)?;
    if prefix.get(..7)? != b"HTTP/1." || prefix.get(8)? != &b' ' {
        return None;
    }
    let d = buf.get(9..12)?;
    let mut v: u16 = 0;
    for &c in d {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u16;
    }
    if let Some(&c) = buf.get(12) {
        if c != b' ' && c != b'\r' {
            return None;
        }
    }
    Some(v)
}

/// How a response body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3Body {
    /// No body: a response to HEAD, a 204, a 304, or an interim 1xx.
    None,
    /// Exactly this many bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Everything until the endpoint closes the connection.
    Close,
}

/// The header lines of a complete response head (after its status line,
/// before the blank line).
fn s3_head_lines(head: &[u8]) -> Option<&[u8]> {
    let first = head.windows(2).position(|w| w == b"\r\n")? + 2;
    let end = head.len().checked_sub(2)?;
    if first > end {
        return None;
    }
    head.get(first..end)
}

/// The body framing of a complete response head. `request_was_head` is true
/// for a response to a HEAD request, which never has a body whatever it
/// declares. `None` when the framing is contradictory or unparsable: a
/// transfer coding other than `chunked` last, or `Content-Length` values that
/// disagree.
pub fn s3_response_body(head: &[u8], status: u16, request_was_head: bool) -> Option<S3Body> {
    let lines = s3_head_lines(head)?;
    let mut length = None;
    let mut chunked = false;
    let mut at = 0usize;
    while at < lines.len() {
        let (name, value, next) = s3_line(lines, at)?;
        if name.eq_ignore_ascii_case(b"content-length") {
            let v = s3_digits(value)?;
            if length.is_some_and(|l| l != v) {
                return None;
            }
            length = Some(v);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // Only the last coding frames the body; anything but `chunked`
            // there leaves no way to find the body's end short of a close.
            let last = value.rsplit(|&c| c == b',').next().unwrap_or(value);
            let mut last = last;
            while let [b' ' | b'\t', tail @ ..] = last {
                last = tail;
            }
            if !last.eq_ignore_ascii_case(b"chunked") {
                return None;
            }
            chunked = true;
        }
        at = next;
    }
    if request_was_head || status == 204 || status == 304 || (100..200).contains(&status) {
        return Some(S3Body::None);
    }
    if chunked {
        return Some(S3Body::Chunked);
    }
    Some(match length {
        Some(n) => S3Body::Length(n),
        None => S3Body::Close,
    })
}

/// Split a complete response head into what a caller is handed: the
/// `Content-Type` value into `ct`, and every other header line, normalised to
/// `name: value\r\n`, into `headers` — except the connection's own framing
/// (`Connection`, `Keep-Alive`, `Transfer-Encoding`). `Content-Length` is
/// kept: it tells a caller the object's size. Returns the two lengths, or
/// `None` when the head is malformed or a field does not fit.
pub fn s3_forward_headers(
    head: &[u8],
    ct: &mut [u8],
    headers: &mut [u8],
) -> Option<(usize, usize)> {
    let lines = s3_head_lines(head)?;
    let mut ct_len = 0usize;
    let mut w = S3Put::new(headers);
    let mut at = 0usize;
    while at < lines.len() {
        let (name, value, next) = s3_line(lines, at)?;
        at = next;
        if name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"keep-alive")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
        {
            continue;
        }
        if name.eq_ignore_ascii_case(b"content-type") && ct_len == 0 {
            if let Some(dst) = ct.get_mut(..value.len()) {
                dst.copy_from_slice(value);
                ct_len = value.len();
                continue;
            }
        }
        w.put(name);
        w.put(b": ");
        w.put(value);
        w.put(b"\r\n");
    }
    Some((ct_len, w.done()?))
}

const CH_LENGTH: u8 = 0;
const CH_EXT: u8 = 1;
const CH_LENGTH_LF: u8 = 2;
const CH_DATA: u8 = 3;
const CH_DATA_CR: u8 = 4;
const CH_DATA_LF: u8 = 5;
const CH_TRAILER: u8 = 6;
const CH_TRAILER_LINE: u8 = 7;
const CH_TRAILER_LF: u8 = 8;
const CH_END_LF: u8 = 9;
const CH_DONE: u8 = 10;

/// Incremental `Transfer-Encoding: chunked` decoder. Holds no data: each call
/// decodes what it is given into the caller's buffer and remembers only where
/// in the framing it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S3Chunked {
    state: u8,
    remaining: u64,
    digits: u8,
}

impl Default for S3Chunked {
    fn default() -> Self {
        Self::new()
    }
}

impl S3Chunked {
    pub const fn new() -> Self {
        Self {
            state: CH_LENGTH,
            remaining: 0,
            digits: 0,
        }
    }

    /// The final chunk and its trailer section have been read.
    pub fn done(&self) -> bool {
        self.state == CH_DONE
    }

    /// Decode from `input` into `out`. Returns `(consumed, produced)`; stops
    /// when the input is used up, when `out` is full at chunk data, or at the
    /// end of the body. `None` when the framing is malformed.
    pub fn feed(&mut self, input: &[u8], out: &mut [u8]) -> Option<(usize, usize)> {
        let mut i = 0usize;
        let mut o = 0usize;
        while i < input.len() && self.state != CH_DONE {
            if self.state == CH_DATA {
                let room = out.len() - o;
                if room == 0 {
                    break;
                }
                let avail = input.len() - i;
                let n = (self.remaining.min(avail as u64) as usize).min(room);
                out.get_mut(o..o + n)?.copy_from_slice(input.get(i..i + n)?);
                i += n;
                o += n;
                self.remaining -= n as u64;
                if self.remaining == 0 {
                    self.state = CH_DATA_CR;
                }
                continue;
            }
            let c = *input.get(i)?;
            i += 1;
            match self.state {
                CH_LENGTH => {
                    let nib = match c {
                        b'0'..=b'9' => Some(c - b'0'),
                        b'a'..=b'f' => Some(c - b'a' + 10),
                        b'A'..=b'F' => Some(c - b'A' + 10),
                        _ => None,
                    };
                    match nib {
                        Some(d) => {
                            if self.digits >= 16 {
                                return None;
                            }
                            self.remaining = (self.remaining << 4) | d as u64;
                            self.digits += 1;
                        }
                        None if self.digits == 0 => return None,
                        None if c == b';' || c == b' ' || c == b'\t' => self.state = CH_EXT,
                        None if c == b'\r' => self.state = CH_LENGTH_LF,
                        None => return None,
                    }
                }
                CH_EXT => match c {
                    b'\r' => self.state = CH_LENGTH_LF,
                    b'\n' => return None,
                    _ => {}
                },
                CH_LENGTH_LF => {
                    if c != b'\n' {
                        return None;
                    }
                    self.digits = 0;
                    self.state = if self.remaining == 0 {
                        CH_TRAILER
                    } else {
                        CH_DATA
                    };
                }
                CH_DATA_CR => {
                    if c != b'\r' {
                        return None;
                    }
                    self.state = CH_DATA_LF;
                }
                CH_DATA_LF => {
                    if c != b'\n' {
                        return None;
                    }
                    self.state = CH_LENGTH;
                }
                CH_TRAILER => {
                    self.state = if c == b'\r' {
                        CH_END_LF
                    } else {
                        CH_TRAILER_LINE
                    };
                }
                CH_TRAILER_LINE => {
                    if c == b'\r' {
                        self.state = CH_TRAILER_LF;
                    }
                }
                CH_TRAILER_LF => {
                    if c != b'\n' {
                        return None;
                    }
                    self.state = CH_TRAILER;
                }
                CH_END_LF => {
                    if c != b'\n' {
                        return None;
                    }
                    self.state = CH_DONE;
                }
                _ => return None,
            }
        }
        Some((i, o))
    }
}
