//! HTTP/1 wire codec — text framing.
//!
//! Pure byte-level read and write helpers. No syscalls, no channel I/O,
//! no module state: each function takes raw byte slices so the same
//! routines serve both the server and client state machines.

use super::method;

/// Decide whether the response to a parsed request head should
/// keep the connection open. RFC 9112 §9.3 default rules:
///   HTTP/1.1 + no `Connection: close`        → keep-alive
///   HTTP/1.1 + `Connection: close`           → close
///   HTTP/1.0 + `Connection: keep-alive`      → keep-alive
///   HTTP/1.0 (no Connection or anything else) → close
///   anything older / malformed               → close
///
/// `head` is the request bytes up to and including the `\r\n\r\n`
/// terminator. Header name match is case-insensitive; value tokens
/// are comma-separated, each trimmed and compared case-insensitively.
pub fn request_keeps_alive(head: &[u8]) -> bool {
    // 1) Find end of request line (first \r\n).
    let mut line_end = 0usize;
    while line_end + 1 < head.len() {
        if head[line_end] == b'\r' && head[line_end + 1] == b'\n' {
            break;
        }
        line_end += 1;
    }
    if line_end + 1 >= head.len() {
        return false;
    }

    // 2) HTTP version is the token after the second space on the
    //    request line: `METHOD SP PATH SP HTTP/1.x CRLF`.
    let req_line = &head[..line_end];
    let v_is_11 = req_line.ends_with(b"HTTP/1.1");
    let v_is_10 = req_line.ends_with(b"HTTP/1.0");
    if !v_is_11 && !v_is_10 {
        return false;
    }

    // 3) Walk header lines for `Connection:`. Last wins (per RFC
    //    9110 §5.3 it's a "list-based" header; multiple Connection
    //    headers are merged in order, so the union of tokens
    //    decides). We track two bits: saw `close`, saw `keep-alive`.
    let mut saw_close = false;
    let mut saw_keep = false;
    let mut cursor = line_end + 2;
    while cursor < head.len() {
        let line_start = cursor;
        let mut nl = line_start;
        while nl + 1 < head.len() {
            if head[nl] == b'\r' && head[nl + 1] == b'\n' {
                break;
            }
            nl += 1;
        }
        if nl == line_start {
            break; // blank line = end of head
        }
        if nl + 1 >= head.len() {
            break; // truncated
        }
        let line = &head[line_start..nl];
        if let Some(colon) = line.iter().position(|c| *c == b':') {
            let name = &line[..colon];
            if name.eq_ignore_ascii_case(b"connection") {
                let mut value_start = colon + 1;
                while value_start < line.len()
                    && (line[value_start] == b' ' || line[value_start] == b'\t')
                {
                    value_start += 1;
                }
                let value = &line[value_start..];
                for tok in value.split(|c| *c == b',') {
                    // Trim whitespace each side.
                    let mut start = 0;
                    let mut end = tok.len();
                    while start < end && (tok[start] == b' ' || tok[start] == b'\t') {
                        start += 1;
                    }
                    while end > start && (tok[end - 1] == b' ' || tok[end - 1] == b'\t') {
                        end -= 1;
                    }
                    let trimmed = &tok[start..end];
                    if trimmed.eq_ignore_ascii_case(b"close") {
                        saw_close = true;
                    } else if trimmed.eq_ignore_ascii_case(b"keep-alive") {
                        saw_keep = true;
                    }
                }
            }
        }
        cursor = nl + 2;
    }

    if saw_close {
        return false;
    }
    if v_is_11 {
        return true;
    }
    // HTTP/1.0: only keep-alive if explicitly requested.
    saw_keep
}

/// Find an HTTP/1 header by case-insensitive name in a parsed request head
/// (request line + header lines through the blank line). Returns the trimmed
/// value of the first matching header, or `None`. Used for `traceparent`
/// trace-context ingress.
pub fn find_header<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    // Skip the request line (up to its CRLF).
    let mut cursor = 0usize;
    while cursor + 1 < head.len() {
        if head[cursor] == b'\r' && head[cursor + 1] == b'\n' {
            break;
        }
        cursor += 1;
    }
    if cursor + 1 >= head.len() {
        return None;
    }
    cursor += 2;
    while cursor < head.len() {
        let line_start = cursor;
        let mut nl = line_start;
        while nl + 1 < head.len() {
            if head[nl] == b'\r' && head[nl + 1] == b'\n' {
                break;
            }
            nl += 1;
        }
        if nl == line_start {
            break; // blank line = end of head
        }
        if nl + 1 >= head.len() {
            break; // truncated
        }
        let line = &head[line_start..nl];
        if let Some(colon) = line.iter().position(|c| *c == b':') {
            if line[..colon].eq_ignore_ascii_case(name) {
                let mut vs = colon + 1;
                while vs < line.len() && (line[vs] == b' ' || line[vs] == b'\t') {
                    vs += 1;
                }
                let mut ve = line.len();
                while ve > vs && (line[ve - 1] == b' ' || line[ve - 1] == b'\t') {
                    ve -= 1;
                }
                return Some(&line[vs..ve]);
            }
        }
        cursor = nl + 2;
    }
    None
}

/// Locate the end-of-headers sentinel `\r\n\r\n` in a partial HTTP/1
/// message. Returns the byte offset *after* the sentinel — i.e. where
/// the body begins — or `None` if the sentinel is not yet present.
///
/// `len` may be smaller than `buf.len()` to scan only the populated
/// prefix of a fixed-size receive buffer.
///
/// # Safety
/// `buf` must be valid for reads of `len` bytes (which may be ≤ `buf.len()`).
/// Internal pointer arithmetic stays inside that prefix.
pub unsafe fn find_header_end(buf: &[u8], len: usize) -> Option<usize> {
    if len < 4 {
        return None;
    }
    let ptr = buf.as_ptr();
    let mut i = 0;
    while i + 3 < len {
        if *ptr.add(i) == b'\r'
            && *ptr.add(i + 1) == b'\n'
            && *ptr.add(i + 2) == b'\r'
            && *ptr.add(i + 3) == b'\n'
        {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

/// Parse an HTTP/1 request line (`METHOD /path HTTP/1.x\r\n`) out of `src`
/// and copy the path bytes into `dst`. Returns `(method, path_len)` on
/// success or `None` if the line is malformed, truncated, or too short
/// to contain the minimum viable request.
///
/// The method is returned rather than enforced. An unrecognised-but-well-formed
/// token yields [`method::METHOD_NONE`] with the path still parsed, so the
/// caller can answer **501 Not Implemented** — which is what RFC 9110 §9.1 asks
/// for — instead of the 400 that a parse failure would produce. Only a
/// genuinely malformed line (no method token, no space-delimited path, a path
/// that does not start with `/`) is `None`. The recognised tokens are
/// `wire::method`'s, the same table h2 and h3 resolve against.
///
/// # Safety
/// `src` must be valid for reads of `src_len` bytes; `dst` must be
/// valid for writes of up to `dst_cap` bytes. The returned length is
/// clamped to `dst_cap` so writes never overshoot.
pub unsafe fn parse_request_line(
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
) -> Option<(u8, usize)> {
    // Shortest viable line: `GET / HTTP/1.0\r\n` — 14 bytes before the CRLF.
    if src_len < 14 {
        return None;
    }

    // 1) Method token: bytes up to the first space. Bounded by
    //    MAX_METHOD_SCAN so a pathological line without a space cannot walk
    //    the whole buffer before failing. The bound is wider than the
    //    recognised table on purpose — see `method::MAX_METHOD_SCAN`, which
    //    is what keeps "unimplemented" (501) distinct from "malformed" (400).
    let mut m_end = 0usize;
    let scan_cap = (method::MAX_METHOD_SCAN + 1).min(src_len);
    while m_end < scan_cap && *src.add(m_end) != b' ' {
        m_end += 1;
    }
    if m_end == 0 || m_end >= scan_cap {
        return None;
    }
    let mut tok = [0u8; method::MAX_METHOD_SCAN];
    let mut i = 0;
    while i < m_end {
        tok[i] = *src.add(i);
        i += 1;
    }
    let verb = method::method_from_token(&tok[..m_end]);

    // 2) Path: from just past the space to the next space. An origin-form
    //    target must start with `/` (RFC 9112 §3.2.1); authority-form and
    //    asterisk-form belong to CONNECT and OPTIONS *, neither of which this
    //    server routes.
    let path_start = m_end + 1;
    let mut path_end = path_start;
    while path_end < src_len && *src.add(path_end) != b' ' {
        path_end += 1;
    }
    if path_end <= path_start || *src.add(path_start) != b'/' {
        return None;
    }

    let plen = (path_end - path_start).min(dst_cap);
    let mut i = 0;
    while i < plen {
        *dst.add(i) = *src.add(path_start + i);
        i += 1;
    }
    Some((verb, plen))
}

/// Write a minimal HTTP/1.1 response status line plus a
/// `Connection:` header (`keep-alive` or `close` per the
/// `keepalive` flag), `Cache-Control: no-store`, and a `Content-Type`
/// header into `dst`, terminated by the blank line that ends the head. Returns the
/// number of bytes written (capped at `dst_cap`).
///
/// The HTTP module serves mutable development/runtime artifacts at stable URLs
/// (`/`, `/host_shims.js`, `/fluxor.wasm`). Caching those independently can run a
/// new shell with an old shim or kernel after a rebuild, so responses are
/// deliberately non-cacheable until the scenario synthesizer emits content-hashed
/// asset URLs.
///
/// `keepalive = true` is what the server SHOULD emit when the
/// matching request was HTTP/1.1 without an explicit `Connection:
/// close`, or HTTP/1.0 with `Connection: keep-alive`. The server's
/// per-slot `Phase::RecvRequest` decides this and threads the flag
/// down to here; the caller never picks unilaterally.
///
/// # Safety
/// `dst` must be valid for writes of `dst_cap` bytes.
pub unsafe fn write_status_line(
    dst: *mut u8,
    dst_cap: usize,
    status: &[u8],
    content_type: &[u8],
    keepalive: bool,
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"HTTP/1.1 ");
    put!(status);
    if keepalive {
        put!(b"\r\nConnection: keep-alive\r\nCache-Control: no-store\r\nContent-Type: ");
    } else {
        put!(b"\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: ");
    }
    put!(content_type);
    put!(b"\r\n\r\n");

    off
}

/// Write a minimal HTTP/1.1 error response (status line + Connection:
/// close + blank line + body) into `dst`. Returns total bytes written.
///
/// # Safety
/// `dst` must be valid for writes of `dst_cap` bytes.
pub unsafe fn write_error_response(
    dst: *mut u8,
    dst_cap: usize,
    code: &[u8],
    body: &[u8],
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"HTTP/1.1 ");
    put!(code);
    put!(b"\r\nConnection: close\r\n\r\n");
    put!(body);

    off
}

// ── Request body framing ──────────────────────────────────────────────────
//
// RFC 9112 §6 decides how long a request body is, and the order matters:
// `Transfer-Encoding` beats `Content-Length` when both appear, and a request
// carrying both is a smuggling vector rather than a merely ambiguous message.
// Everything here is a pure read over the parsed head — the server state
// machine owns what to DO about each answer.

/// How the body of a request is delimited.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BodyFraming {
    /// No body: neither framing header is present.
    None,
    /// `Content-Length: n` — exactly `n` more bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked` — a sequence of size-prefixed chunks
    /// terminated by a zero-size chunk.
    Chunked,
    /// The framing headers contradict each other, or a value is unparseable.
    /// Must be answered 400 and the connection closed — RFC 9112 §6.3 is
    /// explicit that a server MUST NOT guess, because a proxy guessing
    /// differently is exactly how request smuggling works.
    Invalid,
}

/// Whether `head` carries more than one field line named `name` with values
/// that are not byte-identical.
///
/// `find_header` answers with the FIRST match, which is the right shape for
/// every header whose meaning does not change when it is repeated. Framing
/// headers are not those: RFC 9112 §6.3 makes multiple `Content-Length` lines
/// with differing values an unrecoverable error precisely because a server and
/// an intermediary in front of it may pick different ones, and the bytes
/// between the two lengths become a second request the front end never saw.
///
/// Identical repeats are permitted by the RFC (they can be collapsed to one
/// value), so this reports only genuine disagreement.
pub fn header_values_disagree(head: &[u8], name: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor + 1 < head.len() {
        if head[cursor] == b'\r' && head[cursor + 1] == b'\n' {
            break;
        }
        cursor += 1;
    }
    if cursor + 1 >= head.len() {
        return false;
    }
    cursor += 2;
    let mut first: Option<&[u8]> = None;
    while cursor < head.len() {
        let line_start = cursor;
        let mut nl = line_start;
        while nl + 1 < head.len() {
            if head[nl] == b'\r' && head[nl + 1] == b'\n' {
                break;
            }
            nl += 1;
        }
        if nl == line_start || nl + 1 >= head.len() {
            break;
        }
        let line = &head[line_start..nl];
        if let Some(colon) = line.iter().position(|c| *c == b':') {
            if line[..colon].eq_ignore_ascii_case(name) {
                let mut vs = colon + 1;
                while vs < line.len() && (line[vs] == b' ' || line[vs] == b'\t') {
                    vs += 1;
                }
                let mut ve = line.len();
                while ve > vs && (line[ve - 1] == b' ' || line[ve - 1] == b'\t') {
                    ve -= 1;
                }
                let val = &line[vs..ve];
                match first {
                    None => first = Some(val),
                    Some(prev) => {
                        if prev != val {
                            return true;
                        }
                    }
                }
            }
        }
        cursor = nl + 2;
    }
    false
}

/// Decide how a request's body is framed, from its parsed head.
pub fn body_framing(head: &[u8]) -> BodyFraming {
    let te = find_header(head, b"transfer-encoding");
    let cl = find_header(head, b"content-length");

    if let Some(te) = te {
        // Both present: reject. RFC 9112 §6.1 says Transfer-Encoding
        // overrides Content-Length, and §6.3 says a message with both "ought
        // to be handled as an error" — the disagreement between two
        // intermediaries about which to honour is the smuggle.
        if cl.is_some() {
            return BodyFraming::Invalid;
        }
        // Only `chunked`, and only as the final encoding, is supported. The
        // value is a comma-separated list; `chunked` must come last.
        let mut last: &[u8] = b"";
        for part in te.split(|c| *c == b',') {
            let mut a = 0usize;
            let mut b = part.len();
            while a < b && (part[a] == b' ' || part[a] == b'\t') {
                a += 1;
            }
            while b > a && (part[b - 1] == b' ' || part[b - 1] == b'\t') {
                b -= 1;
            }
            last = &part[a..b];
        }
        if last.eq_ignore_ascii_case(b"chunked") {
            return BodyFraming::Chunked;
        }
        return BodyFraming::Invalid;
    }

    match cl {
        None => BodyFraming::None,
        Some(v) => {
            if v.is_empty() {
                return BodyFraming::Invalid;
            }
            // Several `Content-Length` lines that disagree, or one line
            // carrying a list, are the same ambiguity the CL+TE case above
            // refuses and for the same reason: whichever value this server
            // picks, an intermediary may pick the other, and the bytes between
            // them become a request nobody authorised. `find_header` returns
            // the first match, so without this the second length was simply
            // ignored and the message served.
            // clippy prefers `v.contains(&b',')` here and it is wrong to take
            // the advice: `<[u8]>::contains` lowers to `core::slice::memchr`,
            // which the bare-metal PIC link has no symbol for. The explicit
            // scan is the same check and is the only one that links.
            #[allow(
                clippy::manual_contains,
                reason = "slice::contains pulls in core::slice::memchr, which the PIC link cannot resolve"
            )]
            let listed = v.iter().any(|c| *c == b',');
            if header_values_disagree(head, b"content-length") || listed {
                return BodyFraming::Invalid;
            }
            let mut n: u64 = 0;
            for c in v {
                if !c.is_ascii_digit() {
                    return BodyFraming::Invalid;
                }
                // A length that cannot fit a u64 is not a length. Saturating
                // here would silently accept a truncated value.
                n = match n
                    .checked_mul(10)
                    .and_then(|n| n.checked_add((*c - b'0') as u64))
                {
                    Some(n) => n,
                    None => return BodyFraming::Invalid,
                };
            }
            BodyFraming::Length(n)
        }
    }
}

/// Whether the client asked for a `100 Continue` interim response before
/// sending its body (RFC 9110 §10.1.1).
///
/// Not a nicety: `docker push` and `curl -T` on a large upload both send
/// `Expect: 100-continue` and WAIT. A server that ignores the header answers
/// nothing until the client's timeout expires, which presents as a hang rather
/// than as an error.
pub fn expects_continue(head: &[u8]) -> bool {
    match find_header(head, b"expect") {
        Some(v) => v.eq_ignore_ascii_case(b"100-continue"),
        None => false,
    }
}

/// Result of parsing one chunk header line from a chunked body.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ChunkHeader {
    /// Parsed: this chunk carries `size` bytes, and the header line occupied
    /// `consumed` bytes (through its CRLF). `size == 0` is the terminating
    /// chunk.
    Ok { size: u64, consumed: usize },
    /// The line is incomplete — more bytes needed before it can be parsed.
    Need,
    /// Malformed size line. 400, and close.
    Bad,
}

/// Longest chunk-size line accepted, including any `;ext=val` parameters and
/// the CRLF. A chunked sender that needs more than this to say how big the
/// next chunk is, is not one worth accommodating — and without the cap, a
/// stream of garbage without a CRLF is scanned in full on every tick.
pub const MAX_CHUNK_LINE: usize = 64;

/// Parse a chunk-size line: `1a2b[;ext]\r\n` (RFC 9112 §7.1).
///
/// Chunk extensions are parsed and DISCARDED. No extension has a registered
/// meaning, but a sender is allowed to emit them, and treating one as a
/// malformed size would reject a legal stream.
pub fn parse_chunk_header(buf: &[u8]) -> ChunkHeader {
    let cap = buf.len().min(MAX_CHUNK_LINE);
    let mut i = 0usize;
    // Hex digits.
    let mut size: u64 = 0;
    let mut digits = 0usize;
    while i < cap {
        let c = buf[i];
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        size = match size.checked_mul(16).and_then(|s| s.checked_add(d as u64)) {
            Some(s) => s,
            None => return ChunkHeader::Bad,
        };
        digits += 1;
        i += 1;
    }
    if digits == 0 {
        // Not a hex digit in first position: either malformed, or we have not
        // yet received anything to judge.
        return if buf.is_empty() {
            ChunkHeader::Need
        } else {
            ChunkHeader::Bad
        };
    }
    // Optional extensions, then CRLF.
    while i < cap && buf[i] != b'\r' {
        i += 1;
    }
    if i >= cap {
        // Ran out of buffer looking for the CRLF. Only "need more" if we
        // stopped because the buffer ended, not because the cap did.
        return if buf.len() <= MAX_CHUNK_LINE {
            ChunkHeader::Need
        } else {
            ChunkHeader::Bad
        };
    }
    if i + 1 >= buf.len() {
        return ChunkHeader::Need;
    }
    if buf[i + 1] != b'\n' {
        return ChunkHeader::Bad;
    }
    ChunkHeader::Ok {
        size,
        consumed: i + 2,
    }
}

/// Outcome of parsing an HTTP `Range:` header value against a known
/// resource size.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RangeParse {
    /// No `Range:` header was present, or it was malformed / used an
    /// unsupported unit. Serve the full body as 200 OK.
    None,
    /// Header parsed; serve `start..=end` (inclusive byte offsets) as 206.
    Satisfiable { start: u32, end: u32 },
    /// Header parsed but the requested range can't intersect `[0, size)`.
    /// Emit 416 with `Content-Range: bytes */<size>`.
    Unsatisfiable,
}

/// Parse a single-range HTTP `Range:` header value against the
/// resource's total size in bytes.
///
/// Accepts `bytes=N-`, `bytes=N-M`, and `bytes=-N` (suffix). Multipart
/// byterange specs (`bytes=0-99,200-299`) fall through to `None` so the
/// caller serves plain 200 — RFC 9110 §14.2 lets a server promising
/// only single ranges ignore the extras.
///
/// `value` is the trimmed header value (no `Range:` prefix, no
/// surrounding whitespace).
pub fn parse_range_header(value: &[u8], size: u32) -> RangeParse {
    if size == 0 {
        return RangeParse::None;
    }
    const PREFIX: &[u8] = b"bytes=";
    if value.len() < PREFIX.len() {
        return RangeParse::None;
    }
    let mut i = 0usize;
    while i < PREFIX.len() {
        let c = value[i];
        let lower = if c.is_ascii_uppercase() { c + 32 } else { c };
        if lower != PREFIX[i] {
            return RangeParse::None;
        }
        i += 1;
    }
    // One byte-walk that finds the dash and rejects multipart specs
    // (`bytes=0-99,200-299` → fall through to plain 200 OK; RFC 9110
    // §14.2 lets a single-range server ignore the extras).
    let spec = &value[PREFIX.len()..];
    let mut dash: Option<usize> = None;
    let mut k = 0usize;
    while k < spec.len() {
        let c = spec[k];
        if c == b',' {
            return RangeParse::None;
        }
        if c == b'-' && dash.is_none() {
            dash = Some(k);
        }
        k += 1;
    }
    let dash = match dash {
        Some(d) => d,
        None => return RangeParse::None,
    };
    let last = size - 1;

    // Saturating u64 parse — `bytes=9999999999-` (and larger) must
    // resolve cleanly as out-of-range rather than wrap u32 or panic.
    let parse_u64 = |bytes: &[u8]| -> Option<u64> {
        if bytes.is_empty() {
            return None;
        }
        let mut acc: u64 = 0;
        let mut j = 0;
        while j < bytes.len() {
            let c = bytes[j];
            if !c.is_ascii_digit() {
                return None;
            }
            acc = acc.saturating_mul(10).saturating_add((c - b'0') as u64);
            j += 1;
        }
        Some(acc)
    };

    let start_bytes = &spec[..dash];
    let end_bytes = &spec[dash + 1..];
    let size64 = size as u64;

    if start_bytes.is_empty() {
        // Suffix form: bytes=-N → last N bytes (clamped to the file).
        let n = match parse_u64(end_bytes) {
            Some(v) if v > 0 => v,
            Some(_) => return RangeParse::Unsatisfiable,
            None => return RangeParse::None,
        };
        let n = n.min(size64);
        return RangeParse::Satisfiable {
            start: (size64 - n) as u32,
            end: last,
        };
    }

    let start = match parse_u64(start_bytes) {
        Some(v) => v,
        None => return RangeParse::None,
    };
    if start >= size64 {
        return RangeParse::Unsatisfiable;
    }
    let end = if end_bytes.is_empty() {
        last as u64
    } else {
        match parse_u64(end_bytes) {
            Some(v) => v,
            None => return RangeParse::None,
        }
    };
    if end < start {
        return RangeParse::Unsatisfiable;
    }
    RangeParse::Satisfiable {
        start: start as u32,
        end: end.min(last as u64) as u32,
    }
}

/// Write an HTTP/1.0 GET request line plus `Host:` header (using the
/// peer's dotted-quad IP) and the `Connection: close` terminator into
/// `dst`. Returns the total request length.
///
/// Capped at 256 bytes total — `dst_cap` must reflect the caller's
/// scratch capacity. The host IP is written in big-endian dotted-quad.
///
/// # Safety
/// `dst` must be valid for writes of `dst_cap` bytes.
pub unsafe fn write_request_line(
    dst: *mut u8,
    dst_cap: usize,
    path: *const u8,
    path_len: usize,
    host_ip_be: u32,
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"GET ");

    let mut i = 0;
    while i < path_len && off < dst_cap {
        *dst.add(off) = *path.add(i);
        off += 1;
        i += 1;
    }

    put!(b" HTTP/1.0\r\nHost: ");

    // host IP, big-endian dotted-quad
    let ip = host_ip_be.to_be_bytes();
    let octets = [ip[0], ip[1], ip[2], ip[3]];
    let mut o = 0;
    while o < 4 {
        let b = octets[o];
        if b >= 100 && off < dst_cap {
            *dst.add(off) = b'0' + (b / 100);
            off += 1;
        }
        if b >= 10 && off < dst_cap {
            *dst.add(off) = b'0' + ((b / 10) % 10);
            off += 1;
        }
        if off < dst_cap {
            *dst.add(off) = b'0' + (b % 10);
            off += 1;
        }
        if o < 3 && off < dst_cap {
            *dst.add(off) = b'.';
            off += 1;
        }
        o += 1;
    }

    put!(b"\r\nConnection: close\r\n\r\n");

    off
}
