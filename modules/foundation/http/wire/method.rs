//! HTTP request methods — one vocabulary, shared by every generation.
//!
//! h1, h2 and h3 all resolve a method against this table, so a request means
//! the same thing whichever generation carried it. A per-generation table is
//! how the same request comes to succeed on one and fail on another, which
//! `http_interop.rs` asserts against from both sides.
//!
//! The values are STABLE and PUBLIC: `HttpRequest` envelopes on the `req_out`
//! port carry `method` as one byte, so a downstream application module decodes
//! them with this table. Appending a method is safe; renumbering one is a
//! wire-format break, exactly as for Fluxor's content-type table.
//!
//! `GET`/`CONNECT`/`POST` keep the values 1/2/3 that h2 and h3 already used, so
//! widening the vocabulary did not renumber the three values already in
//! service. The rest are appended.
//!
//! Deliberately NOT a Rust enum: the value crosses a channel as a byte, and a
//! `#[repr(u8)]` enum would make every decode a fallible transmute at the
//! receiver for no gain over a `u8` plus these constants.

/// No method parsed yet, or an unrecognised token.
pub const METHOD_NONE: u8 = 0;
pub const METHOD_GET: u8 = 1;
/// Kept at 2 because h2 tests `method_kind == 2` for the RFC 8441 extended
/// CONNECT that carries a WebSocket upgrade, and h3 does the same for RFC 9220.
pub const METHOD_CONNECT: u8 = 2;
pub const METHOD_POST: u8 = 3;
pub const METHOD_HEAD: u8 = 4;
pub const METHOD_PUT: u8 = 5;
pub const METHOD_PATCH: u8 = 6;
pub const METHOD_DELETE: u8 = 7;
pub const METHOD_OPTIONS: u8 = 8;

/// How far a request-line parser scans for the space that ends the method
/// token before giving up and calling the line malformed.
///
/// Deliberately wider than the longest token this table recognises (7 bytes,
/// `OPTIONS`/`CONNECT`). RFC 9110 §9.1 puts no length limit on a method token,
/// and the parser has to distinguish two different failures: a well-formed line
/// naming a method this server does not implement (`PROPFIND`, `MKCOL`,
/// `SUBSCRIBE` — 501 Not Implemented), and a line with no method token at all
/// (400 Bad Request). Capping the scan at the width of the recognised table
/// collapses the first case into the second, and answers 400 to a request that
/// was never malformed.
///
/// 24 bytes covers every method in the IANA registry with room to spare, while
/// keeping the scan bounded — without a cap, a line containing no space walks
/// the entire receive buffer on every parse attempt.
pub const MAX_METHOD_SCAN: usize = 24;

/// Map a method token to its constant. Case-SENSITIVE, per RFC 9110 §9.1:
/// method names are case-sensitive tokens, and `get` is not `GET`. Returns
/// [`METHOD_NONE`] for anything unrecognised — the caller decides whether that
/// is a 400 (malformed request line) or a 501 (well-formed, unimplemented),
/// which is a distinction the parser has no standing to make.
pub fn method_from_token(tok: &[u8]) -> u8 {
    match tok {
        b"GET" => METHOD_GET,
        b"HEAD" => METHOD_HEAD,
        b"POST" => METHOD_POST,
        b"PUT" => METHOD_PUT,
        b"PATCH" => METHOD_PATCH,
        b"DELETE" => METHOD_DELETE,
        b"OPTIONS" => METHOD_OPTIONS,
        b"CONNECT" => METHOD_CONNECT,
        _ => METHOD_NONE,
    }
}

/// The token for a method constant — for logging, and for the `method` field
/// an application module echoes back. Empty slice for [`METHOD_NONE`].
pub fn method_name(m: u8) -> &'static [u8] {
    match m {
        METHOD_GET => b"GET",
        METHOD_HEAD => b"HEAD",
        METHOD_POST => b"POST",
        METHOD_PUT => b"PUT",
        METHOD_PATCH => b"PATCH",
        METHOD_DELETE => b"DELETE",
        METHOD_OPTIONS => b"OPTIONS",
        METHOD_CONNECT => b"CONNECT",
        _ => b"",
    }
}

/// Whether a request with this method may carry a body that the server should
/// read before dispatching.
///
/// This is about what the server must be PREPARED for, not what the RFC
/// encourages. RFC 9110 §9.3.5 says a DELETE body has no defined semantics and
/// §9.3.1 says the same of GET — but "no defined semantics" is not "cannot
/// occur", and a server that ignores a declared `Content-Length` leaves those
/// bytes in the stream to be misread as the next request on a keep-alive
/// connection. So the answer is driven by the framing headers for every method
/// except the two that cannot have one; this function names the methods where a
/// body is EXPECTED, and the body reader consults it only to decide whether an
/// absent `Content-Length` is worth a 411.
pub fn method_expects_request_body(m: u8) -> bool {
    matches!(m, METHOD_POST | METHOD_PUT | METHOD_PATCH)
}

/// Whether the response to this method carries a body. HEAD is the whole point:
/// RFC 9110 §9.3.2 requires the same headers as the equivalent GET —
/// `Content-Length` included — with the body suppressed.
pub fn method_sends_response_body(m: u8) -> bool {
    m != METHOD_HEAD
}

/// Whether this method is dispatchable to an ordinary route handler. CONNECT is
/// excluded because it is a tunnel request: the server either handles it as an
/// upgrade (RFC 8441 / 9220 WebSocket) or refuses it, and never resolves it
/// against the route table's path match.
pub fn method_is_dispatchable(m: u8) -> bool {
    m != METHOD_NONE && m != METHOD_CONNECT
}
