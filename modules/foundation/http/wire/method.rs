//! HTTP request methods — one vocabulary, shared by every generation.
//!
//! h1, h2 and h3 all resolve a method against one table, so a request means
//! the same thing whichever generation carried it. That table is the
//! `http_exchange` contract's: a request record carries its method as one
//! byte, and every reader of that byte — this server, an application module
//! decoding `HttpRequest`, and each connector that performs a request — must
//! decode it identically. The values are STABLE and PUBLIC; appending a
//! method is safe, renumbering one is a wire-format break.
//!
//! What stays here is what only a server needs: how far a request-line
//! parser scans for a method token, and which methods carry a body it must
//! be prepared to read.
//!
//! Deliberately NOT a Rust enum: the value crosses a channel as a byte, and a
//! `#[repr(u8)]` enum would make every decode a fallible transmute at the
//! receiver for no gain over a `u8` plus these constants.

/// The method vocabulary and its lookups are the `http_exchange` contract's,
/// re-exported here so every generation resolves a method through one name.
pub use super::super::http_exchange::{
    method_from_token, method_name, METHOD_CONNECT, METHOD_DELETE, METHOD_GET, METHOD_HEAD,
    METHOD_NONE, METHOD_OPTIONS, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};

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
