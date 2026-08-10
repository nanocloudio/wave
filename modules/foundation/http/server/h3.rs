//! HTTP/3 request and response layer (RFC 9114 + RFC 9204).
//!
//! Mirrors `h2.rs`'s structure: per-connection `H3State` with a slot
//! table, an emission cursor, and the same `arm_slot_for_emission` /
//! `try_dispatch_pending` pattern. Routes through the existing
//! `server.rs` body renderers (`render_static_into`,
//! `render_template_into`, `render_file_into`, `render_index_into`)
//! which already operate on `(dst, cap) → (n, more)` and don't care
//! about the underlying transport.
//!
//! # Status — read this before assuming a request can be served
//!
//! IMPLEMENTED here and vector-tested in `tests/harness/tests/http3.rs`:
//! [`decode_request_headers`] (the QPACK field section plus the RFC 9114
//! §4.3 message rules), [`encode_response_headers`] / [`build_response`],
//! [`ingest_request_frame`] (per-frame request-stream handling with §7.1
//! legality and §8.1 error codes), and [`dispatch_request`] — which matches
//! a decoded request against the module's REAL route table and renders a
//! static route's response from the same body pool h1 and h2 serve from.
//!
//! ABSENT: the pump loop and the QUIC binding. Nothing in `mod.rs` or
//! `server.rs` calls into this module, no stream is bound to Fluxor's
//! `quic` provider, and no HTTP/3 request has been served end to end.
//! `H3State` / `H3StreamSlot` are the shapes that loop will use; they are
//! not driven by anything today.
//!
//! ALSO ABSENT, and deliberately: every handler except `HANDLER_STATIC`.
//! `render_template_into`, `render_file_into`, the proxy relay and the
//! WebSocket paths all thread their state through `server::cur_slot_mut`,
//! which models ONE TCP connection with ONE request in flight. HTTP/3 has
//! many concurrent streams per connection, so sharing those renderers means
//! giving them a stream-scoped cursor instead of a connection-scoped one.
//! [`dispatch_request`] returns `HandlerNotShared(id)` for those rather than
//! serving one concurrent request correctly and the rest wrongly.
//!
//! # Phase E — WebSocket over HTTP/3 (RFC 9220)
//!
//! RFC 9220 reuses RFC 8441's extended-CONNECT machinery wholesale:
//! the request carries `:method = CONNECT`, `:protocol = websocket`,
//! `:scheme`, `:authority`, `:path`, plus the standard WS subprotocol
//! / extension headers, and the server replies 200 — no
//! `Sec-WebSocket-Accept` (that header is h1-only). Differences from
//! the h2 path (`accept_ws_upgrade` in `h2.rs`):
//!
//! - **Frame transport** — HEADERS / DATA are HTTP/3 frames carried on
//!   a QUIC bidirectional stream rather than h2 frames on a TCP
//!   connection. The slot table here (`H3StreamSlot`) replaces
//!   `H2StreamSlot`; emission uses `build_h3_frame_header` instead of
//!   `wire_h2::write_data`.
//! - **Header coding** — QPACK (`qpack.rs`) replaces HPACK
//!   (`hpack.rs`). The pseudo-headers and WS-extension headers are
//!   the same wire bytes; only the compression frames change.
//! - **SETTINGS** — `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (h2) maps to
//!   the equivalent setting in h3's SETTINGS frame; same advertise.
//! - **No Upgrade-style transition** — h3 has no preface-sniff path
//!   like h2c. The connection is QUIC from packet zero; extended
//!   CONNECT is a per-request decision.
//!
//! The wire-up is therefore: in `h3.rs` request-path dispatch, when a
//! HEADERS frame's `:method == CONNECT` and `:protocol == websocket`,
//! call into the same `match_route` + `HANDLER_WEBSOCKET` check that
//! `accept_ws_upgrade` already does in `h2.rs`. Differ only in the
//! emitted 200 HEADERS encoding (QPACK) and the body framing (h3
//! DATA frames carrying WS frames). The WS frame layer itself
//! (`wire_ws.rs`) is transport-agnostic — `wire_ws::encode_text` /
//! `decode_frame` produce / consume the same bytes that go in the
//! payload of an h3 DATA frame.

use super::super::wire::h3::{
    build_h3_frame_header, parse_h3_frame, H3Frame, H3_FRAME_DATA, H3_FRAME_HEADERS,
    H3_FRAME_SETTINGS, H3_UNI_STREAM_CONTROL, H3_UNI_STREAM_QPACK_DECODER,
    H3_UNI_STREAM_QPACK_ENCODER,
};
use super::super::wire::qpack;

/// Maximum concurrent h3 request streams handled per connection.
/// Mirrors h2's `MAX_STREAMS = 4` so the slot table size is unchanged.
pub const MAX_H3_STREAMS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum H3StreamState {
    Idle,
    HeadersRecv,
    BodyRecv,
    HeadersSent,
    BodySend,
    Complete,
    Reset,
}

/// Per-slot ingress accumulator. One HTTP/3 request head must fit whole: the
/// QPACK field section is decoded in one pass, so a head split across QUIC
/// stream chunks is buffered until complete.
pub const H3_RECV_BUF: usize = 1024;

/// Per-slot egress buffer. Holds one rendered response (HEADERS + DATA frames)
/// awaiting the transport's willingness to take it.
///
/// A response larger than this is refused rather than truncated — see
/// [`H3StreamOutcome::ResponseTooLarge`]. Chunked rendering needs the
/// stream-scoped cursor that `server::cur_slot_mut` does not yet have.
pub const H3_SEND_BUF: usize = 2048;

pub struct H3StreamSlot {
    /// Transport-association handle (`mux` session_id) — one QUIC connection.
    pub session_id: u32,
    pub stream_id: u64,
    pub state: H3StreamState,
    /// Allocated to a request? Mirrors h2's `StreamSlot.allocated`.
    pub allocated: bool,
    /// Ingress accumulator — HEADERS frame body waiting for QPACK.
    pub recv_hdr_buf: [u8; H3_RECV_BUF],
    pub recv_hdr_len: usize,
    /// Egress: the rendered response and how much of it the transport has
    /// taken. Per slot, not per connection — that is the whole point of the
    /// multiplexed design.
    pub send_buf: [u8; H3_SEND_BUF],
    pub send_len: usize,
    pub send_off: usize,
    /// RFC 9220: this stream carried an extended CONNECT that was accepted, so
    /// it is a WebSocket tunnel for the life of the connection rather than one
    /// request. The lifecycle difference is the whole reason this is not just
    /// "another handler": a request slot is released the moment its response
    /// drains; a tunnel must survive it.
    pub ws_active: bool,
    /// Bytes of `recv_hdr_buf` currently holding un-parsed RFC 6455 frame data.
    /// The request-head accumulator is reused once the head is consumed — the
    /// alternative is a second kilobyte per slot for a buffer that can never be
    /// live at the same time.
    pub ws_buf_len: usize,
    /// The response has fully drained and the stream still owes its close.
    /// An HTTP/3 response ENDS the stream; without it a client waits for more
    /// body until its idle timeout — found by a load run, and hidden from the
    /// functional tests because they tolerate the wait.
    pub close_pending: bool,
    /// Egress book-keeping — same shape as h2's slot.
    pub headers_sent: bool,
    pub body_done: bool,
    pub matched_route: i16,
    pub file_index: i16,
    pub tmpl_pos: usize,
}

impl H3StreamSlot {
    pub const fn empty() -> Self {
        Self {
            session_id: 0,
            stream_id: 0,
            state: H3StreamState::Idle,
            allocated: false,
            recv_hdr_buf: [0; H3_RECV_BUF],
            recv_hdr_len: 0,
            ws_active: false,
            ws_buf_len: 0,
            close_pending: false,
            send_buf: [0; H3_SEND_BUF],
            send_len: 0,
            send_off: 0,
            headers_sent: false,
            body_done: false,
            matched_route: -1,
            file_index: -1,
            tmpl_pos: 0,
        }
    }

    /// Release the slot for reuse. Buffers are left as they are — nothing reads
    /// them while `allocated` is false, and zeroing 3 KiB per completed request
    /// would be work with no observable effect.
    pub fn release(&mut self) {
        self.allocated = false;
        self.state = H3StreamState::Idle;
        self.session_id = 0;
        self.stream_id = 0;
        self.recv_hdr_len = 0;
        self.ws_active = false;
        self.ws_buf_len = 0;
        self.close_pending = false;
        self.send_len = 0;
        self.send_off = 0;
        self.headers_sent = false;
        self.body_done = false;
        self.matched_route = -1;
        self.tmpl_pos = 0;
    }

    pub fn pending_out(&self) -> usize {
        self.send_len.saturating_sub(self.send_off)
    }
}

pub struct H3State {
    pub slots: [H3StreamSlot; MAX_H3_STREAMS],
    pub emit_cursor: u8,
    pub control_stream_seen: bool,
    pub qpack_encoder_stream_seen: bool,
    pub qpack_decoder_stream_seen: bool,
    pub settings_received: bool,
    pub goaway_sent: bool,
    pub max_field_section_size: u64,
}

impl H3State {
    pub const fn new() -> Self {
        Self {
            slots: [
                H3StreamSlot::empty(),
                H3StreamSlot::empty(),
                H3StreamSlot::empty(),
                H3StreamSlot::empty(),
            ],
            emit_cursor: 0,
            control_stream_seen: false,
            qpack_encoder_stream_seen: false,
            qpack_decoder_stream_seen: false,
            settings_received: false,
            goaway_sent: false,
            max_field_section_size: 0,
        }
    }
}

/// Identify a unidirectional control stream by its first varint.
/// Returns one of the `H3_UNI_STREAM_*` constants on success.
pub fn classify_uni_stream_prefix(buf: &[u8]) -> Option<(u64, usize)> {
    #[path = "../../../../target/fluxor/fluxor-abi/sdk/wire/varint.rs"]
    mod varint;
    // SAFETY: pointer/length pair derived from a Rust slice; varint_decode
    // bounds-checks against the supplied length.
    unsafe { varint::varint_decode(buf.as_ptr(), buf.len()) }
}

// ----------------------------------------------------------------------
// Request header decoding (RFC 9114 §4.1, RFC 9204 §4.5)
// ----------------------------------------------------------------------

/// Longest request target this module will accept on an h3 stream.
/// Deliberately the same ceiling h2 uses (`server::MAX_PATH`), restated
/// here rather than imported so the h3 build does not depend on h2.
pub const H3_MAX_PATH: usize = 200;

/// Longest `:authority` retained. Only its presence and length are
/// protocol-relevant here; routing is by path.
pub const H3_MAX_AUTHORITY: usize = 64;

/// Largest WebSocket payload this module will carry over an h3 tunnel. Sized
/// against the per-slot send buffer, not against RFC 6455 — a bigger frame is
/// answered with CLOSE 1009 rather than buffered.
pub const H3_WS_PAYLOAD_MAX: usize = 512;

/// Rendered-template scratch for one response body. A template that does not
/// fit is refused, not truncated — see [`H3Dispatch::TooLarge`].
pub const H3_TEMPLATE_BUF: usize = 1024;

/// Scratch for one decoded field line (name + value). A field larger than
/// this is refused rather than truncated — a truncated header is a
/// different request from the one the peer sent.
const H3_FIELD_SCRATCH: usize = 512;

/// Why a header section was refused. The values are the RFC 9114 §8.1
/// error codes the caller puts on the wire, so a caller cannot invent its
/// own mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3Error {
    /// `H3_MESSAGE_ERROR` (0x0105) — malformed request message: a missing
    /// or repeated pseudo-header, a pseudo-header after a regular one, or
    /// a field this module cannot store.
    MessageError,
    /// `QPACK_DECOMPRESSION_FAILED` (0x0200) — the field section did not
    /// decode: a bad prefix, a truncated field line, or a dynamic-table
    /// reference (this module advertises
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so a dynamic reference is
    /// the peer disregarding our SETTINGS).
    QpackFailed,
    /// `H3_FRAME_UNEXPECTED` (0x0105 class) — a frame type that is legal
    /// in h3 but not on a request stream (RFC 9114 §7.1).
    FrameUnexpected,
}

impl H3Error {
    /// The RFC 9114 §8.1 code to send.
    pub const fn code(self) -> u64 {
        match self {
            H3Error::MessageError => 0x0105,
            H3Error::QpackFailed => 0x0200,
            H3Error::FrameUnexpected => 0x0104,
        }
    }
}

/// What `:method` the peer asked for, in the same 1/2/3 encoding
/// `h2.rs` uses so both generations feed one dispatcher.
pub const H3_METHOD_NONE: u8 = 0;
pub const H3_METHOD_GET: u8 = 1;
pub const H3_METHOD_CONNECT: u8 = 2;
pub const H3_METHOD_BODY: u8 = 3;

/// A decoded request header section.
pub struct H3Request {
    pub method_kind: u8,
    pub path: [u8; H3_MAX_PATH],
    pub path_len: u8,
    pub authority: [u8; H3_MAX_AUTHORITY],
    pub authority_len: u8,
    /// RFC 9220 extended CONNECT — `:protocol = websocket`.
    pub protocol_ws: bool,
    /// `content-length`, when the peer stated one.
    pub content_length: Option<u64>,
}

impl H3Request {
    pub const fn empty() -> Self {
        Self {
            method_kind: H3_METHOD_NONE,
            path: [0; H3_MAX_PATH],
            path_len: 0,
            authority: [0; H3_MAX_AUTHORITY],
            authority_len: 0,
            protocol_ws: false,
            content_length: None,
        }
    }

    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    pub fn authority_bytes(&self) -> &[u8] {
        &self.authority[..self.authority_len as usize]
    }
}

fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut v: u64 = 0;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// Decode a HEADERS frame payload — a QPACK field section — into `out`.
///
/// This is the request path the module did not have. Every field line goes
/// through [`qpack::qpack_decode_field_into`], so Huffman-coded names and
/// values decode rather than being refused: real clients Huffman-encode by
/// default, and the RFC 9204 §4.1.2 table is the RFC 7541 one this module
/// already pins to the Appendix C vectors.
///
/// The message rules enforced here are RFC 9114 §4.3:
///
/// * `:method`, `:scheme` and `:path` are mandatory for a non-CONNECT
///   request, and `:authority` for CONNECT;
/// * a pseudo-header may not appear after a regular field;
/// * a pseudo-header may not repeat;
/// * an unknown pseudo-header is a malformed request.
///
/// Returns the number of field lines decoded.
pub fn decode_request_headers(block: &[u8], out: &mut H3Request) -> Result<usize, H3Error> {
    *out = H3Request::empty();

    let mut off = qpack::qpack_decode_block_prefix(block).ok_or(H3Error::QpackFailed)?;

    let mut scratch = [0u8; H3_FIELD_SCRATCH];
    let mut fields = 0usize;
    let mut seen_regular = false;
    let mut seen_scheme = false;
    let mut seen_method = false;
    let mut seen_path = false;
    let mut seen_authority = false;

    while off < block.len() {
        let ranges = qpack::qpack_decode_field_into(&block[off..], &mut scratch)
            .ok_or(H3Error::QpackFailed)?;
        if ranges.consumed == 0 {
            // A zero-width field line would loop forever. The decoder should
            // never return one; refusing here means a future change to it
            // cannot turn into a hang on the device.
            return Err(H3Error::QpackFailed);
        }
        let name = &scratch[ranges.name.0..ranges.name.1];
        let value = &scratch[ranges.value.0..ranges.value.1];

        if name.first() == Some(&b':') {
            if seen_regular {
                // RFC 9114 §4.3: pseudo-headers precede regular fields.
                return Err(H3Error::MessageError);
            }
            match name {
                b":method" => {
                    if seen_method {
                        return Err(H3Error::MessageError);
                    }
                    seen_method = true;
                    out.method_kind = if value == b"GET" || value == b"HEAD" {
                        H3_METHOD_GET
                    } else if value == b"CONNECT" {
                        H3_METHOD_CONNECT
                    } else if value == b"POST"
                        || value == b"PUT"
                        || value == b"PATCH"
                        || value == b"DELETE"
                    {
                        H3_METHOD_BODY
                    } else {
                        return Err(H3Error::MessageError);
                    };
                }
                b":path" => {
                    if seen_path {
                        return Err(H3Error::MessageError);
                    }
                    seen_path = true;
                    if value.is_empty() || value.len() > H3_MAX_PATH {
                        return Err(H3Error::MessageError);
                    }
                    out.path[..value.len()].copy_from_slice(value);
                    out.path_len = value.len() as u8;
                }
                b":authority" => {
                    if seen_authority {
                        return Err(H3Error::MessageError);
                    }
                    seen_authority = true;
                    let n = value.len().min(H3_MAX_AUTHORITY);
                    out.authority[..n].copy_from_slice(&value[..n]);
                    out.authority_len = n as u8;
                }
                b":scheme" => {
                    if seen_scheme {
                        return Err(H3Error::MessageError);
                    }
                    seen_scheme = true;
                }
                b":protocol" => {
                    out.protocol_ws = value == b"websocket";
                }
                _ => return Err(H3Error::MessageError),
            }
        } else {
            seen_regular = true;
            if eq_ascii_ci(name, b"content-length") {
                out.content_length = Some(parse_u64(value).ok_or(H3Error::MessageError)?);
            }
            // RFC 9114 §4.2: a field name must be lowercase on the wire.
            if name.iter().any(|c| c.is_ascii_uppercase()) {
                return Err(H3Error::MessageError);
            }
        }

        fields += 1;
        off += ranges.consumed;
    }

    if out.method_kind == H3_METHOD_CONNECT {
        // Extended CONNECT (RFC 9220) keeps :scheme and :path; classic
        // CONNECT carries only :authority.
        if !seen_authority {
            return Err(H3Error::MessageError);
        }
    } else {
        if !seen_method || !seen_path || !seen_scheme {
            return Err(H3Error::MessageError);
        }
        if out.path_len == 0 {
            return Err(H3Error::MessageError);
        }
    }

    Ok(fields)
}

// ----------------------------------------------------------------------
// Response encoding
// ----------------------------------------------------------------------

/// Encode a response field section: block prefix, `:status`, and the
/// supplied regular fields.
///
/// The prefix is `qpack_emit_block_prefix`'s all-zero
/// Required-Insert-Count / Delta-Base, which is what
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` obliges: this encoder never
/// references a dynamic table, so a decoder can never block on it.
///
/// Returns bytes written, or 0 if `out` is too small — never a partial
/// section, which would decode as a different set of headers.
pub fn encode_response_headers(status: &[u8], fields: &[(&[u8], &[u8])], out: &mut [u8]) -> usize {
    let mut off = qpack::qpack_emit_block_prefix(out);
    if off == 0 {
        return 0;
    }
    let n = qpack::qpack_encode_field(b":status", status, &mut out[off..]);
    if n == 0 {
        return 0;
    }
    off += n;
    for (name, value) in fields {
        let n = qpack::qpack_encode_field(name, value, &mut out[off..]);
        if n == 0 {
            return 0;
        }
        off += n;
    }
    off
}

/// Frame a complete response — HEADERS then DATA — into `out`.
///
/// Returns bytes written, or 0 if it does not fit whole. Partial output is
/// never emitted: half a response on a QUIC stream is a protocol error the
/// peer attributes to us, and a caller that appended more later would have
/// interleaved it with another stream's frames.
pub fn build_response(
    status: &[u8],
    fields: &[(&[u8], &[u8])],
    body: &[u8],
    out: &mut [u8],
) -> usize {
    let mut hdr_block = [0u8; 512];
    let block_len = encode_response_headers(status, fields, &mut hdr_block);
    if block_len == 0 {
        return 0;
    }

    // Size the WHOLE response before writing any of it. Writing the HEADERS
    // frame header first and discovering the body does not fit leaves the
    // caller's buffer holding a frame header for a response that was never
    // emitted — and the return of 0 says nothing was written.
    let mut scratch = [0u8; 16];
    let hdr_frame_len = build_h3_frame_header(H3_FRAME_HEADERS, block_len, &mut scratch);
    if hdr_frame_len == 0 {
        return 0;
    }
    let data_frame_len = if body.is_empty() {
        0
    } else {
        let n = build_h3_frame_header(H3_FRAME_DATA, body.len(), &mut scratch);
        if n == 0 {
            return 0;
        }
        n + body.len()
    };
    if out.len() < hdr_frame_len + block_len + data_frame_len {
        return 0;
    }

    let mut off = 0usize;
    let n = build_h3_frame_header(H3_FRAME_HEADERS, block_len, &mut out[off..]);
    if n == 0 {
        return 0;
    }
    off += n;
    out[off..off + block_len].copy_from_slice(&hdr_block[..block_len]);
    off += block_len;

    if !body.is_empty() {
        let n = build_h3_frame_header(H3_FRAME_DATA, body.len(), &mut out[off..]);
        if n == 0 {
            return 0;
        }
        off += n;
        if out.len() < off + body.len() {
            return 0;
        }
        out[off..off + body.len()].copy_from_slice(body);
        off += body.len();
    }
    off
}

// ----------------------------------------------------------------------
// Dispatch — decoded request to rendered response
// ----------------------------------------------------------------------

/// What dispatching a decoded request produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3Dispatch {
    /// A complete response was written: `n` bytes of HEADERS + DATA frames.
    Response(usize),
    /// No route matched. The 404 response IS written — `n` bytes — because a
    /// caller that had to synthesise its own would diverge from what h1 and h2
    /// send for the same request.
    NotFound(usize),
    /// The route matched, but its handler needs the per-connection slot
    /// machinery that only the h1/h2 path has today (`cur_slot_mut`, the
    /// chunked renderers, the file/proxy state). Carries the handler id so the
    /// caller can say which, rather than reporting a generic failure.
    HandlerNotShared(u8),
    /// The response does not fit `out`. Nothing is written.
    TooLarge,
    /// RFC 9220 extended CONNECT accepted: `n` bytes of a 200 response with no
    /// body are written, and the stream becomes a WebSocket tunnel.
    WebSocketAccepted(usize),
}

/// Match a decoded request to a route and render its response.
///
/// This is the layer between [`decode_request_headers`] and the transport. It
/// deliberately covers only what can be served WITHOUT the per-connection slot:
/// `HANDLER_STATIC` reads its body straight out of the shared body pool, which
/// is connection-independent, and a miss renders the same 404 the other
/// generations send.
///
/// Every other handler returns [`H3Dispatch::HandlerNotShared`]. That is not a
/// stub — it is the honest boundary. `render_template_into`,
/// `render_file_into`, the proxy relay and the WebSocket paths all thread their
/// state through `server::cur_slot_mut`, which models one TCP connection with
/// one request in flight. HTTP/3 has many concurrent streams per connection, so
/// sharing those renderers means giving them a stream-scoped cursor rather than
/// a connection-scoped one. That refactor belongs with the pump loop, not here,
/// and pretending otherwise would produce a path that works for exactly one
/// concurrent request.
///
/// # Safety
///
/// `s` must be a live `HttpState` — the same contract every `server::` helper
/// here already has.
// `pub(crate)`, not `pub`: it takes `&HttpState`, which is crate-private. The
// public surface for a host test is `test_decode_and_dispatch` below, on the
// same precedent as `server::test_inject_dyn_route`.
pub(crate) unsafe fn dispatch_request(
    s: &super::super::HttpState,
    req: &H3Request,
    out: &mut [u8],
) -> H3Dispatch {
    dispatch_request_bounded(s, req, out, H3_TEMPLATE_BUF)
}

/// [`dispatch_request`] with the template scratch capacity injected.
///
/// Exists because the refusal path cannot otherwise be reached from a test: a
/// route body arrives through a TLV parameter whose length field is one byte,
/// so no configurable body can exceed the 1 KiB scratch. Injecting the bound
/// exercises the SAME code with a smaller ceiling rather than leaving
/// "templates that do not fit are refused, not truncated" as an untested claim
/// — which is exactly what a mutation test caught it being.
pub(crate) unsafe fn dispatch_request_bounded(
    s: &super::super::HttpState,
    req: &H3Request,
    out: &mut [u8],
    tmpl_cap: usize,
) -> H3Dispatch {
    let path = req.path_bytes();
    let matched = super::match_route_path(s, path.as_ptr(), path.len());
    if matched < 0 {
        // The literals are copied into stack buffers before being put in the
        // field array, and that is NOT style — it is the PIC constraint
        // `qpack.rs` documents ("avoid PIC relocation issues with const
        // arrays"). A fully-const `&[(&[u8], &[u8])]` is materialised in
        // .rodata as an array of fat pointers whose inner pointers need
        // relocation the loader does not apply; dereferencing them on device
        // segfaults. Found end to end: every 404 crashed the runtime while the
        // matched path — whose array holds a runtime slice, so it is built on
        // the stack — was fine.
        let mut status = [0u8; 3];
        status.copy_from_slice(b"404");
        let mut name = [0u8; 12];
        name.copy_from_slice(b"content-type");
        let mut ctype = [0u8; 10];
        ctype.copy_from_slice(b"text/plain");
        let mut body = [0u8; 10];
        body.copy_from_slice(b"Not Found\n");
        let fields = [(&name[..], &ctype[..])];
        let n = build_response(&status, &fields, &body, out);
        return if n == 0 {
            H3Dispatch::TooLarge
        } else {
            H3Dispatch::NotFound(n)
        };
    }

    let route = &*s.server.routes.as_ptr().add(matched as usize);
    let handler = route.handler;

    // RFC 9220 extended CONNECT. The response is a bare 200 — no
    // `Sec-WebSocket-Accept`, which is an HTTP/1 handshake header and has no
    // meaning here (RFC 8441 §5.1, inherited by RFC 9220). The 200 alone is the
    // upgrade.
    if req.method_kind == H3_METHOD_CONNECT && req.protocol_ws {
        if handler != super::HANDLER_WEBSOCKET {
            return H3Dispatch::HandlerNotShared(handler);
        }
        let mut status = [0u8; 3];
        status.copy_from_slice(b"200");
        let n = build_response(&status, &[], &[], out);
        return if n == 0 {
            H3Dispatch::TooLarge
        } else {
            H3Dispatch::WebSocketAccepted(n)
        };
    }

    // Rendered-template scratch. One `ptime`-style single shot: the whole body
    // must fit, because chunked rendering across steps needs the response
    // cursor to survive between calls — which the streaming path has and this
    // one deliberately does not yet.
    let mut tmpl = [0u8; H3_TEMPLATE_BUF];

    let body: &[u8] = if handler == super::HANDLER_STATIC {
        // The static body lives in the shared pool at a fixed offset — no slot,
        // no cursor, no chunking state.
        let body_start = route.body_offset as usize;
        let body_len = route.body_len as usize;
        core::slice::from_raw_parts((s.server.body_pool as *const u8).add(body_start), body_len)
    } else if handler == super::HANDLER_TEMPLATE {
        // Same renderer h1 and h2 use, with the cursor supplied per STREAM
        // rather than per connection (`render_template_route_into`). Variables
        // resolve out of the same table, so a `{{var}}` reads identically over
        // every generation.
        let mut cursor = 0u32;
        let cap = tmpl_cap.min(tmpl.len());
        let (n, more) = super::body::render_template_route_into(
            s,
            matched,
            &mut cursor,
            tmpl.as_mut_ptr(),
            cap,
        );
        if more {
            // The body did not fit one shot. Refuse rather than send a
            // truncated page that looks like a complete one.
            return H3Dispatch::TooLarge;
        }
        &tmpl[..n]
    } else {
        return H3Dispatch::HandlerNotShared(handler);
    };

    let ctype_len = route.content_type_len as usize;
    let mut ctype_default = [0u8; 10];
    ctype_default.copy_from_slice(b"text/plain");
    let ctype: &[u8] = if ctype_len == 0 {
        &ctype_default[..]
    } else {
        &route.content_type[..ctype_len]
    };

    // Same PIC constraint as the 404 above: keep every pointer in the field
    // array pointing at stack or state memory, never at .rodata.
    let mut status = [0u8; 3];
    status.copy_from_slice(b"200");
    let mut name = [0u8; 12];
    name.copy_from_slice(b"content-type");
    let fields = [(&name[..], ctype)];
    let n = build_response(&status, &fields, body, out);
    if n == 0 {
        H3Dispatch::TooLarge
    } else {
        H3Dispatch::Response(n)
    }
}

// ----------------------------------------------------------------------
// Request-stream ingest
// ----------------------------------------------------------------------

/// What a chunk of request-stream bytes produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3Ingest {
    /// No complete frame yet — the caller buffers and calls again.
    NeedMore,
    /// A complete HEADERS section was decoded into the caller's request.
    Headers,
    /// DATA payload, as a `(start, end)` range within the buffer passed in.
    Data(usize, usize),
    /// Terminal: the stream must be reset with this error.
    Error(H3Error),
}

/// Consume one frame from a request stream.
///
/// Returns the outcome and the number of bytes consumed. Frame legality is
/// RFC 9114 §7.1: a request stream carries DATA, HEADERS and grease types
/// only — a SETTINGS or GOAWAY arriving here is `H3_FRAME_UNEXPECTED`, not
/// something to skip quietly, because it means the peer has confused a
/// request stream with the control stream.
pub fn ingest_request_frame(buf: &[u8], req: &mut H3Request) -> (H3Ingest, usize) {
    let Some((frame, consumed)) = parse_h3_frame(buf) else {
        return (H3Ingest::NeedMore, 0);
    };

    if !is_request_stream_frame(frame.frame_type) {
        return (H3Ingest::Error(H3Error::FrameUnexpected), consumed);
    }

    match frame.frame_type {
        H3_FRAME_HEADERS => match decode_request_headers(frame.payload, req) {
            Ok(_) => (H3Ingest::Headers, consumed),
            Err(e) => (H3Ingest::Error(e), consumed),
        },
        H3_FRAME_DATA => {
            let start = consumed - frame.payload.len();
            (H3Ingest::Data(start, consumed), consumed)
        }
        // A grease frame is legal and carries no meaning: skip it.
        _ => (H3Ingest::NeedMore, consumed),
    }
}

/// Identify whether `frame` is a request-stream-legal frame type
/// (RFC 9114 §7 — only DATA, HEADERS, and reserved-grease types are
/// allowed on request streams).
pub fn is_request_stream_frame(frame_type: u64) -> bool {
    matches!(frame_type, H3_FRAME_DATA | H3_FRAME_HEADERS) ||
        // Reserved frame types per RFC 9114 §7.2.8 (formula: 0x1f * N + 0x21)
        ((frame_type >= 0x21) && (frame_type - 0x21).is_multiple_of(0x1f))
}

/// Identify whether `frame` is a control-stream-legal frame type.
pub fn is_control_stream_frame(frame_type: u64) -> bool {
    matches!(
        frame_type,
        H3_FRAME_SETTINGS
            | super::super::wire::h3::H3_FRAME_GOAWAY
            | super::super::wire::h3::H3_FRAME_MAX_PUSH_ID
            | super::super::wire::h3::H3_FRAME_CANCEL_PUSH
    )
}

/// The remaining unwired pieces: the unidirectional-stream type constants and
/// the `H3State` slot table are used by the pump loop, which is the one part of
/// h3 still absent (it needs the QUIC transport binding). Named here so an
/// unused-item warning does not hide a real one.
#[allow(
    dead_code,
    reason = "consumed by the pump loop, which awaits the QUIC transport binding"
)]
fn _pending_transport_anchor() {
    let _ = H3_UNI_STREAM_CONTROL;
    let _ = H3_UNI_STREAM_QPACK_ENCODER;
    let _ = H3_UNI_STREAM_QPACK_DECODER;
    let _: H3Frame<'_>;
}

// ----------------------------------------------------------------------
// Host-test hooks
// ----------------------------------------------------------------------

/// Decode a QPACK header section and dispatch it against a booted module's
/// routes, in one call.
///
/// The same shape as `server::test_inject_dyn_route`: the harness holds the
/// module state as an opaque buffer, so the hook takes the raw pointer rather
/// than exposing `HttpState`. Compiled only under `host-test`, so the firmware
/// symbol surface is unchanged.
///
/// # Safety
///
/// `state` must point at a `module_state` buffer initialised by `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_decode_and_dispatch(
    state: *mut u8,
    block: &[u8],
    out: &mut [u8],
) -> Result<H3Dispatch, H3Error> {
    let s = &*(state as *const super::super::HttpState);
    let mut req = H3Request::empty();
    decode_request_headers(block, &mut req)?;
    Ok(dispatch_request(s, &req, out))
}

// ----------------------------------------------------------------------
// Stream-multiplexed pump
// ----------------------------------------------------------------------
//
// The transport seam. Everything above is per-frame or per-request; this is
// what a QUIC provider drives, and it is deliberately I/O-free: no syscalls, no
// channels, no clock. A transport module hands it stream-addressed bytes and
// takes stream-addressed bytes back, exactly as `ws_stream` does for WebSocket
// frames, so the protocol logic stays testable without a socket and the
// transport stays free of protocol knowledge.
//
// WHY THIS LIVES IN WAVE. `docs/specification.md` puts QUIC transport, streams
// and packet protection in Fluxor, and HTTP/3 request/response semantics and
// QPACK in Wave. Fluxor's `quic` module currently carries its own h3 dispatcher
// as well — and its own comment records the cost: it "processes only the legacy
// stream id 0 for request-bearing traffic", because its `extra_streams` table
// is 6 slots of 256 bytes, "too small for full HEADERS+DATA flights". A single
// in-flight request is not HTTP/3; multiplexing is the protocol's reason to
// exist. This pump is per-stream from the start.

/// Fluxor's `mux` contract — the multiplexed session surface, consumed
/// verbatim rather than restated. `../fluxor/modules/sdk/contracts/net/mux.rs` names QUIC as its
/// canonical provider and says exactly what this module needs: "a transport
/// exposes many logical streams over one association" and "the app owns the
/// protocol".
///
/// Frames share the `[msg_type u8][len u16 LE][payload]` TLV header with
/// net_proto and the datagram surface, and the mux opcode range (0xB0..0xCF) is
/// disjoint from theirs — which is why h3 needs no new ports: one channel pair
/// carries both contracts unambiguously.
#[path = "../../../../target/fluxor/fluxor-abi/sdk/contracts/net/mux.rs"]
pub mod mux;

/// Header shared by every contract on a net channel.
pub const FRAME_HDR: usize = 3;

/// What feeding a stream produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3StreamOutcome {
    /// Buffered; the request head is not complete yet.
    Buffered,
    /// A request was served: `n` bytes of response are queued on this stream,
    /// drainable with [`pump_next_out`].
    Responded(usize),
    /// The route matched a handler HTTP/3 cannot serve yet
    /// ([`H3Dispatch::HandlerNotShared`]). The stream is reset rather than
    /// answered with a lie about what happened.
    HandlerNotShared(u8),
    /// The rendered response exceeds [`H3_SEND_BUF`]. Reset, never truncated:
    /// half a response is a protocol error the peer attributes to us.
    ResponseTooLarge,
    /// Protocol error — reset the stream with `H3Error::code()`.
    StreamError(H3Error),
    /// No free slot. RFC 9114 §8.1 `H3_EXCESSIVE_LOAD` is the honest answer:
    /// the peer opened more concurrent requests than this device advertises.
    SlotsExhausted,
    /// RFC 9220 extended CONNECT accepted: `n` bytes of 200 are queued and the
    /// stream is now a WebSocket tunnel.
    WebSocketUpgraded(usize),
    /// Tunnel traffic: `n` bytes are queued in answer.
    WebSocketFrame(usize),
    /// The tunnel closed with this RFC 6455 code.
    WebSocketClosed(u16),
    /// More bytes arrived on a stream whose response is already queued. The
    /// peer is pipelining into a half-closed stream; ignored, not fatal.
    Ignored,
}

/// The RFC 9114 §8.1 code for `H3_EXCESSIVE_LOAD`.
pub const H3_EXCESSIVE_LOAD: u64 = 0x0107;

impl H3State {
    /// Find or allocate the slot for one stream.
    ///
    /// Keyed on `(session, stream)`, not on the stream id alone: `mux`
    /// stream ids are per-session, so two connections both have a stream 0 and
    /// keying on the id would cross their requests over.
    fn slot_for(&mut self, session_id: u32, stream_id: u64) -> Option<usize> {
        if let Some(i) = self
            .slots
            .iter()
            .position(|s| s.allocated && s.session_id == session_id && s.stream_id == stream_id)
        {
            return Some(i);
        }
        let free = self.slots.iter().position(|s| !s.allocated)?;
        self.slots[free].release();
        self.slots[free].allocated = true;
        self.slots[free].session_id = session_id;
        self.slots[free].stream_id = stream_id;
        self.slots[free].state = H3StreamState::HeadersRecv;
        Some(free)
    }
}

/// Feed inbound bytes for one QUIC stream and serve the request if it is
/// complete.
///
/// Streams are independent: bytes for stream 4 cannot disturb stream 0, and a
/// request on one is served while another is still arriving. That is what
/// distinguishes this from a single-request dispatcher.
///
/// # Safety
///
/// `s` must be a live `HttpState`, as for [`dispatch_request`].
// `pub(crate)` for the same reason as `dispatch_request`: it takes
// `&HttpState`, which is crate-private. `test_pump_stream_in` is the public
// host-test surface.
pub(crate) unsafe fn pump_stream_in(
    st: &mut H3State,
    s: &super::super::HttpState,
    session_id: u32,
    stream_id: u64,
    data: &[u8],
    _fin: bool,
) -> H3StreamOutcome {
    let Some(idx) = st.slot_for(session_id, stream_id) else {
        return H3StreamOutcome::SlotsExhausted;
    };

    // An upgraded stream is a tunnel, not a request: its bytes are WebSocket
    // frames inside h3 DATA frames, and it is never released on drain.
    if st.slots[idx].ws_active {
        return ws_stream_in(st, idx, data);
    }

    // A response is already queued: the exchange is over as far as we are
    // concerned. Trailers or a pipelined second request on the same stream are
    // not something this module answers, and dropping them is bounded.
    if st.slots[idx].pending_out() > 0 || st.slots[idx].state == H3StreamState::HeadersSent {
        return H3StreamOutcome::Ignored;
    }

    // Accumulate. A head larger than the buffer is refused rather than
    // silently parsed from a prefix.
    {
        let slot = &mut st.slots[idx];
        let room = H3_RECV_BUF - slot.recv_hdr_len;
        if data.len() > room {
            slot.state = H3StreamState::Reset;
            return H3StreamOutcome::StreamError(H3Error::MessageError);
        }
        slot.recv_hdr_buf[slot.recv_hdr_len..slot.recv_hdr_len + data.len()].copy_from_slice(data);
        slot.recv_hdr_len += data.len();
    }

    // Walk complete frames. HEADERS ends the request head for this module's
    // purposes: bodies are not consumed by any handler h3 can serve yet, so a
    // DATA frame is accounted for and dropped rather than buffered unbounded.
    let mut req = H3Request::empty();
    let mut have_request = false;
    let mut consumed_total = 0usize;
    loop {
        let (outcome, consumed) = {
            let slot = &st.slots[idx];
            ingest_request_frame(
                &slot.recv_hdr_buf[consumed_total..slot.recv_hdr_len],
                &mut req,
            )
        };
        match outcome {
            H3Ingest::NeedMore if consumed == 0 => break,
            H3Ingest::NeedMore => {}
            H3Ingest::Headers => have_request = true,
            H3Ingest::Data(_, _) => {}
            H3Ingest::Error(e) => {
                st.slots[idx].state = H3StreamState::Reset;
                return H3StreamOutcome::StreamError(e);
            }
        }
        consumed_total += consumed;
        if consumed_total >= st.slots[idx].recv_hdr_len {
            break;
        }
    }

    if !have_request {
        // Keep the unconsumed tail for the next chunk.
        let slot = &mut st.slots[idx];
        if consumed_total > 0 {
            slot.recv_hdr_buf
                .copy_within(consumed_total..slot.recv_hdr_len, 0);
            slot.recv_hdr_len -= consumed_total;
        }
        return H3StreamOutcome::Buffered;
    }

    // Render into the slot's own send buffer — per stream, so two concurrent
    // requests cannot overwrite each other's response.
    let mut rendered = [0u8; H3_SEND_BUF];
    let outcome = dispatch_request(s, &req, &mut rendered);
    let mut upgraded = false;
    let n = match outcome {
        H3Dispatch::WebSocketAccepted(n) => {
            upgraded = true;
            n
        }
        H3Dispatch::Response(n) | H3Dispatch::NotFound(n) => n,
        H3Dispatch::HandlerNotShared(h) => {
            st.slots[idx].state = H3StreamState::Reset;
            return H3StreamOutcome::HandlerNotShared(h);
        }
        H3Dispatch::TooLarge => {
            st.slots[idx].state = H3StreamState::Reset;
            return H3StreamOutcome::ResponseTooLarge;
        }
    };

    let slot = &mut st.slots[idx];
    slot.send_buf[..n].copy_from_slice(&rendered[..n]);
    slot.send_len = n;
    slot.send_off = 0;
    slot.state = H3StreamState::HeadersSent;
    slot.recv_hdr_len = 0;
    if upgraded {
        slot.ws_active = true;
        slot.ws_buf_len = 0;
        return H3StreamOutcome::WebSocketUpgraded(n);
    }
    H3StreamOutcome::Responded(n)
}

/// Feed bytes to an upgraded WebSocket stream (RFC 9220).
///
/// The frames ride h3 DATA frames, and `wire_ws` neither knows nor cares —
/// which is why the WebSocket layer did not have to be written twice. What IS
/// different from h1/h2 is the lifecycle: this stream stays open, so nothing
/// here releases the slot.
unsafe fn ws_stream_in(st: &mut H3State, idx: usize, data: &[u8]) -> H3StreamOutcome {
    // Accumulate into the (now-idle) request-head buffer.
    {
        let slot = &mut st.slots[idx];
        let room = H3_RECV_BUF - slot.ws_buf_len;
        if data.len() > room {
            // A frame larger than the accumulator can never complete. Close
            // rather than buffer forever.
            return ws_queue_close(st, idx, super::super::wire::ws::CLOSE_MESSAGE_TOO_BIG);
        }
        slot.ws_buf_len += data.len();
        let at = slot.ws_buf_len - data.len();
        slot.recv_hdr_buf[at..at + data.len()].copy_from_slice(data);
    }

    // Walk the h3 DATA frames, then the RFC 6455 frames inside them.
    let mut consumed = 0usize;
    loop {
        let (frame_type, payload_range, total) = {
            let slot = &st.slots[idx];
            let buf = &slot.recv_hdr_buf[consumed..slot.ws_buf_len];
            match parse_h3_frame(buf) {
                Some((f, n)) => {
                    let start = consumed + (n - f.payload.len());
                    (f.frame_type, (start, start + f.payload.len()), n)
                }
                None => break,
            }
        };
        consumed += total;
        if frame_type != H3_FRAME_DATA {
            continue; // grease or a frame with no meaning in a tunnel
        }
        if let Some(err) = ws_drain_payload(st, idx, payload_range) {
            return err;
        }
    }

    // Retain the tail.
    let slot = &mut st.slots[idx];
    if consumed > 0 {
        slot.recv_hdr_buf.copy_within(consumed..slot.ws_buf_len, 0);
        slot.ws_buf_len -= consumed;
    }
    if slot.pending_out() > 0 {
        H3StreamOutcome::WebSocketFrame(slot.pending_out())
    } else {
        H3StreamOutcome::Buffered
    }
}

/// Parse and answer the RFC 6455 frames in one h3 DATA payload.
///
/// Echo semantics, matching what `HANDLER_WEBSOCKET` already means for HTTP/1
/// and HTTP/2 in this module — a route behaves the same way whichever
/// generation reached it, which is the point of sharing the handler id.
unsafe fn ws_drain_payload(
    st: &mut H3State,
    idx: usize,
    range: (usize, usize),
) -> Option<H3StreamOutcome> {
    use super::super::wire::ws;
    let mut pos = range.0;
    while pos < range.1 {
        let avail = range.1 - pos;
        let frame = {
            let slot = &st.slots[idx];
            match ws::parse_frame(slot.recv_hdr_buf.as_ptr().add(pos), avail) {
                Ok(Some(f)) => f,
                Ok(None) => break, // incomplete: wait for more DATA
                Err(()) => return Some(ws_queue_close(st, idx, ws::CLOSE_PROTOCOL_ERROR)),
            }
        };
        let hdr = frame.header_len as usize;
        let plen = frame.payload_len as usize;
        if hdr + plen > avail {
            break;
        }
        // RFC 6455 §5.3 / RFC 8441 §5.1: client-to-server frames are masked.
        if !frame.masked {
            return Some(ws_queue_close(st, idx, ws::CLOSE_PROTOCOL_ERROR));
        }

        let mut payload = [0u8; H3_WS_PAYLOAD_MAX];
        if plen > payload.len() {
            return Some(ws_queue_close(st, idx, ws::CLOSE_MESSAGE_TOO_BIG));
        }
        {
            let slot = &mut st.slots[idx];
            payload[..plen].copy_from_slice(&slot.recv_hdr_buf[pos + hdr..pos + hdr + plen]);
        }
        ws::unmask(payload.as_mut_ptr(), frame.payload_len, &frame.mask_key);

        match frame.opcode {
            ws::OP_CLOSE => {
                return Some(ws_queue_close(st, idx, ws::CLOSE_NORMAL));
            }
            ws::OP_PING => {
                ws_queue_frame(st, idx, ws::OP_PONG, &payload[..plen]);
            }
            ws::OP_PONG => {}
            _ => {
                ws_queue_frame(st, idx, frame.opcode, &payload[..plen]);
            }
        }
        pos += hdr + plen;
    }
    None
}

/// Queue one server-to-client WebSocket frame, wrapped in an h3 DATA frame.
unsafe fn ws_queue_frame(st: &mut H3State, idx: usize, opcode: u8, payload: &[u8]) {
    let mut ws_buf = [0u8; H3_WS_PAYLOAD_MAX + 16];
    let n = super::super::wire::ws::write_frame(
        ws_buf.as_mut_ptr(),
        ws_buf.len(),
        true, // fin — this module never fragments its own frames
        opcode,
        payload.as_ptr(),
        payload.len(),
    );
    if n == 0 {
        return;
    }
    let mut framed = [0u8; H3_WS_PAYLOAD_MAX + 24];
    let hdr = build_h3_frame_header(H3_FRAME_DATA, n, &mut framed);
    if hdr == 0 || hdr + n > framed.len() {
        return;
    }
    framed[hdr..hdr + n].copy_from_slice(&ws_buf[..n]);

    let slot = &mut st.slots[idx];
    let total = hdr + n;
    // Append behind anything still queued: a tunnel's frames are ordered.
    if slot.send_len + total > H3_SEND_BUF {
        return; // drop rather than corrupt the frame sequence
    }
    slot.send_buf[slot.send_len..slot.send_len + total].copy_from_slice(&framed[..total]);
    slot.send_len += total;
}

/// Queue a CLOSE frame and end the tunnel.
unsafe fn ws_queue_close(st: &mut H3State, idx: usize, code: u16) -> H3StreamOutcome {
    let body = code.to_be_bytes();
    ws_queue_frame(st, idx, super::super::wire::ws::OP_CLOSE, &body);
    st.slots[idx].ws_active = false;
    H3StreamOutcome::WebSocketClosed(code)
}

/// Feed one `mux` frame from the transport.
///
/// Handles the three downstream messages QUIC's constrained profile emits for a
/// request stream: `MSG_MUX_STREAM_ACCEPTED` (a peer opened it),
/// `MSG_MUX_STREAM_RX` (bytes), `MSG_MUX_STREAM_CLOSED` (peer FIN). Anything
/// else on the channel — net_proto frames for the h1/h2 path, session events —
/// is not ours and is reported as `Ignored` rather than misparsed.
///
/// # Safety
///
/// `s` must be a live `HttpState`.
pub(crate) unsafe fn pump_mux_frame(
    st: &mut H3State,
    s: &super::super::HttpState,
    msg_type: u8,
    payload: &[u8],
) -> H3StreamOutcome {
    if payload.len() < mux::STREAM_DATA_PREFIX {
        return H3StreamOutcome::Ignored;
    }
    let session = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let stream = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as u64;
    let body = &payload[mux::STREAM_DATA_PREFIX..];

    match msg_type {
        mux::MSG_MUX_STREAM_ACCEPTED => {
            // Reserve the slot now so a later RX cannot be refused while a
            // stream that has already been announced is in flight.
            match st.slot_for(session, stream) {
                Some(_) => H3StreamOutcome::Buffered,
                None => H3StreamOutcome::SlotsExhausted,
            }
        }
        mux::MSG_MUX_STREAM_RX => pump_stream_in(st, s, session, stream, body, false),
        mux::MSG_MUX_STREAM_CLOSED => {
            // The peer is done sending. Any response already queued still
            // drains; a stream with nothing queued is released.
            if let Some(i) = st
                .slots
                .iter()
                .position(|sl| sl.allocated && sl.session_id == session && sl.stream_id == stream)
            {
                if st.slots[i].pending_out() == 0 {
                    st.slots[i].release();
                }
            }
            H3StreamOutcome::Ignored
        }
        _ => H3StreamOutcome::Ignored,
    }
}

/// Drain the next queued response chunk as a `CMD_MUX_STREAM_SEND` frame.
///
/// Round-robins over slots from `emit_cursor` so one stream with a large
/// response cannot starve another — the same fairness `h2.rs` gives its own
/// emission cursor. Returns bytes written into `out`, or `None` when nothing is
/// pending.
///
/// Chunks are capped at `MUX_QUIC_STREAM_SEND_MAX`, which the contract states is
/// the engine's single-MTU stream send buffer: a larger reliable write is
/// rejected outright by the provider, not truncated, so exceeding it would lose
/// the response rather than slow it down.
pub fn pump_next_out(st: &mut H3State, out: &mut [u8]) -> Option<usize> {
    let hdr = FRAME_HDR + mux::STREAM_DATA_PREFIX;
    if out.len() <= hdr {
        return None;
    }
    let max_payload = (out.len() - hdr)
        .min(mux::MUX_QUIC_STREAM_SEND_MAX)
        .min(u16::MAX as usize - mux::STREAM_DATA_PREFIX);

    // A stream whose response has drained still owes its close: RFC 9114 has
    // the response END the stream, and `mux` says so with CMD_MUX_STREAM_CLOSE.
    // Without it the peer waits for more body until its idle timeout.
    for step in 0..MAX_H3_STREAMS {
        let idx = (st.emit_cursor as usize + step) % MAX_H3_STREAMS;
        if st.slots[idx].close_pending && st.slots[idx].pending_out() == 0 {
            let (session, stream) = {
                let slot = &st.slots[idx];
                (slot.session_id, slot.stream_id as u32)
            };
            let plen = mux::STREAM_DATA_PREFIX + 1;
            if out.len() < FRAME_HDR + plen {
                return None;
            }
            out[0] = mux::CMD_MUX_STREAM_CLOSE;
            out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
            out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
            out[FRAME_HDR + 4..FRAME_HDR + 8].copy_from_slice(&stream.to_le_bytes());
            out[FRAME_HDR + 8] = mux::STATUS_OK;
            st.emit_cursor = ((idx + 1) % MAX_H3_STREAMS) as u8;
            st.slots[idx].release();
            return Some(FRAME_HDR + plen);
        }
    }

    for step in 0..MAX_H3_STREAMS {
        let idx = (st.emit_cursor as usize + step) % MAX_H3_STREAMS;
        let pending = st.slots[idx].pending_out();
        if pending == 0 {
            continue;
        }
        let take = pending.min(max_payload);
        let (session, stream) = {
            let slot = &st.slots[idx];
            (slot.session_id, slot.stream_id as u32)
        };
        let last = take == pending;

        let plen = mux::STREAM_DATA_PREFIX + take;
        out[0] = mux::CMD_MUX_STREAM_SEND;
        out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
        out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
        out[FRAME_HDR + 4..hdr].copy_from_slice(&stream.to_le_bytes());
        let start = st.slots[idx].send_off;
        out[hdr..hdr + take].copy_from_slice(&st.slots[idx].send_buf[start..start + take]);

        st.slots[idx].send_off += take;
        st.emit_cursor = ((idx + 1) % MAX_H3_STREAMS) as u8;
        if last && st.slots[idx].ws_active {
            // A tunnel outlives its traffic: rewind the cursor rather than
            // releasing the slot, so the next frame appends to an empty buffer.
            st.slots[idx].send_len = 0;
            st.slots[idx].send_off = 0;
            return Some(hdr + take);
        }
        if last {
            // The whole response is handed over. The stream is NOT released
            // yet: it owes a close, which the next call emits.
            st.slots[idx].close_pending = true;
        }
        return Some(hdr + take);
    }
    None
}

// ----------------------------------------------------------------------
// Stream-multiplexed pump
// ----------------------------------------------------------------------
//
// The transport seam. Everything above is per-frame or per-request; this is
// what a QUIC provider drives, and it is deliberately I/O-free: no syscalls, no
// channels, no clock. A transport module hands it stream-addressed bytes and
// takes stream-addressed bytes back, exactly as `ws_stream` does for WebSocket
// frames, so the protocol logic stays testable without a socket and the
// transport stays free of protocol knowledge.
//
// WHY THIS LIVES IN WAVE. `docs/specification.md` puts QUIC transport, streams
// and packet protection in Fluxor, and HTTP/3 request/response semantics and
// QPACK in Wave. Fluxor's `quic` module currently carries its own h3 dispatcher
// as well — and its own comment records the cost: it "processes only the legacy
// stream id 0 for request-bearing traffic", because its `extra_streams` table
// is 6 slots of 256 bytes, "too small for full HEADERS+DATA flights". A single
// in-flight request is not HTTP/3; multiplexing is the protocol's reason to
// exist. This pump is per-stream from the start.

/// Fluxor's `mux` contract — the multiplexed session surface, consumed
/// verbatim rather than restated. `../fluxor/modules/sdk/contracts/net/mux.rs` names QUIC as its
/// canonical provider and says exactly what this module needs: "a transport
/// exposes many logical streams over one association" and "the app owns the
/// protocol".
///
/// Frames share the `[msg_type u8][len u16 LE][payload]` TLV header with
/// net_proto and the datagram surface, and the mux opcode range (0xB0..0xCF) is
/// disjoint from theirs — which is why h3 needs no new ports: one channel pair
/// carries both contracts unambiguously.
/// `state` must point at a `module_state` buffer initialised by `module_new`.
/// Decode and dispatch with an injected template-scratch bound, for host tests.
///
/// # Safety
///
/// `state` must point at a `module_state` buffer initialised by `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_decode_and_dispatch_bounded(
    state: *mut u8,
    block: &[u8],
    out: &mut [u8],
    tmpl_cap: usize,
) -> Result<H3Dispatch, H3Error> {
    let s = &*(state as *const super::super::HttpState);
    let mut req = H3Request::empty();
    decode_request_headers(block, &mut req)?;
    Ok(dispatch_request_bounded(s, &req, out, tmpl_cap))
}

#[cfg(feature = "host-test")]
/// Drive one connection's h3 state from a `mux` frame, for host tests. Takes
/// the opaque module-state pointer, as `server::test_*` hooks do.
///
/// # Safety
///
/// `state` must point at a `module_state` buffer initialised by `module_new`.
pub unsafe fn test_pump_mux_frame(
    st: &mut H3State,
    state: *mut u8,
    msg_type: u8,
    payload: &[u8],
) -> H3StreamOutcome {
    let s = &*(state as *const super::super::HttpState);
    pump_mux_frame(st, s, msg_type, payload)
}

/// Build a `mux` stream frame the way a transport would, for host tests.
#[cfg(feature = "host-test")]
pub fn test_mux_frame(msg_type: u8, session: u32, stream: u32, data: &[u8]) -> alloc_vec::Vec<u8> {
    let mut v = alloc_vec::Vec::with_capacity(FRAME_HDR + mux::STREAM_DATA_PREFIX + data.len());
    let plen = mux::STREAM_DATA_PREFIX + data.len();
    v.push(msg_type);
    v.extend_from_slice(&(plen as u16).to_le_bytes());
    v.extend_from_slice(&session.to_le_bytes());
    v.extend_from_slice(&stream.to_le_bytes());
    v.extend_from_slice(data);
    v
}

#[cfg(feature = "host-test")]
mod alloc_vec {
    pub use std::vec::Vec;
}

// ----------------------------------------------------------------------
// Module step — the h3 server loop
// ----------------------------------------------------------------------

/// One step of the HTTP/3 server: drain inbound `mux` frames, serve what
/// completes, and hand queued responses back to the transport.
///
/// Wired on the module's ordinary `net_in` / `net_out` ports. HTTP/3 needs no
/// ports of its own because `../fluxor/modules/sdk/contracts/net/mux.rs` reserves an opcode range
/// disjoint from net_proto's — one channel pair carries both contracts, and a
/// frame that is not ours is left alone (`H3StreamOutcome::Ignored`).
///
/// # Safety
///
/// `s` must be a live `HttpState` with its channels resolved.
unsafe fn log_h3(s: &super::super::HttpState, msg: &[u8]) {
    super::super::dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

pub(crate) unsafe fn step_mux(s: &mut super::super::HttpState) -> i32 {
    let sys = &*s.syscalls;
    let in_chan = s.net_in_chan;
    let out_chan = s.net_out_chan;
    if in_chan < 0 || out_chan < 0 {
        return 0;
    }

    // Ingress: drain everything available this step. A bounded loop, because
    // the channel is bounded — this cannot spin.
    loop {
        let poll = (sys.channel_poll)(in_chan, super::super::POLL_IN);
        if poll <= 0 || (poll as u32 & super::super::POLL_IN) == 0 {
            break;
        }
        let buf = s.net_buf.as_mut_ptr();
        let (msg_type, payload_len) =
            super::super::net_read_frame(sys, in_chan, buf, super::super::NET_BUF_SIZE);
        if msg_type == 0 {
            break;
        }
        // Copy the payload out of `net_buf` before touching state: the pump
        // borrows `HttpState` immutably and `net_buf` lives inside it.
        let mut frame = [0u8; H3_RECV_BUF];
        let n = payload_len.min(frame.len());
        core::ptr::copy_nonoverlapping(
            s.net_buf.as_ptr().add(super::super::NET_FRAME_HDR),
            frame.as_mut_ptr(),
            n,
        );

        let st = &mut *(&mut s.h3 as *mut H3State);
        let outcome = pump_mux_frame(st, s, msg_type, &frame[..n]);
        match outcome {
            H3StreamOutcome::StreamError(e) => {
                // The stream is finished as far as we are concerned; the
                // transport tears it down when the peer FINs. The RFC 9114
                // §8.1 code is available for a future RESET_STREAM once the
                // mux contract carries one (it has no reset opcode today).
                let _ = e.code();
                log_h3(s, b"[http] h3 stream error");
            }
            H3StreamOutcome::SlotsExhausted => log_h3(s, b"[http] h3 slots exhausted"),
            H3StreamOutcome::ResponseTooLarge => log_h3(s, b"[http] h3 response too large"),
            H3StreamOutcome::HandlerNotShared(_) => {
                log_h3(s, b"[http] h3 handler not available over h3")
            }
            _ => {}
        }
    }

    // Egress: hand back as much as the channel will take, all-or-nothing per
    // frame (a partial mux frame would desync the transport's reader).
    loop {
        let poll = (sys.channel_poll)(out_chan, super::super::POLL_OUT);
        if poll <= 0 || (poll as u32 & super::super::POLL_OUT) == 0 {
            s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
            break;
        }
        let mut frame = [0u8; FRAME_HDR + mux::STREAM_DATA_PREFIX + mux::MUX_QUIC_STREAM_SEND_MAX];
        let st = &mut *(&mut s.h3 as *mut H3State);
        let Some(n) = pump_next_out(st, &mut frame) else {
            break;
        };
        if (sys.channel_write)(out_chan, frame.as_ptr(), n) <= 0 {
            // The write failed after the poll said ready: the bytes stay
            // queued in the slot only if we have not advanced its cursor —
            // which `pump_next_out` already did. Count it and move on rather
            // than re-emitting a duplicate chunk.
            s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
            break;
        }
        s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add((n - FRAME_HDR) as u32);
    }
    0
}

// ----------------------------------------------------------------------
// Client mode
// ----------------------------------------------------------------------
//
// The other half of owning HTTP/3. `quic` carries an h3 client of its own, but
// it issues a hardcoded `GET /` to `localhost` — a transport self-test, the
// mirror of its hardcoded server table. An application client needs to choose
// its own method, authority and path, and to hand the response body onward,
// which is protocol work and therefore Wave's.
//
// The transport still owns everything below: `CMD_MUX_STREAM_OPEN` asks it for
// a stream, and the id it returns is the only thing this module knows about
// QUIC's stream space.

/// Client state machine for one request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3ClientState {
    /// Nothing asked for yet.
    Idle,
    /// `CMD_MUX_STREAM_OPEN` sent; waiting for the transport's stream id.
    Opening,
    /// Request sent; accumulating the response.
    AwaitingResponse,
    /// `:status` and body complete.
    Complete,
    /// The exchange failed; `status` carries 0.
    Failed,
}

/// One client-side HTTP/3 exchange.
pub struct H3Client {
    pub state: H3ClientState,
    pub session_id: u32,
    pub stream_id: u32,
    /// Decoded `:status`, once the response headers arrive.
    pub status: u16,
    pub recv_buf: [u8; H3_RECV_BUF],
    pub recv_len: usize,
    pub body: [u8; H3_TEMPLATE_BUF],
    pub body_len: usize,
    /// The response body has been handed to the app port.
    pub body_emitted: bool,
}

impl H3Client {
    pub const fn new() -> Self {
        Self {
            state: H3ClientState::Idle,
            session_id: 0,
            stream_id: 0,
            status: 0,
            recv_buf: [0; H3_RECV_BUF],
            recv_len: 0,
            body: [0; H3_TEMPLATE_BUF],
            body_len: 0,
            body_emitted: false,
        }
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body[..self.body_len]
    }
}

/// Encode a client request field section: block prefix then the pseudo-headers
/// RFC 9114 §4.3.1 requires of a request.
///
/// Returns bytes written, or 0 if it does not fit whole — a partial field
/// section decodes as a different request, so there is no partial success.
pub fn encode_request_headers(
    method: &[u8],
    scheme: &[u8],
    authority: &[u8],
    path: &[u8],
    out: &mut [u8],
) -> usize {
    let mut off = qpack::qpack_emit_block_prefix(out);
    if off == 0 {
        return 0;
    }
    // Names copied into stack buffers, never a const array of fat pointers:
    // that lands in .rodata with pointers the PIC loader does not relocate.
    let mut n_method = [0u8; 7];
    n_method.copy_from_slice(b":method");
    let mut n_scheme = [0u8; 7];
    n_scheme.copy_from_slice(b":scheme");
    let mut n_auth = [0u8; 10];
    n_auth.copy_from_slice(b":authority");
    let mut n_path = [0u8; 5];
    n_path.copy_from_slice(b":path");

    for (name, value) in [
        (&n_method[..], method),
        (&n_scheme[..], scheme),
        (&n_auth[..], authority),
        (&n_path[..], path),
    ] {
        let n = qpack::qpack_encode_field(name, value, &mut out[off..]);
        if n == 0 {
            return 0;
        }
        off += n;
    }
    off
}

/// Build a complete request: a HEADERS frame carrying the field section.
pub fn build_request(
    method: &[u8],
    scheme: &[u8],
    authority: &[u8],
    path: &[u8],
    out: &mut [u8],
) -> usize {
    let mut block = [0u8; 512];
    let block_len = encode_request_headers(method, scheme, authority, path, &mut block);
    if block_len == 0 {
        return 0;
    }
    let mut scratch = [0u8; 16];
    let hdr = build_h3_frame_header(H3_FRAME_HEADERS, block_len, &mut scratch);
    if hdr == 0 || out.len() < hdr + block_len {
        return 0;
    }
    out[..hdr].copy_from_slice(&scratch[..hdr]);
    out[hdr..hdr + block_len].copy_from_slice(&block[..block_len]);
    hdr + block_len
}

/// Decode a response field section far enough to learn `:status`.
///
/// Returns the status, or None if the section did not decode or carried no
/// `:status` — which RFC 9114 §4.3.2 requires of every response.
pub fn decode_response_status(block: &[u8]) -> Option<u16> {
    let mut off = qpack::qpack_decode_block_prefix(block)?;
    let mut scratch = [0u8; H3_FIELD_SCRATCH];
    while off < block.len() {
        let r = qpack::qpack_decode_field_into(&block[off..], &mut scratch)?;
        if r.consumed == 0 {
            return None;
        }
        let name = &scratch[r.name.0..r.name.1];
        if name == b":status" {
            let value = &scratch[r.value.0..r.value.1];
            let mut code: u16 = 0;
            for b in value {
                if !b.is_ascii_digit() {
                    return None;
                }
                code = code.checked_mul(10)?.checked_add((b - b'0') as u16)?;
            }
            return Some(code);
        }
        off += r.consumed;
    }
    None
}

/// Feed one `mux` frame to the client.
pub fn client_mux_frame(c: &mut H3Client, msg_type: u8, payload: &[u8]) -> H3ClientState {
    if payload.len() < mux::SESSION_ID_BYTES {
        return c.state;
    }
    match msg_type {
        mux::MSG_MUX_STREAM_OPENED => {
            if payload.len() < mux::STREAM_DATA_PREFIX + 1 {
                return c.state;
            }
            let status = payload[mux::STREAM_DATA_PREFIX];
            if status != mux::STATUS_OK {
                c.state = H3ClientState::Failed;
                return c.state;
            }
            c.session_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            c.stream_id = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            c.state = H3ClientState::AwaitingResponse;
        }
        mux::MSG_MUX_STREAM_RX => {
            if payload.len() < mux::STREAM_DATA_PREFIX {
                return c.state;
            }
            let body = &payload[mux::STREAM_DATA_PREFIX..];
            let room = H3_RECV_BUF - c.recv_len;
            if body.len() > room {
                c.state = H3ClientState::Failed;
                return c.state;
            }
            c.recv_buf[c.recv_len..c.recv_len + body.len()].copy_from_slice(body);
            c.recv_len += body.len();
            client_drain(c);
        }
        mux::MSG_MUX_STREAM_CLOSED => {
            if c.state == H3ClientState::AwaitingResponse {
                // The peer finished. A response without a `:status` never
                // arrived, and reporting Complete would invent one.
                c.state = if c.status > 0 {
                    H3ClientState::Complete
                } else {
                    H3ClientState::Failed
                };
            }
        }
        _ => {}
    }
    c.state
}

/// Walk complete h3 frames out of the client's accumulator.
fn client_drain(c: &mut H3Client) {
    let mut consumed = 0usize;
    loop {
        let (kind, range, total) = {
            let buf = &c.recv_buf[consumed..c.recv_len];
            match parse_h3_frame(buf) {
                Some((f, n)) => {
                    let start = consumed + (n - f.payload.len());
                    (f.frame_type, (start, start + f.payload.len()), n)
                }
                None => break,
            }
        };
        if kind == H3_FRAME_HEADERS {
            match decode_response_status(&c.recv_buf[range.0..range.1]) {
                Some(code) => c.status = code,
                None => {
                    c.state = H3ClientState::Failed;
                    return;
                }
            }
        } else if kind == H3_FRAME_DATA {
            let n = (range.1 - range.0).min(H3_TEMPLATE_BUF - c.body_len);
            let (a, b) = (range.0, range.0 + n);
            c.body.copy_within(0..0, 0); // no-op, keeps the borrow shape obvious
            let mut tmp = [0u8; H3_TEMPLATE_BUF];
            tmp[..n].copy_from_slice(&c.recv_buf[a..b]);
            c.body[c.body_len..c.body_len + n].copy_from_slice(&tmp[..n]);
            c.body_len += n;
        }
        consumed += total;
        if consumed >= c.recv_len {
            break;
        }
    }
    if consumed > 0 {
        c.recv_buf.copy_within(consumed..c.recv_len, 0);
        c.recv_len -= consumed;
    }
}

/// One step of the HTTP/3 client: ask for a stream, send the request, collect
/// the response, hand the body to the app.
///
/// # Safety
///
/// `s` must be a live `HttpState` with its channels resolved.
pub(crate) unsafe fn step_mux_client(s: &mut super::super::HttpState) -> i32 {
    let sys = &*s.syscalls;
    let (in_chan, out_chan) = (s.net_in_chan, s.net_out_chan);
    if in_chan < 0 || out_chan < 0 {
        return 0;
    }

    // Ask the transport for a stream, once. It answers MSG_MUX_STREAM_OPENED
    // with the id — the only thing this module ever learns about QUIC's stream
    // space.
    if s.h3_client.state == H3ClientState::Idle {
        let plen = mux::SESSION_ID_BYTES + 1;
        let mut frame = [0u8; FRAME_HDR + mux::SESSION_ID_BYTES + 1];
        frame[0] = mux::CMD_MUX_STREAM_OPEN;
        frame[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
        frame[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&0u32.to_le_bytes());
        frame[FRAME_HDR + 4] = mux::STREAM_FLAG_BIDI;
        let poll = (sys.channel_poll)(out_chan, super::super::POLL_OUT);
        if poll > 0
            && (poll as u32) & super::super::POLL_OUT != 0
            && (sys.channel_write)(out_chan, frame.as_ptr(), frame.len()) > 0
        {
            s.h3_client.state = H3ClientState::Opening;
        }
        return 0;
    }

    // Drain inbound mux frames.
    loop {
        let poll = (sys.channel_poll)(in_chan, super::super::POLL_IN);
        if poll <= 0 || (poll as u32) & super::super::POLL_IN == 0 {
            break;
        }
        let buf = s.net_buf.as_mut_ptr();
        let (msg_type, plen) =
            super::super::net_read_frame(sys, in_chan, buf, super::super::NET_BUF_SIZE);
        if msg_type == 0 {
            break;
        }
        let mut frame = [0u8; H3_RECV_BUF];
        let n = plen.min(frame.len());
        core::ptr::copy_nonoverlapping(
            s.net_buf.as_ptr().add(super::super::NET_FRAME_HDR),
            frame.as_mut_ptr(),
            n,
        );
        let was = s.h3_client.state;
        let now = client_mux_frame(&mut s.h3_client, msg_type, &frame[..n]);

        // The stream has just been granted: send the request on it.
        if was == H3ClientState::Opening && now == H3ClientState::AwaitingResponse {
            client_send_request(s);
        }
    }

    // Hand the body onward, once, the way the h1 client does (out[1]).
    if s.h3_client.state == H3ClientState::Complete && !s.h3_client.body_emitted {
        {
            // One line per exchange, so a graph without out[1] wired still
            // shows whether the request completed and with what.
            let mut lb = [0u8; 64];
            let pre = b"[http] h3 client status=";
            let mut p = 0usize;
            for &c in pre {
                lb[p] = c;
                p += 1;
            }
            let st = s.h3_client.status;
            lb[p] = b'0' + ((st / 100) % 10) as u8;
            lb[p + 1] = b'0' + ((st / 10) % 10) as u8;
            lb[p + 2] = b'0' + (st % 10) as u8;
            p += 3;
            let tail = b" body=";
            for &c in tail {
                lb[p] = c;
                p += 1;
            }
            let n = s.h3_client.body_len.min(999);
            lb[p] = b'0' + ((n / 100) % 10) as u8;
            lb[p + 1] = b'0' + ((n / 10) % 10) as u8;
            lb[p + 2] = b'0' + (n % 10) as u8;
            p += 3;
            super::super::dev_log(sys, 3, lb.as_ptr(), p);
        }
        let chan = s.client.out_chan;
        if chan >= 0 && s.h3_client.body_len > 0 {
            let poll = (sys.channel_poll)(chan, super::super::POLL_OUT);
            if poll > 0 && (poll as u32) & super::super::POLL_OUT != 0 {
                let mut body = [0u8; H3_TEMPLATE_BUF];
                let n = s.h3_client.body_len;
                body[..n].copy_from_slice(&s.h3_client.body[..n]);
                if (sys.channel_write)(chan, body.as_ptr(), n) > 0 {
                    s.h3_client.body_emitted = true;
                }
            }
        } else {
            s.h3_client.body_emitted = true;
        }
    }
    0
}

/// Build and send the configured request, then FIN the stream — a GET carries
/// no body, so the request is complete the moment its headers are sent.
unsafe fn client_send_request(s: &mut super::super::HttpState) {
    let sys = &*s.syscalls;
    let out_chan = s.net_out_chan;

    let plen = s.client.path_len as usize;
    let mut path = [0u8; 128];
    let plen = plen.min(path.len());
    path[..plen].copy_from_slice(&s.client.path[..plen]);
    let path: &[u8] = if plen == 0 { b"/" } else { &path[..plen] };

    // `:authority` is not configurable yet. Virtual hosting needs it to be, and
    // that is a parameter away — but inventing one here would be a surface
    // nobody asked for.
    let mut authority = [0u8; 9];
    authority.copy_from_slice(b"localhost");
    let mut method = [0u8; 3];
    method.copy_from_slice(b"GET");
    let mut scheme = [0u8; 5];
    scheme.copy_from_slice(b"https");

    let mut req = [0u8; 512];
    let n = build_request(&method, &scheme, &authority, path, &mut req);
    if n == 0 {
        s.h3_client.state = H3ClientState::Failed;
        return;
    }

    let (session, stream) = (s.h3_client.session_id, s.h3_client.stream_id);
    let body_len = mux::STREAM_DATA_PREFIX + n;
    let mut frame = [0u8; FRAME_HDR + mux::STREAM_DATA_PREFIX + 512];
    frame[0] = mux::CMD_MUX_STREAM_SEND;
    frame[1..3].copy_from_slice(&(body_len as u16).to_le_bytes());
    frame[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
    frame[FRAME_HDR + 4..FRAME_HDR + 8].copy_from_slice(&stream.to_le_bytes());
    frame[FRAME_HDR + mux::STREAM_DATA_PREFIX..FRAME_HDR + mux::STREAM_DATA_PREFIX + n]
        .copy_from_slice(&req[..n]);
    let total = FRAME_HDR + body_len;
    if (sys.channel_write)(out_chan, frame.as_ptr(), total) <= 0 {
        s.h3_client.state = H3ClientState::Failed;
        return;
    }

    // FIN the request half: a server waits for it before responding.
    let cplen = mux::STREAM_DATA_PREFIX + 1;
    let mut close = [0u8; FRAME_HDR + mux::STREAM_DATA_PREFIX + 1];
    close[0] = mux::CMD_MUX_STREAM_CLOSE;
    close[1..3].copy_from_slice(&(cplen as u16).to_le_bytes());
    close[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
    close[FRAME_HDR + 4..FRAME_HDR + 8].copy_from_slice(&stream.to_le_bytes());
    close[FRAME_HDR + 8] = mux::STATUS_OK;
    let _ = (sys.channel_write)(out_chan, close.as_ptr(), close.len());
}
