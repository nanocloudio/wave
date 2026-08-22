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
//! [`dispatch_request`] answers those with a **501** — the route exists and is
//! understood, this generation cannot fulfil it (RFC 9110 §15.6.2) — rather
//! than serving one concurrent request correctly and the rest wrongly. The
//! handler id rides along so `http.h3.handler_unavailable` and the log can name
//! which one, since a 501 only the client sees is a misconfiguration nobody
//! operating the server can find.
//!
//! For the file handler in particular, "sharing" would not even be an
//! improvement: `render_file_into` pulls from ONE module-scoped `file_chan`, so
//! every stream on the connection would serialise behind one file. Per-stream
//! file channels are a storage-contract change, not an h3 one.
//!
//! # WebSocket over HTTP/3 (RFC 9220)
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
    build_h3_frame_header, build_h3_settings_payload, parse_h3_frame, H3Frame,
    H3_FRAME_CANCEL_PUSH, H3_FRAME_DATA, H3_FRAME_GOAWAY, H3_FRAME_HEADERS, H3_FRAME_MAX_PUSH_ID,
    H3_FRAME_PRIORITY_UPDATE_PUSH, H3_FRAME_PRIORITY_UPDATE_REQUEST, H3_FRAME_SETTINGS,
    H3_SETTING_ENABLE_CONNECT_PROTOCOL, H3_SETTING_MAX_FIELD_SECTION_SIZE,
    H3_SETTING_QPACK_BLOCKED_STREAMS, H3_SETTING_QPACK_MAX_TABLE_CAPACITY, H3_UNI_STREAM_CONTROL,
    H3_UNI_STREAM_PUSH, H3_UNI_STREAM_QPACK_DECODER, H3_UNI_STREAM_QPACK_ENCODER,
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
///
/// This is a PROTOCOL budget — how much request head this server will hold —
/// and it is unrelated to how much the transport may hand over in one frame.
/// Sizing a wire scratch from it is what silently truncated `MSG_MUX_STREAM_RX`;
/// the assertion below the ingress copy keeps the two apart.
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
    /// The transport's OPAQUE handle for this stream, which is what every
    /// mux command addresses it by.
    pub stream_id: u64,
    /// The transport's own 62-bit QUIC stream identity, reported
    /// alongside the handle when the stream was accepted.
    ///
    /// Kept because HTTP/3 names streams by it on the wire — GOAWAY
    /// (§5.2) and PRIORITY_UPDATE (RFC 9218 §7.2) both carry a request
    /// stream id — and it is NOT derivable from the handle. Doing
    /// arithmetic on the handle to guess it would couple this module to
    /// the transport's slot allocator.
    pub quic_stream_id: u64,
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
    /// A RESET_STREAM is owed on this stream, carrying this RFC 9114 §8.1
    /// code. Zero means none.
    ///
    /// Without it a request that broke a protocol rule simply went quiet,
    /// which the peer cannot distinguish from a slow server: it waits out
    /// its own timeout and reports a hang instead of the rule it broke.
    pub reset_code: u64,
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
            quic_stream_id: 0,
            reset_code: 0,
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
        self.quic_stream_id = 0;
        self.reset_code = 0;
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
    /// One entry per QUIC connection the transport is carrying.
    ///
    /// Connection-scoped HTTP/3 state lives here rather than beside the
    /// slot table, because it is not one connection's worth of state: two
    /// sessions advertise their own SETTINGS, run their own control and
    /// QPACK streams, and drain independently. Holding any of it
    /// module-globally lets one connection's limits govern how another
    /// connection's responses are encoded.
    pub sessions: [H3Session; MAX_H3_SESSIONS],
    /// Round-robin cursor for session-scoped emission (preamble opens,
    /// control-stream writes, connection closes), so one session's
    /// preamble cannot hold up another's.
    pub sess_cursor: u8,
    /// The module has been asked to shut down gracefully.
    ///
    /// Mirrored here from the server state so admission and emission stay
    /// I/O-free: a pump that had to reach for the module state to know
    /// whether it may admit a stream could not be driven without one.
    pub draining: bool,
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
            sessions: [H3Session::empty(), H3Session::empty()],
            sess_cursor: 0,
            draining: false,
        }
    }
}

// ----------------------------------------------------------------------
// Per-session HTTP/3 connection state (RFC 9114 §6, §7.2)
// ----------------------------------------------------------------------
//
// This is HTTP/3, so it is here. The transport underneath is a QUIC engine
// that knows nothing about HTTP/3: it delivers sessions, streams and bytes,
// and the meaning of those bytes is this module's.
//
// The state is PER SESSION rather than per module. Two QUIC connections
// can both carry a stream the transport numbered the same way and can
// advertise different SETTINGS; a module-global `peer_max_field_section`
// would let one connection's limits govern how another connection's
// responses are encoded.

/// Concurrent HTTP/3 sessions. Matches the QUIC engine's connection pool,
/// so a session the transport can carry always has somewhere to live.
pub const MAX_H3_SESSIONS: usize = 2;

/// Peer-initiated unidirectional streams tracked per session: control,
/// QPACK encoder, QPACK decoder, plus one spare for a push or greased
/// stream the peer opens.
pub const MAX_PEER_UNI: usize = 4;

/// Accumulator for a peer unidirectional stream. Small on purpose — a
/// control stream carries SETTINGS, GOAWAY and priority frames, none of
/// which are large, and a peer that sends more than this on one is not
/// speaking HTTP/3.
pub const H3_UNI_BUF: usize = 256;

/// Longest QUIC varint, so a stream-type prefix split across mux records
/// can always be reassembled.
pub const H3_VARINT_MAX: usize = 8;

/// SETTINGS this module advertises. Its own policy, built here — the
/// transport does not know these exist.
///
/// `QPACK_MAX_TABLE_CAPACITY = 0` and `QPACK_BLOCKED_STREAMS = 0` say the
/// encoder never references a dynamic table, which is true: it emits
/// static and literal fields only. Advertising a capacity it does not use
/// would invite the peer to send encoder instructions this module would
/// then have to reject.
pub const LOCAL_MAX_FIELD_SECTION: u64 = 16384;

/// What a peer unidirectional stream turned out to be, once its leading
/// varint is complete.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UniRole {
    /// Prefix not yet complete — the varint is still arriving.
    Pending,
    Control,
    Push,
    QpackEncoder,
    QpackDecoder,
    /// A type this module does not implement. RFC 9114 §6.2 requires
    /// these to be IGNORED, not refused: the reserved stream types exist
    /// precisely to catch an implementation that refuses them.
    Unknown,
}

#[derive(Clone, Copy)]
pub struct PeerUni {
    pub allocated: bool,
    /// The transport's opaque handle for this stream.
    pub handle: u32,
    pub role: UniRole,
    /// Partial stream-type varint, held across mux records. A prefix can
    /// be split — a transport is free to deliver one byte at a time —
    /// and consuming an incomplete varint would classify the stream from
    /// half a number.
    pub prefix: [u8; H3_VARINT_MAX],
    pub prefix_len: usize,
    /// Frame accumulator for a control stream.
    pub buf: [u8; H3_UNI_BUF],
    pub buf_len: usize,
}

impl PeerUni {
    pub const fn empty() -> Self {
        Self {
            allocated: false,
            handle: 0,
            role: UniRole::Pending,
            prefix: [0; H3_VARINT_MAX],
            prefix_len: 0,
            buf: [0; H3_UNI_BUF],
            buf_len: 0,
        }
    }
}

/// One of the three unidirectional streams this endpoint opens as its
/// connection preamble.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LocalUniState {
    /// Nothing asked for yet.
    Idle,
    /// A `CMD_MUX_STREAM_OPEN` is outstanding; the transport owes us a
    /// handle.
    Opening,
    /// We have a handle; the type prefix (and, on control, SETTINGS) is
    /// still to be written.
    Open,
    /// Prefix and any preamble frame have been handed to the transport.
    Ready,
    /// The transport refused the open. Recorded rather than retried
    /// forever: the pool is fixed, and a session that cannot get its
    /// critical streams is a session that cannot serve.
    Refused,
}

#[derive(Clone, Copy)]
pub struct LocalUni {
    pub state: LocalUniState,
    pub handle: u32,
    pub stream_type: u64,
}

impl LocalUni {
    pub const fn new(stream_type: u64) -> Self {
        Self {
            state: LocalUniState::Idle,
            handle: 0,
            stream_type,
        }
    }
}

pub struct H3Session {
    pub allocated: bool,
    pub session_id: u32,
    /// The session negotiated this module's HTTP/3 ALPN token.
    ///
    /// Decided HERE, from the opaque bytes the transport reported. The
    /// transport performs the negotiation and does not know what the
    /// result means; choosing HTTP/3 because of it is this module's call.
    pub is_h3: bool,

    // ── local connection preamble (RFC 9114 §6.2.1, RFC 9204 §4.2) ──
    pub ctrl: LocalUni,
    pub qpack_enc: LocalUni,
    pub qpack_dec: LocalUni,
    /// Our SETTINGS frame has been queued onto the control stream.
    pub settings_sent: bool,

    // ── peer state ────────────────────────────────────────────────
    pub peer_uni: [PeerUni; MAX_PEER_UNI],
    /// A peer control stream has been seen. A second one is
    /// H3_STREAM_CREATION_ERROR (RFC 9114 §6.2.1).
    pub peer_control_seen: bool,
    pub peer_qpack_enc_seen: bool,
    pub peer_qpack_dec_seen: bool,
    /// The peer's SETTINGS has arrived and validated. Until it has, a
    /// response cannot be encoded under the peer's limits, because they
    /// are not known — see `responses_gated`.
    pub peer_settings_seen: bool,
    /// `u32::MAX` = no limit advertised (the identifier's default is
    /// unlimited). Distinct from an advertised `0`, which forbids header
    /// sections outright — hence the sentinel rather than treating 0 as
    /// "unset", which would silently ignore that instruction.
    pub peer_max_field_section: u32,
    /// The peer advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`
    /// (RFC 9220 §3). Per session: two connections may differ.
    pub peer_enable_connect: bool,
    /// The peer sent GOAWAY; it is draining and will not accept new
    /// requests beyond `goaway_id`.
    pub peer_goaway: bool,
    pub peer_goaway_id: u64,

    /// A connection error is owed to the peer. Non-zero code, emitted as
    /// a `CMD_MUX_SESSION_CLOSE` carrying it.
    pub conn_error: u64,
    pub conn_error_pending: bool,

    /// The first request stream this endpoint will NOT process, as GOAWAY
    /// (RFC 9114 §5.2) names it. Raised past every request stream admitted,
    /// so the boundary a later GOAWAY announces covers everything already
    /// accepted and cannot take an accepted request back.
    pub goaway_id: u64,
    /// GOAWAY has been handed to the transport. The session close follows
    /// once it has: closing first would leave the peer unable to tell a
    /// graceful shutdown from a connection that simply died, which is the
    /// difference between a client that re-issues its requests elsewhere
    /// and one that reports them failed.
    pub goaway_sent: bool,
}

impl H3Session {
    pub const fn empty() -> Self {
        Self {
            allocated: false,
            session_id: 0,
            is_h3: false,
            ctrl: LocalUni::new(H3_UNI_STREAM_CONTROL),
            qpack_enc: LocalUni::new(H3_UNI_STREAM_QPACK_ENCODER),
            qpack_dec: LocalUni::new(H3_UNI_STREAM_QPACK_DECODER),
            settings_sent: false,
            peer_uni: [PeerUni::empty(); MAX_PEER_UNI],
            peer_control_seen: false,
            peer_qpack_enc_seen: false,
            peer_qpack_dec_seen: false,
            peer_settings_seen: false,
            peer_max_field_section: u32::MAX,
            peer_enable_connect: false,
            peer_goaway: false,
            peer_goaway_id: 0,
            conn_error: 0,
            conn_error_pending: false,
            goaway_id: 0,
            goaway_sent: false,
        }
    }

    /// Whether a response may be ENCODED yet.
    ///
    /// Request bytes are accepted before the peer's SETTINGS — cross-stream
    /// arrival order is not an assurance that the control stream is
    /// delivered first, and refusing a request that merely arrived early
    /// would be this module inventing an ordering rule QUIC does not
    /// provide. What must wait is the RESPONSE: encoding one under guessed
    /// limits risks a header section the peer rejects, and it answers with
    /// a frame-size error that names a frame rather than the setting that
    /// refused it.
    pub fn responses_gated(&self) -> bool {
        self.is_h3 && !self.peer_settings_seen
    }

    /// Raise a connection error once. The first cause is the one that
    /// gets reported: later errors are usually consequences of it, and
    /// overwriting would name the symptom instead of the fault.
    pub fn fail(&mut self, code: u64) {
        if !self.conn_error_pending {
            self.conn_error = code;
            self.conn_error_pending = true;
        }
    }

    pub fn release(&mut self) {
        *self = Self::empty();
    }
}

/// Find or allocate the per-session entry for `session_id`.
pub fn session_slot(st: &mut H3State, session_id: u32) -> Option<usize> {
    let mut i = 0;
    while i < MAX_H3_SESSIONS {
        if st.sessions[i].allocated && st.sessions[i].session_id == session_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn session_alloc(st: &mut H3State, session_id: u32) -> Option<usize> {
    if let Some(i) = session_slot(st, session_id) {
        return Some(i);
    }
    let mut i = 0;
    while i < MAX_H3_SESSIONS {
        if !st.sessions[i].allocated {
            st.sessions[i] = H3Session::empty();
            st.sessions[i].allocated = true;
            st.sessions[i].session_id = session_id;
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Locate a peer unidirectional stream by its transport handle.
pub(crate) fn peer_uni_slot(sess: &H3Session, handle: u32) -> Option<usize> {
    let mut i = 0;
    while i < MAX_PEER_UNI {
        if sess.peer_uni[i].allocated && sess.peer_uni[i].handle == handle {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub(crate) fn peer_uni_alloc(sess: &mut H3Session, handle: u32) -> Option<usize> {
    if let Some(i) = peer_uni_slot(sess, handle) {
        return Some(i);
    }
    let mut i = 0;
    while i < MAX_PEER_UNI {
        if !sess.peer_uni[i].allocated {
            sess.peer_uni[i] = PeerUni::empty();
            sess.peer_uni[i].allocated = true;
            sess.peer_uni[i].handle = handle;
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Classify a peer unidirectional stream from its leading varint, then
/// feed the remainder to whatever that varint said it was.
///
/// The prefix is accumulated rather than assumed complete: a transport
/// may deliver it one byte at a time, and a partial varint decoded as if
/// whole names the wrong stream type. Bytes after the prefix are NOT
/// consumed by the classification — they belong to the stream.
pub(crate) fn uni_ingest(sess: &mut H3Session, slot: usize, data: &[u8]) -> Option<u64> {
    let mut rest = data;
    if sess.peer_uni[slot].role == UniRole::Pending {
        // Accumulate until a varint decodes.
        let u = &mut sess.peer_uni[slot];
        let take = rest.len().min(H3_VARINT_MAX - u.prefix_len);
        u.prefix[u.prefix_len..u.prefix_len + take].copy_from_slice(&rest[..take]);
        u.prefix_len += take;
        // Without a whole varint there is nothing to classify yet; the `take`
        // bytes stay held in `prefix`, so waiting loses nothing.
        let (stype, used) = classify_uni_stream_prefix(&u.prefix[..u.prefix_len])?;
        // The classification consumed `used` bytes of what we buffered;
        // the rest of THIS record follows the prefix.
        let consumed_from_rest = used.saturating_sub(u.prefix_len - take);
        u.role = match stype {
            H3_UNI_STREAM_CONTROL => UniRole::Control,
            H3_UNI_STREAM_PUSH => UniRole::Push,
            H3_UNI_STREAM_QPACK_ENCODER => UniRole::QpackEncoder,
            H3_UNI_STREAM_QPACK_DECODER => UniRole::QpackDecoder,
            _ => UniRole::Unknown,
        };
        rest = &rest[consumed_from_rest.min(rest.len())..];

        // RFC 9114 §6.2.1 / RFC 9204 §4.2: exactly one of each critical
        // stream per connection. A duplicate is a connection error, not a
        // stream one — the peer's state machine has diverged from ours and
        // nothing further on the connection can be trusted.
        match sess.peer_uni[slot].role {
            UniRole::Control => {
                if sess.peer_control_seen {
                    return Some(H3_STREAM_CREATION_ERROR);
                }
                sess.peer_control_seen = true;
            }
            UniRole::QpackEncoder => {
                if sess.peer_qpack_enc_seen {
                    return Some(H3_STREAM_CREATION_ERROR);
                }
                sess.peer_qpack_enc_seen = true;
            }
            UniRole::QpackDecoder => {
                if sess.peer_qpack_dec_seen {
                    return Some(H3_STREAM_CREATION_ERROR);
                }
                sess.peer_qpack_dec_seen = true;
            }
            UniRole::Push => {
                // A server never receives push streams (RFC 9114 §4.6);
                // a client sending one has the roles inverted.
                return Some(H3_STREAM_CREATION_ERROR);
            }
            _ => {}
        }
    }

    match sess.peer_uni[slot].role {
        UniRole::Control => uni_control_ingest(sess, slot, rest),
        UniRole::QpackEncoder => qpack_instruction_ingest(rest, true),
        UniRole::QpackDecoder => qpack_instruction_ingest(rest, false),
        // RFC 9114 §6.2: unknown stream types are ignored. The bytes are
        // dropped here rather than buffered — there is nothing that will
        // ever read them, and holding them would be a slow leak on a
        // connection a peer greases aggressively.
        UniRole::Unknown => None,
        UniRole::Push | UniRole::Pending => None,
    }
}

/// Accumulate control-stream bytes and process whole frames.
fn uni_control_ingest(sess: &mut H3Session, slot: usize, data: &[u8]) -> Option<u64> {
    {
        let u = &mut sess.peer_uni[slot];
        let space = H3_UNI_BUF - u.buf_len;
        if data.len() > space {
            // A control stream carrying more than this in one flight is
            // not a control stream we can make sense of. Refusing beats
            // silently dropping the tail, which would desynchronise the
            // frame parse and surface later as an unexplained error.
            return Some(H3_EXCESSIVE_LOAD);
        }
        u.buf[u.buf_len..u.buf_len + data.len()].copy_from_slice(data);
        u.buf_len += data.len();
    }
    loop {
        let (ftype, payload_off, payload_len, consumed) = {
            let u = &sess.peer_uni[slot];
            if u.buf_len == 0 {
                return None;
            }
            match parse_h3_frame(&u.buf[..u.buf_len]) {
                Some((f, n)) => {
                    let off = n - f.payload.len();
                    (f.frame_type, off, f.payload.len(), n)
                }
                // Partial frame — wait for the rest.
                None => return None,
            }
        };
        let mut payload = [0u8; H3_UNI_BUF];
        payload[..payload_len]
            .copy_from_slice(&sess.peer_uni[slot].buf[payload_off..payload_off + payload_len]);

        if let Some(code) = control_frame(sess, ftype, &payload[..payload_len]) {
            return Some(code);
        }

        let u = &mut sess.peer_uni[slot];
        let rest = u.buf_len - consumed;
        if rest > 0 {
            u.buf.copy_within(consumed..u.buf_len, 0);
        }
        u.buf_len = rest;
    }
}

/// Apply one control-stream frame. Returns a connection error code when
/// the frame breaks a rule the connection cannot continue past.
fn control_frame(sess: &mut H3Session, ftype: u64, payload: &[u8]) -> Option<u64> {
    // RFC 9114 §6.2.1: SETTINGS MUST be the first frame on the control
    // stream. A peer that starts with anything else has not established
    // the parameters every later frame is interpreted under.
    if !sess.peer_settings_seen && ftype != H3_FRAME_SETTINGS {
        return Some(H3_MISSING_SETTINGS);
    }
    match ftype {
        H3_FRAME_SETTINGS => {
            if sess.peer_settings_seen {
                // §7.2.4: exactly one SETTINGS per control stream.
                return Some(H3_FRAME_UNEXPECTED);
            }
            match parse_peer_settings(payload) {
                Some(s) => {
                    sess.peer_max_field_section = s.max_field_section_size;
                    sess.peer_enable_connect = s.enable_connect_protocol;
                    sess.peer_settings_seen = true;
                    None
                }
                None => Some(H3_SETTINGS_ERROR),
            }
        }
        H3_FRAME_GOAWAY => {
            // §5.2: the peer is draining. The identifier is the first
            // request it will NOT process; it must not increase on a
            // later GOAWAY, since that would take back a promise.
            let id = match decode_varint_prefix(payload) {
                Some((v, _)) => v,
                None => return Some(H3_FRAME_ERROR),
            };
            if sess.peer_goaway && id > sess.peer_goaway_id {
                return Some(H3_ID_ERROR);
            }
            sess.peer_goaway = true;
            sess.peer_goaway_id = id;
            None
        }
        H3_FRAME_MAX_PUSH_ID => {
            // A server may receive MAX_PUSH_ID; it never pushes, so the
            // cap is accepted and nothing is scheduled against it.
            // Accepting is required — refusing a legal frame would be a
            // protocol error of our own making.
            if decode_varint_prefix(payload).is_none() {
                return Some(H3_FRAME_ERROR);
            }
            None
        }
        H3_FRAME_CANCEL_PUSH => {
            // Nothing was ever pushed, so there is nothing to cancel.
            // §7.2.3 makes a CANCEL_PUSH for an unpromised id an ID_ERROR.
            Some(H3_ID_ERROR)
        }
        H3_FRAME_PRIORITY_UPDATE_REQUEST | H3_FRAME_PRIORITY_UPDATE_PUSH => {
            // RFC 9218 §7.2. Parsed and accepted; the emission cursor is
            // strict round-robin and does not yet honour urgency. Silence
            // is the right response to a priority hint we do not act on —
            // refusing it would be an error the peer cannot fix.
            if decode_varint_prefix(payload).is_none() {
                return Some(H3_FRAME_ERROR);
            }
            None
        }
        H3_FRAME_DATA | H3_FRAME_HEADERS => {
            // §7.1: request frames are illegal on the control stream.
            Some(H3_FRAME_UNEXPECTED)
        }
        // Unknown and greased frame types are ignored (§9). The parse
        // already skipped the payload, so there is nothing to do.
        _ => None,
    }
}

/// The peer's SETTINGS, as far as this module uses them.
pub struct PeerSettings {
    pub max_field_section_size: u32,
    pub enable_connect_protocol: bool,
}

/// Walk a SETTINGS payload (RFC 9114 §7.2.4).
///
/// Returns `None` on a malformed payload: it is a whole number of
/// (varint id, varint value) pairs with nothing left over, and anything
/// else is an error. A half-read set is discarded with it rather than
/// applied — half a limit is worse than the default, because the
/// application acts on it as though the peer had stated it.
///
/// **Fills a fixed struct; takes no callback.** A per-entry
/// `&mut dyn FnMut(u64, u64)` is a trait object, and a trait object is a
/// vtable: these modules are position-independent with no relocation
/// processing for one, so calling through it jumps to an unrelocated
/// address. That failure is invisible to the build and to the host
/// harness — it faults the runtime the first time a peer's SETTINGS
/// arrives, immediately after the handshake completes.
pub fn parse_peer_settings(payload: &[u8]) -> Option<PeerSettings> {
    let mut out = PeerSettings {
        // RFC 9114 §7.2.4.1: absent means unlimited, which is NOT the
        // same as an advertised 0 (that forbids header sections).
        max_field_section_size: u32::MAX,
        enable_connect_protocol: false,
    };
    let mut pos = 0;
    let mut seen_ids = [u64::MAX; 8];
    let mut seen_n = 0usize;
    while pos < payload.len() {
        let (id, n1) = decode_varint_prefix(&payload[pos..])?;
        pos += n1;
        let (val, n2) = decode_varint_prefix(&payload[pos..])?;
        pos += n2;
        // §7.2.4: a repeated identifier is a SETTINGS_ERROR. Only the
        // ones we track are checked — a peer greasing with many reserved
        // identifiers must not exhaust the table and be refused for it.
        let tracked = id == H3_SETTING_MAX_FIELD_SECTION_SIZE
            || id == H3_SETTING_QPACK_MAX_TABLE_CAPACITY
            || id == H3_SETTING_QPACK_BLOCKED_STREAMS
            || id == H3_SETTING_ENABLE_CONNECT_PROTOCOL;
        if tracked {
            let mut k = 0;
            while k < seen_n {
                if seen_ids[k] == id {
                    return None;
                }
                k += 1;
            }
            if seen_n < seen_ids.len() {
                seen_ids[seen_n] = id;
                seen_n += 1;
            }
        }
        // The wire type is a varint up to 2^62; this field is a u32.
        // Saturate rather than truncate — a truncated 2^32 reads as 0,
        // which for `max_field_section_size` means "no header section may
        // be sent" and would refuse every request on the connection.
        let val32 = if val > u32::MAX as u64 {
            u32::MAX
        } else {
            val as u32
        };
        if id == H3_SETTING_MAX_FIELD_SECTION_SIZE {
            out.max_field_section_size = val32;
        } else if id == H3_SETTING_ENABLE_CONNECT_PROTOCOL {
            // §3 of RFC 9220: only 0 and 1 are defined.
            if val > 1 {
                return None;
            }
            out.enable_connect_protocol = val == 1;
        }
        // QPACK capacity and blocked-stream limits are read past
        // deliberately: this encoder never references a dynamic table, so
        // neither can constrain anything it produces. Storing them to look
        // thorough would be state nothing reads.
    }
    Some(out)
}

/// QPACK encoder/decoder instruction streams under a zero-capacity
/// advertisement (RFC 9204 §4.3, §4.4).
///
/// This endpoint advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so
/// the only instructions a conforming peer may send are ones that do not
/// touch a dynamic table. Anything else is the peer disregarding our
/// SETTINGS, and the error is ours to raise: an endpoint that discarded
/// these bytes would let a peer violate the setting indefinitely without
/// the endpoint that set it ever finding out.
fn qpack_instruction_ingest(data: &[u8], encoder: bool) -> Option<u64> {
    let mut pos = 0;
    while pos < data.len() {
        let b = data[pos];
        if encoder {
            // §4.3.1 Set Dynamic Table Capacity: `001xxxxx`. The only
            // legal value under a zero advertisement is 0.
            if b & 0xE0 == 0x20 {
                let (cap, n) = decode_prefix_int(&data[pos..], 5)?;
                if cap != 0 {
                    return Some(QPACK_ENCODER_STREAM_ERROR);
                }
                pos += n;
                continue;
            }
            // Every other encoder instruction — Insert With Name
            // Reference (`1xxxxxxx`), Insert With Literal Name
            // (`01xxxxxx`), Duplicate (`000xxxxx`) — inserts into the
            // dynamic table, which has no capacity.
            return Some(QPACK_ENCODER_STREAM_ERROR);
        }
        // Decoder stream (§4.4). Section Acknowledgement (`1xxxxxxx`) and
        // Stream Cancellation (`01xxxxxx`) refer to field sections that
        // used the dynamic table; Insert Count Increment (`00xxxxxx`)
        // acknowledges insertions. None can occur when we never inserted.
        let _ = b;
        return Some(QPACK_DECODER_STREAM_ERROR);
    }
    None
}

/// Decode a QPACK prefix-encoded integer with an `n`-bit prefix
/// (RFC 7541 §5.1, reused by RFC 9204 §4.1.1).
fn decode_prefix_int(buf: &[u8], prefix_bits: u32) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let mask = ((1u32 << prefix_bits) - 1) as u8;
    let mut value = (buf[0] & mask) as u64;
    if value < mask as u64 {
        return Some((value, 1));
    }
    let mut pos = 1;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() || shift > 56 {
            return None;
        }
        let b = buf[pos];
        pos += 1;
        value = value.checked_add(((b & 0x7F) as u64) << shift)?;
        if b & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
    }
}

/// Decode a QUIC varint from the front of `buf`.
fn decode_varint_prefix(buf: &[u8]) -> Option<(u64, usize)> {
    classify_uni_stream_prefix(buf)
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

// ── RFC 9114 §8.1 / RFC 9204 §6 error codes ────────────────────────
//
// Named rather than written inline at each use. These are values a PEER
// reads to decide what went wrong, so a wrong one is not a cosmetic slip:
// it tells the other end to take a different recovery path, and the
// symptom appears on their side, in their logs, describing a fault that
// did not happen.

pub const H3_NO_ERROR: u64 = 0x0100;
pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
pub const H3_INTERNAL_ERROR: u64 = 0x0102;
pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
pub const H3_FRAME_ERROR: u64 = 0x0106;
pub const H3_EXCESSIVE_LOAD: u64 = 0x0107;
pub const H3_ID_ERROR: u64 = 0x0108;
pub const H3_SETTINGS_ERROR: u64 = 0x0109;
pub const H3_MISSING_SETTINGS: u64 = 0x010A;
pub const H3_REQUEST_REJECTED: u64 = 0x010B;
pub const H3_REQUEST_CANCELLED: u64 = 0x010C;
pub const H3_REQUEST_INCOMPLETE: u64 = 0x010D;
pub const H3_MESSAGE_ERROR: u64 = 0x010E;
pub const H3_CONNECT_ERROR: u64 = 0x010F;
pub const H3_VERSION_FALLBACK: u64 = 0x0110;
pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;

/// Why a header section was refused. The values are the RFC 9114 §8.1
/// error codes the caller puts on the wire, so a caller cannot invent its
/// own mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3Error {
    /// `H3_MESSAGE_ERROR` — malformed request message: a missing or
    /// repeated pseudo-header, a pseudo-header after a regular one, or a
    /// field this module cannot store.
    MessageError,
    /// `QPACK_DECOMPRESSION_FAILED` — the field section did not decode: a
    /// bad prefix, a truncated field line, or a dynamic-table reference
    /// (this module advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so
    /// a dynamic reference is the peer disregarding our SETTINGS).
    QpackFailed,
    /// `H3_FRAME_UNEXPECTED` — a frame type that is legal in h3 but not on
    /// a request stream (RFC 9114 §7.1).
    FrameUnexpected,
}

impl H3Error {
    /// The RFC 9114 §8.1 code to send.
    pub const fn code(self) -> u64 {
        match self {
            H3Error::MessageError => H3_MESSAGE_ERROR,
            H3Error::QpackFailed => QPACK_DECOMPRESSION_FAILED,
            H3Error::FrameUnexpected => H3_FRAME_UNEXPECTED,
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

/// The size RFC 9114 §4.2.2 counts a field section as, for the purpose of
/// `SETTINGS_MAX_FIELD_SECTION_SIZE`: the sum over fields of
/// `name.len() + value.len() + 32`, on the UNCOMPRESSED values.
///
/// The +32 per field is not padding — it is the spec's allowance for a
/// decoder's per-entry overhead, and omitting it under-counts every section by
/// 32 bytes per header, which is exactly enough to sail past a tight limit and
/// have the peer reject a response we measured as fitting.
pub fn field_section_size(status: &[u8], fields: &[(&[u8], &[u8])]) -> usize {
    // `:status` is a field like any other for this calculation.
    let mut total = b":status".len() + status.len() + 32;
    for (name, value) in fields {
        total += name.len() + value.len() + 32;
    }
    total
}

/// Whether a response's field section is within what the peer will accept.
///
/// `u32::MAX` means the peer advertised no limit. A `0` limit is real and
/// forbids every section, including a bare `:status` — which is why this is a
/// comparison against a sentinel rather than a `limit == 0` short-circuit.
fn fits_peer_field_limit(limit: u32, status: &[u8], fields: &[(&[u8], &[u8])]) -> bool {
    limit == u32::MAX || field_section_size(status, fields) as u64 <= u64::from(limit)
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
    /// chunked renderers, the file/proxy state).
    ///
    /// A **501 response IS written** — `n` bytes — and the handler id rides
    /// along so the caller can name which one in a log and a counter. It used
    /// to reset the stream instead, which is the wrong answer twice over: a
    /// reset is indistinguishable from a transport fault, so an operator who
    /// configured a file route and reached it over HTTP/3 saw a connection
    /// problem rather than a configuration one; and RFC 9110 §15.6.2 has a
    /// status that means exactly this — the server does not support the
    /// functionality required to fulfil the request.
    HandlerNotShared(usize, u8),
    /// The response does not fit `out`. Nothing is written.
    TooLarge,
    /// The peer advertised a `SETTINGS_MAX_FIELD_SECTION_SIZE` smaller than the
    /// response's field section (RFC 9114 §4.2.2). Nothing is written.
    ///
    /// Refusing is the better failure. Sending it anyway is not "best effort":
    /// the peer is entitled to treat an over-limit section as malformed and
    /// reset the stream, so the request fails either way — but it fails with a
    /// QPACK/frame error at the client, which points at the encoder rather than
    /// at the limit the client itself set.
    PeerFieldLimit,
    /// RFC 9220 extended CONNECT accepted: `n` bytes of a 200 response with no
    /// body are written, and the stream becomes a WebSocket tunnel.
    WebSocketAccepted(usize),
}

/// Render the 501 an unshared handler gets.
///
/// The body names the situation rather than saying "error": whoever sees this
/// configured a route that works over HTTP/1.1 and HTTP/2 and reached it over
/// HTTP/3, and the useful thing to tell them is which of those two facts to act
/// on. `Not Implemented\n` alone would send them looking for a missing feature
/// in their own client.
///
/// Field literals go through stack buffers for the same PIC reason the 404 path
/// documents below — a const array of fat pointers needs relocation the loader
/// does not apply, and dereferencing it on device segfaults.
unsafe fn not_implemented(peer_limit: u32, handler: u8, out: &mut [u8]) -> H3Dispatch {
    let mut status = [0u8; 3];
    status.copy_from_slice(b"501");
    let mut name = [0u8; 12];
    name.copy_from_slice(b"content-type");
    let mut ctype = [0u8; 10];
    ctype.copy_from_slice(b"text/plain");
    let mut body = [0u8; 42];
    body.copy_from_slice(b"Handler not available over HTTP/3 for this");
    let fields = [(&name[..], &ctype[..])];
    if !fits_peer_field_limit(peer_limit, &status, &fields) {
        return H3Dispatch::PeerFieldLimit;
    }
    let n = build_response(&status, &fields, &body, out);
    if n == 0 {
        H3Dispatch::TooLarge
    } else {
        H3Dispatch::HandlerNotShared(n, handler)
    }
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
    peer_limit: u32,
) -> H3Dispatch {
    dispatch_request_bounded(s, req, out, H3_TEMPLATE_BUF, peer_limit)
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
    peer_limit: u32,
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
        if !fits_peer_field_limit(peer_limit, &status, &fields) {
            return H3Dispatch::PeerFieldLimit;
        }
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
            return not_implemented(peer_limit, handler, out);
        }
        let mut status = [0u8; 3];
        status.copy_from_slice(b"200");
        if !fits_peer_field_limit(peer_limit, &status, &[]) {
            return H3Dispatch::PeerFieldLimit;
        }
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
        return not_implemented(peer_limit, handler, out);
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
    if !fits_peer_field_limit(peer_limit, &status, &fields) {
        return H3Dispatch::PeerFieldLimit;
    }
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
    // `u32::MAX` = no peer limit, which is the standing default until a
    // transport delivers `MSG_MUX_PEER_SETTINGS`. The limit's own behaviour is
    // driven through the pump, where it actually arrives.
    test_decode_and_dispatch_limited(state, block, out, u32::MAX)
}

/// [`test_decode_and_dispatch`] with the peer's advertised field-section limit
/// injected, for the refusal path.
///
/// # Safety
///
/// `state` must point at a `module_state` buffer initialised by `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_decode_and_dispatch_limited(
    state: *mut u8,
    block: &[u8],
    out: &mut [u8],
    peer_limit: u32,
) -> Result<H3Dispatch, H3Error> {
    let s = &*(state as *const super::super::HttpState);
    let mut req = H3Request::empty();
    decode_request_headers(block, &mut req)?;
    Ok(dispatch_request(s, &req, out, peer_limit))
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
pub use super::super::connection::{mux, FRAME_HDR};

/// What feeding a stream produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3StreamOutcome {
    /// Buffered; the request head is not complete yet.
    Buffered,
    /// A request was served: `n` bytes of response are queued on this stream,
    /// drainable with [`pump_next_out`].
    Responded(usize),
    /// The route matched a handler HTTP/3 cannot serve yet
    /// ([`H3Dispatch::HandlerNotShared`]). A 501 is queued on the stream — the
    /// request is answered, not dropped — and the handler id rides along so the
    /// caller can name which one.
    HandlerNotShared(u8),
    /// The response's field section exceeds the peer's advertised
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`. Reset, because there is no response
    /// we are permitted to send: even a bare `:status` is over a limit this
    /// tight, so a smaller answer is not available either.
    PeerFieldLimit,
    /// A session-scoped event was consumed (session opened or closed, a
    /// control-stream frame, a QPACK instruction). Names no stream.
    SessionEvent,
    /// The peer broke a connection-level rule. The session is failed with
    /// the RFC 9114 §8.1 code and torn down; nothing further on it can be
    /// trusted, because the peer's state machine has diverged from ours.
    ConnectionError(u64),
    /// The rendered response exceeds [`H3_SEND_BUF`]. Reset, never truncated:
    /// half a response is a protocol error the peer attributes to us.
    ResponseTooLarge,
    /// Protocol error — reset the stream with `H3Error::code()`.
    StreamError(H3Error),
    /// No free slot. RFC 9114 §8.1 `H3_EXCESSIVE_LOAD` is the honest answer:
    /// the peer opened more concurrent requests than this device advertises.
    SlotsExhausted,
    /// The endpoint is draining and will not admit new work. The peer learns
    /// the boundary from GOAWAY (RFC 9114 §5.2), which names this stream as
    /// one it may safely re-issue elsewhere.
    DrainRefused,
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
        // Draining admits nothing new. Work accepted before the drain began
        // still holds its slot and is still answered — matched above — but a
        // stream that arrives afterwards is refused, so a continuous arrival
        // stream cannot keep the module from ever reaching quiescence.
        if self.draining {
            return None;
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
        return if st.draining {
            H3StreamOutcome::DrainRefused
        } else {
            H3StreamOutcome::SlotsExhausted
        };
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

    // The peer's own limits, per session. Which session a stream belongs
    // to decides how its response may be encoded, so this is read here
    // rather than from anything module-scoped: two connections advertise
    // independently, and using one's limit on the other's stream would
    // encode a header section the peer never agreed to accept.
    let (gated, peer_limit) = match session_slot(st, session_id) {
        Some(si) => (
            st.sessions[si].responses_gated(),
            st.sessions[si].peer_max_field_section,
        ),
        // No session entry: nothing has told us this connection's limits,
        // so the RFC 9114 §7.2.4.1 default (unlimited) is what applies.
        None => (false, u32::MAX),
    };

    // Accumulate. A head larger than the buffer is refused rather than
    // silently parsed from a prefix.
    {
        let slot = &mut st.slots[idx];
        let room = H3_RECV_BUF - slot.recv_hdr_len;
        if data.len() > room {
            slot.state = H3StreamState::Reset;
            slot.reset_code = H3Error::MessageError.code();
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
                st.slots[idx].reset_code = e.code();
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

    // Hold the request until the peer's SETTINGS have arrived.
    //
    // The REQUEST is accepted early on purpose: cross-stream arrival order
    // is not an assurance that the control stream is delivered first, and
    // refusing a request that merely arrived promptly would invent an
    // ordering rule QUIC does not provide. What waits is the RESPONSE —
    // encoding one under guessed limits risks a header section the peer
    // rejects, and it answers with a frame-size error that names a frame
    // rather than the setting that refused it.
    //
    // The accumulated bytes stay in the slot; `retry_gated_streams` re-runs
    // this the moment SETTINGS land.
    if gated {
        return H3StreamOutcome::Buffered;
    }

    // Render into the slot's own send buffer — per stream, so two concurrent
    // requests cannot overwrite each other's response.
    let mut rendered = [0u8; H3_SEND_BUF];
    let outcome = dispatch_request(s, &req, &mut rendered, peer_limit);
    let mut upgraded = false;
    let mut not_shared_handler: Option<u8> = None;
    let n = match outcome {
        H3Dispatch::WebSocketAccepted(n) => {
            upgraded = true;
            n
        }
        H3Dispatch::Response(n) | H3Dispatch::NotFound(n) => n,
        // Answered, not reset — so the queue-and-drain below runs for this
        // stream exactly as it does for a 404. The outcome is still reported so
        // the caller logs and counts it; a 501 that only the client ever sees
        // is a misconfiguration nobody operating the server can find.
        H3Dispatch::HandlerNotShared(n, h) => {
            not_shared_handler = Some(h);
            n
        }
        H3Dispatch::TooLarge => {
            // Nothing can be sent: half a response is a protocol error the
            // peer attributes to us, so the stream is reset instead.
            st.slots[idx].state = H3StreamState::Reset;
            st.slots[idx].reset_code = H3_INTERNAL_ERROR;
            return H3StreamOutcome::ResponseTooLarge;
        }
        H3Dispatch::PeerFieldLimit => {
            // Even a bare `:status` is over a limit this tight, so there is
            // no smaller answer available either.
            st.slots[idx].state = H3StreamState::Reset;
            st.slots[idx].reset_code = H3_INTERNAL_ERROR;
            return H3StreamOutcome::PeerFieldLimit;
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
    if let Some(h) = not_shared_handler {
        return H3StreamOutcome::HandlerNotShared(h);
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
/// The transport delivers sessions, streams and bytes. Everything that
/// gives those bytes meaning is here: which session a stream belongs to,
/// what a unidirectional stream's leading varint says it is, what a
/// control frame does, and which HTTP/3 error a violation deserves.
///
/// A frame that is not ours — net_proto frames for the h1/h2 path on the
/// same channel pair — is reported as `Ignored` rather than misparsed.
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
    if payload.len() < mux::SESSION_ID_BYTES {
        return H3StreamOutcome::Ignored;
    }
    let session = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);

    // ── session-scoped events ──────────────────────────────────────
    // Handled before the stream-prefix parse, because their bytes 4..8
    // are not a stream handle. Reading them as one would address a
    // stream that does not exist.
    match msg_type {
        mux::MSG_MUX_SESSION_OPENED => {
            if payload.len() < mux::SESSION_ID_BYTES + mux::SESSION_OPENED_BODY_MIN {
                return H3StreamOutcome::Ignored;
            }
            let b = &payload[mux::SESSION_ID_BYTES..];
            if b[0] != mux::STATUS_OK {
                return H3StreamOutcome::Ignored;
            }
            let alpn_len = b[2] as usize;
            if b.len() < 3 + alpn_len {
                return H3StreamOutcome::Ignored;
            }
            let alpn = &b[3..3 + alpn_len];
            let Some(i) = session_alloc(st, session) else {
                // More sessions than this device advertises it can hold.
                return H3StreamOutcome::SlotsExhausted;
            };
            // The ALPN arrives as opaque bytes and means nothing to the
            // transport. Deciding that these particular bytes select
            // HTTP/3 is this module's job, and this is where it happens.
            st.sessions[i].is_h3 = alpn == H3_ALPN_TOKEN;
            return H3StreamOutcome::SessionEvent;
        }
        mux::MSG_MUX_SESSION_CLOSED => {
            if let Some(i) = session_slot(st, session) {
                st.sessions[i].release();
            }
            // Streams belonging to a session that no longer exists are
            // released with it. Leaving them allocated would hold slots
            // for a connection nothing can ever answer on.
            let mut k = 0;
            while k < MAX_H3_STREAMS {
                if st.slots[k].allocated && st.slots[k].session_id == session {
                    st.slots[k].release();
                }
                k += 1;
            }
            return H3StreamOutcome::SessionEvent;
        }
        mux::MSG_MUX_PEER_IDENTITY | mux::MSG_MUX_DATAGRAM_RX => {
            // Peer identity is transport metadata this generation has no
            // use for; HTTP/3 DATAGRAM (RFC 9297) is not implemented, and
            // an unimplemented extension is silently ignored rather than
            // treated as an error.
            return H3StreamOutcome::SessionEvent;
        }
        _ => {}
    }

    if payload.len() < mux::STREAM_DATA_PREFIX {
        return H3StreamOutcome::Ignored;
    }
    let handle = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let body = &payload[mux::STREAM_DATA_PREFIX..];

    let Some(si) = session_slot(st, session) else {
        // A stream on a session we were never told about. The transport
        // announces a session before anything that belongs to it, so this
        // is either a session we refused for want of a slot or a stale
        // frame — either way there is no state to apply it to.
        return H3StreamOutcome::Ignored;
    };
    if !st.sessions[si].is_h3 {
        return H3StreamOutcome::Ignored;
    }

    match msg_type {
        mux::MSG_MUX_STREAM_OPENED => {
            // The answer to one of our own preamble opens.
            if body.len() < mux::STREAM_OPENED_BODY {
                return H3StreamOutcome::Ignored;
            }
            let status = body[0];
            local_uni_opened(&mut st.sessions[si], handle, status);
            H3StreamOutcome::SessionEvent
        }
        mux::MSG_MUX_STREAM_ACCEPTED => {
            if body.len() < mux::STREAM_ACCEPTED_BODY {
                return H3StreamOutcome::Ignored;
            }
            let flags = body[0];
            let quic_id = u64::from_le_bytes([
                body[1], body[2], body[3], body[4], body[5], body[6], body[7], body[8],
            ]);
            if flags & mux::STREAM_FLAG_UNI != 0 {
                // A peer unidirectional stream. What it IS is decided from
                // its first bytes, which have not arrived yet — so it is
                // registered and classified on its first RX.
                return match peer_uni_alloc(&mut st.sessions[si], handle) {
                    Some(_) => H3StreamOutcome::SessionEvent,
                    None => H3StreamOutcome::SessionEvent,
                };
            }
            // A peer bidirectional stream is a request stream. Reserve the
            // slot now so a later RX cannot be refused while a stream that
            // has already been announced is in flight.
            match st.slot_for(session, u64::from(handle)) {
                Some(i) => {
                    // The transport's own stream identity, kept because
                    // GOAWAY and PRIORITY_UPDATE name streams by it and
                    // the opaque handle is not derivable from it.
                    st.slots[i].quic_stream_id = quic_id;
                    // GOAWAY must not take an accepted request back, so the
                    // boundary it will name is raised past this stream now
                    // rather than when the drain begins.
                    let next = quic_id.saturating_add(4);
                    if next > st.sessions[si].goaway_id {
                        st.sessions[si].goaway_id = next;
                    }
                    H3StreamOutcome::Buffered
                }
                None if st.draining => H3StreamOutcome::DrainRefused,
                None => H3StreamOutcome::SlotsExhausted,
            }
        }
        mux::MSG_MUX_STREAM_RX => {
            // Unidirectional first: a peer uni stream is registered under
            // its handle, and its bytes are the connection's control or
            // QPACK traffic rather than a request.
            if let Some(ui) = peer_uni_slot(&st.sessions[si], handle) {
                if let Some(code) = uni_ingest(&mut st.sessions[si], ui, body) {
                    st.sessions[si].fail(code);
                    return H3StreamOutcome::ConnectionError(code);
                }
                return H3StreamOutcome::SessionEvent;
            }
            pump_stream_in(st, s, session, u64::from(handle), body, false)
        }
        mux::MSG_MUX_STREAM_CLOSED => {
            // RFC 9114 §6.2.1: closing a critical stream is a connection
            // error. The connection depends on those streams for its whole
            // life, so a peer that ends one has ended the connection.
            if let Some(ui) = peer_uni_slot(&st.sessions[si], handle) {
                let critical = matches!(
                    st.sessions[si].peer_uni[ui].role,
                    UniRole::Control | UniRole::QpackEncoder | UniRole::QpackDecoder
                );
                st.sessions[si].peer_uni[ui] = PeerUni::empty();
                if critical {
                    st.sessions[si].fail(H3_CLOSED_CRITICAL_STREAM);
                    return H3StreamOutcome::ConnectionError(H3_CLOSED_CRITICAL_STREAM);
                }
                return H3StreamOutcome::SessionEvent;
            }
            // The peer is done sending on a request stream. Any response
            // already queued still drains; a stream with nothing queued is
            // released.
            if let Some(i) = st.slots.iter().position(|sl| {
                sl.allocated && sl.session_id == session && sl.stream_id == u64::from(handle)
            }) {
                if st.slots[i].pending_out() == 0 {
                    st.slots[i].release();
                }
            }
            H3StreamOutcome::Ignored
        }
        mux::MSG_MUX_STREAM_RESET | mux::MSG_MUX_STREAM_STOPPED => {
            // The peer abandoned the stream, or asked us to stop producing
            // on it. Either way the exchange is over: drop whatever was
            // queued rather than spending the connection's capacity
            // finishing a response nobody will read.
            if let Some(ui) = peer_uni_slot(&st.sessions[si], handle) {
                let critical = matches!(
                    st.sessions[si].peer_uni[ui].role,
                    UniRole::Control | UniRole::QpackEncoder | UniRole::QpackDecoder
                );
                st.sessions[si].peer_uni[ui] = PeerUni::empty();
                if critical {
                    st.sessions[si].fail(H3_CLOSED_CRITICAL_STREAM);
                    return H3StreamOutcome::ConnectionError(H3_CLOSED_CRITICAL_STREAM);
                }
                return H3StreamOutcome::SessionEvent;
            }
            if let Some(i) = st.slots.iter().position(|sl| {
                sl.allocated && sl.session_id == session && sl.stream_id == u64::from(handle)
            }) {
                st.slots[i].release();
            }
            H3StreamOutcome::SessionEvent
        }
        _ => H3StreamOutcome::Ignored,
    }
}

/// The ALPN token this module answers HTTP/3 on.
///
/// Compared HERE, against bytes the transport reported without
/// interpreting. That is the whole shape of the boundary: the transport
/// negotiates a byte string, and the application decides what it means.
pub const H3_ALPN_TOKEN: &[u8] = b"h3";

/// Match a `MSG_MUX_STREAM_OPENED` to whichever preamble stream is
/// outstanding.
///
/// Exactly one open is in flight at a time (see `pump_next_out`), so the
/// correlation is unambiguous without the transport having to say which
/// request it is answering. Issuing all three at once and matching by
/// arrival order would be faster and would silently mis-assign the
/// handles the first time the transport answered out of order.
pub(crate) fn local_uni_opened(sess: &mut H3Session, handle: u32, status: u8) {
    let ok = status == mux::STATUS_OK;
    for uni in [&mut sess.ctrl, &mut sess.qpack_enc, &mut sess.qpack_dec] {
        if uni.state == LocalUniState::Opening {
            if ok {
                uni.handle = handle;
                uni.state = LocalUniState::Open;
            } else {
                uni.state = LocalUniState::Refused;
            }
            return;
        }
    }
}

/// Build this endpoint's SETTINGS frame body (RFC 9114 §7.2.4).
///
/// These values are Wave's policy. The transport has no opinion about
/// them and no longer has any way to form one — it never sees this frame
/// as anything but bytes on a stream.
fn build_local_settings(out: &mut [u8]) -> usize {
    // (identifier, value) pairs as QUIC varints.
    //
    // QPACK capacity and blocked streams are 0 because this encoder emits
    // only static and literal fields. ENABLE_CONNECT_PROTOCOL is
    // advertised because a SERVER is the role permitted to (RFC 9220 §3);
    // it is what lets a client open a WebSocket tunnel.
    let pairs: [(u64, u64); 4] = [
        (H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 0),
        (H3_SETTING_MAX_FIELD_SECTION_SIZE, LOCAL_MAX_FIELD_SECTION),
        (H3_SETTING_QPACK_BLOCKED_STREAMS, 0),
        (H3_SETTING_ENABLE_CONNECT_PROTOCOL, 1),
    ];
    let mut body = [0u8; 32];
    let n = build_h3_settings_payload(&pairs, &mut body);
    if n == 0 {
        return 0;
    }
    let mut hdr = [0u8; 8];
    let hn = build_h3_frame_header(H3_FRAME_SETTINGS, n, &mut hdr);
    if hn == 0 || hn + n > out.len() {
        return 0;
    }
    out[..hn].copy_from_slice(&hdr[..hn]);
    out[hn..hn + n].copy_from_slice(&body[..n]);
    hn + n
}

/// Re-drive any request that was held waiting for the peer's SETTINGS.
///
/// Without this a request that arrived before the control stream would sit
/// in its slot forever: the bytes are all present, nothing further will
/// arrive on that stream to trigger another parse, and the client waits
/// for a response that is never rendered. The window is small and entirely
/// real — the two streams are independent, so which lands first is a
/// scheduling accident.
///
/// # Safety
///
/// `s` must be a live `HttpState`.
pub(crate) unsafe fn retry_gated_streams(
    st: &mut H3State,
    s: &super::super::HttpState,
) -> Option<H3StreamOutcome> {
    let mut k = 0;
    while k < MAX_H3_STREAMS {
        let ready = st.slots[k].allocated
            && st.slots[k].recv_hdr_len > 0
            && st.slots[k].pending_out() == 0
            && st.slots[k].state != H3StreamState::HeadersSent
            && !st.slots[k].ws_active
            && match session_slot(st, st.slots[k].session_id) {
                Some(si) => !st.sessions[si].responses_gated(),
                None => true,
            };
        if ready {
            let (session, stream) = (st.slots[k].session_id, st.slots[k].stream_id);
            // Re-parse from the bytes already held; nothing new is added.
            let outcome = pump_stream_in(st, s, session, stream, &[], false);
            if !matches!(outcome, H3StreamOutcome::Buffered) {
                return Some(outcome);
            }
        }
        k += 1;
    }
    None
}

/// What accepting a staged session frame settles.
///
/// Kept separate from the frame bytes so the state moves only after the
/// transport has taken them. The three preamble streams are named by
/// index — 0 control, 1 QPACK encoder, 2 QPACK decoder — in the order
/// [`session_preamble_out`] walks them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessCommit {
    /// The session close carrying the connection error has gone out.
    ConnError,
    /// A preamble stream's open has been issued and is now outstanding.
    UniOpening(u8),
    /// A preamble stream's type prefix — and, on the control stream, the
    /// SETTINGS frame that must be its first — has gone out.
    UniReady(u8),
    /// The GOAWAY naming the drain boundary has gone out.
    GoawaySent,
    /// The session close has gone out; the session is over.
    Closed,
}

/// What accepting a staged outbound frame settles.
///
/// Egress is staged and committed in two steps because `POLL_OUT` reports
/// that the channel has capacity, not that a whole atomic frame will fit.
/// A cursor advanced before the write is a chunk the peer never receives
/// and nothing re-offers; a cursor advanced twice is a chunk the peer
/// receives twice. Staging leaves every cursor where it was, so a refused
/// frame is restaged identically on the next step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3Commit {
    /// A session-scoped frame from the session at this index.
    Session(usize, SessCommit),
    /// The slot's RESET_STREAM has gone out; the slot is now free.
    ResetSent(usize),
    /// The slot's close has gone out; the slot is now free.
    CloseSent(usize),
    /// `take` response bytes have gone out from the slot's send buffer.
    /// `last` marks the chunk that empties it.
    DataSent { idx: usize, take: usize, last: bool },
}

/// Apply a session commit once the transport has taken the frame whole.
pub(crate) fn commit_session(sess: &mut H3Session, what: SessCommit) {
    match what {
        SessCommit::ConnError => sess.conn_error_pending = false,
        SessCommit::UniOpening(which) => match which {
            0 => sess.ctrl.state = LocalUniState::Opening,
            1 => sess.qpack_enc.state = LocalUniState::Opening,
            _ => sess.qpack_dec.state = LocalUniState::Opening,
        },
        SessCommit::UniReady(which) => match which {
            0 => {
                sess.ctrl.state = LocalUniState::Ready;
                sess.settings_sent = true;
            }
            1 => sess.qpack_enc.state = LocalUniState::Ready,
            _ => sess.qpack_dec.state = LocalUniState::Ready,
        },
        SessCommit::GoawaySent => sess.goaway_sent = true,
        SessCommit::Closed => sess.release(),
    }
}

/// Apply an egress commit once the transport has taken the frame whole.
///
/// The emission cursors move here rather than at staging time, so a frame
/// the channel refused is restaged for the same slot rather than skipped
/// in favour of its neighbour.
pub fn commit_out(st: &mut H3State, what: H3Commit) {
    match what {
        H3Commit::Session(si, w) => {
            commit_session(&mut st.sessions[si], w);
            st.sess_cursor = ((si + 1) % MAX_H3_SESSIONS) as u8;
        }
        H3Commit::ResetSent(idx) | H3Commit::CloseSent(idx) => {
            st.slots[idx].release();
            st.emit_cursor = ((idx + 1) % MAX_H3_STREAMS) as u8;
        }
        H3Commit::DataSent { idx, take, last } => {
            st.slots[idx].send_off += take;
            st.emit_cursor = ((idx + 1) % MAX_H3_STREAMS) as u8;
            if last {
                if st.slots[idx].ws_active {
                    // A tunnel outlives its traffic: rewind the cursor
                    // rather than releasing the slot, so the next frame
                    // appends to an empty buffer.
                    st.slots[idx].send_len = 0;
                    st.slots[idx].send_off = 0;
                } else {
                    // The whole response is handed over. The stream is NOT
                    // released yet: it owes a close, which the next stage
                    // emits.
                    st.slots[idx].close_pending = true;
                }
            }
        }
    }
}

/// Emit whatever a session owes before any request traffic: its
/// connection preamble, and any connection error it has raised.
///
/// RFC 9114 §6.2.1 makes the control stream and its SETTINGS the first
/// thing an endpoint sends. That ordering is an HTTP/3 state-machine
/// requirement, and it is met here — by opening streams and writing bytes
/// through the generic transport surface — rather than by the transport
/// running a preamble it would have to understand.
///
/// One open is outstanding at a time. The transport answers each with a
/// handle but does not say WHICH open it is answering, so issuing all
/// three at once and matching by arrival order would silently mis-assign
/// the handles the first time it answered out of order. The cost is a
/// scheduler round trip per stream, once per connection.
fn session_next_out(st: &H3State, out: &mut [u8]) -> Option<(usize, H3Commit)> {
    for step in 0..MAX_H3_SESSIONS {
        let si = (st.sess_cursor as usize + step) % MAX_H3_SESSIONS;
        let sess = &st.sessions[si];
        if !sess.allocated || !sess.is_h3 {
            continue;
        }
        // A session still carrying admitted work owes its preamble: the
        // requests in flight are owed responses, and RFC 9114 §6.2.1 puts
        // SETTINGS ahead of any of them. A connection error outranks the
        // drain for the same reason it outranks everything else.
        let live = session_has_live_stream(st, si);
        if !st.draining || live || sess.conn_error_pending {
            if let Some((n, what)) = session_preamble_out(sess, out) {
                return Some((n, H3Commit::Session(si, what)));
            }
        }
        if st.draining && !live {
            if let Some((n, what)) = session_drain_out(sess, out) {
                return Some((n, H3Commit::Session(si, what)));
            }
        }
    }
    None
}

/// Whether any request stream is still admitted on this session.
///
/// Occupancy is not the test — a session with no streams holds no admitted
/// work however long it has been open, which is what lets an idle HTTP/3
/// connection drain instead of waiting on a client that has no reason to
/// close it.
pub(crate) fn session_has_live_stream(st: &H3State, si: usize) -> bool {
    let session = st.sessions[si].session_id;
    let mut k = 0;
    while k < MAX_H3_STREAMS {
        if st.slots[k].allocated && st.slots[k].session_id == session {
            return true;
        }
        k += 1;
    }
    false
}

/// What a draining session owes: GOAWAY, then its close.
///
/// GOAWAY (RFC 9114 §5.2) names the first request stream this endpoint will
/// not process, so the peer knows exactly which of its requests were served
/// and which it may re-issue elsewhere. The close follows, and only then:
/// closing first leaves the peer unable to tell a graceful shutdown from a
/// connection that died, which is the difference between a client that
/// reconnects and one that reports its requests failed.
///
/// A session whose control stream never opened has nothing to send GOAWAY on
/// and goes straight to the close.
fn session_drain_out(sess: &H3Session, out: &mut [u8]) -> Option<(usize, SessCommit)> {
    let session = sess.session_id;

    if !sess.goaway_sent && sess.ctrl.state == LocalUniState::Ready && sess.conn_error == 0 {
        let mut id = [0u8; H3_VARINT_MAX];
        let idn = encode_varint(sess.goaway_id, &mut id);
        if idn == 0 {
            return None;
        }
        let mut framed = [0u8; 24];
        let hn = build_h3_frame_header(H3_FRAME_GOAWAY, idn, &mut framed);
        if hn == 0 || hn + idn > framed.len() {
            return None;
        }
        framed[hn..hn + idn].copy_from_slice(&id[..idn]);
        let total = hn + idn;
        let plen = mux::STREAM_DATA_PREFIX + total;
        if out.len() < FRAME_HDR + plen {
            return None;
        }
        out[0] = mux::CMD_MUX_STREAM_SEND;
        out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
        out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
        out[FRAME_HDR + 4..FRAME_HDR + 8].copy_from_slice(&sess.ctrl.handle.to_le_bytes());
        out[FRAME_HDR + 8..FRAME_HDR + 8 + total].copy_from_slice(&framed[..total]);
        return Some((FRAME_HDR + plen, SessCommit::GoawaySent));
    }

    let plen = mux::SESSION_ID_BYTES + 1 + mux::APP_ERROR_BYTES;
    if out.len() < FRAME_HDR + plen {
        return None;
    }
    out[0] = mux::CMD_MUX_SESSION_CLOSE;
    out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
    out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
    out[FRAME_HDR + 4] = mux::STATUS_OK;
    out[FRAME_HDR + 5..FRAME_HDR + 13].copy_from_slice(&0u64.to_le_bytes());
    Some((FRAME_HDR + plen, SessCommit::Closed))
}

/// The per-session half of the above, shared with the client.
///
/// Both roles owe the same connection preamble — RFC 9114 §6.2.1 requires
/// it of an endpoint, not of a server — so it is written once. A second
/// copy in the client is how the two drift, and the drift shows up as one
/// role interoperating and the other not.
///
/// Returns `None` when the session owes nothing right now, including while
/// an open is outstanding: nothing else may go out on the session until
/// the transport has answered it.
///
/// Nothing is mutated here. The frame is staged into `out` and the state
/// change it implies is returned as a [`SessCommit`] for the caller to
/// apply once the transport has taken the whole frame — see [`H3Commit`].
pub(crate) fn session_preamble_out(
    sess: &H3Session,
    out: &mut [u8],
) -> Option<(usize, SessCommit)> {
    let session = sess.session_id;

    // A connection error supersedes everything: nothing further on this
    // connection can be trusted, so there is no point finishing a preamble
    // or a response first.
    if sess.conn_error_pending {
        let code = sess.conn_error;
        let plen = mux::SESSION_ID_BYTES + 1 + mux::APP_ERROR_BYTES;
        if out.len() < FRAME_HDR + plen {
            return None;
        }
        out[0] = mux::CMD_MUX_SESSION_CLOSE;
        out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
        out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
        out[FRAME_HDR + 4] = mux::STATUS_PROTOCOL_ERROR;
        out[FRAME_HDR + 5..FRAME_HDR + 13].copy_from_slice(&code.to_le_bytes());
        return Some((FRAME_HDR + plen, SessCommit::ConnError));
    }

    // Preamble, in order: control, QPACK encoder, QPACK decoder.
    for which in 0..3usize {
        let uni = match which {
            0 => sess.ctrl,
            1 => sess.qpack_enc,
            _ => sess.qpack_dec,
        };
        match uni.state {
            LocalUniState::Idle => {
                let plen = mux::SESSION_ID_BYTES + 1;
                if out.len() < FRAME_HDR + plen {
                    return None;
                }
                out[0] = mux::CMD_MUX_STREAM_OPEN;
                out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
                out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
                out[FRAME_HDR + 4] = mux::STREAM_FLAG_UNI;
                return Some((FRAME_HDR + plen, SessCommit::UniOpening(which as u8)));
            }
            // Waiting on the transport's answer.
            LocalUniState::Opening => return None,
            LocalUniState::Open => {
                // The stream-type prefix, and on the control stream the
                // SETTINGS frame that must be its first.
                let mut body = [0u8; 64];
                let mut n = 0usize;
                let vn = encode_varint(uni.stream_type, &mut body[n..]);
                if vn == 0 {
                    return None;
                }
                n += vn;
                if which == 0 {
                    let sn = build_local_settings(&mut body[n..]);
                    if sn == 0 {
                        return None;
                    }
                    n += sn;
                }
                let plen = mux::STREAM_DATA_PREFIX + n;
                if out.len() < FRAME_HDR + plen {
                    return None;
                }
                out[0] = mux::CMD_MUX_STREAM_SEND;
                out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
                out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
                out[FRAME_HDR + 4..FRAME_HDR + 8].copy_from_slice(&uni.handle.to_le_bytes());
                out[FRAME_HDR + 8..FRAME_HDR + 8 + n].copy_from_slice(&body[..n]);
                return Some((FRAME_HDR + plen, SessCommit::UniReady(which as u8)));
            }
            // Done, or the transport had no capacity for it. A refused
            // critical stream is not retried: the pool is fixed, so the
            // next attempt would be refused too.
            LocalUniState::Ready | LocalUniState::Refused => {}
        }
    }
    None
}

/// Whether one of the preamble opens is still awaiting an answer.
///
/// This, not the caller's own state, is what decides whether a
/// `MSG_MUX_STREAM_OPENED` is answering a preamble stream or a request
/// stream. Keying on caller state instead would mis-route the first
/// request open of any connection whose caller had not yet advanced.
pub(crate) fn preamble_open_outstanding(sess: &H3Session) -> bool {
    sess.ctrl.state == LocalUniState::Opening
        || sess.qpack_enc.state == LocalUniState::Opening
        || sess.qpack_dec.state == LocalUniState::Opening
}

/// Whether a session has finished handing its preamble to the transport.
pub(crate) fn preamble_done(sess: &H3Session) -> bool {
    matches!(
        sess.ctrl.state,
        LocalUniState::Ready | LocalUniState::Refused
    ) && matches!(
        sess.qpack_enc.state,
        LocalUniState::Ready | LocalUniState::Refused
    ) && matches!(
        sess.qpack_dec.state,
        LocalUniState::Ready | LocalUniState::Refused
    )
}

/// Encode a value as a QUIC varint (RFC 9000 §16).
///
/// Used for a unidirectional stream's type prefix and for the stream
/// identifier GOAWAY carries — both are bare varints rather than frames.
fn encode_varint(value: u64, out: &mut [u8]) -> usize {
    // `build_h3_frame_header` writes a type and a length; here only the
    // type is wanted, so a zero-length "frame" gives the varint plus one
    // trailing zero byte. Written directly instead, to avoid emitting a
    // stray byte onto a stream whose first bytes are load-bearing.
    let mut tmp = [0u8; 16];
    let n = build_h3_frame_header(value, 0, &mut tmp);
    if n < 2 || n - 1 > out.len() {
        return 0;
    }
    // The last byte is the zero length; drop it.
    out[..n - 1].copy_from_slice(&tmp[..n - 1]);
    n - 1
}

/// Drain the next queued frame, staging and committing it in one call.
///
/// For a sink that cannot refuse a write. Anything driving a real channel must
/// use [`stage_next_out`] and [`commit_out`] separately, because the commit is
/// only correct once the transport has taken the whole frame — so no shipped
/// path uses this, and it stays out of the flash image.
#[cfg(feature = "host-test")]
pub fn pump_next_out(st: &mut H3State, out: &mut [u8]) -> Option<usize> {
    let (n, what) = stage_next_out(st, out)?;
    commit_out(st, what);
    Some(n)
}

/// Stage the next outbound frame without moving any state.
///
/// The companion of [`commit_out`]: this writes the frame into `out` and
/// says what accepting it would settle; nothing in `st` changes until the
/// caller applies that commit. A caller whose sink can refuse a write must
/// use the pair, so the refused bytes are staged again next step instead of
/// being counted as sent.
///
/// Order is session-scoped work, then resets, then closes, then response
/// bytes. Stream work round-robins from `emit_cursor` so one stream with a
/// large response cannot starve another — the same fairness `h2.rs` gives its
/// own emission cursor.
///
/// Chunks are capped at `MUX_QUIC_STREAM_SEND_MAX`, which the contract states is
/// the engine's single-MTU stream send buffer: a larger reliable write is
/// rejected outright by the provider, not truncated, so exceeding it would lose
/// the response rather than slow it down.
pub fn stage_next_out(st: &H3State, out: &mut [u8]) -> Option<(usize, H3Commit)> {
    let hdr = FRAME_HDR + mux::STREAM_DATA_PREFIX;
    if out.len() <= hdr {
        return None;
    }
    // Session-scoped work first. A response cannot precede the control
    // stream that carries our SETTINGS: RFC 9114 §6.2.1 makes SETTINGS the
    // first frame an endpoint sends, and a peer that receives a response
    // beforehand is entitled to treat the connection as broken.
    if let Some(staged) = session_next_out(st, out) {
        return Some(staged);
    }
    let max_payload = (out.len() - hdr)
        .min(mux::MUX_QUIC_STREAM_SEND_MAX)
        .min(u16::MAX as usize - mux::STREAM_DATA_PREFIX);

    // A stream that broke a rule owes a RESET_STREAM before anything else:
    // whatever was queued on it is not going to be sent, and the peer needs
    // the reason rather than silence.
    for step in 0..MAX_H3_STREAMS {
        let idx = (st.emit_cursor as usize + step) % MAX_H3_STREAMS;
        if !st.slots[idx].allocated || st.slots[idx].reset_code == 0 {
            continue;
        }
        let (session, stream, code) = {
            let slot = &st.slots[idx];
            (slot.session_id, slot.stream_id as u32, slot.reset_code)
        };
        let plen = mux::STREAM_DATA_PREFIX + mux::STREAM_APP_ERROR_BODY;
        if out.len() < FRAME_HDR + plen {
            return None;
        }
        out[0] = mux::CMD_MUX_STREAM_RESET;
        out[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
        out[FRAME_HDR..FRAME_HDR + 4].copy_from_slice(&session.to_le_bytes());
        out[FRAME_HDR + 4..FRAME_HDR + 8].copy_from_slice(&stream.to_le_bytes());
        out[FRAME_HDR + 8..FRAME_HDR + 16].copy_from_slice(&code.to_le_bytes());
        return Some((FRAME_HDR + plen, H3Commit::ResetSent(idx)));
    }

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
            return Some((FRAME_HDR + plen, H3Commit::CloseSent(idx)));
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

        return Some((hdr + take, H3Commit::DataSent { idx, take, last }));
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
    Ok(dispatch_request_bounded(s, &req, out, tmpl_cap, u32::MAX))
}

/// Re-drive requests held for the peer's SETTINGS, for host tests.
///
/// # Safety
///
/// `state` must point at a `module_state` buffer initialised by `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_retry_gated_streams(
    st: &mut H3State,
    state: *mut u8,
) -> Option<H3StreamOutcome> {
    let s = &*(state as *const super::super::HttpState);
    retry_gated_streams(st, s)
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
    {
        let st = &mut *(&mut s.h3 as *mut H3State);
        st.draining = s.server.draining != 0;
        if st.draining {
            begin_drain(st);
        }
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
        //
        // Sized from the TRANSPORT's published bound, not from a protocol
        // budget. `H3_RECV_BUF` is a per-slot request-head accumulator and has
        // no bearing on how much the transport may hand over at once; sizing
        // this from it truncated any `MSG_MUX_STREAM_RX` above 1 KiB, and
        // because the channel frame had already been consumed the loss was
        // silent — a short request head, or a body missing its tail, with no
        // error anywhere.
        // Gated, not merely intended: a scratch smaller than the transport's
        // published frame bound cannot hold what the provider is entitled to
        // send, and the resulting truncation is silent at every layer.
        const _: () = assert!(
            mux::MUX_QUIC_STREAM_RX_FRAME_MAX
                >= mux::STREAM_DATA_PREFIX + mux::MUX_QUIC_STREAM_RX_MAX
        );
        let mut frame = [0u8; mux::MUX_QUIC_STREAM_RX_FRAME_MAX];
        if payload_len > frame.len() {
            // Cannot happen against a conforming provider; if it does, the
            // stream is failed rather than half-copied. A prefix of a frame is
            // indistinguishable from a complete one downstream.
            log_h3(s, b"[http] h3 mux frame over transport bound - dropped");
            continue;
        }
        let n = payload_len;
        core::ptr::copy_nonoverlapping(
            s.net_buf.as_ptr().add(super::super::NET_FRAME_HDR),
            frame.as_mut_ptr(),
            n,
        );

        let st = &mut *(&mut s.h3 as *mut H3State);
        let mut outcome = pump_mux_frame(st, s, msg_type, &frame[..n]);
        // A session event may have been the peer's SETTINGS, which is what
        // a request held back by `responses_gated` was waiting for.
        if matches!(outcome, H3StreamOutcome::SessionEvent) {
            if let Some(o) = retry_gated_streams(st, s) {
                outcome = o;
            }
        }
        match outcome {
            H3StreamOutcome::StreamError(e) => {
                // Reset the stream with the RFC 9114 §8.1 code. The peer
                // learns WHICH rule its request broke, rather than watching
                // a stream go quiet — which it cannot distinguish from a
                // slow server.
                let _ = e;
                log_h3(s, b"[http] h3 stream error");
            }
            H3StreamOutcome::ConnectionError(_) => {
                // The session has already been failed; `session_next_out`
                // emits the close carrying the code.
                log_h3(s, b"[http] h3 connection error");
            }
            H3StreamOutcome::SlotsExhausted => log_h3(s, b"[http] h3 slots exhausted"),
            H3StreamOutcome::DrainRefused => log_h3(s, b"[http] h3 draining - stream refused"),
            H3StreamOutcome::ResponseTooLarge => log_h3(s, b"[http] h3 response too large"),
            H3StreamOutcome::HandlerNotShared(_) => {
                s.server.h3_handler_unavailable = s.server.h3_handler_unavailable.wrapping_add(1);
                log_h3(s, b"[http] h3 501 - handler not served over h3")
            }
            H3StreamOutcome::PeerFieldLimit => {
                s.server.h3_field_limit_refused = s.server.h3_field_limit_refused.wrapping_add(1);
                log_h3(
                    s,
                    b"[http] h3 peer max_field_section_size too small to answer",
                )
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
        let Some((n, what)) = stage_next_out(st, &mut frame) else {
            break;
        };
        if (sys.channel_write)(out_chan, frame.as_ptr(), n) <= 0 {
            // The write failed after the poll said ready — POLL_OUT reports
            // capacity, not that a whole frame fits. Staging moved nothing,
            // so the commit is simply not applied and the identical frame is
            // staged again next step.
            s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
            break;
        }
        commit_out(st, what);
        s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add((n - FRAME_HDR) as u32);
    }

    let st = &mut *(&mut s.h3 as *mut H3State);
    if st.draining && drained(st) {
        return 1;
    }
    0
}

/// Terminate what a drain cannot wait out, so the module can reach a state
/// where nothing is owed.
///
/// Two kinds of work never end on their own. A WebSocket tunnel is long-lived
/// by construction, so waiting for the peer to close it is waiting forever; it
/// is told `1001 going away`, which is what lets a client reconnect instead of
/// reporting a broken connection. And a session this module owes nothing on —
/// one that never negotiated HTTP/3, or one already closed with a connection
/// error — is released rather than left holding the drain open for a peer that
/// is not listening.
///
/// # Safety
///
/// `st` must be a live `H3State`; `ws_queue_close` writes through its slot
/// buffers.
unsafe fn begin_drain(st: &mut H3State) {
    let mut idx = 0;
    while idx < MAX_H3_STREAMS {
        if st.slots[idx].allocated && st.slots[idx].ws_active && st.slots[idx].pending_out() == 0 {
            ws_queue_close(st, idx, super::super::wire::ws::CLOSE_GOING_AWAY);
        }
        idx += 1;
    }
    let mut si = 0;
    while si < MAX_H3_SESSIONS {
        let owes_nothing = st.sessions[si].allocated
            && (!st.sessions[si].is_h3
                || (st.sessions[si].conn_error != 0 && !st.sessions[si].conn_error_pending));
        if owes_nothing && !session_has_live_stream(st, si) {
            st.sessions[si].release();
        }
        si += 1;
    }
}

/// Whether the drain has reached semantic quiescence.
///
/// Every admitted stream has been answered and released, and every session
/// has been told the endpoint is going away and closed. Reporting this is what
/// lets the scheduler tear the instance down immediately instead of falling
/// through to its forced-drain timeout, which always loses whatever was still
/// in flight and never says how much.
fn drained(st: &H3State) -> bool {
    let mut k = 0;
    while k < MAX_H3_STREAMS {
        if st.slots[k].allocated {
            return false;
        }
        k += 1;
    }
    let mut si = 0;
    while si < MAX_H3_SESSIONS {
        if st.sessions[si].allocated {
            return false;
        }
        si += 1;
    }
    true
}
