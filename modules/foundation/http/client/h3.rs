//! HTTP/3 client (RFC 9114 + RFC 9204) over Fluxor's `mux` contract.
//!
//! The other half of owning HTTP/3, and it sits here rather than beside the
//! server for the reason the module header gives: a file is named for what it
//! is, its directory for whose it is. It was written inside the server's h3
//! file while h3 was server-only, which made the one capability three documents
//! denied having also the one capability filed under the wrong role.
//!
//! `quic` carries an h3 client of its own, but it issues a hardcoded `GET /` to
//! `localhost` — a transport self-test, the mirror of its hardcoded server
//! table. An application client needs to choose its own method, authority and
//! path, and to hand the response body onward, which is protocol work and
//! therefore Wave's.
//!
//! The transport still owns everything below: `CMD_MUX_STREAM_OPEN` asks it for
//! a stream, and the id it returns is the only thing this module knows about
//! QUIC's stream space.
//!
//! The codecs are shared with the server, not duplicated: `wire::h3` frames and
//! `wire::qpack` field sections are role-neutral, which is what lets one
//! implementation serve both directions.

use super::super::connection::{mux, FRAME_HDR};
// The connection-scoped HTTP/3 machinery, shared with the server role.
// RFC 9114 §6.2.1 asks it of an ENDPOINT, not of a server, so both roles
// use one implementation rather than two that can disagree.
use super::super::server::h3::{
    commit_session, local_uni_opened, peer_uni_alloc, peer_uni_slot, preamble_done,
    preamble_open_outstanding, session_preamble_out, uni_ingest, H3Session, H3_ALPN_TOKEN,
};
use super::super::wire::h3::{
    build_h3_frame_header, parse_h3_frame_head, H3Frame, H3_FRAME_DATA, H3_FRAME_HEADERS,
};
use super::super::wire::qpack;

/// Scratch for one decoded QPACK field. Client-owned for the same reason the
/// buffers below are.
const H3_FIELD_SCRATCH: usize = 512;

/// Response head accumulated for one client exchange.
///
/// Client-owned rather than shared with `server::h3`: the two happen to want
/// the same number today, but a client's inbound budget and a server's are
/// different questions, and importing the server's would make the client
/// depend on the role it is deliberately separate from.
pub const H3_CLIENT_RECV_BUF: usize = 1024;
/// Response body accumulated for one client exchange, at the contract's
/// payload ceiling — the same number h1 and h2 accumulate to, so a response
/// this client can hold does not depend on which generation carried it.
pub const H3_CLIENT_BODY_BUF: usize = super::super::exchange::PAYLOAD_MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H3ClientState {
    /// No session yet. The transport has not announced one, so there is
    /// nothing to open a stream ON.
    ///
    /// The client WAITS for that announcement rather than assuming session
    /// 0: which session id a connection gets is the transport's to
    /// allocate, and a client that guessed would address a session that
    /// does not exist the moment more than one is in play.
    Idle,
    /// A session exists and its connection preamble — control and QPACK
    /// streams, SETTINGS — is being opened. RFC 9114 §6.2.1 puts SETTINGS
    /// first, so no request may go out until this completes.
    Preamble,
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
    /// The connection-scoped HTTP/3 state, shared in shape with the
    /// server's. Both roles owe the same preamble and read the peer's
    /// SETTINGS the same way, so the state and the code are the same; a
    /// second copy here is how the two drift.
    pub session: H3Session,
    pub session_id: u32,
    /// The transport's opaque handle for the request stream.
    pub stream_id: u32,
    /// Decoded `:status`, once the response headers arrive.
    pub status: u16,
    pub recv_buf: [u8; H3_CLIENT_RECV_BUF],
    pub recv_len: usize,
    pub body: [u8; H3_CLIENT_BODY_BUF],
    pub body_len: usize,
    /// The response body has been handed to the app port.
    pub body_emitted: bool,
    pub expected_len: Option<u64>,
    pub trailers: bool,
    pub informational: u8,
    pub head_only: bool,
    pub total_body: u64,
    pub frame_remaining: u64,
    pub frame_kind: u64,
    pub reading_frame: bool,
    /// The request head has been taken by the transport in full. Until it
    /// has, the identical frame is offered again: a request the channel
    /// refused is one the server never sees, and the exchange would sit
    /// awaiting a response to something never sent.
    pub request_sent: bool,
    pub request_offset: usize,
    /// The FIN closing the request half has been taken. A server waits for
    /// it before responding, so a refused close is retried rather than
    /// dropped.
    pub fin_sent: bool,
}

impl H3Client {
    pub const fn new() -> Self {
        Self {
            state: H3ClientState::Idle,
            session: H3Session::empty(),
            session_id: 0,
            stream_id: 0,
            status: 0,
            recv_buf: [0; H3_CLIENT_RECV_BUF],
            recv_len: 0,
            body: [0; H3_CLIENT_BODY_BUF],
            body_len: 0,
            body_emitted: false,
            expected_len: None,
            trailers: false,
            informational: 0,
            head_only: false,
            total_body: 0,
            frame_remaining: 0,
            frame_kind: 0,
            reading_frame: false,
            request_sent: false,
            request_offset: 0,
            fin_sent: false,
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
    response_fields(block, false)?.0
}

fn response_fields(block: &[u8], trailers: bool) -> Option<(Option<u16>, Option<u64>)> {
    let mut off = qpack::qpack_decode_block_prefix(block)?;
    let mut scratch = [0u8; H3_FIELD_SCRATCH];
    let mut status = None;
    let mut length = None;
    let mut regular = false;
    while off < block.len() {
        let r = qpack::qpack_decode_field_into(&block[off..], &mut scratch)?;
        if r.consumed == 0 {
            return None;
        }
        let name = &scratch[r.name.0..r.name.1];
        let value = &scratch[r.value.0..r.value.1];
        if name.is_empty()
            || name
                .iter()
                .any(|b| b.is_ascii_uppercase() || *b <= 32 || *b >= 127)
            || value.iter().any(|b| *b == 0 || *b == 10 || *b == 13)
        {
            return None;
        }
        if name.starts_with(b":") {
            if trailers
                || regular
                || name != b":status"
                || status.is_some()
                || value.len() != 3
                || !value.iter().all(u8::is_ascii_digit)
            {
                return None;
            }
            let code = u16::from(value[0] - b'0') * 100
                + u16::from(value[1] - b'0') * 10
                + u16::from(value[2] - b'0');
            if !(100..600).contains(&code) || code == 101 {
                return None;
            }
            status = Some(code);
        } else {
            regular = true;
            if matches!(
                name,
                b"connection"
                    | b"transfer-encoding"
                    | b"upgrade"
                    | b"keep-alive"
                    | b"proxy-connection"
            ) {
                return None;
            }
            if name == b"content-length" {
                if trailers || length.is_some() || value.is_empty() {
                    return None;
                }
                let mut n = 0u64;
                for b in value {
                    if !b.is_ascii_digit() {
                        return None;
                    }
                    n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
                }
                length = Some(n);
            }
        }
        off += r.consumed;
    }
    if !trailers && status.is_none() {
        return None;
    }
    Some((status, length))
}

/// Feed one `mux` frame to the client.
pub fn client_mux_frame(c: &mut H3Client, msg_type: u8, payload: &[u8]) -> H3ClientState {
    if payload.len() < mux::SESSION_ID_BYTES {
        return c.state;
    }
    let session = mux::session_id(payload);

    // Session-scoped events first: their bytes 4..8 are not a stream
    // handle, and reading them as one would address a stream that does not
    // exist.
    if msg_type == mux::MSG_MUX_SESSION_OPENED {
        if c.session.allocated || c.state != H3ClientState::Idle {
            return c.state;
        }
        if payload.len() < mux::SESSION_ID_BYTES + mux::SESSION_OPENED_BODY_MIN {
            return c.state;
        }
        let b = &payload[mux::SESSION_ID_BYTES..];
        if b[0] != mux::STATUS_OK {
            c.state = H3ClientState::Failed;
            return c.state;
        }
        let alpn_len = b[2] as usize;
        if b.len() < 3 + alpn_len {
            return c.state;
        }
        // The transport reports the negotiated token; deciding it selects
        // HTTP/3 is this module's call.
        if &b[3..3 + alpn_len] != H3_ALPN_TOKEN {
            return c.state;
        }
        c.session = H3Session::empty();
        c.session.allocated = true;
        c.session.session_id = session;
        c.session.is_h3 = true;
        c.session_id = session;
        if c.state == H3ClientState::Idle {
            c.state = H3ClientState::Preamble;
        }
        return c.state;
    }
    if session != c.session_id {
        return c.state;
    }
    if msg_type == mux::MSG_MUX_SESSION_CLOSED {
        c.session.allocated = false;
        if !matches!(c.state, H3ClientState::Complete | H3ClientState::Failed) {
            c.state = H3ClientState::Failed;
        }
        return c.state;
    }
    if payload.len() < mux::STREAM_DATA_PREFIX {
        return c.state;
    }
    let handle = mux::stream_id(payload);

    match msg_type {
        mux::MSG_MUX_STREAM_ACCEPTED => {
            if payload.len() < mux::STREAM_DATA_PREFIX + mux::STREAM_ACCEPTED_BODY {
                return c.state;
            }
            let flags = payload[mux::STREAM_DATA_PREFIX];
            if flags & mux::STREAM_FLAG_UNI != 0 {
                // The server's control and QPACK streams. Registered now,
                // classified from their first bytes.
                let _ = peer_uni_alloc(&mut c.session, handle);
            }
        }
        mux::MSG_MUX_STREAM_OPENED => {
            if payload.len() < mux::STREAM_DATA_PREFIX + mux::STREAM_OPENED_BODY {
                return c.state;
            }
            let status = payload[mux::STREAM_DATA_PREFIX];
            // Which open this answers is decided by whether a preamble
            // open is outstanding, not by the client's own state: the
            // transport does not say which request it is answering, and
            // one open is in flight at a time precisely so this is
            // unambiguous.
            if preamble_open_outstanding(&c.session) {
                local_uni_opened(&mut c.session, handle, status);
                if status != mux::STATUS_OK {
                    c.state = H3ClientState::Failed;
                }
                return c.state;
            }
            if c.state != H3ClientState::Opening {
                return c.state;
            }
            if status != mux::STATUS_OK {
                c.state = H3ClientState::Failed;
                return c.state;
            }
            c.session_id = session;
            c.stream_id = handle;
            c.state = H3ClientState::AwaitingResponse;
        }
        mux::MSG_MUX_STREAM_RX => {
            if payload.len() < mux::STREAM_DATA_PREFIX {
                return c.state;
            }
            // A server unidirectional stream carries the connection's
            // control or QPACK traffic, not our response.
            if let Some(ui) = peer_uni_slot(&c.session, handle) {
                let body = &payload[mux::STREAM_DATA_PREFIX..];
                if let Some(code) = uni_ingest(&mut c.session, ui, body) {
                    c.session.fail(code);
                    c.state = H3ClientState::Failed;
                }
                return c.state;
            }
            if handle != c.stream_id || c.state != H3ClientState::AwaitingResponse {
                return c.state;
            }
            let body = &payload[mux::STREAM_DATA_PREFIX..];
            client_ingest(c, body);
        }
        mux::MSG_MUX_STREAM_RESET => {
            // The server abandoned the exchange. Whatever arrived is a
            // fragment of a response it withdrew, so reporting Complete
            // would present a truncated body as a whole one.
            if handle == c.stream_id && c.state == H3ClientState::AwaitingResponse {
                c.state = H3ClientState::Failed;
            }
        }
        mux::MSG_MUX_STREAM_CLOSED => {
            if peer_uni_slot(&c.session, handle).is_some() {
                // RFC 9114 §6.2.1: a critical stream the connection
                // depends on for its whole life has ended.
                c.state = H3ClientState::Failed;
                return c.state;
            }
            if handle == c.stream_id && c.state == H3ClientState::AwaitingResponse {
                // The peer finished. A response without a `:status` never
                // arrived, and reporting Complete would invent one.
                c.state = if c.status >= 200
                    && c.recv_len == 0
                    && !c.reading_frame
                    && (c.head_only
                        || c.status == 304
                        || c.expected_len.is_none_or(|n| n == c.total_body))
                {
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

/// Feed a response without buffering whole DATA frames. Metadata has its own
/// bound; unknown extension payloads are skipped without allocating for length.
fn client_ingest(c: &mut H3Client, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        if !c.reading_frame {
            if c.recv_len == 16 {
                c.state = H3ClientState::Failed;
                return;
            }
            c.recv_buf[c.recv_len] = bytes[0];
            c.recv_len += 1;
            bytes = &bytes[1..];
            let Some((kind, len, _)) = parse_h3_frame_head(&c.recv_buf[..c.recv_len]) else {
                continue;
            };
            c.recv_len = 0;
            c.frame_kind = kind;
            c.frame_remaining = len;
            c.reading_frame = true;
            if matches!(kind, 2..=5 | 7 | 13)
                || (kind == H3_FRAME_HEADERS && len > H3_CLIENT_RECV_BUF as u64)
                || (kind == H3_FRAME_DATA
                    && (c.status < 200
                        || c.trailers
                        || c.head_only
                        || matches!(c.status, 204 | 304)))
            {
                c.state = H3ClientState::Failed;
                return;
            }
        }
        let n = c.frame_remaining.min(bytes.len() as u64) as usize;
        if c.frame_kind == H3_FRAME_HEADERS {
            c.recv_buf[c.recv_len..c.recv_len + n].copy_from_slice(&bytes[..n]);
            c.recv_len += n;
        } else if c.frame_kind == H3_FRAME_DATA {
            if n > H3_CLIENT_BODY_BUF - c.body_len
                || c.total_body.checked_add(n as u64).is_none()
                || c.expected_len
                    .is_some_and(|len| c.total_body + n as u64 > len)
            {
                c.state = H3ClientState::Failed;
                return;
            }
            c.body[c.body_len..c.body_len + n].copy_from_slice(&bytes[..n]);
            c.body_len += n;
            c.total_body += n as u64;
        }
        bytes = &bytes[n..];
        c.frame_remaining -= n as u64;
        if c.frame_remaining == 0 {
            c.reading_frame = false;
            if c.frame_kind == H3_FRAME_HEADERS {
                let trailer = c.status >= 200;
                match response_fields(&c.recv_buf[..c.recv_len], trailer) {
                    Some((code, length)) if !c.trailers => {
                        if trailer {
                            c.trailers = true;
                        } else if let Some(code) = code {
                            if code < 200 {
                                c.informational += 1;
                                if c.informational > 16 {
                                    c.state = H3ClientState::Failed;
                                    return;
                                }
                            } else {
                                c.status = code;
                                c.expected_len = length;
                                if code == 204 && length.is_some() {
                                    c.state = H3ClientState::Failed;
                                    return;
                                }
                            }
                        }
                    }
                    _ => {
                        c.state = H3ClientState::Failed;
                        return;
                    }
                }
            }
            c.recv_len = 0;
        }
    }
}

/// Retain the session identity until the transport accepts cancellation.
pub(crate) unsafe fn close_session(s: &mut super::super::HttpState) -> bool {
    if !s.h3_client.session.allocated {
        return true;
    }
    let mut frame = [0u8; FRAME_HDR + mux::SESSION_ID_BYTES + 1 + mux::APP_ERROR_BYTES];
    frame[0] = mux::CMD_MUX_SESSION_CLOSE;
    let plen = (frame.len() - FRAME_HDR) as u16;
    frame[1..3].copy_from_slice(&plen.to_le_bytes());
    mux::put_session_id(&mut frame[FRAME_HDR..], s.h3_client.session_id);
    frame[FRAME_HDR + 4] = mux::STATUS_OK;
    frame[FRAME_HDR + 5..].copy_from_slice(&0x10Cu64.to_le_bytes());
    if ((*s.syscalls).channel_write)(s.net_out_chan, frame.as_ptr(), frame.len())
        != frame.len() as i32
    {
        return false;
    }
    s.h3_client.session.allocated = false;
    true
}

/// Reset exchange-local state while preserving the negotiated connection.
pub(crate) fn next_request(s: &mut super::super::HttpState) {
    let c = &mut s.h3_client;
    c.state = if c.session.allocated {
        H3ClientState::Preamble
    } else {
        H3ClientState::Idle
    };
    c.stream_id = 0;
    c.status = 0;
    c.recv_len = 0;
    c.body_len = 0;
    c.total_body = 0;
    c.frame_remaining = 0;
    c.reading_frame = false;
    c.body_emitted = false;
    c.expected_len = None;
    c.trailers = false;
    c.informational = 0;
    c.head_only = s.client.method == super::super::wire::method::METHOD_HEAD;
    c.request_sent = false;
    c.request_offset = 0;
    c.fin_sent = false;
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

    let now = super::super::dev_millis(sys);
    if s.client.phase == super::Phase::Init {
        s.client.phase = super::Phase::SendRequest;
        s.client.request_start_ms = now;
        s.client.progress_ms = now;
        s.h3_client.head_only = s.client.method == super::super::wire::method::METHOD_HEAD;
    }
    let expired = |start, budget: u32| budget != 0 && now.wrapping_sub(start) >= u64::from(budget);
    if s.client.draining != 0
        || s.client.request_invalid != 0
        || (!s.h3_client.body_emitted
            && (expired(s.client.request_start_ms, s.client.client_total_ms)
                || expired(s.client.progress_ms, s.client.client_stall_ms)
                || (s.h3_client.fin_sent
                    && s.h3_client.status == 0
                    && expired(s.client.response_start_ms, s.client.client_header_ms))))
    {
        s.h3_client.state = H3ClientState::Failed;
    }
    if s.h3_client.state == H3ClientState::Failed {
        if !close_session(s) {
            return 0;
        }
        #[cfg(feature = "exchange")]
        if super::exchange::armed(s) {
            super::exchange::fail(s);
            return 0;
        }
        return if s.client.draining != 0 { 1 } else { -1 };
    }

    #[cfg(feature = "exchange")]
    let streaming = !super::exchange::armed(s);
    #[cfg(not(feature = "exchange"))]
    let streaming = true;
    if streaming && s.h3_client.body_len != 0 {
        let c = &mut s.h3_client;
        if s.client.out_chan < 0 {
            c.body_len = 0;
        } else {
            let written = (sys.channel_write)(
                s.client.out_chan,
                c.body.as_ptr(),
                c.body_len.min(super::OUTPUT_CHUNK),
            );
            if written > 0 && written as usize <= c.body_len {
                let n = written as usize;
                c.body.copy_within(n..c.body_len, 0);
                c.body_len -= n;
                s.client.progress_ms = now;
            }
        }
        if c.body_len != 0 {
            return 0;
        }
    }

    // Idle means the transport has not announced a session yet. There is
    // nothing to open a stream on, and guessing session 0 would address a
    // session that need not exist — so the loop falls through to the
    // ingress drain and waits for MSG_MUX_SESSION_OPENED.
    //
    // Preamble means a session exists and its control and QPACK streams
    // are being opened. RFC 9114 §6.2.1 makes SETTINGS the first frame an
    // endpoint sends, so the request stream waits for that to finish.
    if s.h3_client.state == H3ClientState::Preamble {
        let mut frame = [0u8; FRAME_HDR + mux::STREAM_DATA_PREFIX + 64];
        if let Some((n, what)) = session_preamble_out(&s.h3_client.session, &mut frame) {
            let poll = (sys.channel_poll)(out_chan, super::super::POLL_OUT);
            // All-or-nothing: a partial mux frame would desync the
            // transport's reader. The preamble advances only once the whole
            // frame is taken, so a refusal restages the identical bytes
            // rather than skipping a critical stream.
            if poll > 0
                && (poll as u32) & super::super::POLL_OUT != 0
                && (sys.channel_write)(out_chan, frame.as_ptr(), n) == n as i32
            {
                commit_session(&mut s.h3_client.session, what);
            }
        } else if preamble_done(&s.h3_client.session) {
            // Preamble handed over: ask for the request stream, on the
            // session the transport named.
            let plen = mux::SESSION_ID_BYTES + 1;
            let mut open = [0u8; FRAME_HDR + mux::SESSION_ID_BYTES + 1];
            open[0] = mux::CMD_MUX_STREAM_OPEN;
            open[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
            mux::put_session_id(&mut open[FRAME_HDR..], s.h3_client.session_id);
            open[FRAME_HDR + 4] = mux::STREAM_FLAG_BIDI;
            let poll = (sys.channel_poll)(out_chan, super::super::POLL_OUT);
            if poll > 0
                && (poll as u32) & super::super::POLL_OUT != 0
                && (sys.channel_write)(out_chan, open.as_ptr(), open.len()) == open.len() as i32
            {
                s.h3_client.state = H3ClientState::Opening;
            }
        }
        // Either way, fall through: the answer to whatever was just sent
        // arrives on the ingress drain below.
    }

    // Bound input work per scheduler step.
    for _ in 0..8 {
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
        // Sized from the transport's published bound, not from
        // `H3_CLIENT_RECV_BUF` — that is the response-head accumulator, a
        // protocol budget, and sizing the wire scratch from it truncated any
        // frame above it after the channel had already consumed it.
        let mut frame = [0u8; mux::MUX_QUIC_STREAM_RX_FRAME_MAX];
        if plen > frame.len() {
            // A conforming provider cannot exceed its own bound. Fail the
            // exchange rather than decode a prefix as if it were whole.
            s.h3_client.state = H3ClientState::Failed;
            continue;
        }
        let n = plen;
        core::ptr::copy_nonoverlapping(
            s.net_buf.as_ptr().add(super::super::NET_FRAME_HDR),
            frame.as_mut_ptr(),
            n,
        );
        let before = (
            s.h3_client.state,
            s.h3_client.recv_len,
            s.h3_client.body_len,
        );
        client_mux_frame(&mut s.h3_client, msg_type, &frame[..n]);
        if before
            != (
                s.h3_client.state,
                s.h3_client.recv_len,
                s.h3_client.body_len,
            )
        {
            s.client.progress_ms = now;
        }
        if s.h3_client.state == H3ClientState::Failed || (streaming && s.h3_client.body_len != 0) {
            break;
        }
    }

    // The stream is granted: send the request on it, then FIN the request
    // half. Each is retried until the transport takes it whole.
    if s.h3_client.state == H3ClientState::AwaitingResponse {
        client_send_request(s);
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
        // Graph-driven: answer the request that produced this response
        // instead of streaming it to `file_ctrl`. h3 has already accumulated
        // the whole body, so there is nothing to re-assemble here.
        #[cfg(feature = "exchange")]
        if super::exchange::busy(s) {
            s.client.last_status = s.h3_client.status;
            let n = s.h3_client.body_len;
            let src = s.h3_client.body.as_ptr();
            super::exchange::accumulate(s, src, n);
            super::exchange::complete(s);
            s.h3_client.body_emitted = true;
            return 0;
        }

        if s.h3_client.body_len == 0 {
            s.h3_client.body_emitted = true;
        }
    }
    0
}

/// Fields supplied by the application, before encoding the request head.
pub struct RequestHead<'a> {
    pub method: &'a [u8],
    pub authority: &'a [u8],
    pub path: &'a [u8],
    pub content_type: &'a [u8],
    pub body_len: usize,
}

/// Encode a configured request without truncating any field.
pub fn configured_request(head: &RequestHead<'_>, out: &mut [u8]) -> usize {
    if head.method.is_empty()
        || head.method.iter().any(|b| !b.is_ascii_uppercase())
        || head.method == b"CONNECT"
        || !head.path.starts_with(b"/")
        || head.path.iter().any(|b| *b <= 32 || *b == 127)
        || head.authority.is_empty()
        || head.authority.iter().any(|b| *b <= 32 || *b == 127)
        || head.content_type.iter().any(|b| *b < 32 || *b == 127)
    {
        return 0;
    }
    let mut block = [0u8; super::REQUEST_BUF_SIZE];
    let mut scheme = [0u8; 5];
    scheme.copy_from_slice(b"https");
    let mut n = encode_request_headers(head.method, &scheme, head.authority, head.path, &mut block);
    if n == 0 {
        return 0;
    }
    if !head.content_type.is_empty() {
        let mut name = [0u8; 12];
        name.copy_from_slice(b"content-type");
        let added = qpack::qpack_encode_field(&name, head.content_type, &mut block[n..]);
        if added == 0 {
            return 0;
        }
        n += added;
    }
    if head.body_len > 0 {
        let mut digits = [0u8; 20];
        let mut start = digits.len();
        let mut value = head.body_len;
        while value > 0 {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        let mut name = [0u8; 14];
        name.copy_from_slice(b"content-length");
        let added = qpack::qpack_encode_field(&name, &digits[start..], &mut block[n..]);
        if added == 0 {
            return 0;
        }
        n += added;
    }
    let mut frame_head = [0u8; 16];
    let hn = build_h3_frame_header(H3_FRAME_HEADERS, n, &mut frame_head);
    if hn == 0 || hn + n > out.len() {
        return 0;
    }
    out[..hn].copy_from_slice(&frame_head[..hn]);
    out[hn..hn + n].copy_from_slice(&block[..n]);
    hn + n
}

unsafe fn send_stream_bytes(s: &mut super::super::HttpState, bytes: &[u8]) -> bool {
    if bytes.len() > mux::MUX_QUIC_STREAM_SEND_MAX {
        return false;
    }
    let mut frame = [0u8; FRAME_HDR + mux::STREAM_DATA_PREFIX + mux::MUX_QUIC_STREAM_SEND_MAX];
    let plen = mux::STREAM_DATA_PREFIX + bytes.len();
    frame[0] = mux::CMD_MUX_STREAM_SEND;
    frame[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
    mux::put_session_id(&mut frame[FRAME_HDR..], s.h3_client.session_id);
    mux::put_stream_id(&mut frame[FRAME_HDR..], s.h3_client.stream_id);
    frame[FRAME_HDR + mux::STREAM_DATA_PREFIX..FRAME_HDR + plen].copy_from_slice(bytes);
    ((*s.syscalls).channel_write)(s.net_out_chan, frame.as_ptr(), FRAME_HDR + plen)
        == (FRAME_HDR + plen) as i32
}

/// Bound each send to the transport's maximum. Offsets advance only when the
/// complete mux record was accepted, including headers larger than one record.
unsafe fn client_send_request(s: &mut super::super::HttpState) {
    if s.h3_client.fin_sent {
        return;
    }
    if s.client.request_invalid != 0 {
        s.h3_client.state = H3ClientState::Failed;
        return;
    }
    if !s.h3_client.request_sent {
        let method = super::super::wire::method::method_name(s.client.method);
        let mut fallback = [0u8; 9];
        fallback.copy_from_slice(b"localhost");
        let authority = if s.client.authority_len == 0 {
            &fallback[..]
        } else {
            &s.client.authority[..s.client.authority_len as usize]
        };
        let head = RequestHead {
            method,
            authority,
            path: &s.client.path[..s.client.path_len as usize],
            content_type: &s.client.content_type[..s.client.content_type_len as usize],
            body_len: s.client.request_body_len as usize,
        };
        let mut req = [0u8; super::REQUEST_BUF_SIZE];
        let len = configured_request(&head, &mut req);
        if len == 0 {
            s.h3_client.state = H3ClientState::Failed;
            return;
        }
        let at = s.h3_client.request_offset;
        let end = (at + mux::MUX_QUIC_STREAM_SEND_MAX).min(len);
        if !send_stream_bytes(s, &req[at..end]) {
            return;
        }
        s.client.progress_ms = super::super::dev_millis(&*s.syscalls);
        s.h3_client.request_offset = end;
        if end < len {
            return;
        }
        s.h3_client.request_sent = true;
    }
    if s.client.request_body_sent < s.client.request_body_len {
        let at = s.client.request_body_sent as usize;
        let n = (s.client.request_body_len as usize - at).min(mux::MUX_QUIC_STREAM_SEND_MAX - 16);
        let mut frame = [0u8; mux::MUX_QUIC_STREAM_SEND_MAX];
        let hn = build_h3_frame_header(H3_FRAME_DATA, n, &mut frame);
        frame[hn..hn + n].copy_from_slice(&s.client.request_body[at..at + n]);
        if !send_stream_bytes(s, &frame[..hn + n]) {
            return;
        }
        s.client.progress_ms = super::super::dev_millis(&*s.syscalls);
        s.client.request_body_sent += n as u16;
        if s.client.request_body_sent < s.client.request_body_len {
            return;
        }
    }
    let plen = mux::STREAM_DATA_PREFIX + 1;
    let mut close = [0u8; FRAME_HDR + mux::STREAM_DATA_PREFIX + 1];
    close[0] = mux::CMD_MUX_STREAM_CLOSE;
    close[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
    mux::put_session_id(&mut close[FRAME_HDR..], s.h3_client.session_id);
    mux::put_stream_id(&mut close[FRAME_HDR..], s.h3_client.stream_id);
    close[FRAME_HDR + mux::STREAM_DATA_PREFIX] = mux::STATUS_OK;
    if ((*s.syscalls).channel_write)(s.net_out_chan, close.as_ptr(), close.len())
        == close.len() as i32
    {
        s.h3_client.fin_sent = true;
        s.client.response_start_ms = super::super::dev_millis(&*s.syscalls);
    }
}
