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
use super::super::wire::h3::{
    build_h3_frame_header, parse_h3_frame, H3Frame, H3_FRAME_DATA, H3_FRAME_HEADERS,
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
/// Response body accumulated for one client exchange.
pub const H3_CLIENT_BODY_BUF: usize = 1024;

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
    pub recv_buf: [u8; H3_CLIENT_RECV_BUF],
    pub recv_len: usize,
    pub body: [u8; H3_CLIENT_BODY_BUF],
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
            recv_buf: [0; H3_CLIENT_RECV_BUF],
            recv_len: 0,
            body: [0; H3_CLIENT_BODY_BUF],
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
            let room = H3_CLIENT_RECV_BUF - c.recv_len;
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
            let n = (range.1 - range.0).min(H3_CLIENT_BODY_BUF - c.body_len);
            let (a, b) = (range.0, range.0 + n);
            c.body.copy_within(0..0, 0); // no-op, keeps the borrow shape obvious
            let mut tmp = [0u8; H3_CLIENT_BODY_BUF];
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
        let mut frame = [0u8; H3_CLIENT_RECV_BUF];
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
                let mut body = [0u8; H3_CLIENT_BODY_BUF];
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
