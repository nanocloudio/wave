// Bounded, no_std, no-alloc WebSocket (RFC 6455) client core — the HTTP upgrade
// handshake and the masked frame codec. `include!`d by the host crate (tests) and
// the `websocket` .fmod.
//
// WebSocket is the "protocol upgrade + masked bidirectional framing" class. The
// connection begins as HTTP: the client sends an Upgrade request with a random
// Sec-WebSocket-Key, and the server proves it spoke WebSocket by returning
//   Sec-WebSocket-Accept = base64(SHA1(key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
// which the client verifies. After the 101 switch, both sides exchange frames;
// CLIENT frames MUST be masked with a per-frame key (payload XOR key). A protocol
// that mutates from HTTP into a masked frame stream and cryptographically
// verifies the switch is a stateful session — not request/reply. Reuses SHA-1
// (mysql_core) and Base64 (scram_core).

/// The RFC 6455 magic GUID appended to the key before hashing.
pub const WS_MAGIC: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn wput(out: &mut [u8], pos: &mut usize, b: &[u8]) -> Option<()> {
    if *pos + b.len() > out.len() {
        return None;
    }
    out[*pos..*pos + b.len()].copy_from_slice(b);
    *pos += b.len();
    Some(())
}

/// The expected `Sec-WebSocket-Accept` value for a given `Sec-WebSocket-Key`:
/// `base64(SHA1(key ++ WS_MAGIC))`. Writes into `out` (28 bytes) and returns the
/// length.
pub fn ws_accept(key_b64: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut cat = [0u8; 96];
    let mut c = 0;
    wput(&mut cat, &mut c, key_b64)?;
    wput(&mut cat, &mut c, WS_MAGIC)?;
    let digest = sha1(&cat[..c]); // from mysql_core
    b64_encode(&digest, out) // from scram_core
}

/// Build the HTTP upgrade request. `key_b64` is the client's base64 nonce.
pub fn ws_upgrade_request(
    host: &[u8],
    path: &[u8],
    key_b64: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut p = 0;
    wput(out, &mut p, b"GET ")?;
    wput(out, &mut p, path)?;
    wput(out, &mut p, b" HTTP/1.1\r\nHost: ")?;
    wput(out, &mut p, host)?;
    wput(
        out,
        &mut p,
        b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ",
    )?;
    wput(out, &mut p, key_b64)?;
    wput(out, &mut p, b"\r\nSec-WebSocket-Version: 13\r\n\r\n")?;
    Some(p)
}

/// True once the buffer holds a complete HTTP response header block whose status
/// is `101` and whose `Sec-WebSocket-Accept` matches `expected_accept`. Returns
/// `None` if the header block (terminated by `\r\n\r\n`) has not fully arrived.
pub fn ws_verify_upgrade(buf: &[u8], expected_accept: &[u8]) -> Option<bool> {
    // header block end
    let mut end = None;
    let mut i = 0;
    while i + 3 < buf.len() {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            end = Some(i + 4);
            break;
        }
        i += 1;
    }
    let hdr_end = end?;
    let hdr = &buf[..hdr_end];
    // status 101 on the first line
    let is101 = hdr.len() >= 12 && &hdr[9..12] == b"101";
    // find the accept header value (case-insensitive header name)
    let accept_ok = find_header_value(hdr, b"sec-websocket-accept")
        .map(|v| v == expected_accept)
        .unwrap_or(false);
    Some(is101 && accept_ok)
}

fn find_header_value<'a>(hdr: &'a [u8], name_lower: &[u8]) -> Option<&'a [u8]> {
    let mut ls = 0;
    while ls < hdr.len() {
        // line end
        let mut le = ls;
        while le + 1 < hdr.len() && !(hdr[le] == b'\r' && hdr[le + 1] == b'\n') {
            le += 1;
        }
        let line = &hdr[ls..le];
        if let Some(colon) = line.iter().position(|&c| c == b':') {
            let (nm, val) = line.split_at(colon);
            if nm.len() == name_lower.len()
                && nm
                    .iter()
                    .zip(name_lower)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                // trim leading space after ':'
                let mut v = &val[1..];
                while !v.is_empty() && v[0] == b' ' {
                    v = &v[1..];
                }
                return Some(v);
            }
        }
        ls = le + 2;
    }
    None
}

/// WebSocket opcodes.
pub mod ws_op {
    pub const CONT: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// Build a masked client frame for `opcode` carrying `payload`, using the 4-byte
/// `mask`. Client→server frames must be masked (payload XOR mask, cycling).
pub fn ws_frame(opcode: u8, payload: &[u8], mask: [u8; 4], out: &mut [u8]) -> Option<usize> {
    let mut p = 0;
    if out.is_empty() {
        return None;
    }
    out[p] = 0x80 | (opcode & 0x0f); // FIN + opcode
    p += 1;
    let n = payload.len();
    if n < 126 {
        wput(out, &mut p, &[0x80 | n as u8])?; // MASK + len
    } else if n < 65536 {
        wput(out, &mut p, &[0x80 | 126])?;
        wput(out, &mut p, &(n as u16).to_be_bytes())?;
    } else {
        wput(out, &mut p, &[0x80 | 127])?;
        wput(out, &mut p, &(n as u64).to_be_bytes())?;
    }
    wput(out, &mut p, &mask)?;
    if p + n > out.len() {
        return None;
    }
    out[p..p + n].copy_from_slice(payload);
    ws_mask_apply(&mut out[p..p + n], mask);
    Some(p + n)
}

/// A parsed inbound frame (server frames are unmasked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsFrame {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    pub payload_start: usize,
    pub payload_end: usize,
    pub total: usize,
}

/// Frame the first complete WebSocket frame in `buf`.
///
/// `None` means either "not all here yet" or "illegal" — see
/// [`ws_parse_frame_checked`] when the difference matters, which it does for
/// any caller that would otherwise keep buffering a frame that can never
/// become valid.
///
/// Header decoding and the RFC 6455 validation rules come from
/// `ws_frame_core.rs`, shared with `http`'s codec in `modules/foundation/http/wire/ws.rs`.
/// Never panics.
pub fn ws_parse_frame(buf: &[u8]) -> Option<WsFrame> {
    match ws_parse_frame_checked(buf) {
        WsFrameParse::Frame(f) => Some(f),
        _ => None,
    }
}

/// Outcome of parsing one whole frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsFrameParse {
    Frame(WsFrame),
    /// The frame has not fully arrived; buffer more and retry.
    Incomplete,
    /// A protocol violation — fail the connection rather than retrying.
    Invalid,
}

/// Like [`ws_parse_frame`] but distinguishes "incomplete" from "illegal".
///
/// The whole-frame requirement is this side's policy, not the shared core's.
/// The server has the same requirement but expresses it differently: it bounds
/// the frame against its slot receive buffer and closes 1009 when one will not
/// fit, working in place through a raw pointer, while this side reports
/// `Incomplete` and waits for its accumulator to fill.
#[must_use]
pub fn ws_parse_frame_checked(buf: &[u8]) -> WsFrameParse {
    let h = match ws_decode_header(buf) {
        WsHeaderParse::Header(h) => h,
        WsHeaderParse::Incomplete => return WsFrameParse::Incomplete,
        WsHeaderParse::Invalid => return WsFrameParse::Invalid,
    };
    // `ws_decode_header` already rejected a length whose total would overflow,
    // so this cannot wrap; `usize::try_from` still guards a 32-bit target where
    // a legal 64-bit length simply cannot be addressed.
    let Ok(payload_len) = usize::try_from(h.payload_len) else {
        return WsFrameParse::Invalid;
    };
    let Some(total) = h.header_len.checked_add(payload_len) else {
        return WsFrameParse::Invalid;
    };
    if buf.len() < total {
        return WsFrameParse::Incomplete;
    }
    WsFrameParse::Frame(WsFrame {
        fin: h.fin,
        opcode: h.opcode,
        masked: h.masked,
        payload_start: h.header_len,
        payload_end: total,
        total,
    })
}

// ---- state machine ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WsPhase {
    Disconnected = 0,
    Connecting = 1,
    /// Upgrade request sent; awaiting/verifying the 101 response.
    AwaitUpgrade = 2,
    /// Connected as a WebSocket; exchanging frames.
    Ready = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsEv {
    Start,
    Connected,
    Upgraded,
    UpgradeFailed,
    PeerClosed,
    NetError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsAct {
    None,
    Connect,
    SendUpgrade,
    Fail,
}

/// The WebSocket client state machine — pure and host-testable. The upgrade
/// verification (a crypto check on the server's Accept) gates `Ready`.
pub fn ws_transition(phase: WsPhase, ev: WsEv) -> (WsAct, WsPhase) {
    use WsAct::*;
    use WsEv::*;
    use WsPhase::*;
    match (phase, ev) {
        (Disconnected, Start) => (Connect, Connecting),
        (Connecting, Connected) => (SendUpgrade, AwaitUpgrade),
        (AwaitUpgrade, Upgraded) => (None, Ready),
        (AwaitUpgrade, UpgradeFailed) => (Fail, Disconnected),
        (_, PeerClosed) | (_, NetError) => (Fail, Disconnected),
        _ => (None, phase),
    }
}
