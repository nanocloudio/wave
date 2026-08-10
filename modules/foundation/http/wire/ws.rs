//! WebSocket wire codec — RFC 6455 frames + handshake helpers.
//!
//! Pure byte-level routines: no syscalls, no module state. The server
//! and (future) client state machines drive the I/O; this file owns
//! the cryptographic handshake derivation and the frame format.
//!
//! # Handshake
//!
//! `compute_accept` produces the `Sec-WebSocket-Accept` base64 string
//! from the client's `Sec-WebSocket-Key`. RFC 6455 §1.3:
//!
//! ```text
//! accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
//! ```
//!
//! # Frames
//!
//! `parse_frame` decodes a frame header out of a partial byte stream;
//! `write_frame` builds an unmasked server-to-client frame. Client
//! frames must be masked (RFC 6455 §5.3); the server rejects unmasked
//! data frames per spec.

// ── Opcodes (RFC 6455 §5.2) ──────────────────────────────────────────────

pub(crate) const OP_CONTINUATION: u8 = 0x0;
pub(crate) const OP_TEXT: u8 = 0x1;
pub(crate) const OP_BINARY: u8 = 0x2;
pub(crate) const OP_CLOSE: u8 = 0x8;
pub(crate) const OP_PING: u8 = 0x9;
pub(crate) const OP_PONG: u8 = 0xA;

// ── Close codes (RFC 6455 §7.4) ──────────────────────────────────────────

pub(crate) const CLOSE_NORMAL: u16 = 1000;
/// Server-initiated close: "this conn was displaced by a newer
/// fan-out client and will not be reused. Clients that see this code
/// should NOT auto-reconnect — `last connection wins` is the intent."
pub(crate) const CLOSE_GOING_AWAY: u16 = 1001;
pub(crate) const CLOSE_PROTOCOL_ERROR: u16 = 1002;
pub(crate) const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
pub(crate) const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;

/// RFC 6455 magic GUID concatenated with the client key before SHA-1.
const MAGIC_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAGIC_GUID_LEN: usize = 36;

// fluxor SDK SHA-1 + Base64 — the repo set's single crypto owner (the SDK
// sha1.rs carries the must-not-use-for-new-designs caveat; RFC 6455 requires
// SHA-1 here). Mounted in a mod so the flat SDK sources keep their own scope.
// RFC 6455 frame-header decode + validation, shared verbatim with the client
// core in `modules/common/ws_core.rs`. Before this was split out the
// rules below existed only here, so the client accepted RSV bits, reserved
// opcodes and oversized control frames that this side rejected (T2.2.4).
include!("../../../common/ws_frame_core.rs");

mod sdkcrypto {
    include!("../../../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs");
    include!("../../../../target/fluxor/fluxor-abi/sdk/crypto/b64.rs");
}
use sdkcrypto::{b64_encode, sha1};

// ── Sec-WebSocket-Accept derivation ──────────────────────────────────────

/// Compute `base64(sha1(client_key + MAGIC_GUID))` — the value that
/// goes into the server's `Sec-WebSocket-Accept` response header.
///
/// Output is exactly 28 ASCII bytes (no terminator).
///
/// # Safety
/// `key` must be valid for reads of `key_len` bytes. `out` must be
/// valid for writes of 28 bytes.
pub unsafe fn compute_accept(key: *const u8, key_len: usize, out: *mut u8) {
    // A Sec-WebSocket-Key is 24 base64 chars; cap defensively so key + GUID
    // always fits the concat buffer (an oversized key just derives a wrong
    // accept value, which the client rejects — never a buffer overrun).
    let mut msg = [0u8; 64 + MAGIC_GUID_LEN];
    let klen = key_len.min(64);
    let mut i = 0;
    while i < klen {
        msg[i] = *key.add(i);
        i += 1;
    }
    msg[klen..klen + MAGIC_GUID_LEN].copy_from_slice(MAGIC_GUID);
    let digest = sha1(&msg[..klen + MAGIC_GUID_LEN]);
    let mut acc = [0u8; 28];
    let n = b64_encode(&digest, &mut acc).unwrap_or(0);
    let mut o = 0;
    while o < n {
        *out.add(o) = acc[o];
        o += 1;
    }
}

// ── Parsed frame header ───────────────────────────────────────────────────

/// Parsed result of `parse_frame`. `header_len` is the number of bytes
/// consumed by the frame header (start of payload); `payload_len` is
/// the payload byte count; `mask_key` is the 4-byte XOR key when
/// `masked == true`.
#[cfg_attr(feature = "host-test", derive(Debug))]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    pub mask_key: [u8; 4],
    pub header_len: u16,
    pub payload_len: u32,
}

/// Parse a frame header. Returns `Ok(Some(frame))` on success,
/// `Ok(None)` if the header is incomplete (caller should buffer more
/// data and retry), and `Err(())` on protocol violation.
///
/// Frames with 64-bit extended length are rejected as
/// "message too big" — the http module is sized for embedded targets
/// and never accepts payloads beyond 65535 bytes.
pub unsafe fn parse_frame(buf: *const u8, len: usize) -> Result<Option<Frame>, ()> {
    let slice = core::slice::from_raw_parts(buf, len);
    match ws_decode_header(slice) {
        WsHeaderParse::Incomplete => Ok(None),
        WsHeaderParse::Invalid => Err(()),
        WsHeaderParse::Header(h) => {
            // This module is sized for embedded targets and streams the payload
            // rather than buffering it, but its `Frame.payload_len` is a u32 and
            // its receive path is bounded well below 4 GiB. A longer frame is
            // refused as "message too big" rather than truncated into the field.
            if h.payload_len > u64::from(u32::MAX) {
                return Err(());
            }
            Ok(Some(Frame {
                fin: h.fin,
                opcode: h.opcode,
                masked: h.masked,
                mask_key: h.mask_key,
                header_len: h.header_len as u16,
                payload_len: h.payload_len as u32,
            }))
        }
    }
}

/// Apply the frame's masking key in place over `payload_len` bytes
/// starting at `payload`. RFC 6455 §5.3.
pub(crate) unsafe fn unmask(payload: *mut u8, payload_len: u32, mask_key: &[u8; 4]) {
    ws_mask_apply(
        core::slice::from_raw_parts_mut(payload, payload_len as usize),
        *mask_key,
    );
}

/// Write an unmasked server-to-client frame into `dst`. Returns the
/// total number of bytes written (header + payload). The caller is
/// responsible for keeping `payload_len` ≤ 65535 — server-emitted
/// frames in this module never use the 64-bit length form.
///
/// Returns 0 if `dst_cap` is too small to hold the frame.
pub(crate) unsafe fn write_frame(
    dst: *mut u8,
    dst_cap: usize,
    fin: bool,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
) -> usize {
    let header_len = if payload_len <= 125 {
        2
    } else if payload_len <= 65535 {
        4
    } else {
        return 0;
    };
    if dst_cap < header_len + payload_len {
        return 0;
    }

    let fin_bit = if fin { 0x80 } else { 0 };
    *dst = fin_bit | (opcode & 0x0F);

    if payload_len <= 125 {
        *dst.add(1) = payload_len as u8;
    } else {
        *dst.add(1) = 126;
        *dst.add(2) = ((payload_len >> 8) & 0xFF) as u8;
        *dst.add(3) = (payload_len & 0xFF) as u8;
    }

    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(payload, dst.add(header_len), payload_len);
    }
    header_len + payload_len
}

/// Write a masked client-to-server frame (RFC 6455 §5.3). Layout:
/// header (1 + 1 or 1 + 3) + 4-byte mask key + XOR-masked payload.
/// Returns total bytes written or 0 if `dst_cap` is too small.
pub(crate) unsafe fn write_frame_masked(
    dst: *mut u8,
    dst_cap: usize,
    fin: bool,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    mask_key: &[u8; 4],
) -> usize {
    let extended_len = if payload_len <= 125 {
        0
    } else if payload_len <= 65535 {
        2
    } else {
        return 0;
    };
    let header_len = 2 + extended_len + 4;
    if dst_cap < header_len + payload_len {
        return 0;
    }

    let fin_bit: u8 = if fin { 0x80 } else { 0 };
    *dst = fin_bit | (opcode & 0x0F);

    let mut o = 1usize;
    if payload_len <= 125 {
        *dst.add(o) = 0x80 | (payload_len as u8);
        o += 1;
    } else {
        *dst.add(o) = 0x80 | 126;
        o += 1;
        *dst.add(o) = ((payload_len >> 8) & 0xFF) as u8;
        *dst.add(o + 1) = (payload_len & 0xFF) as u8;
        o += 2;
    }

    *dst.add(o) = mask_key[0];
    *dst.add(o + 1) = mask_key[1];
    *dst.add(o + 2) = mask_key[2];
    *dst.add(o + 3) = mask_key[3];
    o += 4;

    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(payload, dst.add(o), payload_len);
        ws_mask_apply(
            core::slice::from_raw_parts_mut(dst.add(o), payload_len),
            *mask_key,
        );
    }
    o + payload_len
}

// ── HTTP/1.1 handshake response ──────────────────────────────────────────

/// Write the `101 Switching Protocols` response for a successful
/// WebSocket upgrade. `accept` is the 28-byte ASCII output of
/// `compute_accept`. Returns total bytes written.
pub(crate) unsafe fn write_handshake_response(
    dst: *mut u8,
    dst_cap: usize,
    accept: *const u8,
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

    put!(b"HTTP/1.1 101 Switching Protocols\r\n");
    put!(b"Upgrade: websocket\r\n");
    put!(b"Connection: Upgrade\r\n");
    put!(b"Sec-WebSocket-Accept: ");
    let mut i = 0;
    while i < 28 && off < dst_cap {
        *dst.add(off) = *accept.add(i);
        off += 1;
        i += 1;
    }
    put!(b"\r\n\r\n");

    off
}

/// Locate the value of a header field in a parsed HTTP/1 request,
/// case-insensitive. `name` should not include the trailing `:`. The
/// search ends at the blank line that closes the head.
///
/// Returns `(offset, length)` of the trimmed value within `buf`, or
/// `None` if the header is not present.
pub(crate) unsafe fn find_header_value(
    buf: *const u8,
    len: usize,
    name: &[u8],
) -> Option<(usize, usize)> {
    let mut line_start = 0usize;
    while line_start < len {
        // Find end of line.
        let mut eol = line_start;
        while eol + 1 < len {
            if *buf.add(eol) == b'\r' && *buf.add(eol + 1) == b'\n' {
                break;
            }
            eol += 1;
        }
        if eol + 1 >= len {
            return None;
        }
        if eol == line_start {
            // Blank line — end of headers.
            return None;
        }

        // Look for `name:` at the start of this line, case-insensitive.
        if eol - line_start > name.len() && *buf.add(line_start + name.len()) == b':' {
            let mut matches = true;
            let mut j = 0;
            while j < name.len() {
                let a = ascii_lower(*buf.add(line_start + j));
                let b = ascii_lower(name[j]);
                if a != b {
                    matches = false;
                    break;
                }
                j += 1;
            }
            if matches {
                let mut v_start = line_start + name.len() + 1;
                while v_start < eol && (*buf.add(v_start) == b' ' || *buf.add(v_start) == b'\t') {
                    v_start += 1;
                }
                let mut v_end = eol;
                while v_end > v_start
                    && (*buf.add(v_end - 1) == b' ' || *buf.add(v_end - 1) == b'\t')
                {
                    v_end -= 1;
                }
                return Some((v_start, v_end - v_start));
            }
        }

        line_start = eol + 2;
    }
    None
}

/// Search for `needle` in the value of a header, case-insensitive,
/// treating commas as separators. Useful for `Connection: keep-alive,
/// Upgrade` where `Upgrade` must be present alongside other tokens.
pub(crate) unsafe fn header_value_contains_token(
    buf: *const u8,
    val_off: usize,
    val_len: usize,
    needle: &[u8],
) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut tok_start = val_off;
    let end = val_off + val_len;
    let mut i = val_off;
    loop {
        if i >= end || *buf.add(i) == b',' {
            // Trim whitespace around [tok_start, i).
            let mut s = tok_start;
            let mut e = i;
            while s < e && (*buf.add(s) == b' ' || *buf.add(s) == b'\t') {
                s += 1;
            }
            while e > s && (*buf.add(e - 1) == b' ' || *buf.add(e - 1) == b'\t') {
                e -= 1;
            }
            if e - s == needle.len() {
                let mut ok = true;
                let mut j = 0;
                while j < needle.len() {
                    let a = ascii_lower(*buf.add(s + j));
                    let b = ascii_lower(needle[j]);
                    if a != b {
                        ok = false;
                        break;
                    }
                    j += 1;
                }
                if ok {
                    return true;
                }
            }
            if i >= end {
                break;
            }
            tok_start = i + 1;
        }
        i += 1;
    }
    false
}

#[inline]
fn ascii_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}
