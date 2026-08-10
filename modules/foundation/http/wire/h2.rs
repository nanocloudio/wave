//! HTTP/2 wire codec — RFC 7540 frame format.
//!
//! Items are `pub` rather than `pub(crate)` so the host test harness can pin
//! them directly (`tests/harness/tests/codec_conformance.rs`). This does NOT
//! widen the PIC surface: `mod.rs` declares `mod wire_h2` privately unless the
//! `host-test` feature is on, so on-device these stay crate-internal.
//!
//! Pure byte-level routines: frame header parsing, type-specific
//! payload decoders, and outbound frame writers. The state machine in
//! `h2.rs` drives the connection lifecycle.
//!
//! # Frame layout (§4.1)
//!
//! ```text
//! +-----------------------------------------------+
//! |                 Length (24)                   |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+-------------------------------+
//! |R|                 Stream Identifier (31)                      |
//! +=+=============================================================+
//! |                   Frame Payload (0...)                      ...
//! +---------------------------------------------------------------+
//! ```

// ── Connection preface (§3.5) ────────────────────────────────────────────

/// 24-byte client preface that opens every HTTP/2 connection.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ── Frame types (§6) ─────────────────────────────────────────────────────

pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_PRIORITY: u8 = 0x2;
pub const FRAME_RST_STREAM: u8 = 0x3;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_PING: u8 = 0x6;
pub const FRAME_GOAWAY: u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_CONTINUATION: u8 = 0x9;

// ── Flags (§6) ───────────────────────────────────────────────────────────

pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_ACK: u8 = 0x1; // re-used by SETTINGS, PING
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;

// ── Settings identifiers (§6.5.2) ────────────────────────────────────────

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
/// RFC 8441 §3 — server signals support for the extended CONNECT
/// method (`:method = CONNECT` with `:protocol`). Sending `1`
/// authorizes WebSocket-over-h2 bootstrap.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;

// ── Error codes (§7) ─────────────────────────────────────────────────────

pub const ERR_NO_ERROR: u32 = 0x0;
pub const ERR_PROTOCOL_ERROR: u32 = 0x1;
pub const ERR_INTERNAL_ERROR: u32 = 0x2;
pub const ERR_FLOW_CONTROL_ERROR: u32 = 0x3;
pub const ERR_FRAME_SIZE_ERROR: u32 = 0x6;
pub const ERR_STREAM_CLOSED: u32 = 0x5;
pub const ERR_REFUSED_STREAM: u32 = 0x7;
pub const ERR_COMPRESSION_ERROR: u32 = 0x9;
pub const ERR_ENHANCE_YOUR_CALM: u32 = 0xB;

/// Frame header is fixed at 9 bytes: length(3) + type(1) + flags(1) +
/// reserved-bit + stream-id(31) packed into 4 bytes.
pub const FRAME_HEADER_LEN: usize = 9;

/// Parsed frame header. The payload starts at offset `FRAME_HEADER_LEN`
/// in the source buffer; callers must ensure `len >= header.length`
/// before processing.
pub struct Header {
    pub length: u32,
    pub ftype: u8,
    pub flags: u8,
    pub stream_id: u32,
}

/// Parse a 9-byte frame header. Returns `None` if `len < 9`.
pub unsafe fn parse_header(buf: *const u8, len: usize) -> Option<Header> {
    if len < FRAME_HEADER_LEN {
        return None;
    }
    let length = ((*buf as u32) << 16) | ((*buf.add(1) as u32) << 8) | (*buf.add(2) as u32);
    let ftype = *buf.add(3);
    let flags = *buf.add(4);
    let stream_id = (((*buf.add(5) as u32) & 0x7F) << 24)
        | ((*buf.add(6) as u32) << 16)
        | ((*buf.add(7) as u32) << 8)
        | (*buf.add(8) as u32);
    Some(Header {
        length,
        ftype,
        flags,
        stream_id,
    })
}

/// Write a 9-byte frame header into `dst`. Caller is responsible for
/// `length` ≤ peer's `SETTINGS_MAX_FRAME_SIZE` (we never exceed 16384,
/// the protocol minimum, so this is safe by construction).
pub unsafe fn write_header(dst: *mut u8, length: u32, ftype: u8, flags: u8, stream_id: u32) {
    *dst = ((length >> 16) & 0xFF) as u8;
    *dst.add(1) = ((length >> 8) & 0xFF) as u8;
    *dst.add(2) = (length & 0xFF) as u8;
    *dst.add(3) = ftype;
    *dst.add(4) = flags;
    *dst.add(5) = ((stream_id >> 24) & 0x7F) as u8; // R bit cleared
    *dst.add(6) = ((stream_id >> 16) & 0xFF) as u8;
    *dst.add(7) = ((stream_id >> 8) & 0xFF) as u8;
    *dst.add(8) = (stream_id & 0xFF) as u8;
}

/// Write an empty SETTINGS-ACK frame. Used to acknowledge the peer's
/// SETTINGS frame; required by §6.5.3 for every non-ACK SETTINGS we
/// receive.
pub unsafe fn write_settings_ack(dst: *mut u8) -> usize {
    write_header(dst, 0, FRAME_SETTINGS, FLAG_ACK, 0);
    FRAME_HEADER_LEN
}

/// Write an initial SETTINGS frame carrying our advertised values.
/// Each setting is 6 bytes (id u16 + value u32), packed into the frame
/// payload; the frame header carries the total payload length. Up to
/// 6 settings fit in `dst`.
pub unsafe fn write_settings(dst: *mut u8, settings: &[(u16, u32)]) -> usize {
    let payload_len = settings.len() * 6;
    write_header(dst, payload_len as u32, FRAME_SETTINGS, 0, 0);
    let mut o = FRAME_HEADER_LEN;
    for &(id, val) in settings {
        *dst.add(o) = (id >> 8) as u8;
        *dst.add(o + 1) = (id & 0xFF) as u8;
        *dst.add(o + 2) = ((val >> 24) & 0xFF) as u8;
        *dst.add(o + 3) = ((val >> 16) & 0xFF) as u8;
        *dst.add(o + 4) = ((val >> 8) & 0xFF) as u8;
        *dst.add(o + 5) = (val & 0xFF) as u8;
        o += 6;
    }
    o
}

/// Write a HEADERS frame header (the actual header block fragment is
/// HPACK-encoded by the caller and placed at offset
/// `FRAME_HEADER_LEN`).
pub unsafe fn write_headers_frame_header(
    dst: *mut u8,
    block_len: usize,
    stream_id: u32,
    end_stream: bool,
    end_headers: bool,
) {
    let mut flags = 0u8;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if end_headers {
        flags |= FLAG_END_HEADERS;
    }
    write_header(dst, block_len as u32, FRAME_HEADERS, flags, stream_id);
}

/// Write a DATA frame header. The payload is whatever bytes the caller
/// has placed at offset `FRAME_HEADER_LEN`.
pub unsafe fn write_data_frame_header(
    dst: *mut u8,
    payload_len: usize,
    stream_id: u32,
    end_stream: bool,
) {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    write_header(dst, payload_len as u32, FRAME_DATA, flags, stream_id);
}

/// Write a WINDOW_UPDATE frame (§6.9). `stream_id == 0` updates the
/// connection-level window; non-zero updates a single stream's window.
/// `delta` must be 1..=2^31-1 (the spec rejects 0 with PROTOCOL_ERROR).
pub unsafe fn write_window_update(dst: *mut u8, stream_id: u32, delta: u32) -> usize {
    write_header(dst, 4, FRAME_WINDOW_UPDATE, 0, stream_id);
    *dst.add(FRAME_HEADER_LEN) = ((delta >> 24) & 0x7F) as u8;
    *dst.add(FRAME_HEADER_LEN + 1) = ((delta >> 16) & 0xFF) as u8;
    *dst.add(FRAME_HEADER_LEN + 2) = ((delta >> 8) & 0xFF) as u8;
    *dst.add(FRAME_HEADER_LEN + 3) = (delta & 0xFF) as u8;
    FRAME_HEADER_LEN + 4
}

/// Write an RST_STREAM frame (§6.4). Closes one stream with the given
/// error code; the connection stays up.
pub unsafe fn write_rst_stream(dst: *mut u8, stream_id: u32, error_code: u32) -> usize {
    write_header(dst, 4, FRAME_RST_STREAM, 0, stream_id);
    *dst.add(FRAME_HEADER_LEN) = ((error_code >> 24) & 0xFF) as u8;
    *dst.add(FRAME_HEADER_LEN + 1) = ((error_code >> 16) & 0xFF) as u8;
    *dst.add(FRAME_HEADER_LEN + 2) = ((error_code >> 8) & 0xFF) as u8;
    *dst.add(FRAME_HEADER_LEN + 3) = (error_code & 0xFF) as u8;
    FRAME_HEADER_LEN + 4
}

/// Write a GOAWAY frame (§6.8). Tells the peer we're tearing the
/// connection down at or after `last_stream_id`. No debug data.
pub unsafe fn write_goaway(dst: *mut u8, last_stream_id: u32, error_code: u32) -> usize {
    write_header(dst, 8, FRAME_GOAWAY, 0, 0);
    let mut o = FRAME_HEADER_LEN;
    *dst.add(o) = ((last_stream_id >> 24) & 0x7F) as u8;
    *dst.add(o + 1) = ((last_stream_id >> 16) & 0xFF) as u8;
    *dst.add(o + 2) = ((last_stream_id >> 8) & 0xFF) as u8;
    *dst.add(o + 3) = (last_stream_id & 0xFF) as u8;
    o += 4;
    *dst.add(o) = ((error_code >> 24) & 0xFF) as u8;
    *dst.add(o + 1) = ((error_code >> 16) & 0xFF) as u8;
    *dst.add(o + 2) = ((error_code >> 8) & 0xFF) as u8;
    *dst.add(o + 3) = (error_code & 0xFF) as u8;
    o + 4
}

/// Write a PING-ACK frame echoing the peer's 8-byte opaque data.
pub unsafe fn write_ping_ack(dst: *mut u8, opaque: *const u8) -> usize {
    write_header(dst, 8, FRAME_PING, FLAG_ACK, 0);
    core::ptr::copy_nonoverlapping(opaque, dst.add(FRAME_HEADER_LEN), 8);
    FRAME_HEADER_LEN + 8
}

/// Decode the optional PADDED + PRIORITY prefixes on a HEADERS frame
/// payload. Returns the byte offset where the actual header block
/// fragment starts, the fragment length, and `Err(())` on malformed
/// input.
///
/// Per §6.2: if PADDED is set, the first byte is the pad length; if
/// PRIORITY is set, 5 bytes of stream-dependency + weight follow.
/// Padding is then trimmed from the tail. We accept these layouts but
/// ignore PRIORITY values (no priority enforcement) and reject any
/// frame whose claimed pad would underflow the payload.
pub unsafe fn headers_block_extent(
    payload: *const u8,
    payload_len: u32,
    flags: u8,
) -> Result<(usize, usize), ()> {
    let mut start = 0usize;
    let mut pad: u32 = 0;

    if (flags & FLAG_PADDED) != 0 {
        if payload_len < 1 {
            return Err(());
        }
        pad = *payload as u32;
        start = 1;
    }
    if (flags & FLAG_PRIORITY) != 0 {
        if payload_len < (start as u32 + 5) {
            return Err(());
        }
        start += 5;
    }
    let block_end = (payload_len as i64) - (pad as i64);
    if block_end < start as i64 {
        return Err(());
    }
    Ok((start, (block_end as usize) - start))
}
