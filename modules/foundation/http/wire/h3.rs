//! HTTP/3 wire format (RFC 9114 §7).
//!
//! HTTP/3 frames are length-prefixed with two RFC 9000 §16 varints —
//! frame type and frame length:
//!
//!   <varint type> <varint length> <payload[length]>
//!
//! A QUIC stream carries one HTTP exchange (request/response) on a
//! bidirectional client-initiated stream, plus optional unidirectional
//! "control" / "qpack-encoder" / "qpack-decoder" / "push" streams
//! identified by the first byte of payload.
//!
//! Status: frame type table, parser and builder — consumed by `h3.rs`'s
//! request ingest and response framing. Live wiring into the server
//! (which runs h1/h2 over TCP today) waits for the QUIC transport.

#[path = "../../../../target/fluxor/fluxor-abi/sdk/wire/varint.rs"]
mod varint;
use self::varint::{varint_decode, varint_encode, varint_size};

// ----------------------------------------------------------------------
// Frame types (RFC 9114 §11.2)
// ----------------------------------------------------------------------

pub const H3_FRAME_DATA: u64 = 0x00;
pub const H3_FRAME_HEADERS: u64 = 0x01;
pub const H3_FRAME_CANCEL_PUSH: u64 = 0x03;
pub const H3_FRAME_SETTINGS: u64 = 0x04;
pub const H3_FRAME_PUSH_PROMISE: u64 = 0x05;
pub const H3_FRAME_GOAWAY: u64 = 0x07;
pub const H3_FRAME_MAX_PUSH_ID: u64 = 0x0D;

// ----------------------------------------------------------------------
// Unidirectional stream type prefixes (RFC 9114 §6.2)
// ----------------------------------------------------------------------

pub const H3_UNI_STREAM_CONTROL: u64 = 0x00;
pub const H3_UNI_STREAM_PUSH: u64 = 0x01;
pub const H3_UNI_STREAM_QPACK_ENCODER: u64 = 0x02;
pub const H3_UNI_STREAM_QPACK_DECODER: u64 = 0x03;

// ----------------------------------------------------------------------
// SETTINGS identifiers (RFC 9114 §7.2.4 + RFC 9204 §5)
// ----------------------------------------------------------------------

pub const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const H3_SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const H3_SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// RFC 9220 §3 / RFC 8441 — the peer permits extended CONNECT, which is
/// how a WebSocket tunnel is opened over HTTP/3.
pub const H3_SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

// ----------------------------------------------------------------------
// PRIORITY_UPDATE frames (RFC 9218 §7.2)
// ----------------------------------------------------------------------
//
// Both types are 0xF07xx, so both encode as a 4-byte QUIC varint.

pub const H3_FRAME_PRIORITY_UPDATE_REQUEST: u64 = 0xF0700;
pub const H3_FRAME_PRIORITY_UPDATE_PUSH: u64 = 0xF0701;

// ----------------------------------------------------------------------
// Parsing
// ----------------------------------------------------------------------

pub struct H3Frame<'a> {
    pub frame_type: u64,
    pub payload: &'a [u8],
}

/// Parse one frame from `buf`. Returns `Some((frame, total_consumed))`
/// or `None` on truncation (caller should buffer more bytes).
pub fn parse_h3_frame(buf: &[u8]) -> Option<(H3Frame<'_>, usize)> {
    // SAFETY: pointer/length pair derived from a Rust slice; varint_decode
    // bounds-checks internally against the supplied length.
    let (frame_type, type_len) = unsafe { varint_decode(buf.as_ptr(), buf.len()) }?;
    let after_type = &buf[type_len..];
    // SAFETY: as above; `after_type` is a sub-slice of `buf`.
    let (length, len_len) = unsafe { varint_decode(after_type.as_ptr(), after_type.len()) }?;
    let length = length as usize;
    let payload_off = type_len + len_len;
    if buf.len() < payload_off + length {
        return None;
    }
    Some((
        H3Frame {
            frame_type,
            payload: &buf[payload_off..payload_off + length],
        },
        payload_off + length,
    ))
}

/// Build a SETTINGS frame body: a sequence of (varint id, varint value)
/// pairs (RFC 9114 §7.2.4). Returns bytes written, or 0 on overflow.
///
/// Takes a slice of pairs rather than a callback. A per-entry
/// `&mut dyn FnMut` is a trait object, and a trait object is a vtable:
/// these modules are position-independent with no relocation processing
/// for one, so the call jumps to an unrelocated address and faults the
/// runtime rather than failing the build.
pub fn build_h3_settings_payload(settings: &[(u64, u64)], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    for (id, val) in settings {
        for v in [*id, *val] {
            if pos >= out.len() {
                return 0;
            }
            // SAFETY: pointer derived from a Rust slice; `out.len() - pos`
            // is the exact remaining capacity passed for bounds.
            let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, v) };
            if n == 0 {
                return 0;
            }
            pos += n;
        }
    }
    pos
}

/// Build a frame header (type + length) into `out`, returning bytes
/// written. The caller appends `payload` afterwards.
pub fn build_h3_frame_header(frame_type: u64, payload_len: usize, out: &mut [u8]) -> usize {
    let type_size = varint_size(frame_type);
    let len_size = varint_size(payload_len as u64);
    if out.len() < type_size + len_size {
        return 0;
    }
    let mut cursor = 0;
    // SAFETY: pointer derived from a Rust slice; `out.len() - cursor` is
    // the exact remaining capacity passed to varint_encode for bounds.
    let n = unsafe { varint_encode(out.as_mut_ptr().add(cursor), out.len() - cursor, frame_type) };
    if n == 0 {
        return 0;
    }
    cursor += n;
    // SAFETY: as above; `cursor` has advanced by the returned byte count.
    let n = unsafe {
        varint_encode(
            out.as_mut_ptr().add(cursor),
            out.len() - cursor,
            payload_len as u64,
        )
    };
    if n == 0 {
        return 0;
    }
    cursor += n;
    cursor
}
