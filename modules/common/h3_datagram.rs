//! Bounded HTTP/3 DATAGRAM/WebTransport capsule payload.

pub const H3_DATAGRAM_MAX_PAYLOAD: usize = 1200;
pub const H3_DATAGRAM_HDR: usize = 4 + 8 + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3Datagram<'a> {
    pub session_id: u32,
    pub context_id: u64,
    pub payload: &'a [u8],
}

pub fn write(d: &H3Datagram<'_>, out: &mut [u8]) -> Option<usize> {
    if d.payload.len() > H3_DATAGRAM_MAX_PAYLOAD || d.payload.len() > u16::MAX as usize {
        return None;
    }
    let total = H3_DATAGRAM_HDR.checked_add(d.payload.len())?;
    if total > out.len() {
        return None;
    }
    out[..4].copy_from_slice(&d.session_id.to_le_bytes());
    out[4..12].copy_from_slice(&d.context_id.to_le_bytes());
    out[12..14].copy_from_slice(&(d.payload.len() as u16).to_le_bytes());
    out[14..total].copy_from_slice(d.payload);
    Some(total)
}

pub fn parse(buf: &[u8]) -> Option<H3Datagram<'_>> {
    if buf.len() < H3_DATAGRAM_HDR {
        return None;
    }
    let len = u16::from_le_bytes([buf[12], buf[13]]) as usize;
    if len > H3_DATAGRAM_MAX_PAYLOAD || H3_DATAGRAM_HDR.checked_add(len)? != buf.len() {
        return None;
    }
    Some(H3Datagram {
        session_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        context_id: u64::from_le_bytes(buf[4..12].try_into().ok()?),
        payload: &buf[14..],
    })
}

/// Decode the RFC 9297 context-id prefix carried by an HTTP/3 DATAGRAM
/// payload. The remaining bytes are application data.
pub fn parse_quic_payload(buf: &[u8]) -> Option<(u64, &[u8])> {
    let first = *buf.first()?;
    let width = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if buf.len() < width {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..width] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, &buf[width..]))
}

/// Encode a WebTransport context-id prefix followed by its payload.
pub fn write_quic_payload(context_id: u64, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let width: usize = if context_id < (1 << 6) {
        1
    } else if context_id < (1 << 14) {
        2
    } else if context_id < (1 << 30) {
        4
    } else if context_id < (1 << 62) {
        8
    } else {
        return None;
    };
    let total = width.checked_add(payload.len())?;
    if total > out.len() {
        return None;
    }
    let mut value = context_id;
    let prefix = match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xC0,
    };
    let mut i = width;
    while i > 0 {
        i -= 1;
        out[i] = (value & 0xff) as u8;
        value >>= 8;
    }
    out[0] |= prefix;
    out[width..total].copy_from_slice(payload);
    Some(total)
}
