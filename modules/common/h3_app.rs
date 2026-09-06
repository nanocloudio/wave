//! Stream-scoped H3 application envelopes.
//!
//! HTTP/1 and HTTP/2 application envelopes use compact 16-bit identities. QUIC
//! sessions and stream IDs have wider domains, so H3 gets its own contract
//! rather than truncating identifiers and risking response crossover.

pub const H3_APP_REQ_MAGIC: u8 = 0xA3;
pub const H3_APP_RESP_MAGIC: u8 = 0xA4;
pub const H3_APP_FLAG_MORE_BODY: u8 = 0x01;
/// Request is a file-backed route delegated to the application graph.
pub const H3_APP_FLAG_FILE: u8 = 0x02;
/// Request is a proxy route delegated to the application graph.
pub const H3_APP_FLAG_PROXY: u8 = 0x04;
/// Extended CONNECT WebSocket admission is delegated to the application.
pub const H3_APP_FLAG_WEBSOCKET: u8 = 0x08;
/// Response body is an H3 DATAGRAM/WebTransport capsule to send on the
/// session instead of an HTTP response stream.
pub const H3_APP_FLAG_DATAGRAM: u8 = 0x10;
/// Extended CONNECT establishes an application-owned WebTransport session.
pub const H3_APP_FLAG_WEBTRANSPORT: u8 = 0x20;
pub const H3_APP_REQ_HDR: usize = 1 + 4 + 8 + 1 + 1 + 2 + 2 + 4;
pub const H3_APP_RESP_HDR: usize = 1 + 4 + 8 + 2 + 1 + 1 + 2 + 4;
pub const H3_APP_MAX_RECORD: usize = 8192;

// The header section is a run of `[name_len:u8][value_len:u16 LE][name][value]`,
// walked by `next_header`. Names and values are bounded by the enclosing
// record, so neither length needs a ceiling of its own.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3AppRequest<'a> {
    pub session_id: u32,
    pub stream_id: u64,
    pub method: u8,
    pub flags: u8,
    pub path: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3AppResponse<'a> {
    pub session_id: u32,
    pub stream_id: u64,
    pub status: u16,
    pub flags: u8,
    pub content_type: &'a [u8],
    pub body: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3AppHeader<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

/// Decode one header at `offset` from the bounded application header section.
/// Returns the header and the next offset; malformed/truncated fields fail.
pub fn next_header<'a>(headers: &'a [u8], offset: usize) -> Option<(H3AppHeader<'a>, usize)> {
    let name_len = *headers.get(offset)? as usize;
    if name_len == 0 {
        return None;
    }
    let value_len =
        u16::from_le_bytes([*headers.get(offset + 1)?, *headers.get(offset + 2)?]) as usize;
    let name_at = offset.checked_add(3)?;
    let value_at = name_at.checked_add(name_len)?;
    let end = value_at.checked_add(value_len)?;
    if end > headers.len() {
        return None;
    }
    Some((
        H3AppHeader {
            name: &headers[name_at..value_at],
            value: &headers[value_at..end],
        },
        end,
    ))
}

pub fn write_request(req: &H3AppRequest<'_>, out: &mut [u8]) -> Option<usize> {
    let total = H3_APP_REQ_HDR
        .checked_add(req.path.len())?
        .checked_add(req.headers.len())?
        .checked_add(req.body.len())?;
    if total > out.len()
        || total > H3_APP_MAX_RECORD
        || req.path.len() > u16::MAX as usize
        || req.headers.len() > u16::MAX as usize
    {
        return None;
    }
    out[0] = H3_APP_REQ_MAGIC;
    out[1..5].copy_from_slice(&req.session_id.to_le_bytes());
    out[5..13].copy_from_slice(&req.stream_id.to_le_bytes());
    out[13] = req.method;
    out[14] = req.flags;
    out[15..17].copy_from_slice(&(req.path.len() as u16).to_le_bytes());
    out[17..19].copy_from_slice(&(req.headers.len() as u16).to_le_bytes());
    out[19..23].copy_from_slice(&(req.body.len() as u32).to_le_bytes());
    let mut at = H3_APP_REQ_HDR;
    for part in [req.path, req.headers, req.body] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(at)
}

pub fn parse_request(buf: &[u8]) -> Option<H3AppRequest<'_>> {
    if buf.len() < H3_APP_REQ_HDR || buf[0] != H3_APP_REQ_MAGIC {
        return None;
    }
    let path_len = u16::from_le_bytes([buf[15], buf[16]]) as usize;
    let headers_len = u16::from_le_bytes([buf[17], buf[18]]) as usize;
    let body_len = u32::from_le_bytes([buf[19], buf[20], buf[21], buf[22]]) as usize;
    let total = H3_APP_REQ_HDR
        .checked_add(path_len)?
        .checked_add(headers_len)?
        .checked_add(body_len)?;
    if total != buf.len() || total > H3_APP_MAX_RECORD {
        return None;
    }
    let path_start = H3_APP_REQ_HDR;
    let headers_start = path_start + path_len;
    let body_start = headers_start + headers_len;
    Some(H3AppRequest {
        session_id: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        stream_id: u64::from_le_bytes(buf[5..13].try_into().ok()?),
        method: buf[13],
        flags: buf[14],
        path: &buf[path_start..headers_start],
        headers: &buf[headers_start..body_start],
        body: &buf[body_start..],
    })
}

pub fn write_response(resp: &H3AppResponse<'_>, out: &mut [u8]) -> Option<usize> {
    let total = H3_APP_RESP_HDR
        .checked_add(resp.content_type.len())?
        .checked_add(resp.body.len())?;
    if total > out.len() || total > H3_APP_MAX_RECORD || resp.content_type.len() > u16::MAX as usize
    {
        return None;
    }
    out[0] = H3_APP_RESP_MAGIC;
    out[1..5].copy_from_slice(&resp.session_id.to_le_bytes());
    out[5..13].copy_from_slice(&resp.stream_id.to_le_bytes());
    out[13..15].copy_from_slice(&resp.status.to_le_bytes());
    out[15] = resp.flags;
    out[16] = 0;
    out[17..19].copy_from_slice(&(resp.content_type.len() as u16).to_le_bytes());
    out[19..23].copy_from_slice(&(resp.body.len() as u32).to_le_bytes());
    let at = H3_APP_RESP_HDR;
    out[at..at + resp.content_type.len()].copy_from_slice(resp.content_type);
    out[at + resp.content_type.len()..total].copy_from_slice(resp.body);
    Some(total)
}

pub fn parse_response(buf: &[u8]) -> Option<H3AppResponse<'_>> {
    // Byte 16 pads the header to a word boundary and is written zero. It is
    // checked so it stays available: a field only ever written is one no
    // receiver can later be given a meaning for.
    if buf.len() < H3_APP_RESP_HDR || buf[0] != H3_APP_RESP_MAGIC || buf[16] != 0 {
        return None;
    }
    let ct_len = u16::from_le_bytes([buf[17], buf[18]]) as usize;
    let body_len = u32::from_le_bytes([buf[19], buf[20], buf[21], buf[22]]) as usize;
    let total = H3_APP_RESP_HDR.checked_add(ct_len)?.checked_add(body_len)?;
    if total != buf.len() || total > H3_APP_MAX_RECORD {
        return None;
    }
    let body_start = H3_APP_RESP_HDR + ct_len;
    Some(H3AppResponse {
        session_id: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        stream_id: u64::from_le_bytes(buf[5..13].try_into().ok()?),
        status: u16::from_le_bytes([buf[13], buf[14]]),
        flags: buf[15],
        content_type: &buf[H3_APP_RESP_HDR..body_start],
        body: &buf[body_start..],
    })
}
