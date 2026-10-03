// HTTP application records: the `HttpRequest` / `HttpResponse` channel
// contract between the `http` server and the module that answers its
// application routes.
//
// One exchange is one request and its response, both streamed. The server
// sends a HEAD and then, while the request has a body, BODY records; the
// application answers with its own HEAD and BODY records. Every record names
// the exchange it belongs to by a 14-byte id the server chooses and the
// application echoes back verbatim, so any number of exchanges from any
// number of connections, on any HTTP generation, share one channel pair.
//
// Record layout (multi-byte integers little-endian):
//
//   [kind u8][flags u8][origin u8][0 u8][conn u32][stream u64]   16 bytes
//   kind payload
//
// Request direction (server -> application):
//
//   HEAD     [method u8][target_len u16][hdr_len u16][peer_len u16]
//            [resp_credit u32] target | headers | peer
//   BODY     body bytes
//   ABORT    [reason u8]
//   CREDIT   [bytes u32]                 response-body credit
//   DATAGRAM [context u64] payload       HTTP/3 datagram on a session
//
// Response direction (application -> server):
//
//   HEAD     [status u16][ct_len u8][hdr_len u16] content_type | headers | body
//   BODY     body bytes
//   ABORT    [reason u8]
//   CREDIT   [bytes u32]                 request-body credit
//   DATAGRAM [context u64] payload
//
// `target` is the request target as received (path and query). `headers` is
// the request's field lines as `name: value\r\n`, pseudo-header fields
// excluded; on HTTP/2 and HTTP/3 the server adds a `host` line carrying the
// `:authority`. `peer` is the key fingerprint of a mutual-TLS peer the
// handshake verified, empty for an anonymous connection.
//
// Flow is credit-based in both directions. Body bytes, and only body bytes,
// count. The server sends request-body bytes only up to the credit the
// application has granted with CREDIT records; the application sends
// response-body bytes only up to `resp_credit` plus the server's CREDIT
// grants. A side that holds a body back stops granting, and the other side
// stops sending that exchange's body and nothing else's. The first
// request-body credit is also the application's consent to receive the body:
// a client that asked for `100 Continue` is answered then.
//
// MORE on a HEAD or BODY says further BODY records follow; a record without
// it ends that direction (a final BODY may be empty). ABORT ends the whole
// exchange from the side that sends it, and nothing further is sent for it.
// A response that ends before the request does ends the exchange: the server
// stops reading the request body and sends nothing more for it.

/// Fixed prefix of every record.
pub const APP_HDR: usize = 16;
/// Largest record either side writes: one channel record.
pub const APP_RECORD_MAX: usize = 8192;
/// Largest body payload one BODY record carries.
pub const APP_BODY_MAX: usize = APP_RECORD_MAX - APP_HDR;
/// Fixed part of a request HEAD after the prefix.
pub const APP_REQ_HEAD_FIXED: usize = 1 + 2 + 2 + 2 + 4;
/// Fixed part of a response HEAD after the prefix.
pub const APP_RESP_HEAD_FIXED: usize = 2 + 1 + 2;

/// Record kinds. The same values in both directions; HEAD alone differs in
/// payload by direction.
pub mod app_kind {
    pub const HEAD: u8 = 0x01;
    pub const BODY: u8 = 0x02;
    pub const ABORT: u8 = 0x03;
    pub const CREDIT: u8 = 0x04;
    pub const DATAGRAM: u8 = 0x05;
}

/// Record flags.
pub mod app_flag {
    /// More BODY records follow in this direction.
    pub const MORE: u8 = 0x01;
    /// Response: the application holds the stream open on purpose (a watch,
    /// an event stream) and ends it itself; its progress deadline is the long
    /// one.
    pub const HOLD: u8 = 0x02;
    /// Request: an extended CONNECT for a WebSocket on a route that delegates
    /// the upgrade. Response: the upgrade is accepted, and the stream becomes
    /// a WebSocket tunnel the server terminates.
    pub const WEBSOCKET: u8 = 0x04;
    /// Request: an extended CONNECT for a WebTransport session. Response: the
    /// session is accepted; BODY records then carry the session stream.
    pub const WEBTRANSPORT: u8 = 0x08;
    /// Request: the route is a file route this generation delegates.
    pub const ROUTE_FILE: u8 = 0x10;
    /// Request: the route is a proxy route this generation delegates.
    pub const ROUTE_PROXY: u8 = 0x20;
}

/// Which transport the exchange arrived on. Part of the id: a TCP connection
/// and a QUIC session may hold the same number.
pub mod app_origin {
    pub const TCP: u8 = 1;
    pub const QUIC: u8 = 2;
}

/// Why an exchange was aborted.
pub mod app_abort {
    /// The peer closed or reset before the exchange finished.
    pub const PEER_GONE: u8 = 1;
    /// The request body's framing was malformed.
    pub const MALFORMED: u8 = 2;
    /// The request body passed the route's ceiling.
    pub const TOO_LARGE: u8 = 3;
    /// The peer stopped sending or reading past the stall deadline.
    pub const STALLED: u8 = 4;
    /// The server is draining.
    pub const DRAINING: u8 = 5;
    /// The response can no longer reach the peer.
    pub const UNDELIVERABLE: u8 = 6;
    /// The other side sent body bytes past its credit.
    pub const CREDIT_OVERRUN: u8 = 7;
    /// The application could not finish the exchange.
    pub const FAILED: u8 = 8;
}

/// The exchange a record belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppId {
    pub origin: u8,
    pub conn: u32,
    pub stream: u64,
}

impl AppId {
    fn write(&self, out: &mut [u8]) {
        out[2] = self.origin;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.conn.to_le_bytes());
        out[8..16].copy_from_slice(&self.stream.to_le_bytes());
    }

    fn read(b: &[u8]) -> Option<Self> {
        if b.len() < APP_HDR || b[3] != 0 {
            return None;
        }
        Some(Self {
            origin: b[2],
            conn: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            stream: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        })
    }
}

/// A request HEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppRequestHead<'a> {
    pub id: AppId,
    pub flags: u8,
    pub method: u8,
    pub target: &'a [u8],
    pub headers: &'a [u8],
    pub peer: &'a [u8],
    pub resp_credit: u32,
}

/// A response HEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppResponseHead<'a> {
    pub id: AppId,
    pub flags: u8,
    pub status: u16,
    pub content_type: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

/// One decoded record. `Head` carries the direction's own head type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppRecord<'a, H> {
    Head(H),
    Body {
        id: AppId,
        flags: u8,
        data: &'a [u8],
    },
    Abort {
        id: AppId,
        reason: u8,
    },
    Credit {
        id: AppId,
        bytes: u32,
    },
    Datagram {
        id: AppId,
        context: u64,
        data: &'a [u8],
    },
}

impl<'a, H> AppRecord<'a, H> {
    /// The body bytes this record counts against credit.
    pub fn body_len(&self) -> usize {
        match self {
            AppRecord::Body { data, .. } => data.len(),
            _ => 0,
        }
    }
}

/// A record as the application reads it.
pub type AppRequestRecord<'a> = AppRecord<'a, AppRequestHead<'a>>;
/// A record as the server reads it.
pub type AppResponseRecord<'a> = AppRecord<'a, AppResponseHead<'a>>;

fn app_u16(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize)
}

fn app_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn app_prefix(kind: u8, flags: u8, id: &AppId, out: &mut [u8]) -> Option<()> {
    if out.len() < APP_HDR {
        return None;
    }
    out[0] = kind;
    out[1] = flags;
    id.write(out);
    Some(())
}

/// Decode the kinds both directions share. `None` for HEAD (the caller
/// decodes its own), and for a malformed record.
fn app_common<'a, H>(b: &'a [u8], id: AppId) -> Option<AppRecord<'a, H>> {
    let flags = b[1];
    let rest = &b[APP_HDR..];
    match b[0] {
        app_kind::BODY => Some(AppRecord::Body {
            id,
            flags,
            data: rest,
        }),
        app_kind::ABORT if rest.len() == 1 => Some(AppRecord::Abort {
            id,
            reason: rest[0],
        }),
        app_kind::CREDIT if rest.len() == 4 => Some(AppRecord::Credit {
            id,
            bytes: app_u32(rest, 0)?,
        }),
        app_kind::DATAGRAM if rest.len() >= 8 => Some(AppRecord::Datagram {
            id,
            context: u64::from_le_bytes([
                rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6], rest[7],
            ]),
            data: &rest[8..],
        }),
        _ => None,
    }
}

/// Decode one record the server wrote. `None` when it is malformed: a record
/// is exactly one channel read, so a length that disagrees with it is refused
/// rather than read past or short.
pub fn app_parse_request(b: &[u8]) -> Option<AppRequestRecord<'_>> {
    if b.len() > APP_RECORD_MAX {
        return None;
    }
    let id = AppId::read(b)?;
    if b[0] != app_kind::HEAD {
        return app_common(b, id);
    }
    let p = APP_HDR;
    let method = *b.get(p)?;
    let target_len = app_u16(b, p + 1)?;
    let hdr_len = app_u16(b, p + 3)?;
    let peer_len = app_u16(b, p + 5)?;
    let resp_credit = app_u32(b, p + 7)?;
    let target_at = p + APP_REQ_HEAD_FIXED;
    let hdr_at = target_at.checked_add(target_len)?;
    let peer_at = hdr_at.checked_add(hdr_len)?;
    let end = peer_at.checked_add(peer_len)?;
    if end != b.len() {
        return None;
    }
    Some(AppRecord::Head(AppRequestHead {
        id,
        flags: b[1],
        method,
        target: &b[target_at..hdr_at],
        headers: &b[hdr_at..peer_at],
        peer: &b[peer_at..end],
        resp_credit,
    }))
}

/// Decode one record the application wrote. `None` when it is malformed.
pub fn app_parse_response(b: &[u8]) -> Option<AppResponseRecord<'_>> {
    if b.len() > APP_RECORD_MAX {
        return None;
    }
    let id = AppId::read(b)?;
    if b[0] != app_kind::HEAD {
        return app_common(b, id);
    }
    let p = APP_HDR;
    let status = app_u16(b, p)? as u16;
    let ct_len = *b.get(p + 2)? as usize;
    let hdr_len = app_u16(b, p + 3)?;
    let ct_at = p + APP_RESP_HEAD_FIXED;
    let hdr_at = ct_at.checked_add(ct_len)?;
    let body_at = hdr_at.checked_add(hdr_len)?;
    if body_at > b.len() {
        return None;
    }
    Some(AppRecord::Head(AppResponseHead {
        id,
        flags: b[1],
        status,
        content_type: &b[ct_at..hdr_at],
        headers: &b[hdr_at..body_at],
        body: &b[body_at..],
    }))
}

/// Encode a request HEAD. `None` when it does not fit `out` or one record.
pub fn app_write_request_head(h: &AppRequestHead<'_>, out: &mut [u8]) -> Option<usize> {
    let end = APP_HDR
        .checked_add(APP_REQ_HEAD_FIXED)?
        .checked_add(h.target.len())?
        .checked_add(h.headers.len())?
        .checked_add(h.peer.len())?;
    if end > out.len()
        || end > APP_RECORD_MAX
        || h.target.len() > u16::MAX as usize
        || h.headers.len() > u16::MAX as usize
        || h.peer.len() > u16::MAX as usize
    {
        return None;
    }
    app_prefix(app_kind::HEAD, h.flags, &h.id, out)?;
    let p = APP_HDR;
    out[p] = h.method;
    out[p + 1..p + 3].copy_from_slice(&(h.target.len() as u16).to_le_bytes());
    out[p + 3..p + 5].copy_from_slice(&(h.headers.len() as u16).to_le_bytes());
    out[p + 5..p + 7].copy_from_slice(&(h.peer.len() as u16).to_le_bytes());
    out[p + 7..p + 11].copy_from_slice(&h.resp_credit.to_le_bytes());
    let mut at = p + APP_REQ_HEAD_FIXED;
    for part in [h.target, h.headers, h.peer] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(at)
}

/// Encode a response HEAD. `None` when it does not fit `out` or one record.
pub fn app_write_response_head(h: &AppResponseHead<'_>, out: &mut [u8]) -> Option<usize> {
    let end = APP_HDR
        .checked_add(APP_RESP_HEAD_FIXED)?
        .checked_add(h.content_type.len())?
        .checked_add(h.headers.len())?
        .checked_add(h.body.len())?;
    if end > out.len()
        || end > APP_RECORD_MAX
        || h.content_type.len() > u8::MAX as usize
        || h.headers.len() > u16::MAX as usize
    {
        return None;
    }
    app_prefix(app_kind::HEAD, h.flags, &h.id, out)?;
    let p = APP_HDR;
    out[p..p + 2].copy_from_slice(&h.status.to_le_bytes());
    out[p + 2] = h.content_type.len() as u8;
    out[p + 3..p + 5].copy_from_slice(&(h.headers.len() as u16).to_le_bytes());
    let mut at = p + APP_RESP_HEAD_FIXED;
    for part in [h.content_type, h.headers, h.body] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(at)
}

/// Encode a BODY record (either direction).
pub fn app_write_body(id: &AppId, flags: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = APP_HDR.checked_add(data.len())?;
    if end > out.len() || end > APP_RECORD_MAX {
        return None;
    }
    app_prefix(app_kind::BODY, flags, id, out)?;
    out[APP_HDR..end].copy_from_slice(data);
    Some(end)
}

/// Seal a BODY record whose `data_len` payload bytes are already in place at
/// `out[APP_HDR..]`: writes the prefix and returns the record length. For a
/// writer that decodes straight into the record rather than through a copy.
pub fn app_seal_body(id: &AppId, flags: u8, data_len: usize, out: &mut [u8]) -> Option<usize> {
    let end = APP_HDR.checked_add(data_len)?;
    if end > out.len() || end > APP_RECORD_MAX {
        return None;
    }
    app_prefix(app_kind::BODY, flags, id, out)?;
    Some(end)
}

/// Encode an ABORT record (either direction).
pub fn app_write_abort(id: &AppId, reason: u8, out: &mut [u8]) -> Option<usize> {
    if out.len() < APP_HDR + 1 {
        return None;
    }
    app_prefix(app_kind::ABORT, 0, id, out)?;
    out[APP_HDR] = reason;
    Some(APP_HDR + 1)
}

/// Encode a CREDIT record (either direction).
pub fn app_write_credit(id: &AppId, bytes: u32, out: &mut [u8]) -> Option<usize> {
    if out.len() < APP_HDR + 4 {
        return None;
    }
    app_prefix(app_kind::CREDIT, 0, id, out)?;
    out[APP_HDR..APP_HDR + 4].copy_from_slice(&bytes.to_le_bytes());
    Some(APP_HDR + 4)
}

/// Encode a DATAGRAM record (either direction).
pub fn app_write_datagram(id: &AppId, context: u64, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = APP_HDR.checked_add(8)?.checked_add(data.len())?;
    if end > out.len() || end > APP_RECORD_MAX {
        return None;
    }
    app_prefix(app_kind::DATAGRAM, 0, id, out)?;
    out[APP_HDR..APP_HDR + 8].copy_from_slice(&context.to_le_bytes());
    out[APP_HDR + 8..end].copy_from_slice(data);
    Some(end)
}

/// The value of the first header named `name` (ASCII case-insensitive) in a
/// `name: value\r\n` block, with optional whitespace trimmed.
pub fn app_header<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    app_header_lines(headers)
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// The `name: value\r\n` lines of a header block, in order.
pub struct AppHeaderLines<'a> {
    rest: &'a [u8],
}

/// Iterate a header block's fields as `(name, value)` with optional
/// whitespace trimmed from the value. A line without a colon is skipped.
pub fn app_header_lines(headers: &[u8]) -> AppHeaderLines<'_> {
    AppHeaderLines { rest: headers }
}

impl<'a> Iterator for AppHeaderLines<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.rest.is_empty() {
            let end = self
                .rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(self.rest.len());
            let line = &self.rest[..end];
            self.rest = self.rest.get(end + 2..).unwrap_or(&[]);
            let Some(colon) = line.iter().position(|&c| c == b':') else {
                continue;
            };
            let mut v = &line[colon + 1..];
            while let [b' ' | b'\t', tail @ ..] = v {
                v = tail;
            }
            while let [head @ .., b' ' | b'\t'] = v {
                v = head;
            }
            return Some((&line[..colon], v));
        }
        None
    }
}
