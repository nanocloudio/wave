// Wire format for the `http` server's WebSocket ADMISSION ports.
//
// Whether a given browser may open a socket at all is a question only the
// application can answer, and it has to be answered BEFORE the connection
// becomes one — once the 101 is written the peer is entitled to send frames,
// and a rejection after that is a close, not a refusal.
//
// So an admission-gated route asks first. The module reports what it knows
// about the request; the application answers accept or reject; only an accept
// composes the 101. Nothing above ever sees a frame from a connection it did
// not admit.
//
// Layouts (multi-byte ints LE):
//
//   WsAdmitRequest  [op:u8][conn:u32][path_len:u16][hdr_len:u16][proto_len:u16]
//                   [path][headers][subprotocols]
//
//   WsAdmitDecision [op:u8][conn:u32][decision:u8][status:u16][proto_len:u16]
//                   [reason_len:u16][protocol][reason]
//
//   WsEvent         [op:u8][conn:u32][event:u8][origin:u8][code:u16]
//                   [reason_len:u16][reason]
//
// `conn` is the module's connection id — the same one that addresses data
// frames on `ws_out` / `ws_in`, so an application correlates an admission, its
// frames, and its closure without a second identifier scheme.

/// The module asks whether this connection may be admitted.
pub const WS_OP_ADMIT_REQUEST: u8 = 0x80;
/// The application answers.
pub const WS_OP_ADMIT_DECISION: u8 = 0x81;
/// The module reports a committed lifecycle fact.
pub const WS_OP_EVENT: u8 = 0x82;

// There is deliberately no transport-fact field here. The net layer's accept
// event carries a connection id and a local port and no peer address, and this
// module sits above whatever terminated TLS rather than inside it — so a
// "secure" or "peer address" field would be a value invented at this seam.
// Where a deployment terminates TLS through the `tls` module, that module
// publishes the peer identity it actually verified on its own port, and the
// application correlates the two. What this record carries is what the request
// itself said: its path, its headers, and the subprotocols it asked for.

/// Admit the connection.
pub const WS_ADMIT_ACCEPT: u8 = 0;
/// Refuse it, with an HTTP status and a bounded reason.
pub const WS_ADMIT_REJECT: u8 = 1;

/// The upgrade was committed: this connection's frames are live.
pub const WS_EV_OPENED: u8 = 0;
/// The connection closed, and the close is observed rather than requested.
pub const WS_EV_CLOSED: u8 = 1;

/// The peer closed it.
pub const WS_ORIGIN_PEER: u8 = 0;
/// This end closed it.
pub const WS_ORIGIN_LOCAL: u8 = 1;

/// Fixed prefix of a `WsAdmitRequest`.
pub const WS_ADMIT_REQ_HDR: usize = 1 + 4 + 2 + 2 + 2;
/// Fixed prefix of a `WsAdmitDecision`.
pub const WS_ADMIT_DEC_HDR: usize = 1 + 4 + 1 + 2 + 2 + 2;
/// Fixed prefix of a `WsEvent`.
pub const WS_EVENT_HDR: usize = 1 + 4 + 1 + 1 + 2 + 2;

/// A parsed `WsAdmitRequest`, as offsets into the caller's buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WsAdmitReqView {
    pub conn: u32,
    pub path_at: usize,
    pub path_len: usize,
    pub headers_at: usize,
    pub headers_len: usize,
    pub protocols_at: usize,
    pub protocols_len: usize,
}

/// Build a `WsAdmitRequest` into `out`.
pub fn write_ws_admit_request(
    conn: u32,
    path: &[u8],
    headers: &[u8],
    protocols: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = WS_ADMIT_REQ_HDR
        .checked_add(path.len())?
        .checked_add(headers.len())?
        .checked_add(protocols.len())?;
    if out.len() < total
        || path.len() > u16::MAX as usize
        || headers.len() > u16::MAX as usize
        || protocols.len() > u16::MAX as usize
    {
        return None;
    }
    out[0] = WS_OP_ADMIT_REQUEST;
    out[1..5].copy_from_slice(&conn.to_le_bytes());
    out[5..7].copy_from_slice(&(path.len() as u16).to_le_bytes());
    out[7..9].copy_from_slice(&(headers.len() as u16).to_le_bytes());
    out[9..11].copy_from_slice(&(protocols.len() as u16).to_le_bytes());
    let mut p = WS_ADMIT_REQ_HDR;
    out[p..p + path.len()].copy_from_slice(path);
    p += path.len();
    out[p..p + headers.len()].copy_from_slice(headers);
    p += headers.len();
    out[p..p + protocols.len()].copy_from_slice(protocols);
    Some(total)
}

/// Parse a `WsAdmitRequest`.
pub fn parse_ws_admit_request(buf: &[u8]) -> Option<WsAdmitReqView> {
    if buf.len() < WS_ADMIT_REQ_HDR || buf[0] != WS_OP_ADMIT_REQUEST {
        return None;
    }
    let path_len = u16::from_le_bytes([buf[5], buf[6]]) as usize;
    let headers_len = u16::from_le_bytes([buf[7], buf[8]]) as usize;
    let protocols_len = u16::from_le_bytes([buf[9], buf[10]]) as usize;
    let need = WS_ADMIT_REQ_HDR
        .checked_add(path_len)?
        .checked_add(headers_len)?
        .checked_add(protocols_len)?;
    if buf.len() < need {
        return None;
    }
    let path_at = WS_ADMIT_REQ_HDR;
    let headers_at = path_at + path_len;
    let protocols_at = headers_at + headers_len;
    Some(WsAdmitReqView {
        conn: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        path_at,
        path_len,
        headers_at,
        headers_len,
        protocols_at,
        protocols_len,
    })
}

/// A parsed `WsAdmitDecision`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WsAdmitDecView {
    pub conn: u32,
    pub decision: u8,
    pub status: u16,
    pub protocol_at: usize,
    pub protocol_len: usize,
    pub reason_at: usize,
    pub reason_len: usize,
}

impl WsAdmitDecView {
    /// Whether the application admitted the connection.
    ///
    /// Anything that is not an explicit accept is a refusal: a decision byte
    /// this does not recognise must not open a socket.
    pub fn accepted(&self) -> bool {
        self.decision == WS_ADMIT_ACCEPT
    }
}

/// Build a `WsAdmitDecision` into `out`.
pub fn write_ws_admit_decision(
    conn: u32,
    decision: u8,
    status: u16,
    protocol: &[u8],
    reason: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = WS_ADMIT_DEC_HDR
        .checked_add(protocol.len())?
        .checked_add(reason.len())?;
    if out.len() < total || protocol.len() > u16::MAX as usize || reason.len() > u16::MAX as usize {
        return None;
    }
    out[0] = WS_OP_ADMIT_DECISION;
    out[1..5].copy_from_slice(&conn.to_le_bytes());
    out[5] = decision;
    out[6..8].copy_from_slice(&status.to_le_bytes());
    out[8..10].copy_from_slice(&(protocol.len() as u16).to_le_bytes());
    out[10..12].copy_from_slice(&(reason.len() as u16).to_le_bytes());
    let mut p = WS_ADMIT_DEC_HDR;
    out[p..p + protocol.len()].copy_from_slice(protocol);
    p += protocol.len();
    out[p..p + reason.len()].copy_from_slice(reason);
    Some(total)
}

/// Parse a `WsAdmitDecision`.
pub fn parse_ws_admit_decision(buf: &[u8]) -> Option<WsAdmitDecView> {
    if buf.len() < WS_ADMIT_DEC_HDR || buf[0] != WS_OP_ADMIT_DECISION {
        return None;
    }
    let protocol_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let reason_len = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    let need = WS_ADMIT_DEC_HDR
        .checked_add(protocol_len)?
        .checked_add(reason_len)?;
    if buf.len() < need {
        return None;
    }
    let protocol_at = WS_ADMIT_DEC_HDR;
    let reason_at = protocol_at + protocol_len;
    Some(WsAdmitDecView {
        conn: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        decision: buf[5],
        status: u16::from_le_bytes([buf[6], buf[7]]),
        protocol_at,
        protocol_len,
        reason_at,
        reason_len,
    })
}

/// A parsed `WsEvent`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WsEventView {
    pub conn: u32,
    pub event: u8,
    pub origin: u8,
    pub code: u16,
    pub reason_at: usize,
    pub reason_len: usize,
}

/// Build a `WsEvent` into `out`.
pub fn write_ws_event(
    conn: u32,
    event: u8,
    origin: u8,
    code: u16,
    reason: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = WS_EVENT_HDR.checked_add(reason.len())?;
    if out.len() < total || reason.len() > u16::MAX as usize {
        return None;
    }
    out[0] = WS_OP_EVENT;
    out[1..5].copy_from_slice(&conn.to_le_bytes());
    out[5] = event;
    out[6] = origin;
    out[7..9].copy_from_slice(&code.to_le_bytes());
    out[9..11].copy_from_slice(&(reason.len() as u16).to_le_bytes());
    out[WS_EVENT_HDR..total].copy_from_slice(reason);
    Some(total)
}

/// Parse a `WsEvent`.
pub fn parse_ws_event(buf: &[u8]) -> Option<WsEventView> {
    if buf.len() < WS_EVENT_HDR || buf[0] != WS_OP_EVENT {
        return None;
    }
    let reason_len = u16::from_le_bytes([buf[9], buf[10]]) as usize;
    if buf.len() < WS_EVENT_HDR + reason_len {
        return None;
    }
    Some(WsEventView {
        conn: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        event: buf[5],
        origin: buf[6],
        code: u16::from_le_bytes([buf[7], buf[8]]),
        reason_at: WS_EVENT_HDR,
        reason_len,
    })
}
