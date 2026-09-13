// The records that drive a WebSocket connector from outside it, and the
// number of links one carries.
//
// A consumer holding several links addresses them by index, and that index
// rides in `WsFrame`'s `conn` field -- a contract Fluxor owns, so the
// messages themselves need nothing from here. What a frame has no room to
// say is here instead: which resource to open, and what became of a link.
//
// Both ends mount this file, so the count and the layouts are written once.
// The count especially: a consumer that thought there were more links than
// the connector carries would address one that cannot exist, and nothing on
// the wire would say so.

/// How many WebSockets one connector carries at once.
///
/// Four, to match the connection tables of the network adapters that sit
/// under it: a consumer that can hold four sockets open should not find the
/// protocol above them the narrower of the two.
pub const WS_LINKS: usize = 4;

/// An open request: `[conn: u8][path…]`.
///
/// The endpoint stays the graph's to name. A consumer chooses WHAT to open,
/// never WHERE -- which is the same split every other capability here makes,
/// and what lets one connector serve a program that must not choose its own
/// host.
pub mod open {
    /// Bytes before the resource.
    pub const HEAD: usize = 1;
}

/// What became of a link: `[conn: u8][event: u8][code: u16 LE]`.
///
/// Three events, because three is what a consumer has to act on: it opened,
/// it ended, or it never opened. A reader waiting to send cannot infer any of
/// them from silence.
pub mod event {
    /// The upgrade was verified; the link carries messages from here.
    pub const OPEN: u8 = 1;
    /// The link ended. `code` is the WebSocket close code, 1006 if the
    /// transport went before one arrived.
    pub const CLOSED: u8 = 2;
    /// The link never opened: the dial, the upgrade, or its verification.
    pub const FAILED: u8 = 3;
    /// The record's width.
    pub const LEN: usize = 4;
}

/// Compose an open request into `out`, answering its length.
pub fn write_open(conn: u8, path: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = open::HEAD + path.len();
    if total > out.len() {
        return None;
    }
    out[0] = conn;
    out.get_mut(open::HEAD..total)?.copy_from_slice(path);
    Some(total)
}

/// Read an open request, answering the link and the resource it names.
pub fn parse_open(record: &[u8]) -> Option<(usize, &[u8])> {
    let conn = usize::from(*record.first()?);
    if conn >= WS_LINKS {
        return None;
    }
    Some((conn, record.get(open::HEAD..)?))
}

/// Compose a link event into `out`.
pub fn write_event(conn: u8, kind: u8, code: u16, out: &mut [u8]) -> Option<usize> {
    let slot = out.get_mut(..event::LEN)?;
    slot[0] = conn;
    slot[1] = kind;
    let bytes = code.to_le_bytes();
    slot[2] = bytes[0];
    slot[3] = bytes[1];
    Some(event::LEN)
}

/// Read a link event.
pub fn parse_event(record: &[u8]) -> Option<(usize, u8, u16)> {
    let fields = record.get(..event::LEN)?;
    let conn = usize::from(fields[0]);
    if conn >= WS_LINKS {
        return None;
    }
    Some((conn, fields[1], u16::from_le_bytes([fields[2], fields[3]])))
}
