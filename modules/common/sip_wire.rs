// Wire format for the `sip` module's command/event ports.
//
// Commands say what to do about one call; events report what happened to it.
// Every record carries the same call id, so an application follows a call from
// the offer to the outcome.
//
// The record shape is what makes that possible. A command names WHICH call and
// which peer, and can refuse a specific one with a specific reason; an event
// reports how a call ended, and that one arrived at all. A control surface
// narrower than this — a trigger, a flag — can start and stop a call but
// cannot describe one, so the layer above is left inferring state it was never
// told.
//
// Layouts (multi-byte ints LE, except IPv4 addresses which are big-endian as
// the datagram surface carries them):
//
//   SipCommand [op:u8][cid:u32][code:u16][peer_ip:4][peer_port:u16]
//              [media_ip:4][media_port:u16]
//
//   SipEvent   [op:u8][cid:u32][event:u8][code:u16][media_ip:4][media_port:u16]
//              [payload_type:u8][detail_len:u16][detail]
//
// Both are fixed-shape apart from the event's bounded detail, so a caller
// reads one without allocating.

/// Place a call to `peer`, sending media from `media`.
///
/// The peer and media endpoints travel with the command rather than being
/// fixed when the module was built: a connector that can only ever call one
/// address is not a connector.
pub const SIP_CMD_DIAL: u8 = 0x90;
/// Answer the offered call, naming where media should be sent.
pub const SIP_CMD_ACCEPT: u8 = 0x91;
/// Refuse the offered call with a SIP status code.
pub const SIP_CMD_REJECT: u8 = 0x92;
/// End an established call.
pub const SIP_CMD_HANGUP: u8 = 0x93;
/// Abandon a call this end placed but which has not been answered.
pub const SIP_CMD_CANCEL: u8 = 0x94;
/// The op byte every event carries.
pub const SIP_OP_EVENT: u8 = 0x9F;

/// A call has arrived and is waiting for a decision.
///
/// Nothing is answered until one is made. Ringing a caller and then having
/// nobody able to accept is a worse outcome than a refusal, so the decision
/// comes first.
pub const SIP_EV_OFFERED: u8 = 0;
/// A provisional response arrived for a call this end placed (100, 180, 183).
pub const SIP_EV_PROVISIONAL: u8 = 1;
/// The call is established and media is flowing.
pub const SIP_EV_ESTABLISHED: u8 = 2;
/// A final response refused the call, with its status code.
pub const SIP_EV_REJECTED: u8 = 3;
/// A transaction reached its retransmission limit with no final response.
pub const SIP_EV_TIMEOUT: u8 = 4;
/// The transport or the protocol failed.
pub const SIP_EV_FAILED: u8 = 5;
/// The peer ended an established call.
pub const SIP_EV_REMOTE_HANGUP: u8 = 6;
/// This end ended the call.
pub const SIP_EV_LOCAL_CLOSED: u8 = 7;
/// An offered call was refused by this end.
pub const SIP_EV_DECLINED: u8 = 8;

/// Fixed size of a `SipCommand`.
pub const SIP_CMD_LEN: usize = 1 + 4 + 2 + 4 + 2 + 4 + 2;
/// Fixed prefix of a `SipEvent`.
pub const SIP_EVENT_HDR: usize = 1 + 4 + 1 + 2 + 4 + 2 + 1 + 2;

/// A parsed `SipCommand`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SipCommandView {
    pub op: u8,
    pub cid: u32,
    pub code: u16,
    pub peer_ip: [u8; 4],
    pub peer_port: u16,
    pub media_ip: [u8; 4],
    pub media_port: u16,
}

/// Whether an op is one this module performs.
pub fn sip_cmd_is_known(op: u8) -> bool {
    matches!(
        op,
        SIP_CMD_DIAL | SIP_CMD_ACCEPT | SIP_CMD_REJECT | SIP_CMD_HANGUP | SIP_CMD_CANCEL
    )
}

/// Build a `SipCommand` into `out`.
#[expect(
    clippy::too_many_arguments,
    reason = "a command states every fact it carries; a struct here would only move the list"
)]
pub fn write_sip_command(
    op: u8,
    cid: u32,
    code: u16,
    peer_ip: [u8; 4],
    peer_port: u16,
    media_ip: [u8; 4],
    media_port: u16,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < SIP_CMD_LEN {
        return None;
    }
    out[0] = op;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5..7].copy_from_slice(&code.to_le_bytes());
    out[7..11].copy_from_slice(&peer_ip);
    out[11..13].copy_from_slice(&peer_port.to_le_bytes());
    out[13..17].copy_from_slice(&media_ip);
    out[17..19].copy_from_slice(&media_port.to_le_bytes());
    Some(SIP_CMD_LEN)
}

/// Parse a `SipCommand`.
pub fn parse_sip_command(buf: &[u8]) -> Option<SipCommandView> {
    if buf.len() < SIP_CMD_LEN {
        return None;
    }
    Some(SipCommandView {
        op: buf[0],
        cid: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        code: u16::from_le_bytes([buf[5], buf[6]]),
        peer_ip: [buf[7], buf[8], buf[9], buf[10]],
        peer_port: u16::from_le_bytes([buf[11], buf[12]]),
        media_ip: [buf[13], buf[14], buf[15], buf[16]],
        media_port: u16::from_le_bytes([buf[17], buf[18]]),
    })
}

/// A parsed `SipEvent`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SipEventView {
    pub cid: u32,
    pub event: u8,
    pub code: u16,
    /// The negotiated remote media endpoint, where one has been negotiated.
    pub media_ip: [u8; 4],
    pub media_port: u16,
    /// The selected RTP payload type, or 0xFF when none is settled.
    pub payload_type: u8,
    pub detail_at: usize,
    pub detail_len: usize,
}

/// Build a `SipEvent` into `out`.
#[expect(
    clippy::too_many_arguments,
    reason = "an event states every fact it carries; a struct here would only move the list"
)]
pub fn write_sip_event(
    cid: u32,
    event: u8,
    code: u16,
    media_ip: [u8; 4],
    media_port: u16,
    payload_type: u8,
    detail: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = SIP_EVENT_HDR.checked_add(detail.len())?;
    if out.len() < total || detail.len() > u16::MAX as usize {
        return None;
    }
    out[0] = SIP_OP_EVENT;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5] = event;
    out[6..8].copy_from_slice(&code.to_le_bytes());
    out[8..12].copy_from_slice(&media_ip);
    out[12..14].copy_from_slice(&media_port.to_le_bytes());
    out[14] = payload_type;
    out[15..17].copy_from_slice(&(detail.len() as u16).to_le_bytes());
    out[SIP_EVENT_HDR..total].copy_from_slice(detail);
    Some(total)
}

/// Parse a `SipEvent`.
pub fn parse_sip_event(buf: &[u8]) -> Option<SipEventView> {
    if buf.len() < SIP_EVENT_HDR || buf[0] != SIP_OP_EVENT {
        return None;
    }
    let detail_len = u16::from_le_bytes([buf[15], buf[16]]) as usize;
    if buf.len() < SIP_EVENT_HDR + detail_len {
        return None;
    }
    Some(SipEventView {
        cid: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        event: buf[5],
        code: u16::from_le_bytes([buf[6], buf[7]]),
        media_ip: [buf[8], buf[9], buf[10], buf[11]],
        media_port: u16::from_le_bytes([buf[12], buf[13]]),
        payload_type: buf[14],
        detail_at: SIP_EVENT_HDR,
        detail_len,
    })
}

/// Whether an event ends the call it describes.
///
/// Every call reaches exactly one of these, which is what lets a caller free
/// what it was holding without guessing.
pub fn sip_event_is_terminal(event: u8) -> bool {
    matches!(
        event,
        SIP_EV_REJECTED
            | SIP_EV_TIMEOUT
            | SIP_EV_FAILED
            | SIP_EV_REMOTE_HANGUP
            | SIP_EV_LOCAL_CLOSED
            | SIP_EV_DECLINED
    )
}
