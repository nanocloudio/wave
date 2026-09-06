// Shared RFC 3550 header decoder — the single implementation of §5.1's fixed
// header, the CSRC list, the §5.3.1 extension, and §5.1 padding.
//
// `include!`d by BOTH sides:
//   * `modules/foundation/rtp/mod.rs` — the transmitter/receiver
//   * `modules/foundation/sip/mod.rs` — the user agent's receive path, which
//     feeds `jitter_core`
//
// WHY ONLY THE HEADER IS SHARED, as with `ws_frame_core`: where the payload
// goes differs entirely. `rtp` copies it to an output channel; `sip` inserts it
// into a reorder buffer keyed by sequence number. What is genuinely one thing is
// which bytes of a packet are payload at all — and getting that wrong is
// inaudible in a test and audible on a call.
//
// A reader that honours the CSRC count but ignores the X and P bits admits
// non-audio bytes into the µ-law stream from a perfectly conforming sender:
// four or more bytes of extension header at the front of every packet (RFC
// 6464 audio level indication is the common case), or padding at the end.
// ffmpeg sets neither by default, so an interop suite built around it does not
// exercise either — which is why both are decoded here rather than assumed
// absent.

/// §5.1: the only version this decoder accepts.
pub const RTP_VERSION: u8 = 2;

/// §5.1 fixed header: V/P/X/CC, M/PT, sequence, timestamp, SSRC.
pub const RTP_HEADER_SIZE: usize = 12;

/// A decoded header, and the payload bounds it implies.
///
/// `payload` is the half-open range within the packet after the fixed header,
/// the CSRC list and any extension, and before any padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    pub payload_type: u8,
    pub marker: bool,
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload_start: usize,
    pub payload_end: usize,
}

/// Extract the RFC 8285 MID extension (one-byte profile, element id 10) from
/// a packet already accepted by [`rtp_parse`]. The returned slice borrows the
/// packet and is empty when the extension is absent or uses an unsupported
/// profile; no allocation or unbounded scan is possible.
pub fn rtp_mid<'a>(pkt: &'a [u8], header: &RtpHeader) -> &'a [u8] {
    if pkt.len() < RTP_HEADER_SIZE || header.payload_start > pkt.len() {
        return &[];
    }
    let cc = (pkt[0] & 0x0f) as usize;
    let ext = RTP_HEADER_SIZE + cc * 4;
    if pkt[0] & 0x10 == 0 || ext + 4 > header.payload_start {
        return &[];
    }
    let profile = u16::from_be_bytes([pkt[ext], pkt[ext + 1]]);
    let bytes = usize::from(u16::from_be_bytes([pkt[ext + 2], pkt[ext + 3]])) * 4;
    let start = ext + 4;
    if profile != 0xBEDE || start.checked_add(bytes).is_none() || start + bytes > pkt.len() {
        return &[];
    }
    let end = start + bytes;
    let mut at = start;
    while at < end {
        let descriptor = pkt[at];
        at += 1;
        if descriptor == 0 {
            continue;
        }
        let id = descriptor >> 4;
        if id == 15 {
            break;
        }
        let len = (descriptor & 0x0f) as usize + 1;
        if at + len > end {
            return &[];
        }
        if id == 10 {
            return &pkt[at..at + len];
        }
        at += len;
    }
    &[]
}

impl RtpHeader {
    /// Payload length in bytes. Never zero — [`rtp_parse`] rejects a packet
    /// that carries no payload rather than reporting an empty one, because a
    /// zero-length write downstream reads as a codec underrun.
    #[inline]
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload_end - self.payload_start
    }
}

/// Decode one RTP packet header and locate its payload.
///
/// Returns `None` — a packet to drop, never a partial result — when the packet
/// is too short, is not version 2, declares a CSRC list or extension that
/// overruns it, declares padding that overruns the payload, or leaves no
/// payload at all. There is no "incomplete" state: RTP rides datagrams, so a
/// short packet is a bad packet rather than one awaiting more bytes.
#[must_use]
pub fn rtp_parse(pkt: &[u8]) -> Option<RtpHeader> {
    if pkt.len() < RTP_HEADER_SIZE {
        return None;
    }
    let b0 = pkt[0];
    if (b0 >> 6) & 0x03 != RTP_VERSION {
        return None;
    }

    // CSRC list: CC × 4 bytes after the fixed header.
    let cc = (b0 & 0x0F) as usize;
    let mut start = RTP_HEADER_SIZE + cc * 4;
    if pkt.len() <= start {
        return None;
    }

    // §5.3.1 extension: `[profile:2][length:2]` then `length` 32-bit words. A
    // receiver that does not implement the extension must skip it; skipping is
    // the whole obligation.
    if b0 & 0x10 != 0 {
        if pkt.len() < start + 4 {
            return None;
        }
        let words = ((pkt[start + 2] as usize) << 8) | (pkt[start + 3] as usize);
        let total = 4 + words * 4;
        if pkt.len() <= start + total {
            return None;
        }
        start += total;
    }

    // §5.1 padding: the last octet counts the padding octets, itself included.
    let mut end = pkt.len();
    if b0 & 0x20 != 0 {
        let pad = pkt[end - 1] as usize;
        if pad == 0 || pad > end - start {
            return None;
        }
        end -= pad;
    }
    if end == start {
        return None;
    }

    Some(RtpHeader {
        payload_type: pkt[1] & 0x7F,
        marker: pkt[1] & 0x80 != 0,
        seq: u16::from_be_bytes([pkt[2], pkt[3]]),
        timestamp: u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
        ssrc: u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]),
        payload_start: start,
        payload_end: end,
    })
}
