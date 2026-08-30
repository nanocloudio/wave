// The rtp → jitter receive-record seam: one validated RTP payload per frame,
// carried over an OctetStream channel with the shared net TLV framing
// (`net_write_frame` / `net_read_frame`), because channels are byte streams
// and bare records concatenate.
//
//   [REC_RTP_RX: u8] [len: u16 LE] [seq: u16 LE] [payload…]
//
// The sequence rides the record because the reorder buffer downstream keys on
// it — a consumer that cannot see the sequence cannot see loss, let alone
// conceal it (rfc_hardening §9.6). This file owns the layout; `rtp` writes
// it, `jitter` reads it, and no third spelling exists.

/// Frame type of one validated receive record.
pub const REC_RTP_RX: u8 = 0x01;

/// Bytes of sequence number leading the frame payload.
pub const RTP_RX_SEQ_LEN: usize = 2;

/// Read the sequence from a record payload. Callers bounds-check
/// `payload.len() >= RTP_RX_SEQ_LEN` first.
#[inline]
pub fn rtp_rx_seq(payload: &[u8]) -> u16 {
    u16::from_le_bytes([payload[0], payload[1]])
}

/// Write the sequence into the leading bytes of a record payload.
#[inline]
pub fn put_rtp_rx_seq(payload: &mut [u8], seq: u16) {
    payload[0..RTP_RX_SEQ_LEN].copy_from_slice(&seq.to_le_bytes());
}

// ---- RTCP statistics records ----------------------------------------------
//
// `rtp`'s out[2] -> `rtcp`'s in[1]. Two kinds share one channel, each tagged,
// so the control plane can build both halves of RFC 3550 §6.4 without `rtp`
// growing a port per direction.
//
// Defined HERE, in the shared core, rather than at each end. Two modules that
// each hand-roll the same bytes are two places for the layout to drift, and
// the drift is silent: a mismatched field reads as a plausible sequence number
// and a nonsense jitter estimate.
//
// Neither record carries a wall-clock time. `rtp` reads no clock — it attests
// `timer_class = "agnostic"` — so the consumer stamps time from its own. For
// the receive record that is exact: RFC 3550 §A.8 estimates jitter from a
// difference of differences, so a constant offset cancels. For the send record
// it is an approximation, and a stated one: the NTP/RTP pair in a Sender
// Report is read as "these were simultaneous", and they are simultaneous to
// within one scheduler pass rather than exactly.

/// A reception record: one per accepted packet.
pub const RTCP_STAT_RX: u8 = 1;
/// A transmission record: the sender's running counters.
pub const RTCP_STAT_TX: u8 = 2;

/// `[kind: u8][seq: u16 LE][rtp_ts: u32 LE]`.
pub const RTCP_STAT_RX_LEN: usize = 1 + 2 + 4;
/// `[kind: u8][packets: u32 LE][octets: u32 LE][rtp_ts: u32 LE]`.
pub const RTCP_STAT_TX_LEN: usize = 1 + 4 + 4 + 4;
/// The longest record on this channel — what the port must take as one, and
/// what a consumer's staging buffer must hold.
pub const RTCP_STAT_MAX_LEN: usize = if RTCP_STAT_RX_LEN > RTCP_STAT_TX_LEN {
    RTCP_STAT_RX_LEN
} else {
    RTCP_STAT_TX_LEN
};

/// Write a reception record. `None` if `out` is too short.
pub fn put_rtcp_stat_rx(out: &mut [u8], seq: u16, rtp_ts: u32) -> Option<usize> {
    if out.len() < RTCP_STAT_RX_LEN {
        return None;
    }
    out[0] = RTCP_STAT_RX;
    out[1..3].copy_from_slice(&seq.to_le_bytes());
    out[3..7].copy_from_slice(&rtp_ts.to_le_bytes());
    Some(RTCP_STAT_RX_LEN)
}

/// Write a transmission record. `None` if `out` is too short.
pub fn put_rtcp_stat_tx(out: &mut [u8], packets: u32, octets: u32, rtp_ts: u32) -> Option<usize> {
    if out.len() < RTCP_STAT_TX_LEN {
        return None;
    }
    out[0] = RTCP_STAT_TX;
    out[1..5].copy_from_slice(&packets.to_le_bytes());
    out[5..9].copy_from_slice(&octets.to_le_bytes());
    out[9..13].copy_from_slice(&rtp_ts.to_le_bytes());
    Some(RTCP_STAT_TX_LEN)
}

/// What one record on the stats channel says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpStat {
    /// A packet arrived: its sequence number and RTP timestamp.
    Rx { seq: u16, rtp_ts: u32 },
    /// The sender's counters as of its last transmission.
    Tx {
        packets: u32,
        octets: u32,
        rtp_ts: u32,
    },
}

/// How long the record beginning at `buf[0]` is, from its tag alone.
///
/// Read before the body so a consumer can take exactly one record off a
/// byte-stream channel. `None` for a tag this core does not define — a record
/// of unknown length cannot be skipped, so the caller must stop rather than
/// guess and desynchronise everything behind it.
#[must_use]
pub fn rtcp_stat_len(tag: u8) -> Option<usize> {
    match tag {
        RTCP_STAT_RX => Some(RTCP_STAT_RX_LEN),
        RTCP_STAT_TX => Some(RTCP_STAT_TX_LEN),
        _ => None,
    }
}

/// Read one record. `None` unless `buf` is exactly one well-formed record.
#[must_use]
pub fn parse_rtcp_stat(buf: &[u8]) -> Option<RtcpStat> {
    let want = rtcp_stat_len(*buf.first()?)?;
    if buf.len() != want {
        return None;
    }
    // Every tag named explicitly, with no catch-all: a kind added to
    // `rtcp_stat_len` and forgotten here must fail to decode rather than be
    // read as whichever variant the wildcard happened to point at.
    match buf[0] {
        RTCP_STAT_RX => Some(RtcpStat::Rx {
            seq: u16::from_le_bytes([buf[1], buf[2]]),
            rtp_ts: u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]),
        }),
        RTCP_STAT_TX => Some(RtcpStat::Tx {
            packets: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            octets: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
            rtp_ts: u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]),
        }),
        _ => None,
    }
}
