// The rtp → jitter receive-record seam: one validated RTP payload per frame,
// carried over an OctetStream channel with the shared net TLV framing
// (`net_write_frame` / `net_read_frame`), because channels are byte streams
// and bare records concatenate.
//
//   [REC_RTP_RX: u8] [len: u16 LE] [seq: u16 LE] [payload…]
//
// The sequence rides the record because the reorder buffer downstream keys on
// it — a consumer that cannot see the sequence cannot see loss, let alone
// conceal it. This file owns the layout; `rtp` writes
// it, `jitter` reads it, and no third spelling exists.

/// Frame type of one validated receive record.
pub const REC_RTP_RX: u8 = 0x01;
/// Metadata-bearing receive record for negotiated media consumers.
pub const REC_RTP_RX_META: u8 = 0x02;
/// Metadata record variant carrying the RFC 8285 MID extension.
pub const REC_RTP_RX_META_MID: u8 = 0x03;

/// Bytes of sequence number leading the frame payload.
pub const RTP_RX_SEQ_LEN: usize = 2;
/// `[seq][timestamp][ssrc][payload_type][marker]` prefix length.
pub const RTP_RX_META_LEN: usize = 2 + 4 + 4 + 1 + 1;
pub const RTP_MID_MAX: usize = 32;
pub const RTP_RX_META_MID_LEN: usize = RTP_RX_META_LEN + 1 + RTP_MID_MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpReceiveMeta {
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload_type: u8,
    pub marker: bool,
}

/// A bounded negotiated payload table shared by RTP and session adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpPayloadBinding {
    pub payload_type: u8,
    pub clock_rate: u32,
    pub channels: u8,
    pub codec: [u8; 16],
    pub codec_len: u8,
}

pub const RTP_MAX_PAYLOAD_BINDINGS: usize = 16;

#[derive(Clone, Copy)]
pub struct RtpPayloadMap {
    entries: [Option<RtpPayloadBinding>; RTP_MAX_PAYLOAD_BINDINGS],
    len: usize,
}

impl Default for RtpPayloadMap {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpPayloadMap {
    pub const fn new() -> Self {
        Self {
            entries: [None; RTP_MAX_PAYLOAD_BINDINGS],
            len: 0,
        }
    }

    pub fn insert(&mut self, binding: RtpPayloadBinding) -> bool {
        if binding.codec_len == 0
            || binding.codec_len as usize > binding.codec.len()
            || binding.clock_rate == 0
        {
            return false;
        }
        for entry in self.entries.iter_mut().flatten() {
            if entry.payload_type == binding.payload_type {
                return false;
            }
        }
        if self.len == self.entries.len() {
            return false;
        }
        self.entries[self.len] = Some(binding);
        self.len += 1;
        true
    }

    pub fn get(&self, payload_type: u8) -> Option<RtpPayloadBinding> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.payload_type == payload_type)
            .copied()
    }
}

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

/// Write the metadata prefix for one validated RTP receive record.
pub fn put_rtp_rx_meta(
    payload: &mut [u8],
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    marker: bool,
) -> Option<usize> {
    if payload.len() < RTP_RX_META_LEN {
        return None;
    }
    payload[0..2].copy_from_slice(&seq.to_le_bytes());
    payload[2..6].copy_from_slice(&timestamp.to_le_bytes());
    payload[6..10].copy_from_slice(&ssrc.to_le_bytes());
    payload[10] = payload_type;
    payload[11] = marker as u8;
    Some(RTP_RX_META_LEN)
}

/// Decode the fixed metadata prefix. The payload itself remains borrowed by
/// the caller so no media buffer is copied by the wire layer.
pub fn parse_rtp_rx_meta(payload: &[u8]) -> Option<RtpReceiveMeta> {
    if payload.len() < RTP_RX_META_LEN {
        return None;
    }
    if payload[11] > 1 {
        return None;
    }
    Some(RtpReceiveMeta {
        seq: u16::from_le_bytes([payload[0], payload[1]]),
        timestamp: u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]),
        ssrc: u32::from_le_bytes([payload[6], payload[7], payload[8], payload[9]]),
        payload_type: payload[10],
        marker: payload[11] != 0,
    })
}

pub fn put_rtp_rx_meta_mid(
    payload: &mut [u8],
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    marker: bool,
    mid: &[u8],
) -> Option<usize> {
    if mid.is_empty() || mid.len() > RTP_MID_MAX || payload.len() < RTP_RX_META_MID_LEN {
        return None;
    }
    let at = put_rtp_rx_meta(payload, seq, timestamp, ssrc, payload_type, marker)?;
    payload[at] = mid.len() as u8;
    payload[at + 1..at + 1 + RTP_MID_MAX].fill(0);
    payload[at + 1..at + 1 + mid.len()].copy_from_slice(mid);
    Some(RTP_RX_META_MID_LEN)
}

pub fn parse_rtp_rx_meta_mid(payload: &[u8]) -> Option<(RtpReceiveMeta, [u8; RTP_MID_MAX], u8)> {
    if payload.len() < RTP_RX_META_MID_LEN || payload[11] > 1 {
        return None;
    }
    let mid_len = payload[RTP_RX_META_LEN] as usize;
    if mid_len == 0 || mid_len > RTP_MID_MAX || payload.len() != RTP_RX_META_MID_LEN {
        return None;
    }
    let meta = parse_rtp_rx_meta(payload)?;
    let mut mid = [0u8; RTP_MID_MAX];
    mid[..mid_len].copy_from_slice(&payload[RTP_RX_META_LEN + 1..RTP_RX_META_LEN + 1 + mid_len]);
    Some((meta, mid, mid_len as u8))
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
/// Metadata-bearing receive statistic (sequence, RTP timestamp, SSRC).
pub const RTCP_STAT_RX_META: u8 = 3;

/// `[kind: u8][seq: u16 LE][rtp_ts: u32 LE]`.
pub const RTCP_STAT_RX_LEN: usize = 1 + 2 + 4;
pub const RTCP_STAT_RX_META_LEN: usize = 1 + 2 + 4 + 4;
/// `[kind: u8][packets: u32 LE][octets: u32 LE][rtp_ts: u32 LE]`.
pub const RTCP_STAT_TX_LEN: usize = 1 + 4 + 4 + 4;
/// The longest record on this channel — what the port must take as one, and
/// what a consumer's staging buffer must hold.
pub const RTCP_STAT_MAX_LEN: usize = if RTCP_STAT_RX_META_LEN > RTCP_STAT_TX_LEN {
    RTCP_STAT_RX_META_LEN
} else if RTCP_STAT_RX_LEN > RTCP_STAT_TX_LEN {
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

pub fn put_rtcp_stat_rx_meta(out: &mut [u8], seq: u16, rtp_ts: u32, ssrc: u32) -> Option<usize> {
    if out.len() < RTCP_STAT_RX_META_LEN {
        return None;
    }
    out[0] = RTCP_STAT_RX_META;
    out[1..3].copy_from_slice(&seq.to_le_bytes());
    out[3..7].copy_from_slice(&rtp_ts.to_le_bytes());
    out[7..11].copy_from_slice(&ssrc.to_le_bytes());
    Some(RTCP_STAT_RX_META_LEN)
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
    Rx {
        seq: u16,
        rtp_ts: u32,
    },
    RxMeta {
        seq: u16,
        rtp_ts: u32,
        ssrc: u32,
    },
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
        RTCP_STAT_RX_META => Some(RTCP_STAT_RX_META_LEN),
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
        RTCP_STAT_RX_META => Some(RtcpStat::RxMeta {
            seq: u16::from_le_bytes([buf[1], buf[2]]),
            rtp_ts: u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]),
            ssrc: u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]),
        }),
        RTCP_STAT_TX => Some(RtcpStat::Tx {
            packets: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            octets: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
            rtp_ts: u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]),
        }),
        _ => None,
    }
}
