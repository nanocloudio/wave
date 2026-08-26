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
