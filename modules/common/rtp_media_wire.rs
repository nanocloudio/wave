//! Negotiated encoded-media records used between Spectra/Conclave and RTP.
//!
//! One record is `[codec, flags, timestamp:u32 LE, payload_len:u16 LE, payload]`.
//! The record is bounded before it reaches a packetizer, so embedded targets do
//! not need an allocator or an unbounded frame queue.

pub const CODEC_PCMU: u8 = 0;
pub const CODEC_OPUS: u8 = 1;
pub const CODEC_H264: u8 = 2;
pub const CODEC_VP8: u8 = 3;
pub const FLAG_MARKER: u8 = 1;
pub const FRAME_HEADER_LEN: usize = 8;
pub const MAX_ENCODED_FRAME: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedFrame<'a> {
    pub codec: u8,
    pub flags: u8,
    pub timestamp: u32,
    pub payload: &'a [u8],
}

pub fn decode(buf: &[u8]) -> Option<EncodedFrame<'_>> {
    if buf.len() < FRAME_HEADER_LEN {
        return None;
    }
    let codec = buf[0];
    if codec > CODEC_VP8 || buf[1] & !FLAG_MARKER != 0 {
        return None;
    }
    let len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    if len == 0 || len > MAX_ENCODED_FRAME || FRAME_HEADER_LEN.checked_add(len)? != buf.len() {
        return None;
    }
    Some(EncodedFrame {
        codec,
        flags: buf[1],
        timestamp: u32::from_le_bytes(buf[2..6].try_into().ok()?),
        payload: &buf[FRAME_HEADER_LEN..],
    })
}

pub fn encode(frame: EncodedFrame<'_>, out: &mut [u8]) -> Option<usize> {
    if frame.codec > CODEC_VP8
        || frame.flags & !FLAG_MARKER != 0
        || frame.payload.is_empty()
        || frame.payload.len() > MAX_ENCODED_FRAME
        || out.len() < FRAME_HEADER_LEN + frame.payload.len()
    {
        return None;
    }
    out[0] = frame.codec;
    out[1] = frame.flags;
    out[2..6].copy_from_slice(&frame.timestamp.to_le_bytes());
    out[6..8].copy_from_slice(&(frame.payload.len() as u16).to_le_bytes());
    out[FRAME_HEADER_LEN..FRAME_HEADER_LEN + frame.payload.len()].copy_from_slice(frame.payload);
    Some(FRAME_HEADER_LEN + frame.payload.len())
}
