//! Allocation-free VP8 RTP packetizer (RFC 7741).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vp8Packet {
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub marker: bool,
    pub len: usize,
}

pub struct Vp8Packetizer<'a> {
    frame: &'a [u8],
    offset: usize,
    mtu: usize,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
}

impl<'a> Vp8Packetizer<'a> {
    pub fn new(
        frame: &'a [u8],
        mtu_payload: usize,
        seq: u16,
        timestamp: u32,
        ssrc: u32,
    ) -> Option<Self> {
        if frame.is_empty() || mtu_payload < 2 {
            return None;
        }
        Some(Self {
            frame,
            offset: 0,
            mtu: mtu_payload,
            seq,
            timestamp,
            ssrc,
        })
    }

    pub fn next(&mut self, out: &mut [u8]) -> Option<Vp8Packet> {
        if self.offset >= self.frame.len() || out.len() < 2 {
            return None;
        }
        let take = (self.mtu - 1)
            .min(out.len() - 1)
            .min(self.frame.len() - self.offset);
        if take == 0 {
            return None;
        }
        out[0] = if self.offset == 0 { 0x10 } else { 0 };
        out[1..1 + take].copy_from_slice(&self.frame[self.offset..self.offset + take]);
        self.offset += take;
        let marker = self.offset == self.frame.len();
        let packet = Vp8Packet {
            seq: self.seq,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
            marker,
            len: take + 1,
        };
        self.seq = self.seq.wrapping_add(1);
        Some(packet)
    }
}
