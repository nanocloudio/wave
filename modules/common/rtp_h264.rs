//! Allocation-free H.264 RTP FU-A packetizer (RFC 6184 §5.8).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H264Packet {
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub marker: bool,
    pub len: usize,
}

pub struct H264FuA<'a> {
    nal: &'a [u8],
    mtu_payload: usize,
    offset: usize,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    first: bool,
    single: bool,
}

impl<'a> H264FuA<'a> {
    pub fn new(
        nal: &'a [u8],
        mtu_payload: usize,
        seq: u16,
        timestamp: u32,
        ssrc: u32,
    ) -> Option<Self> {
        // Only an EMPTY NAL is rejected. A one-byte NAL is the header of a
        // configuration or empty unit and is a complete RTP payload on its own.
        // The MTU floor is three: an FU-A fragment costs two bytes of indicator
        // and header before it carries any of the unit.
        if nal.is_empty() || mtu_payload < 3 {
            return None;
        }
        Some(Self {
            nal,
            mtu_payload,
            offset: 0,
            seq,
            timestamp,
            ssrc,
            first: true,
            single: nal.len() <= mtu_payload,
        })
    }

    /// Write one RTP payload (FU indicator, FU header, fragment) and advance.
    pub fn next(&mut self, out: &mut [u8]) -> Option<H264Packet> {
        if self.offset >= self.nal.len() || out.len() < 2 {
            return None;
        }
        if self.single {
            if out.len() < self.nal.len() {
                return None;
            }
            out[..self.nal.len()].copy_from_slice(self.nal);
            self.offset = self.nal.len();
            let packet = H264Packet {
                seq: self.seq,
                timestamp: self.timestamp,
                ssrc: self.ssrc,
                marker: true,
                len: self.nal.len(),
            };
            self.seq = self.seq.wrapping_add(1);
            return Some(packet);
        }
        if out.len() < 3 {
            return None;
        }
        if self.offset == 0 {
            self.offset = 1;
        }
        let remaining = self.nal.len() - self.offset;
        let take = remaining
            .min(self.mtu_payload.saturating_sub(2))
            .min(out.len() - 2);
        if take == 0 {
            return None;
        }
        let nal_header = self.nal[0];
        out[0] = (nal_header & 0xE0) | 28;
        out[1] = (if self.first { 0x80 } else { 0 })
            | (if take == remaining { 0x40 } else { 0 })
            | (nal_header & 0x1F);
        out[2..2 + take].copy_from_slice(&self.nal[self.offset..self.offset + take]);
        self.offset += take;
        let packet = H264Packet {
            seq: self.seq,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
            marker: take == remaining,
            len: take + 2,
        };
        self.seq = self.seq.wrapping_add(1);
        self.first = false;
        Some(packet)
    }
}
