//! Small allocation-free sender controller for RTP pacing decisions.
//!
//! This is deliberately transport agnostic: RTCP or a QUIC/WebRTC adapter
//! supplies loss, RTT, and elapsed time, while the controller returns a
//! bounded bitrate target. It never allocates or reads a clock itself.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpCongestion {
    bitrate_bps: u32,
    min_bps: u32,
    max_bps: u32,
}

impl RtpCongestion {
    pub const fn new(initial_bps: u32, min_bps: u32, max_bps: u32) -> Option<Self> {
        if min_bps == 0 || min_bps > max_bps || initial_bps < min_bps || initial_bps > max_bps {
            return None;
        }
        Some(Self {
            bitrate_bps: initial_bps,
            min_bps,
            max_bps,
        })
    }

    /// Apply one interval of aggregate feedback. Loss above 10% performs a
    /// multiplicative decrease; a clean interval performs bounded additive
    /// increase. The arithmetic is saturating so hostile counters cannot
    /// wrap a constrained sender into an enormous rate.
    pub fn feedback(&mut self, lost: u32, received: u32, rtt_ms: u32) {
        let total = lost.saturating_add(received).max(1);
        if lost.saturating_mul(10) > total || rtt_ms > 2_000 {
            self.bitrate_bps = (self.bitrate_bps / 2).max(self.min_bps);
        } else {
            let step = (self.bitrate_bps / 20).max(1);
            self.bitrate_bps = self.bitrate_bps.saturating_add(step).min(self.max_bps);
        }
    }

    pub const fn bitrate_bps(&self) -> u32 {
        self.bitrate_bps
    }
}
