//! RTP-to-wallclock mapping used to align independent audio/video SSRCs.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpClockMap {
    pub rtp_anchor: u32,
    pub ntp_ms_anchor: i64,
    pub clock_rate: u32,
}

impl RtpClockMap {
    pub const fn new(rtp_anchor: u32, ntp_ms_anchor: i64, clock_rate: u32) -> Option<Self> {
        if clock_rate == 0 {
            return None;
        }
        Some(Self {
            rtp_anchor,
            ntp_ms_anchor,
            clock_rate,
        })
    }

    /// Convert a timestamp near the sender-report anchor to wall-clock ms.
    /// Wrapping subtraction keeps normal RTP rollover continuous.
    pub fn timestamp_ms(&self, timestamp: u32) -> i64 {
        let delta = timestamp.wrapping_sub(self.rtp_anchor) as i32 as i64;
        self.ntp_ms_anchor + delta.saturating_mul(1_000) / i64::from(self.clock_rate)
    }

    /// Difference between two mapped streams at their current timestamps.
    pub fn offset_ms(&self, timestamp: u32, other: &Self, other_timestamp: u32) -> i64 {
        other.timestamp_ms(other_timestamp) - self.timestamp_ms(timestamp)
    }
}
