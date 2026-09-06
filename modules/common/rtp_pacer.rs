//! Allocation-free RTP media pacing and clock-drift accounting.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaceDecision {
    Wait { until_ms: u64 },
    Send { timestamp: u32, late_ms: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpPacer {
    clock_rate: u32,
    ptime_ms: u32,
    next_ms: u64,
    timestamp: u32,
    started: bool,
}

impl RtpPacer {
    pub const fn new(clock_rate: u32, ptime_ms: u32) -> Option<Self> {
        if clock_rate == 0 || ptime_ms == 0 {
            return None;
        }
        Some(Self {
            clock_rate,
            ptime_ms,
            next_ms: 0,
            timestamp: 0,
            started: false,
        })
    }

    pub fn reset(&mut self, now_ms: u64, timestamp: u32) {
        self.next_ms = now_ms;
        self.timestamp = timestamp;
        self.started = true;
    }

    pub fn poll(&mut self, now_ms: u64) -> PaceDecision {
        if !self.started {
            self.reset(now_ms, 0);
        }
        if now_ms < self.next_ms {
            return PaceDecision::Wait {
                until_ms: self.next_ms,
            };
        }
        let late = now_ms.saturating_sub(self.next_ms).min(u64::from(u32::MAX)) as u32;
        let step = (u64::from(self.clock_rate) * u64::from(self.ptime_ms) / 1000) as u32;
        self.timestamp = self.timestamp.wrapping_add(step.max(1));
        self.next_ms = self.next_ms.saturating_add(u64::from(self.ptime_ms));
        PaceDecision::Send {
            timestamp: self.timestamp.wrapping_sub(step.max(1)),
            late_ms: late,
        }
    }

    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }
}
