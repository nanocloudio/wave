//! Off-DUT load-harness primitives for Wave: latency histogram, JSON emitter,
//! and the independent crypto/codec pieces the protocol clients need.
//!
//! `LatencyHist`, `JsonObj`, `json_str`, and `fnv1a64` are ported from
//! `lattice-bench` (itself ported from `clustor-bench`) so the three projects
//! report comparable numbers from comparable machinery.
//!
//! # Oracle independence
//!
//! The SHA-1 and Base64 here duplicate the SDK crypto the modules mount. That is deliberate and
//! must stay that way — see this crate's `Cargo.toml`. The measuring instrument
//! may not share code with the thing measured.

pub mod h3;
pub mod proto;

use std::time::Duration;

// ─────────────────────────── latency histogram ───────────────────────────

/// Log-linear latency histogram (microseconds). 64 sub-buckets per octave from
/// 1 µs upward — enough resolution for p50/p99/p999 on a request stream without
/// an external HdrHistogram dependency.
pub struct LatencyHist {
    /// `buckets[i]` counts samples in `[value_at(i), value_at(i+1))`.
    buckets: Vec<u64>,
    count: u64,
    min: u64,
    max: u64,
    sum: u128,
}

const SUB_BITS: u32 = 6; // 64 sub-buckets per octave
const SUB: usize = 1 << SUB_BITS;

impl Default for LatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHist {
    pub fn new() -> Self {
        // 40 octaves × SUB covers ~1 µs .. ~10^12 µs — far past any real RTT.
        LatencyHist {
            buckets: vec![0; 40 * SUB],
            count: 0,
            min: u64::MAX,
            max: 0,
            sum: 0,
        }
    }

    fn bucket_of(us: u64) -> usize {
        if us < SUB as u64 {
            return us as usize;
        }
        let octave = 63 - us.leading_zeros(); // floor(log2(us))
        let sub = (us >> (octave - SUB_BITS)) as usize & (SUB - 1);
        (octave as usize - SUB_BITS as usize + 1) * SUB + sub
    }

    fn value_at(idx: usize) -> u64 {
        if idx < SUB {
            return idx as u64;
        }
        let octave = (idx / SUB) as u32 + SUB_BITS - 1;
        let sub = (idx % SUB) as u64;
        (1u64 << octave) + (sub << (octave - SUB_BITS))
    }

    pub fn record(&mut self, us: u64) {
        let i = Self::bucket_of(us).min(self.buckets.len() - 1);
        self.buckets[i] += 1;
        self.count += 1;
        self.min = self.min.min(us);
        self.max = self.max.max(us);
        self.sum += us as u128;
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn percentile(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = ((self.count as f64) * p / 100.0).ceil() as u64;
        let mut seen = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            seen += c;
            if seen >= target {
                return Self::value_at(i);
            }
        }
        self.max
    }

    pub fn mean(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            (self.sum / self.count as u128) as u64
        }
    }

    pub fn min(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.min
        }
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    /// Merge another histogram into this one (per-shard → global).
    pub fn merge(&mut self, other: &LatencyHist) {
        for (i, &c) in other.buckets.iter().enumerate() {
            self.buckets[i] += c;
        }
        self.count += other.count;
        if other.count > 0 {
            self.min = self.min.min(other.min);
            self.max = self.max.max(other.max);
            self.sum += other.sum;
        }
    }

    /// The standard tail report. Never a bare mean — a mean hides the tail that
    /// the whole open-loop apparatus exists to measure.
    pub fn tail_json(&self) -> String {
        JsonObj::new()
            .num("count", self.count())
            .num("p50_us", self.percentile(50.0))
            .num("p99_us", self.percentile(99.0))
            .num("p999_us", self.percentile(99.9))
            .num("max_us", self.max())
            .num("mean_us", self.mean())
            .render()
    }
}

// ─────────────────────────────── JSON ────────────────────────────────────

/// Minimal JSON object builder — emits a flat/nested object without serde.
/// Values are pre-formatted strings, so callers control escaping via [`json_str`].
#[derive(Default)]
pub struct JsonObj {
    fields: Vec<(String, String)>,
}

impl JsonObj {
    pub fn new() -> Self {
        JsonObj::default()
    }

    pub fn num(mut self, key: &str, v: impl ToString) -> Self {
        self.fields.push((key.to_string(), v.to_string()));
        self
    }

    pub fn str(mut self, key: &str, v: &str) -> Self {
        self.fields.push((key.to_string(), json_str(v)));
        self
    }

    pub fn raw(mut self, key: &str, v: String) -> Self {
        self.fields.push((key.to_string(), v));
        self
    }

    pub fn render(&self) -> String {
        let mut s = String::from("{");
        for (i, (k, v)) in self.fields.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json_str(k));
            s.push(':');
            s.push_str(v);
        }
        s.push('}');
        s
    }
}

/// Quote + escape a string as a JSON string literal.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// FNV-1a 64-bit — stable config hash for run metadata, no crypto dependency.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ───────────────────────────── misc helpers ──────────────────────────────

/// xorshift64* — deterministic per-shard key/payload selection with no `rand`.
pub struct Rng(u64);

impl Rng {
    pub fn seeded(shard: u64) -> Self {
        Rng(shard.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

pub const IO_TIMEOUT: Duration = Duration::from_secs(10);
