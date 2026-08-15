// Bounded, no_std, no-alloc RTP receive jitter buffer — the reorder window and
// loss-concealing playout for a fixed-rate narrowband audio stream. `include!`d
// by the host crate (tests) and the RTP/voice `.fmod`, so the device build and
// the host conformance harness compile identical bytes.
//
// A jitter buffer absorbs network reordering and delay variation: received RTP
// payloads are placed in a small ring keyed by sequence number, and playout
// pulls them back out strictly in order at the codec's frame cadence, emitting
// concealment (u-law silence) for any sequence that never arrived. This core
// owns only that data structure and its two operations — insert and playout.
// The receive socket, the RTP header parse, the wall clock that paces playout,
// and the ptime→byte-length policy are all the caller's, never this file's.
//
// The single implementation of the receive-side reorder and playout ring.
// (`Complete Wave voice protocol ownership`, T4.3.7). Presentation-clock
// adaptation is intentionally excluded — pacing lives in the composing module,
// not hidden in the buffer. Behaviour is parity-exact with the origin ring;
// the vectors live in `tests/harness/tests/sip_jitter_vectors.rs`.

/// Payload bytes held per slot — 20 ms of 8 kHz G.711 (`8000 * 0.02`).
pub const JITTER_SLOT_SIZE: usize = 160;

/// Ring depth in packets — up to 320 ms of reorder tolerance at 20 ms ptime.
pub const JITTER_MAX_SLOTS: usize = 16;

/// G.711 u-law silence octet (decodes to linear zero) used for concealment.
pub const ULAW_SILENCE: u8 = 0xFF;

/// The outcome of a [`JitterBuffer::playout`] call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Playout {
    /// The requested sequence was present; its payload was written.
    Packet,
    /// The sequence was missing; concealment silence was written and the loss
    /// counter advanced.
    Silence,
}

#[derive(Clone, Copy)]
struct Slot {
    data: [u8; JITTER_SLOT_SIZE],
    seq: u16,
    len: u16,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            data: [0u8; JITTER_SLOT_SIZE],
            seq: 0,
            len: 0,
        }
    }
}

/// A fixed-capacity RTP reorder/playout buffer. Sequence-keyed insert, in-order
/// loss-concealing playout; no allocation, no clock, no I/O.
pub struct JitterBuffer {
    slots: [Slot; JITTER_MAX_SLOTS],
    play_seq: u16,
    fill_count: u16,
    packets_received: u32,
    packets_lost: u32,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
    /// A buffer with no packets and no established playout sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [Slot::empty(); JITTER_MAX_SLOTS],
            play_seq: 0,
            fill_count: 0,
            packets_received: 0,
            packets_lost: 0,
        }
    }

    /// Clear all slots and counters, as at the start of a call. The next
    /// inserted packet re-establishes the playout base sequence.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.len = 0;
        }
        self.play_seq = 0;
        self.fill_count = 0;
        self.packets_received = 0;
        self.packets_lost = 0;
    }

    /// Number of filled slots not yet played out — the caller's buffering gauge
    /// for deciding when to begin playout.
    #[must_use]
    pub fn fill_count(&self) -> u16 {
        self.fill_count
    }

    /// Total payloads accepted for reception (before the reorder-window test).
    #[must_use]
    pub fn packets_received(&self) -> u32 {
        self.packets_received
    }

    /// Total playout sequences that arrived missing and were concealed.
    #[must_use]
    pub fn packets_lost(&self) -> u32 {
        self.packets_lost
    }

    /// Insert one RTP payload for sequence `seq`. The first insert establishes
    /// the playout base sequence. Payloads outside the forward reorder window
    /// (too old, or `>= JITTER_MAX_SLOTS` ahead) are dropped. A slot already
    /// holding this exact sequence is not overwritten. Returns `true` when the
    /// payload was stored.
    pub fn insert(&mut self, seq: u16, payload: &[u8]) -> bool {
        self.packets_received = self.packets_received.wrapping_add(1);
        if self.packets_received == 1 {
            self.play_seq = seq;
        }

        // Forward window only: distances in [0, MAX_SLOTS) are in-window;
        // everything else (far ahead, or wrapped-negative "too old") is dropped.
        let distance = seq.wrapping_sub(self.play_seq);
        if distance >= JITTER_MAX_SLOTS as u16 {
            return false;
        }

        let slot = &mut self.slots[seq as usize % JITTER_MAX_SLOTS];
        if slot.len == 0 || slot.seq != seq {
            let n = payload.len().min(JITTER_SLOT_SIZE);
            slot.data[..n].copy_from_slice(&payload[..n]);
            slot.seq = seq;
            slot.len = n as u16;
            self.fill_count = self.fill_count.wrapping_add(1);
            true
        } else {
            false
        }
    }

    /// Produce the next `output_len` bytes of playout into `out`, advancing the
    /// playout sequence by one. When the current sequence is present its payload
    /// is written (silence-padded up to `output_len`); when it is missing,
    /// `output_len` bytes of concealment silence are written and the loss
    /// counter advances. Returns `None` if `out` is shorter than `output_len`.
    pub fn playout(&mut self, output_len: usize, out: &mut [u8]) -> Option<Playout> {
        if out.len() < output_len {
            return None;
        }
        let dst = &mut out[..output_len];

        let slot = &mut self.slots[self.play_seq as usize % JITTER_MAX_SLOTS];
        let result = if slot.seq == self.play_seq && slot.len > 0 {
            let n = (slot.len as usize).min(output_len);
            dst[..n].copy_from_slice(&slot.data[..n]);
            if n < output_len {
                dst[n..].fill(ULAW_SILENCE);
            }
            slot.len = 0;
            Playout::Packet
        } else {
            dst.fill(ULAW_SILENCE);
            self.packets_lost = self.packets_lost.wrapping_add(1);
            Playout::Silence
        };

        self.play_seq = self.play_seq.wrapping_add(1);
        if self.fill_count > 0 {
            self.fill_count -= 1;
        }
        Some(result)
    }
}
