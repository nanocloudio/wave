// Bounded, no_std, no-alloc RTP receive reorder window. `include!`d by the host
// crate (tests) and the `jitter` module, so the device build and the host
// conformance harness compile identical bytes.
//
// Received packets are placed in a small ring keyed by sequence number and
// released strictly in order. A missing sequence holds release until either it
// arrives or the caller decides it has waited long enough and skips it — the
// wait is the caller's policy because it needs a clock, and this core reads
// none.
//
// It knows nothing about codecs. Concealing a loss is the decoder's job: the
// release reports that packets were skipped, and the stream carries that
// forward as a discontinuity. Playout pacing is not here either — presenting
// media on time belongs to the sink that owns the clock.

/// Payload bytes held per slot: one Ethernet MTU of UDP payload less the RTP
/// header, the most an unfragmented packet can carry.
pub const JITTER_SLOT_SIZE: usize = 1460;

/// Ring depth in packets. At 20 ms audio this is 320 ms of reorder tolerance;
/// for video it bounds how far ahead of a hole the window can run.
pub const JITTER_MAX_SLOTS: usize = 16;

/// What the reorder stage needs from each packet besides its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct JitterPacketMeta {
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload_type: u8,
    pub marker: bool,
    /// `abi::contracts::encoded` codec byte of the negotiated stream.
    pub codec: u8,
}

#[derive(Clone, Copy)]
struct Slot {
    data: [u8; JITTER_SLOT_SIZE],
    seq: u16,
    len: u16,
    full: bool,
    meta: JitterPacketMeta,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            data: [0u8; JITTER_SLOT_SIZE],
            seq: 0,
            len: 0,
            full: false,
            meta: JitterPacketMeta {
                timestamp: 0,
                ssrc: 0,
                payload_type: 0,
                marker: false,
                codec: 0,
            },
        }
    }
}

/// A released packet: its payload, metadata, and whether packets before it
/// were skipped as lost.
pub struct Released<'a> {
    pub seq: u16,
    pub meta: JitterPacketMeta,
    pub payload: &'a [u8],
    pub lost_before: bool,
}

/// A fixed-capacity reorder window. Sequence-keyed insert, in-order release,
/// explicit skip; no allocation, no clock, no I/O.
pub struct JitterBuffer {
    slots: [Slot; JITTER_MAX_SLOTS],
    next_seq: u16,
    based: bool,
    fill_count: u16,
    skipped: bool,
    packets_received: u32,
    packets_lost: u32,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
    /// A buffer with no packets and no established release sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [Slot::empty(); JITTER_MAX_SLOTS],
            next_seq: 0,
            based: false,
            fill_count: 0,
            skipped: false,
            packets_received: 0,
            packets_lost: 0,
        }
    }

    /// Clear all slots and counters, as at the start of a call. The next
    /// inserted packet re-establishes the release base sequence.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Packets held and not yet released.
    #[must_use]
    pub fn fill_count(&self) -> u16 {
        self.fill_count
    }

    /// Total payloads offered for insertion.
    #[must_use]
    pub fn packets_received(&self) -> u32 {
        self.packets_received
    }

    /// Total sequences skipped as lost.
    #[must_use]
    pub fn packets_lost(&self) -> u32 {
        self.packets_lost
    }

    /// Insert one payload for sequence `seq`. The first insert establishes the
    /// release base. A payload outside the forward window (already released,
    /// or `JITTER_MAX_SLOTS` or more ahead), longer than a slot, or a duplicate
    /// is dropped. Returns `true` when the payload was stored.
    pub fn insert(&mut self, seq: u16, payload: &[u8], meta: JitterPacketMeta) -> bool {
        self.packets_received = self.packets_received.wrapping_add(1);
        if payload.len() > JITTER_SLOT_SIZE {
            return false;
        }
        if !self.based {
            self.based = true;
            self.next_seq = seq;
        }
        if seq.wrapping_sub(self.next_seq) >= JITTER_MAX_SLOTS as u16 {
            return false;
        }
        let slot = &mut self.slots[seq as usize % JITTER_MAX_SLOTS];
        if slot.full {
            return false;
        }
        slot.data[..payload.len()].copy_from_slice(payload);
        slot.seq = seq;
        slot.len = payload.len() as u16;
        slot.meta = meta;
        slot.full = true;
        self.fill_count += 1;
        true
    }

    /// Whether the next sequence in order is present.
    #[must_use]
    pub fn next_ready(&self) -> bool {
        let slot = &self.slots[self.next_seq as usize % JITTER_MAX_SLOTS];
        self.based && slot.full && slot.seq == self.next_seq
    }

    /// Whether the window holds packets behind a hole — the only state in
    /// which skipping can release anything.
    #[must_use]
    pub fn waiting_on_hole(&self) -> bool {
        self.fill_count > 0 && !self.next_ready()
    }

    /// Declare the hole at the head lost: advance to the next held packet,
    /// counting every sequence passed over. Returns how many were skipped.
    pub fn skip_hole(&mut self) -> u16 {
        if !self.waiting_on_hole() {
            return 0;
        }
        let mut skipped = 0;
        while !self.next_ready() && skipped < JITTER_MAX_SLOTS as u16 {
            self.next_seq = self.next_seq.wrapping_add(1);
            skipped += 1;
        }
        self.packets_lost = self.packets_lost.wrapping_add(u32::from(skipped));
        self.skipped = true;
        skipped
    }

    /// The next in-order packet, borrowed from its slot. The slot stays
    /// occupied until `release` frees it, so a caller that could not pass the
    /// packet on this step keeps it without copying.
    #[must_use]
    pub fn peek(&self) -> Option<Released<'_>> {
        if !self.next_ready() {
            return None;
        }
        let slot = &self.slots[self.next_seq as usize % JITTER_MAX_SLOTS];
        Some(Released {
            seq: slot.seq,
            meta: slot.meta,
            payload: &slot.data[..slot.len as usize],
            lost_before: self.skipped,
        })
    }

    /// Free the packet `peek` returned and advance.
    pub fn release(&mut self) {
        if !self.next_ready() {
            return;
        }
        self.slots[self.next_seq as usize % JITTER_MAX_SLOTS].full = false;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.fill_count -= 1;
        self.skipped = false;
    }
}
