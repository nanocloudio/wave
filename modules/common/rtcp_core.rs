// RFC 3550 §6 RTCP — compound-packet framing, SR/RR report blocks, the
// receiver statistics §A.3/§A.8 define, and the §6.2 transmission interval.
//
// I/O-free, no-alloc, no clock of its own: every function is a pure transform
// or a pure computation over caller-supplied time. The pump owns the socket and
// the wall clock.
//
// WHAT RTCP IS FOR, and why RTP without it is incomplete. RTP carries media and
// says nothing about how it arrived. RTCP is the only channel on which a
// receiver tells a sender what it actually got — how much was lost, how much
// the arrival times jittered, and how long the round trip is — and the only one
// on which a sender publishes the mapping between its RTP timestamp and real
// time, which is what lets a receiver play two streams in sync. A sender with
// no RTCP cannot adapt and cannot lip-sync, and neither failure is visible from
// the media path.
//
// SCOPE. This core owns the wire and the arithmetic: parsing a compound packet,
// building SR and RR, maintaining a receiver's statistics, and computing when
// the next report is due. It does not own what to DO with any of that — rate
// adaptation, call teardown on a BYE, and quality policy are decisions above
// it. Nothing here encrypts: SRTCP is a separate mechanism and its absence is
// stated, not implied.

/// §6.1: RTCP shares RTP's version number.
pub const RTCP_VERSION: u8 = 2;

/// Every RTCP packet begins with this much: V/P/RC, PT, length.
pub const RTCP_HEADER_SIZE: usize = 4;

/// A Sender Report's sender-info block, after the header and SSRC.
pub const RTCP_SENDER_INFO_SIZE: usize = 20;

/// One report block (§6.4.1), the same in SR and RR.
pub const RTCP_REPORT_BLOCK_SIZE: usize = 24;

// ── packet types (§12.1) ─────────────────────────────────────────────────

/// Sender Report — a sender that has also sent media.
pub const RTCP_PT_SR: u8 = 200;
/// Receiver Report — a participant that has sent no media.
pub const RTCP_PT_RR: u8 = 201;
/// Source Description; this core reads its CNAME item and no other.
pub const RTCP_PT_SDES: u8 = 202;
/// Goodbye — the source is leaving.
pub const RTCP_PT_BYE: u8 = 203;
/// Application-defined; parsed as a length and skipped.
pub const RTCP_PT_APP: u8 = 204;

/// SDES item type for the canonical name (§6.5.1), the only one required.
pub const RTCP_SDES_CNAME: u8 = 1;

/// The report count field is five bits: at most 31 blocks in one SR or RR.
pub const RTCP_MAX_REPORT_BLOCKS: usize = 31;

// ── compound-packet framing ──────────────────────────────────────────────

/// One packet located within a compound datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcpPacket {
    pub payload_type: u8,
    /// The `RC`/`SC` five-bit count field — report blocks for SR/RR, sources
    /// for SDES and BYE.
    pub count: u8,
    /// Offset of this packet's first byte within the compound.
    pub at: usize,
    /// Total length of this packet in bytes, header included.
    pub len: usize,
}

/// Why a compound packet was refused.
///
/// Distinguished rather than collapsed to a bool: "this is not RTCP at all"
/// and "this is RTCP and it is malformed" call for different handling on a
/// port that may carry both, and counting them together hides a peer that has
/// started emitting garbage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpReject {
    /// Shorter than one header, or not a multiple of four.
    Truncated,
    /// Version field is not 2.
    Version,
    /// A length field runs past the end of the datagram.
    Overrun,
    /// §6.1: the first packet in a compound MUST be SR or RR.
    NotReportFirst,
    /// §6.1: only the LAST packet may carry padding.
    PaddingNotLast,
    /// More packets than the caller's array can hold.
    TooMany,
}

/// Validate a compound RTCP datagram and locate each packet inside it.
///
/// The checks are §6.1's, in the order it gives them, and they are the reason
/// this is worth a function rather than a loop at each call site: a receiver
/// that trusts a length field walks off the end of the datagram, and one that
/// accepts a compound not beginning with SR/RR accepts a stream of SDES from
/// anyone who can reach the port.
///
/// Returns the number of packets written into `out`.
pub fn rtcp_parse_compound(buf: &[u8], out: &mut [RtcpPacket]) -> Result<usize, RtcpReject> {
    if buf.len() < RTCP_HEADER_SIZE || !buf.len().is_multiple_of(4) {
        return Err(RtcpReject::Truncated);
    }
    let mut at = 0usize;
    let mut n = 0usize;
    while at + RTCP_HEADER_SIZE <= buf.len() {
        let b0 = buf[at];
        if b0 >> 6 != RTCP_VERSION {
            return Err(RtcpReject::Version);
        }
        let padding = (b0 >> 5) & 0x01 == 1;
        let count = b0 & 0x1F;
        let pt = buf[at + 1];
        // §6.4.1: the length is in 32-bit words MINUS ONE, so the shortest
        // legal packet declares 1 and occupies 8 bytes.
        let words = u16::from_be_bytes([buf[at + 2], buf[at + 3]]) as usize;
        let len = (words + 1) * 4;
        if at + len > buf.len() {
            return Err(RtcpReject::Overrun);
        }
        if n == 0 && !matches!(pt, RTCP_PT_SR | RTCP_PT_RR) {
            return Err(RtcpReject::NotReportFirst);
        }
        // Padding belongs to the compound, not to a packet in the middle of
        // it: a padded packet followed by another means the length fields and
        // the pad byte disagree about where the datagram ends.
        if padding && at + len != buf.len() {
            return Err(RtcpReject::PaddingNotLast);
        }
        if n == out.len() {
            return Err(RtcpReject::TooMany);
        }
        out[n] = RtcpPacket {
            payload_type: pt,
            count,
            at,
            len,
        };
        n += 1;
        at += len;
    }
    if at != buf.len() {
        return Err(RtcpReject::Truncated);
    }
    Ok(n)
}

/// Could this datagram plausibly be RTCP rather than RTP?
///
/// The cheap discriminator for a port carrying both (RFC 5761 multiplexing):
/// RTP payload types 72..=76 are exactly the RTCP types 200..=204 seen through
/// RTP's marker+PT byte, so anything in that window is RTCP and anything else
/// is not. Cheap enough to run before the real parse, and it never rejects a
/// well-formed RTCP packet.
#[must_use]
pub fn rtcp_is_plausible(buf: &[u8]) -> bool {
    if buf.len() < RTCP_HEADER_SIZE {
        return false;
    }
    if buf[0] >> 6 != RTCP_VERSION {
        return false;
    }
    matches!(buf[1], RTCP_PT_SR..=RTCP_PT_APP)
}

// ── report blocks ────────────────────────────────────────────────────────

/// One reception report (§6.4.1) — what a receiver tells one sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcpReportBlock {
    /// The source these statistics describe.
    pub ssrc: u32,
    /// Loss since the previous report, as a fraction with denominator 256.
    pub fraction_lost: u8,
    /// Cumulative packets lost, a SIGNED 24-bit quantity: duplicates can make
    /// it negative, and clamping that to zero would hide a peer sending each
    /// packet twice.
    pub cumulative_lost: i32,
    /// Extended highest sequence number received (cycles << 16 | seq).
    pub extended_highest_seq: u32,
    /// Interarrival jitter, in timestamp units.
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp from that source's last SR.
    pub last_sr: u32,
    /// Delay since that SR, in units of 1/65536 s.
    pub delay_since_last_sr: u32,
}

/// Write one report block. Returns bytes written, or `None` if `out` is short.
pub fn rtcp_write_report_block(b: &RtcpReportBlock, out: &mut [u8]) -> Option<usize> {
    if out.len() < RTCP_REPORT_BLOCK_SIZE {
        return None;
    }
    out[0..4].copy_from_slice(&b.ssrc.to_be_bytes());
    out[4] = b.fraction_lost;
    // §6.4.1 puts the cumulative count in 24 bits, two's complement. Clamped
    // to the representable range rather than truncated: a wrapped count reads
    // as a wildly different loss figure, which is worse than a saturated one.
    let clamped = b.cumulative_lost.clamp(-0x0080_0000, 0x007F_FFFF);
    let c = (clamped as u32) & 0x00FF_FFFF;
    out[5] = (c >> 16) as u8;
    out[6] = (c >> 8) as u8;
    out[7] = c as u8;
    out[8..12].copy_from_slice(&b.extended_highest_seq.to_be_bytes());
    out[12..16].copy_from_slice(&b.jitter.to_be_bytes());
    out[16..20].copy_from_slice(&b.last_sr.to_be_bytes());
    out[20..24].copy_from_slice(&b.delay_since_last_sr.to_be_bytes());
    Some(RTCP_REPORT_BLOCK_SIZE)
}

/// Read one report block from `buf` at `at`.
pub fn rtcp_parse_report_block(buf: &[u8], at: usize) -> Option<RtcpReportBlock> {
    let b = buf.get(at..at + RTCP_REPORT_BLOCK_SIZE)?;
    // Sign-extend the 24-bit cumulative count.
    let raw = (u32::from(b[5]) << 16) | (u32::from(b[6]) << 8) | u32::from(b[7]);
    let cumulative_lost = if raw & 0x0080_0000 != 0 {
        (raw | 0xFF00_0000) as i32
    } else {
        raw as i32
    };
    Some(RtcpReportBlock {
        ssrc: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        fraction_lost: b[4],
        cumulative_lost,
        extended_highest_seq: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        jitter: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        last_sr: u32::from_be_bytes([b[16], b[17], b[18], b[19]]),
        delay_since_last_sr: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
    })
}

/// A Sender Report's sender information (§6.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcpSenderInfo {
    /// Wallclock at which this report was sent, as a 64-bit NTP timestamp.
    pub ntp: u64,
    /// The RTP timestamp corresponding to that same instant. The PAIR is the
    /// payload of an SR: it is what lets a receiver map media time to real
    /// time, and so what makes lip-sync between two streams possible.
    pub rtp_timestamp: u32,
    pub packet_count: u32,
    pub octet_count: u32,
}

// ── building reports ─────────────────────────────────────────────────────

/// Write an SR or RR header plus the sender's SSRC.
fn write_head(pt: u8, count: usize, ssrc: u32, body_len: usize, out: &mut [u8]) -> Option<usize> {
    let total = RTCP_HEADER_SIZE + 4 + body_len;
    if out.len() < total || count > RTCP_MAX_REPORT_BLOCKS {
        return None;
    }
    out[0] = (RTCP_VERSION << 6) | (count as u8 & 0x1F);
    out[1] = pt;
    // Length in 32-bit words minus one.
    let words = (total / 4) - 1;
    out[2..4].copy_from_slice(&(words as u16).to_be_bytes());
    out[4..8].copy_from_slice(&ssrc.to_be_bytes());
    Some(RTCP_HEADER_SIZE + 4)
}

/// Build a Receiver Report: `[header][ssrc][blocks…]`.
pub fn rtcp_write_rr(ssrc: u32, blocks: &[RtcpReportBlock], out: &mut [u8]) -> Option<usize> {
    let body = blocks.len().checked_mul(RTCP_REPORT_BLOCK_SIZE)?;
    let mut at = write_head(RTCP_PT_RR, blocks.len(), ssrc, body, out)?;
    for b in blocks {
        at += rtcp_write_report_block(b, out.get_mut(at..)?)?;
    }
    Some(at)
}

/// Build a Sender Report: `[header][ssrc][sender info][blocks…]`.
pub fn rtcp_write_sr(
    ssrc: u32,
    info: &RtcpSenderInfo,
    blocks: &[RtcpReportBlock],
    out: &mut [u8],
) -> Option<usize> {
    let body = RTCP_SENDER_INFO_SIZE + blocks.len().checked_mul(RTCP_REPORT_BLOCK_SIZE)?;
    let mut at = write_head(RTCP_PT_SR, blocks.len(), ssrc, body, out)?;
    let s = out.get_mut(at..at + RTCP_SENDER_INFO_SIZE)?;
    s[0..8].copy_from_slice(&info.ntp.to_be_bytes());
    s[8..12].copy_from_slice(&info.rtp_timestamp.to_be_bytes());
    s[12..16].copy_from_slice(&info.packet_count.to_be_bytes());
    s[16..20].copy_from_slice(&info.octet_count.to_be_bytes());
    at += RTCP_SENDER_INFO_SIZE;
    for b in blocks {
        at += rtcp_write_report_block(b, out.get_mut(at..)?)?;
    }
    Some(at)
}

/// Read the sender info out of an SR located at `at`.
pub fn rtcp_parse_sender_info(buf: &[u8], at: usize) -> Option<RtcpSenderInfo> {
    let s =
        buf.get(at + RTCP_HEADER_SIZE + 4..at + RTCP_HEADER_SIZE + 4 + RTCP_SENDER_INFO_SIZE)?;
    Some(RtcpSenderInfo {
        ntp: u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        rtp_timestamp: u32::from_be_bytes([s[8], s[9], s[10], s[11]]),
        packet_count: u32::from_be_bytes([s[12], s[13], s[14], s[15]]),
        octet_count: u32::from_be_bytes([s[16], s[17], s[18], s[19]]),
    })
}

/// The SSRC of the packet at `at` — the sender, for SR/RR.
pub fn rtcp_packet_ssrc(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at + RTCP_HEADER_SIZE..at + RTCP_HEADER_SIZE + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Offset of the first report block within the SR or RR at `at`.
#[must_use]
pub fn rtcp_first_block_at(payload_type: u8, at: usize) -> usize {
    at + RTCP_HEADER_SIZE
        + 4
        + if payload_type == RTCP_PT_SR {
            RTCP_SENDER_INFO_SIZE
        } else {
            0
        }
}

/// Build a BYE for one source, with no reason phrase.
pub fn rtcp_write_bye(ssrc: u32, out: &mut [u8]) -> Option<usize> {
    if out.len() < 8 {
        return None;
    }
    out[0] = (RTCP_VERSION << 6) | 1;
    out[1] = RTCP_PT_BYE;
    out[2..4].copy_from_slice(&1u16.to_be_bytes());
    out[4..8].copy_from_slice(&ssrc.to_be_bytes());
    Some(8)
}

/// Build a minimal SDES carrying one CNAME item (§6.5.1).
///
/// A compound packet is required to carry a CNAME, because SSRCs collide and
/// change while a CNAME is the stable name of a participant across both.
pub fn rtcp_write_sdes_cname(ssrc: u32, cname: &[u8], out: &mut [u8]) -> Option<usize> {
    if cname.is_empty() || cname.len() > 255 {
        return None;
    }
    // chunk = ssrc(4) + item type(1) + len(1) + text + a terminating zero,
    // padded to a 32-bit boundary.
    let unpadded = 4 + 2 + cname.len() + 1;
    let total = RTCP_HEADER_SIZE + unpadded.div_ceil(4) * 4;
    if out.len() < total {
        return None;
    }
    out[..total].fill(0);
    out[0] = (RTCP_VERSION << 6) | 1;
    out[1] = RTCP_PT_SDES;
    out[2..4].copy_from_slice(&(((total / 4) - 1) as u16).to_be_bytes());
    out[4..8].copy_from_slice(&ssrc.to_be_bytes());
    out[8] = RTCP_SDES_CNAME;
    out[9] = cname.len() as u8;
    out[10..10 + cname.len()].copy_from_slice(cname);
    Some(total)
}

// ── receiver statistics (§A.3, §6.4.1) ───────────────────────────────────

/// Sequence-number and jitter state for one source.
///
/// The arithmetic is RFC 3550's appendix A.1/A.3/A.8, kept together because it
/// is only correct together: the loss fraction is defined against the packets
/// EXPECTED since the last report, and "expected" is a function of the same
/// wrapped sequence tracking that produces the extended highest number a
/// report block carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcpReceiverStats {
    pub ssrc: u32,
    /// Sequence-number cycles, in the high half of the extended number.
    pub cycles: u32,
    pub base_seq: u32,
    pub max_seq: u16,
    pub received: u32,
    /// `expected_prior` / `received_prior` at the previous report, which is
    /// what makes the fraction an interval measure rather than a lifetime one.
    pub expected_prior: u32,
    pub received_prior: u32,
    /// Smoothed interarrival jitter, §6.4.1, held ×16 so the 1/16 gain in
    /// §A.8 is exact in integers.
    jitter_x16: u32,
    /// Transit of the previous packet, for the difference §A.8 takes.
    last_transit: i32,
    started: u8,
}

impl RtcpReceiverStats {
    #[must_use]
    pub fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            ..Self::default()
        }
    }

    /// The extended highest sequence number received.
    #[must_use]
    pub fn extended_max(&self) -> u32 {
        self.cycles | u32::from(self.max_seq)
    }

    /// Packets expected: §A.3's `extended_max - base_seq + 1`.
    #[must_use]
    pub fn expected(&self) -> u32 {
        self.extended_max()
            .wrapping_sub(self.base_seq)
            .wrapping_add(1)
    }

    /// Cumulative packets lost. Signed, because duplicates can push received
    /// above expected and reporting that as zero loss would hide them.
    #[must_use]
    pub fn cumulative_lost(&self) -> i32 {
        self.expected() as i32 - self.received as i32
    }

    /// Smoothed interarrival jitter in timestamp units (§6.4.1).
    #[must_use]
    pub fn jitter(&self) -> u32 {
        self.jitter_x16 >> 4
    }

    /// Account for one received packet.
    ///
    /// `arrival` and `rtp_timestamp` must share a unit and a timebase — the
    /// jitter estimate is the difference of their differences, so a mismatch
    /// does not produce a wrong number, it produces a meaningless one.
    pub fn on_packet(&mut self, seq: u16, rtp_timestamp: u32, arrival: u32) {
        if self.started == 0 {
            self.started = 1;
            self.base_seq = u32::from(seq);
            self.max_seq = seq;
            self.received = 1;
            self.last_transit = arrival.wrapping_sub(rtp_timestamp) as i32;
            return;
        }
        self.received = self.received.wrapping_add(1);
        // §A.1: a sequence number that has wrapped is one that went backwards
        // by more than half the space. Anything smaller is a reorder, which is
        // not a new cycle.
        if seq < self.max_seq && self.max_seq.wrapping_sub(seq) > 0x8000 {
            self.cycles = self.cycles.wrapping_add(0x0001_0000);
        }
        if seq > self.max_seq || seq.wrapping_sub(self.max_seq) < 0x8000 {
            self.max_seq = seq;
        }

        // §A.8, verbatim in integer form: J += (|D| - J) / 16, where D is the
        // difference in relative transit times between this packet and the
        // last. Held ×16 so the division is exact.
        let transit = arrival.wrapping_sub(rtp_timestamp) as i32;
        let d = transit.wrapping_sub(self.last_transit).unsigned_abs();
        self.last_transit = transit;
        self.jitter_x16 = self
            .jitter_x16
            .wrapping_add(d.wrapping_sub(self.jitter_x16 >> 4));
    }

    /// The loss fraction since the previous report, and the state update that
    /// makes the next one an interval measure too.
    ///
    /// §A.3: `(expected_interval - received_interval) * 256 / expected_interval`,
    /// with a zero or negative result reported as zero — more packets than
    /// expected means duplicates, not negative loss.
    pub fn take_fraction_lost(&mut self) -> u8 {
        let expected = self.expected();
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        let received_interval = self.received.wrapping_sub(self.received_prior);
        self.expected_prior = expected;
        self.received_prior = self.received;
        let lost_interval = expected_interval as i32 - received_interval as i32;
        if expected_interval == 0 || lost_interval <= 0 {
            return 0;
        }
        // Unsigned and 32-bit from here. Signed division must be guarded
        // against `i32::MIN / -1`, and 64-bit division needs `__aeabi_uldivmod`
        // — a panic and an unresolvable symbol respectively, on targets with
        // neither an unwinder nor that helper. Both operands are provably
        // positive here, and `lost < expected` always, so the scale-down below
        // cannot divide by zero.
        let lost = lost_interval as u32;
        let (lost, expected_interval) = if lost >= 1 << 23 {
            // `lost << 8` would overrun 32 bits. Both sides shift together, so
            // the ratio the fraction reports is unchanged.
            (lost >> 8, expected_interval >> 8)
        } else {
            (lost, expected_interval)
        };
        // `.max(1)` makes the divisor provably non-zero. It is already
        // non-zero by the reasoning above, but the compiler cannot see that,
        // and an unprovable division emits a panic path that will not link.
        ((lost << 8) / expected_interval.max(1)).min(255) as u8
    }

    /// The report block describing this source.
    ///
    /// `last_sr` and `delay_since_last_sr` come from the pump, which is the
    /// only party that knows when the last SR arrived; a zero pair is the
    /// RFC's own "no SR received yet".
    pub fn report_block(&mut self, last_sr: u32, delay_since_last_sr: u32) -> RtcpReportBlock {
        RtcpReportBlock {
            ssrc: self.ssrc,
            fraction_lost: self.take_fraction_lost(),
            cumulative_lost: self.cumulative_lost(),
            extended_highest_seq: self.extended_max(),
            jitter: self.jitter(),
            last_sr,
            delay_since_last_sr,
        }
    }
}

// ── NTP time and the round trip ──────────────────────────────────────────

/// The middle 32 bits of an NTP timestamp — what a report block's `last_sr`
/// carries, and all of it that a round-trip calculation needs.
#[must_use]
pub fn ntp_middle_32(ntp: u64) -> u32 {
    (ntp >> 16) as u32
}

/// Round-trip time in units of 1/65536 s, from a report block that answers an
/// SR this participant sent.
///
/// §6.4.1: `now - delay_since_last_sr - last_sr`. `None` when the block names
/// no SR (`last_sr == 0`) or when the arithmetic runs backwards, which means
/// the peer's `delay` and the local clock disagree — a negative round trip is
/// not a fast one.
#[must_use]
pub fn rtcp_round_trip(now_middle_32: u32, block: &RtcpReportBlock) -> Option<u32> {
    if block.last_sr == 0 {
        return None;
    }
    now_middle_32
        .checked_sub(block.delay_since_last_sr)?
        .checked_sub(block.last_sr)
}

// ── transmission interval (§6.2, §6.3.1) ─────────────────────────────────

/// Milliseconds until this participant should next send a report.
///
/// §6.2's rule: the interval scales with the number of participants, so total
/// RTCP traffic stays a fixed fraction of the session bandwidth however many
/// join. `members` is the number known; `we_sent` selects the senders' share.
///
/// Two properties the RFC insists on and this preserves. The result is never
/// below `RTCP_MIN_INTERVAL_MS` for a non-initial report — an unbounded scale
/// down is how a large session turns into a report storm. And the caller MUST
/// randomise it; the deterministic value is returned here so the randomisation
/// is the pump's, testable, and not buried in arithmetic that also has to be
/// checked against the spec.
///
/// **32-bit throughout, deliberately.** A `u64` division compiles to
/// `__aeabi_uldivmod` on the 32-bit targets this ships to, and that symbol is
/// not linkable in a PIC module — the build fails outright. Cortex-M33 has a
/// 32-bit `udiv`, so staying in `u32` is both correct and the only thing that
/// links.
#[must_use]
pub fn rtcp_interval_ms(members: u32, senders: u32, we_sent: bool, bandwidth_bps: u32) -> u32 {
    let members = members.max(1);
    let senders = senders.min(members);
    // §6.2 gives RTCP 5% of the session. `/ 20` rather than `* 5 / 100` so the
    // multiply cannot overflow before the divide reins it back in.
    let rtcp_bw = bandwidth_bps / 20;
    // Senders and receivers divide that 25/75, unless senders are more than a
    // quarter of the session — then everyone shares one pool, because the
    // split would otherwise starve the majority.
    let (n, bw) = if senders > 0 && senders.saturating_mul(4) <= members {
        if we_sent {
            (senders, rtcp_bw / 4)
        } else {
            (members - senders, rtcp_bw - rtcp_bw / 4)
        }
    } else {
        (members, rtcp_bw)
    };
    if bw == 0 {
        return RTCP_MIN_INTERVAL_MS;
    }
    // Average compound packet size in bits: the RFC's worked figure of 28
    // octets of lower-layer headers plus a small compound.
    const AVG_PACKET_BITS: u32 = (28 + 72) * 8;
    let numerator = AVG_PACKET_BITS.saturating_mul(n).saturating_mul(1000);
    (numerator / bw.max(1)).max(RTCP_MIN_INTERVAL_MS)
}

/// Reciprocal of e−1.5 (1.21828) in 1/65536ths, so §6.3.1's correction is a
/// multiply and a shift rather than a division the 32-bit link cannot resolve.
const RECIP_E_MINUS_1_5_Q16: u64 = 53_794;

/// Apply §6.3.1's randomisation: the interval is multiplied by a factor drawn
/// uniformly from [0.5, 1.5], then divided by e−1.5 to correct the bias that
/// reconsideration introduces.
///
/// `r` is a caller-supplied draw over the whole `u32` range; its top 16 bits
/// become the fractional part, which needs no division at all. Passed in
/// rather than generated here so the core stays deterministic and the pump
/// owns its entropy — and so a test can pin both ends of the range.
#[must_use]
pub fn rtcp_randomise_interval(interval_ms: u32, r: u32) -> u32 {
    // factor in 1/65536ths: 0.5 + (r >> 16)/65536, i.e. 0.5 ..= ~1.5.
    let factor = 32_768u64 + u64::from(r >> 16);
    let scaled = (u64::from(interval_ms).saturating_mul(factor)) >> 16;
    let corrected = (scaled.saturating_mul(RECIP_E_MINUS_1_5_Q16)) >> 16;
    // Saturating, not truncating, and never zero. A plain `as u32` on a value
    // past 2^32 wraps to a SMALL interval, which is a report storm — the one
    // failure this whole calculation exists to prevent; and a zero interval is
    // a send-immediately loop. Neither is reachable for a session of plausible
    // size, and both are cheap enough not to depend on that.
    (corrected.min(u64::from(u32::MAX)) as u32).max(1)
}

/// Milliseconds to the 1/65536-second units RTCP timestamps use.
///
/// Split into whole seconds and a remainder so neither part overflows 32 bits:
/// `ms * 65536` overflows above 65 seconds, and the whole-second term wraps
/// on purpose — the middle 32 bits of an NTP timestamp wrap every 18 hours
/// anyway, and every use of this value is a difference.
#[must_use]
pub fn ms_to_ntp32(ms: u32) -> u32 {
    (ms / 1_000)
        .wrapping_mul(65_536)
        .wrapping_add((ms % 1_000) * 65_536 / 1_000)
}

/// Milliseconds to RTP timestamp units at `clock_rate_hz`.
///
/// The jitter estimate subtracts an arrival time from an RTP timestamp
/// (§A.8's transit), so the two MUST share a unit. They are not the same unit
/// by nature — the RTP clock rate is a property of the payload type, 8000 Hz
/// for PCMU and 90000 for most video — and a mismatch does not produce a wrong
/// jitter figure, it produces a meaningless one that still looks like a number.
///
/// Split into whole seconds and a remainder so neither term overflows 32 bits:
/// `ms * 90000` overflows above 47 seconds. The whole-second term wraps on
/// purpose, since every use of this value is a difference.
#[must_use]
pub fn ms_to_rtp_units(ms: u32, clock_rate_hz: u32) -> u32 {
    (ms / 1_000)
        .wrapping_mul(clock_rate_hz)
        .wrapping_add((ms % 1_000).wrapping_mul(clock_rate_hz) / 1_000)
}

/// The inverse: 1/65536-second units back to milliseconds.
///
/// Shifts rather than divisions, and split for the same overflow reason.
#[must_use]
pub fn ntp32_to_ms(units: u32) -> u32 {
    (units >> 16)
        .wrapping_mul(1_000)
        .wrapping_add(((units & 0xFFFF) * 1_000) >> 16)
}

/// A full 64-bit NTP timestamp from a local millisecond clock.
///
/// The NTP format is seconds since 1900 in the high 32 bits and a binary
/// fraction of a second in the low 32. `epoch_offset_s` is added to the whole
/// seconds to lift a local clock into that epoch.
///
/// **Zero offset gives a LOCAL timebase, not a real NTP one**, and the
/// distinction matters differently for the two things this field is used for.
/// Round-trip calculation only ever subtracts values the same participant
/// issued, so a local timebase is exact for it. Synchronising two sources
/// against each other compares timestamps from DIFFERENT participants, and
/// that needs a shared epoch — with a zero offset it will be confidently
/// wrong, which is why the offset is a parameter rather than an assumption.
///
/// 32-bit arithmetic throughout: a 64-bit division would need
/// `__aeabi_uldivmod`, which a PIC module cannot link.
#[must_use]
pub fn ms_to_ntp64(ms: u64, epoch_offset_s: u32) -> u64 {
    let ms32 = ms as u32;
    let secs = (ms32 / 1_000).wrapping_add(epoch_offset_s);
    // The sub-second part as a binary fraction: (ms % 1000) / 1000 scaled to
    // 2^32. Computed as (rem * 2^22) / 1000 then shifted up 10, so the
    // multiply stays inside 32 bits (999 * 2^22 < 2^32).
    let rem = ms32 % 1_000;
    let frac = ((rem << 22) / 1_000) << 10;
    (u64::from(secs) << 32) | u64::from(frac)
}

/// The RFC's floor on the interval between reports from one participant.
pub const RTCP_MIN_INTERVAL_MS: u32 = 5_000;
/// §6.2: RTCP claims 5% of the session bandwidth.
pub const RTCP_BW_FRACTION_PERCENT: u32 = 5;

// ---- the record a consumer reads ------------------------------------------
//
// What the peer reported about US, flattened for a graph. Defined here rather
// than in the pump for the same reason the stats record is defined in
// `rtp_wire`: a layout with one owner cannot drift between the end that writes
// it and the end that reads it.

/// `[ssrc: u32 LE][fraction_lost: u8][_pad: u8 x3][cumulative_lost: i32 LE]
///  [jitter: u32 LE][rtt_ms: u32 LE][have_rtt: u8][_pad: u8 x3]`.
pub const RTCP_REPORT_REC_LEN: usize = 24;

/// Flatten a report block, plus the round trip if one could be computed.
///
/// `rtt` is `None` when the block named no SR or the arithmetic ran backwards.
/// It is reported as a separate flag rather than as a zero, because zero is a
/// legitimate sub-millisecond round trip and "unknown" is not a fast link.
pub fn write_rtcp_report_record(
    b: &RtcpReportBlock,
    rtt_ms: Option<u32>,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < RTCP_REPORT_REC_LEN {
        return None;
    }
    out[..RTCP_REPORT_REC_LEN].fill(0);
    out[0..4].copy_from_slice(&b.ssrc.to_le_bytes());
    out[4] = b.fraction_lost;
    out[8..12].copy_from_slice(&b.cumulative_lost.to_le_bytes());
    out[12..16].copy_from_slice(&b.jitter.to_le_bytes());
    if let Some(v) = rtt_ms {
        out[16..20].copy_from_slice(&v.to_le_bytes());
        out[20] = 1;
    }
    Some(RTCP_REPORT_REC_LEN)
}

/// Read one back: `(ssrc, fraction_lost, cumulative_lost, jitter, rtt_ms)`.
#[must_use]
pub fn parse_rtcp_report_record(buf: &[u8]) -> Option<(u32, u8, i32, u32, Option<u32>)> {
    if buf.len() != RTCP_REPORT_REC_LEN {
        return None;
    }
    let rtt = if buf[20] != 0 {
        Some(u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]))
    } else {
        None
    };
    Some((
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        buf[4],
        i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        rtt,
    ))
}
