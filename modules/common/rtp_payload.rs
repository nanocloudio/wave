//! RTP payload formats between the fluxor encoded-media record stream and RTP
//! packets: RFC 3551 PCMU, RFC 7587 Opus, RFC 6184 H.264 (packetization mode
//! 1), RFC 7741 VP8.
//!
//! The split with the codec side is fixed by the stream contract
//! (`abi::contracts::encoded`): codec, packing and clock come from the stream's
//! `STREAM` record, and access-unit boundaries are the record boundaries. This
//! core parses nothing below the payload header except NAL unit boundaries,
//! which the declared packing makes mechanical — Annex B start codes or length
//! prefixes, never slice syntax.
//!
//! No allocation and no whole-unit buffer in either direction. A video access
//! unit arrives as `UNIT` fragments and leaves as RTP packets while it is still
//! arriving; received packets become `UNIT` fragments as they are released in
//! order. The only unit-sized state is one MTU of pending payload.

use super::abi::contracts::encoded as enc;

/// The RTP clock each supported payload format runs at (RFC 3551 §4.5, RFC
/// 7587 §4.1, RFC 6184 §8.2.1, RFC 7741 §6.1). `None` for a codec this core
/// carries no payload format for.
pub const fn rtp_clock(codec: u8) -> Option<u32> {
    match codec {
        enc::CODEC_PCMU => Some(8_000),
        enc::CODEC_OPUS => Some(48_000),
        enc::CODEC_H264 | enc::CODEC_VP8 => Some(90_000),
        _ => None,
    }
}

/// The codec byte for a negotiated payload-format name (`pcmu`, `opus`,
/// `h264`, `vp8`), matched against the vocabulary names; `None` for a name
/// this core carries no payload format for.
pub fn codec_named(name: &[u8]) -> Option<u8> {
    let codec = match name {
        b"pcmu" => enc::CODEC_PCMU,
        b"opus" => enc::CODEC_OPUS,
        b"h264" => enc::CODEC_H264,
        b"vp8" => enc::CODEC_VP8,
        _ => return None,
    };
    Some(codec)
}

/// Whether a stream in `packing` can be packetized as `codec`.
pub const fn can_packetize(codec: u8, packing: u8) -> bool {
    matches!(
        (codec, packing),
        (enc::CODEC_PCMU, enc::PACKING_RAW)
            | (enc::CODEC_OPUS, enc::PACKING_RAW)
            | (enc::CODEC_H264, enc::PACKING_ANNEXB)
            | (enc::CODEC_H264, enc::PACKING_LENGTH_PREFIXED)
            | (enc::CODEC_VP8, enc::PACKING_RAW)
    )
}

/// The stream description a depacketizer emits for `codec`: packing, channel
/// count, clock. H.264 leaves as Annex B because RTP carries parameter sets in
/// band; Opus as two channels because RFC 7587 always signals `opus/48000/2`
/// and the decoder reads the real count from each packet's TOC.
pub const fn received_stream(codec: u8) -> Option<(u8, u8, u32)> {
    match codec {
        enc::CODEC_PCMU => Some((enc::PACKING_RAW, 1, 8_000)),
        enc::CODEC_OPUS => Some((enc::PACKING_RAW, 2, 48_000)),
        enc::CODEC_H264 => Some((enc::PACKING_ANNEXB, 0, 90_000)),
        enc::CODEC_VP8 => Some((enc::PACKING_RAW, 0, 90_000)),
        _ => None,
    }
}

/// Largest RTP payload either direction handles: one Ethernet MTU of UDP
/// payload less the RTP header.
pub const MAX_PAYLOAD: usize = 1460;

/// Largest decoder configuration record kept for re-sending parameter sets.
pub const CONFIG_MAX: usize = 256;

const FU_A: u8 = 28;
const STAP_A: u8 = 24;
const H264_FU_HEADER: usize = 2;
const VP8_DESCRIPTOR: usize = 1;
const VP8_S: u8 = 0x10;

/// One packet `Packetizer::next` wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    pub len: usize,
    pub marker: bool,
}

/// Where the NAL splitter is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nal {
    /// Before the unit's first start code (Annex B) — bytes here are not a NAL.
    Seeking,
    /// Reading a length prefix: this many bytes of it read so far.
    Length(u8),
    /// The next byte is a NAL header.
    Header,
    /// Inside a NAL body.
    Body,
}

/// Access units in, RTP payloads out.
pub struct Packetizer {
    codec: u8,
    packing: u8,
    mtu: usize,
    len_size: u8,
    config: [u8; CONFIG_MAX],
    config_len: usize,
    /// Parameter sets from `config` still to send ahead of this keyframe, as a
    /// byte offset into `config`; `0` when none are queued.
    ps_at: usize,
    ps_left: u8,
    ps_pps_pending: bool,
    // Per-unit state.
    first_of_stream: bool,
    unit_marker: bool,
    unit_done: bool,
    oversize: bool,
    nal: Nal,
    nal_header: u8,
    fragmented: bool,
    held: bool,
    zeros: u8,
    nal_len: u32,
    frame_first: bool,
    pending: [u8; MAX_PAYLOAD],
    pending_len: usize,
}

impl Packetizer {
    pub const fn new() -> Self {
        Self {
            codec: 0,
            packing: 0,
            mtu: MAX_PAYLOAD,
            len_size: 0,
            config: [0; CONFIG_MAX],
            config_len: 0,
            ps_at: 0,
            ps_left: 0,
            ps_pps_pending: false,
            first_of_stream: true,
            unit_marker: false,
            unit_done: true,
            oversize: false,
            nal: Nal::Seeking,
            nal_header: 0,
            fragmented: false,
            held: false,
            zeros: 0,
            nal_len: 0,
            frame_first: true,
            pending: [0; MAX_PAYLOAD],
            pending_len: 0,
        }
    }

    /// Configure for a new stream. `false` when this core has no payload
    /// format for the stream, or its configuration record is unusable.
    pub fn stream(&mut self, codec: u8, packing: u8, config: &[u8], mtu: usize) -> bool {
        if !can_packetize(codec, packing) || !(16..=MAX_PAYLOAD).contains(&mtu) {
            return false;
        }
        self.len_size = 0;
        self.config_len = 0;
        if packing == enc::PACKING_LENGTH_PREFIXED {
            // avcC: lengthSizeMinusOne in the low bits of byte 4.
            if config.len() < 7 || config.len() > CONFIG_MAX {
                return false;
            }
            self.len_size = (config[4] & 0x03) + 1;
            if self.len_size == 3 {
                return false;
            }
            self.config[..config.len()].copy_from_slice(config);
            self.config_len = config.len();
        }
        self.codec = codec;
        self.packing = packing;
        self.mtu = mtu;
        self.first_of_stream = true;
        self.unit_done = true;
        true
    }

    /// Start an access unit carrying `flags` (its first fragment's flags).
    pub fn begin_unit(&mut self, flags: u8) {
        self.unit_done = false;
        self.oversize = false;
        self.pending_len = 0;
        self.fragmented = false;
        self.held = false;
        self.zeros = 0;
        self.frame_first = true;
        self.nal = match self.packing {
            enc::PACKING_ANNEXB => Nal::Seeking,
            enc::PACKING_LENGTH_PREFIXED => Nal::Length(0),
            _ => Nal::Body,
        };
        // RFC 3551 §4.1: the marker opens a talkspurt — the stream's first
        // packet, and the first after a loss.
        self.unit_marker = self.first_of_stream || flags & enc::FLAG_DISCONTINUITY != 0;
        self.first_of_stream = false;
        // A length-prefixed stream's parameter sets live only in avcC, so a
        // receiver joining at this keyframe would have none. Send them first.
        self.ps_left = 0;
        self.ps_pps_pending = false;
        if self.config_len >= 7 && flags & enc::FLAG_KEY != 0 {
            self.ps_at = 6;
            self.ps_left = self.config[5] & 0x1F;
            self.ps_pps_pending = true;
        }
    }

    /// Whether the current unit was dropped for not fitting one packet (audio
    /// payload formats carry a unit whole).
    pub const fn dropped_oversize(&self) -> bool {
        self.oversize
    }

    /// Consume `input[*used..]` — one fragment of the current unit — until a
    /// packet is ready, and write it to `out`. `last` says this is the unit's
    /// final fragment; once it is exhausted the unit's closing packet, with the
    /// marker, is produced. `None` when the fragment is spent and nothing more
    /// is owed. Call until `None`.
    pub fn next(
        &mut self,
        input: &[u8],
        used: &mut usize,
        last: bool,
        out: &mut [u8],
    ) -> Option<Packet> {
        if self.unit_done || out.len() < self.mtu {
            return None;
        }
        match self.codec {
            enc::CODEC_H264 => self.next_h264(input, used, last, out),
            enc::CODEC_VP8 => self.next_vp8(input, used, last, out),
            _ => self.next_audio(input, used, last, out),
        }
    }

    /// PCMU and Opus: one unit, one packet.
    fn next_audio(
        &mut self,
        input: &[u8],
        used: &mut usize,
        last: bool,
        out: &mut [u8],
    ) -> Option<Packet> {
        let rest = &input[*used..];
        *used = input.len();
        if self.pending_len + rest.len() > self.mtu {
            self.oversize = true;
        } else {
            self.pending[self.pending_len..self.pending_len + rest.len()].copy_from_slice(rest);
            self.pending_len += rest.len();
        }
        if !last {
            return None;
        }
        self.unit_done = true;
        if self.oversize || self.pending_len == 0 {
            return None;
        }
        out[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        Some(Packet {
            len: self.pending_len,
            marker: self.unit_marker,
        })
    }

    /// RFC 7741: a one-byte descriptor, `S` on the frame's first packet.
    fn next_vp8(
        &mut self,
        input: &[u8],
        used: &mut usize,
        last: bool,
        out: &mut [u8],
    ) -> Option<Packet> {
        let cap = self.mtu - VP8_DESCRIPTOR;
        while *used < input.len() {
            if self.pending_len == cap {
                return Some(self.vp8_packet(out, false));
            }
            let take = (cap - self.pending_len).min(input.len() - *used);
            self.pending[self.pending_len..self.pending_len + take]
                .copy_from_slice(&input[*used..*used + take]);
            self.pending_len += take;
            *used += take;
        }
        if !last {
            return None;
        }
        self.unit_done = true;
        if self.pending_len == 0 {
            return None;
        }
        Some(self.vp8_packet(out, true))
    }

    fn vp8_packet(&mut self, out: &mut [u8], marker: bool) -> Packet {
        out[0] = if self.frame_first { VP8_S } else { 0 };
        out[1..1 + self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        let len = VP8_DESCRIPTOR + self.pending_len;
        self.frame_first = false;
        self.pending_len = 0;
        Packet { len, marker }
    }

    /// The next queued avcC parameter set as a single-NAL packet, or `None`
    /// once they are all sent.
    fn next_parameter_set(&mut self, out: &mut [u8]) -> Option<Packet> {
        loop {
            if self.ps_left == 0 {
                if !self.ps_pps_pending {
                    return None;
                }
                // After the SPS list: one byte of PPS count.
                self.ps_pps_pending = false;
                if self.ps_at >= self.config_len {
                    return None;
                }
                self.ps_left = self.config[self.ps_at];
                self.ps_at += 1;
                continue;
            }
            self.ps_left -= 1;
            if self.ps_at + 2 > self.config_len {
                self.ps_left = 0;
                self.ps_pps_pending = false;
                return None;
            }
            let len =
                u16::from_be_bytes([self.config[self.ps_at], self.config[self.ps_at + 1]]) as usize;
            let start = self.ps_at + 2;
            self.ps_at = start + len;
            if len == 0 || start + len > self.config_len || len > self.mtu {
                continue;
            }
            out[..len].copy_from_slice(&self.config[start..start + len]);
            return Some(Packet { len, marker: false });
        }
    }

    fn next_h264(
        &mut self,
        input: &[u8],
        used: &mut usize,
        last: bool,
        out: &mut [u8],
    ) -> Option<Packet> {
        if let Some(p) = self.next_parameter_set(out) {
            return Some(p);
        }
        let cap = self.mtu - H264_FU_HEADER;
        while *used < input.len() {
            // A NAL that ended is sent once more input shows it was not the
            // unit's last — only the last carries the marker.
            if self.held {
                self.held = false;
                return Some(self.close_nal(out, false));
            }
            let b = input[*used];
            match self.nal {
                Nal::Seeking => {
                    *used += 1;
                    if b == 0 {
                        self.zeros = (self.zeros + 1).min(3);
                    } else {
                        if b == 1 && self.zeros >= 2 {
                            self.nal = Nal::Header;
                        }
                        self.zeros = 0;
                    }
                }
                Nal::Length(read) => {
                    *used += 1;
                    self.nal_len = if read == 0 { 0 } else { self.nal_len << 8 } | u32::from(b);
                    self.nal = if read + 1 == self.len_size {
                        if self.nal_len == 0 {
                            Nal::Length(0)
                        } else {
                            Nal::Header
                        }
                    } else {
                        Nal::Length(read + 1)
                    };
                }
                Nal::Header => {
                    *used += 1;
                    self.nal_header = b;
                    self.fragmented = false;
                    self.pending_len = 0;
                    self.zeros = 0;
                    if self.packing == enc::PACKING_LENGTH_PREFIXED {
                        self.nal_len -= 1;
                        if self.nal_len == 0 {
                            self.nal = Nal::Length(0);
                            self.held = true;
                            continue;
                        }
                    }
                    self.nal = Nal::Body;
                }
                Nal::Body if self.packing == enc::PACKING_ANNEXB => {
                    if b == 0 {
                        *used += 1;
                        self.zeros = (self.zeros + 1).min(3);
                        continue;
                    }
                    if b == 1 && self.zeros >= 2 {
                        // A start code: the zeros were its prefix, not data.
                        *used += 1;
                        self.zeros = 0;
                        self.nal = Nal::Header;
                        self.held = true;
                        continue;
                    }
                    // Data, with any zeros held back in front of it. One packet
                    // per call: flush first if they do not all fit.
                    let need = usize::from(self.zeros) + 1;
                    if self.pending_len + need > cap {
                        return Some(self.fu_a(out, false));
                    }
                    for _ in 0..self.zeros {
                        self.pending[self.pending_len] = 0;
                        self.pending_len += 1;
                    }
                    self.zeros = 0;
                    self.pending[self.pending_len] = b;
                    self.pending_len += 1;
                    *used += 1;
                }
                Nal::Body => {
                    if self.pending_len == cap {
                        return Some(self.fu_a(out, false));
                    }
                    let take = (cap - self.pending_len)
                        .min(input.len() - *used)
                        .min(self.nal_len as usize);
                    self.pending[self.pending_len..self.pending_len + take]
                        .copy_from_slice(&input[*used..*used + take]);
                    self.pending_len += take;
                    *used += take;
                    self.nal_len -= take as u32;
                    if self.nal_len == 0 {
                        self.nal = Nal::Length(0);
                        self.held = true;
                    }
                }
            }
        }
        if !last {
            return None;
        }
        self.unit_done = true;
        // Trailing zeros after the last NAL are `trailing_zero_8bits`, not data.
        let open = self.held || self.nal == Nal::Body;
        self.held = false;
        if !open {
            return None;
        }
        Some(self.close_nal(out, true))
    }

    /// One FU-A fragment of the pending bytes (RFC 6184 §5.8). Never the last:
    /// a fragment is only cut when more of the NAL is known to follow.
    fn fu_a(&mut self, out: &mut [u8], end: bool) -> Packet {
        out[0] = (self.nal_header & 0xE0) | FU_A;
        out[1] = (if self.fragmented { 0 } else { 0x80 })
            | (if end { 0x40 } else { 0 })
            | (self.nal_header & 0x1F);
        out[2..2 + self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        let len = H264_FU_HEADER + self.pending_len;
        self.fragmented = true;
        self.pending_len = 0;
        Packet { len, marker: false }
    }

    /// Send a completed NAL: whole as a single-NAL packet if it was never
    /// fragmented, else its closing FU-A.
    fn close_nal(&mut self, out: &mut [u8], marker: bool) -> Packet {
        if self.fragmented {
            let mut p = self.fu_a(out, true);
            p.marker = marker;
            return p;
        }
        out[0] = self.nal_header;
        out[1..1 + self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        let len = 1 + self.pending_len;
        self.pending_len = 0;
        Packet { len, marker }
    }
}

impl Default for Packetizer {
    fn default() -> Self {
        Self::new()
    }
}

/// One in-order received packet, as the reorder stage releases it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub codec: u8,
    pub timestamp: u32,
    pub marker: bool,
    /// Packets before this one were never received.
    pub lost_before: bool,
    pub payload: &'a [u8],
}

/// Worst-case record bytes one packet can produce: a `STREAM`, a closing
/// fragment for a damaged unit, and a fragment whose body grew by start codes
/// (a STAP-A of one-byte NALs grows 5/3; a single NAL or FU-A start by 4).
pub const fn depacketized_max(payload: usize) -> usize {
    enc::STREAM_HEADER + 2 * enc::UNIT_HEADER + 4 + payload * 5 / 3 + 4
}

/// RTP packets in, encoded-media records out.
pub struct Depacketizer {
    codec: Option<u8>,
    in_unit: bool,
    unit_ts: u32,
    /// A damaged unit's timestamp: its remaining packets are dropped.
    skip_ts: Option<u32>,
    discontinuity: bool,
    last_ts: u32,
    pts: i64,
    started: bool,
}

impl Depacketizer {
    pub const fn new() -> Self {
        Self {
            codec: None,
            in_unit: false,
            unit_ts: 0,
            skip_ts: None,
            discontinuity: false,
            last_ts: 0,
            pts: 0,
            started: false,
        }
    }

    /// Forget the stream, as at the start of a call.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Records closing the stream: a `TRUNCATED` end for a unit still open,
    /// then `END`. Empty when no stream was ever opened.
    pub fn finish(&mut self, out: &mut [u8]) -> usize {
        if self.codec.is_none() {
            return 0;
        }
        let mut at = 0;
        if self.in_unit {
            at +=
                enc::write_unit(&mut out[at..], enc::FLAG_TRUNCATED, self.pts, 0, &[]).unwrap_or(0);
        }
        at += enc::write_end(&mut out[at..]).unwrap_or(0);
        self.reset();
        at
    }

    /// Turn one packet into records written to `out`, returning how many bytes
    /// of `out` they fill (zero for a packet that produced none). `out` must
    /// hold `depacketized_max(pkt.payload.len())`.
    pub fn packet(&mut self, pkt: Received<'_>, out: &mut [u8]) -> usize {
        let Some((packing, channels, clock)) = received_stream(pkt.codec) else {
            return 0;
        };
        let mut at = 0;
        if self.codec != Some(pkt.codec) {
            at += self.finish(out);
            at += enc::write_stream(&mut out[at..], pkt.codec, packing, channels, clock, &[])
                .unwrap_or(0);
            self.codec = Some(pkt.codec);
        }
        // Extend the 32-bit RTP clock into the stream's signed tick count.
        if self.started {
            self.pts += i64::from(pkt.timestamp.wrapping_sub(self.last_ts) as i32);
        }
        self.started = true;
        self.last_ts = pkt.timestamp;
        if pkt.lost_before {
            self.discontinuity = true;
        }

        if matches!(pkt.codec, enc::CODEC_PCMU | enc::CODEC_OPUS) {
            let flags = enc::FLAG_KEY
                | if core::mem::take(&mut self.discontinuity) {
                    enc::FLAG_DISCONTINUITY
                } else {
                    0
                };
            return at
                + enc::write_unit(&mut out[at..], flags, self.pts, 0, pkt.payload).unwrap_or(0);
        }

        // Video: a unit spans packets sharing a timestamp and ends on the
        // marker. A timestamp change without one, or a loss inside, damages it.
        if self.in_unit && (pkt.timestamp != self.unit_ts || pkt.lost_before) {
            at +=
                enc::write_unit(&mut out[at..], enc::FLAG_TRUNCATED, self.pts, 0, &[]).unwrap_or(0);
            self.in_unit = false;
            self.discontinuity = true;
            if pkt.timestamp == self.unit_ts {
                self.skip_ts = Some(pkt.timestamp);
            }
        }
        if self.skip_ts == Some(pkt.timestamp) {
            if pkt.marker {
                self.skip_ts = None;
            }
            return at;
        }
        self.skip_ts = None;

        let body_at = at + enc::UNIT_HEADER;
        let starting = !self.in_unit;
        let depacked = match pkt.codec {
            enc::CODEC_H264 => h264_to_annexb(pkt.payload, starting, &mut out[body_at..]),
            _ => vp8_frame_data(pkt.payload, starting, &mut out[body_at..]),
        };
        let Some((len, key)) = depacked else {
            // Unreadable, or the middle of a unit whose start was lost.
            self.discontinuity = true;
            if !pkt.marker {
                self.skip_ts = Some(pkt.timestamp);
            }
            return at;
        };
        let mut flags = if pkt.marker { 0 } else { enc::FLAG_CONTINUES };
        if starting {
            if key {
                flags |= enc::FLAG_KEY;
            }
            if core::mem::take(&mut self.discontinuity) {
                flags |= enc::FLAG_DISCONTINUITY;
            }
        }
        if enc::write_unit_header(&mut out[at..], flags, len as u32, self.pts, 0).is_none() {
            return at;
        }
        self.in_unit = !pkt.marker;
        self.unit_ts = pkt.timestamp;
        body_at + len
    }
}

impl Default for Depacketizer {
    fn default() -> Self {
        Self::new()
    }
}

const START_CODE: [u8; 4] = [0, 0, 0, 1];

fn put_nal(out: &mut [u8], at: &mut usize, nal: &[u8], key: &mut bool) -> Option<()> {
    let end = *at + START_CODE.len() + nal.len();
    if end > out.len() || nal.is_empty() {
        return None;
    }
    out[*at..*at + 4].copy_from_slice(&START_CODE);
    out[*at + 4..end].copy_from_slice(nal);
    *key |= matches!(nal[0] & 0x1F, 5 | 7);
    *at = end;
    Some(())
}

/// RFC 6184 payload → Annex B bytes: single NAL units, STAP-A aggregates and
/// FU-A fragments. `None` for a malformed payload, a packetization-mode-2
/// type, or an FU-A continuation arriving with no unit open. The flag is
/// whether the bytes carry an IDR slice or an SPS.
fn h264_to_annexb(payload: &[u8], starting: bool, out: &mut [u8]) -> Option<(usize, bool)> {
    let (&indicator, rest) = payload.split_first()?;
    let mut at = 0;
    let mut key = false;
    match indicator & 0x1F {
        1..=23 => put_nal(out, &mut at, payload, &mut key)?,
        STAP_A => {
            let mut p = rest;
            while !p.is_empty() {
                if p.len() < 2 {
                    return None;
                }
                let n = usize::from(u16::from_be_bytes([p[0], p[1]]));
                let nal = p.get(2..2 + n)?;
                put_nal(out, &mut at, nal, &mut key)?;
                p = &p[2 + n..];
            }
        }
        FU_A => {
            let (&fu, data) = rest.split_first()?;
            if fu & 0x80 != 0 {
                let header = (indicator & 0xE0) | (fu & 0x1F);
                if out.len() < 5 + data.len() {
                    return None;
                }
                out[..4].copy_from_slice(&START_CODE);
                out[4] = header;
                out[5..5 + data.len()].copy_from_slice(data);
                at = 5 + data.len();
                key = matches!(header & 0x1F, 5 | 7);
            } else {
                if starting {
                    return None;
                }
                out.get_mut(..data.len())?.copy_from_slice(data);
                at = data.len();
            }
        }
        _ => return None,
    }
    Some((at, key))
}

/// RFC 7741 payload → VP8 frame bytes: strip the descriptor. `None` for a
/// malformed descriptor, or a continuation arriving with no frame open. The
/// flag is whether this starts a key frame (frame tag P bit clear).
fn vp8_frame_data(payload: &[u8], starting: bool, out: &mut [u8]) -> Option<(usize, bool)> {
    let (&d, _) = payload.split_first()?;
    let mut at = 1;
    if d & 0x80 != 0 {
        let x = *payload.get(1)?;
        at = 2;
        if x & 0x80 != 0 {
            // PictureID: 7 bits, or 15 with the M bit.
            at += if *payload.get(at)? & 0x80 != 0 { 2 } else { 1 };
        }
        if x & 0x40 != 0 {
            at += 1;
        }
        if x & 0x30 != 0 {
            at += 1;
        }
    }
    let data = payload.get(at..)?;
    let frame_start = d & VP8_S != 0 && d & 0x07 == 0;
    if starting != frame_start || data.is_empty() {
        return None;
    }
    out.get_mut(..data.len())?.copy_from_slice(data);
    Some((data.len(), frame_start && data[0] & 0x01 == 0))
}
