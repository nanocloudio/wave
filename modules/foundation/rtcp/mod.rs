//! RTCP (RFC 3550 §6) — the control plane RTP does not have.
//!
//! RTP carries media and says nothing about how it arrived. This module is the
//! channel on which a receiver tells a sender what it actually got — how much
//! was lost, how much arrival times jittered, and how long the round trip is —
//! and on which a sender publishes the mapping between its RTP timestamp and
//! real time that makes lip-sync possible. A media path with no RTCP cannot
//! adapt and cannot synchronise, and neither failure is visible from the media
//! itself.
//!
//! A module rather than a role inside `rtp` because RTCP has its own endpoint,
//! its own clock and its own cost; the decision and its grounds are in
//! `.context/backlog.md` and the README. This is the split `jitter` already
//! uses — a separate realtime adapter over `rtp`'s validated records.
//!
//! Protocol mechanics in the host-tested `modules/common/rtcp_core.rs`; this
//! file is the pump: bind, account for what `rtp` received and sent, report on
//! the interval, and decode what the peer reports back.
//!
//! **What this module is not.** It decides nothing. Rate adaptation, call
//! teardown on a BYE, and quality policy read these numbers and act; this
//! module produces them. Nothing here encrypts — SRTCP is a separate mechanism
//! and its absence is stated, not implied.
//!
//! Ports:  net_in/net_out (the RTCP datagram surface), rtp_stats (in[1], from
//!         `rtp`'s out[2]), reports_out (out[1], what the peer said about us).
//! Params: `port` (local RTCP port), `peer_ip`/`peer_port` (where reports go),
//!         `ssrc` (this participant's synchronisation source), `cname`,
//!         `bandwidth_bps` (session bandwidth the §6.2 interval divides).

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK + shared cores are include!'d wholesale; each module consumes only a subset"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the \
              runtime owns these pointers and their validity is the ABI's contract, and the \
              signature is fixed by that contract rather than chosen here."
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "shared SDK surface across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// The statistics records `rtp` emits. Their layout is owned by the shared
// core rather than restated here — see `rtp_wire.rs` for why.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtp_wire.rs"]
mod rtp_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/rtp_wire.rs"]
pub mod rtp_wire;
use rtp_wire::{parse_rtcp_stat, rtcp_stat_len, RtcpStat, RTCP_STAT_MAX_LEN};

#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtcp_core.rs"]
mod rtcp_core;
#[cfg(feature = "host-test")]
#[path = "../../common/rtcp_core.rs"]
pub mod rtcp_core;
use rtcp_core::{
    ms_to_ntp32, ms_to_ntp64, ms_to_rtp_units, ntp32_to_ms, ntp_middle_32, rtcp_first_block_at,
    rtcp_is_plausible, rtcp_packet_ssrc, rtcp_parse_compound, rtcp_parse_report_block,
    rtcp_parse_sender_info, rtcp_randomise_interval, rtcp_round_trip, rtcp_write_rr,
    rtcp_write_sdes_cname, rtcp_write_sr, write_rtcp_report_record, RtcpPacket, RtcpReceiverStats,
    RtcpReportBlock, RtcpSenderInfo, RTCP_PT_BYE, RTCP_PT_RR, RTCP_PT_SR,
};

const NET_BUF: usize = 1600;
const MSG_BUF: usize = 1500;
const CNAME_BUF: usize = 64;
/// Packets located in one compound. §6.1 compounds are short by construction —
/// a report, an SDES, maybe a BYE — and a datagram claiming more than this is
/// refused rather than partly read.
const MAX_COMPOUND: usize = 8;
/// One report record for the consumer, sized by the core that defines it.
const REPORT_REC: usize = rtcp_core::RTCP_REPORT_REC_LEN;

// The datagram-surface opcodes come from the SDK runtime spliced above, not
// from constants restated here: a locally redeclared contract value is the
// drift `tools/ci/identity_accessor_guard.sh` exists to refuse.

struct RtcpState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    stats_in: i32,
    reports_out: i32,

    port: u16,
    peer_port: u16,
    peer_ip: u32,
    ssrc: u32,
    bandwidth_bps: u32,
    /// Seconds between the local millisecond clock's zero and the NTP epoch.
    ///
    /// Zero means the Sender Report's NTP field is a LOCAL timebase. That is
    /// sufficient for the round-trip calculation, which only ever takes
    /// differences of values this participant issued — and it is NOT
    /// sufficient for synchronising two sources against each other, which
    /// needs a shared epoch. A graph with a real clock supplies one here; one
    /// without gets working RTT and honest nonsense for cross-source sync,
    /// stated rather than hidden.
    ntp_epoch_offset_s: u32,
    /// The RTP clock rate of the stream being reported on, in Hz.
    ///
    /// It must match what `rtp` is carrying: §A.8's transit subtracts an
    /// arrival time from an RTP timestamp, so the two share a unit or the
    /// jitter figure means nothing. 8000 is PCMU, which is what `rtp` and
    /// `sip` compose by default; video payloads are usually 90000.
    clock_rate_hz: u32,
    bound: u8,
    ep_id: u8,
    cname: [u8; CNAME_BUF],
    cname_len: u16,

    /// What we have received FROM the peer — the statistics our reports carry.
    stats: RtcpReceiverStats,
    /// 1 once a reception record has arrived, so an idle receiver reports
    /// nothing rather than reporting a source it has never heard.
    stats_seen: u8,

    /// The transmit counters `rtp` last published, and whether any have been.
    /// A participant that has sent media owes a SENDER report, which is the
    /// only place the NTP/RTP pair a receiver needs for synchronisation
    /// appears.
    tx_packets: u32,
    tx_octets: u32,
    tx_rtp_ts: u32,
    have_tx: u8,

    /// Middle 32 bits of the NTP timestamp in the peer's last SR, and the
    /// local time it arrived — the pair §6.4.1 needs to fill `last_sr` and
    /// `delay_since_last_sr`.
    last_sr_ntp: u32,
    last_sr_at_ms: u64,
    have_last_sr: u8,

    /// When the next report is due, and the randomised interval that set it.
    next_report_ms: u64,
    /// Cheap PRNG state for §6.3.1's draw. Seeded from the SSRC so two
    /// instances in one graph do not report in lockstep.
    rng: u32,

    /// The report the peer sent about US, held until `reports_out` takes it.
    report: [u8; REPORT_REC],
    report_owed: u8,

    msg: [u8; MSG_BUF],
    net_buf: [u8; NET_BUF],

    reports_sent: u32,
    reports_received: u32,
    dropped: u32,
    byes: u32,
    draining: u8,
}

define_params! {
    RtcpState;

    1, port, u16, 5005
        => |s, d, len| { s.port = p_u16(d, len, 0, 5005); };
    2, peer_ip, u32, 0
        => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0); };
    3, peer_port, u16, 5005
        => |s, d, len| { s.peer_port = p_u16(d, len, 0, 5005); };
    4, ssrc, u32, 0x46585254
        => |s, d, len| { s.ssrc = p_u32(d, len, 0, 0x46585254); };
    5, cname, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.cname_len as usize) < CNAME_BUF {
            s.cname[s.cname_len as usize] = *d.add(i); s.cname_len += 1; i += 1;
        }
    };
    6, bandwidth_bps, u32, 64000
        => |s, d, len| { s.bandwidth_bps = p_u32(d, len, 0, 64_000); };
    7, ntp_epoch_offset_s, u32, 0
        => |s, d, len| { s.ntp_epoch_offset_s = p_u32(d, len, 0, 0); };
    8, clock_rate_hz, u32, 8000
        => |s, d, len| { s.clock_rate_hz = p_u32(d, len, 0, 8_000).max(1); };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<RtcpState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut RtcpState)).draining = 1;
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<RtcpState>() {
            return -2;
        }
        let s = &mut *(state as *mut RtcpState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.bound = 0;
        s.ep_id = 0xFF;
        s.cname_len = 0;
        s.stats_seen = 0;
        s.tx_packets = 0;
        s.tx_octets = 0;
        s.tx_rtp_ts = 0;
        s.have_tx = 0;
        s.have_last_sr = 0;
        s.last_sr_ntp = 0;
        s.last_sr_at_ms = 0;
        s.report_owed = 0;
        s.reports_sent = 0;
        s.reports_received = 0;
        s.dropped = 0;
        s.byes = 0;
        s.draining = 0;
        set_defaults(s);
        parse_tlv(s, params, params_len);
        s.stats_in = dev_channel_port(sys, 0, 1);
        s.reports_out = dev_channel_port(sys, 1, 1);
        s.stats = RtcpReceiverStats::new(0);
        // Seeded from the SSRC so two participants in one graph draw different
        // intervals; §6.3.1's randomisation is pointless if everyone draws the
        // same number.
        s.rng = s.ssrc | 1;
        // The first report is due after a randomised interval, not at once:
        // §6.2 requires the initial wait so a joining participant does not add
        // a burst to a session it has just discovered.
        s.next_report_ms = dev_millis(sys).wrapping_add(schedule(s));
        dev_log(sys, 3, b"[rtcp] init".as_ptr(), 11);
        0
    }
}

/// A xorshift draw. Not cryptographic and does not need to be — §6.3.1 wants
/// participants desynchronised, not unpredictable.
fn next_random(s: &mut RtcpState) -> u32 {
    let mut x = s.rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s.rng = x;
    x
}

/// The randomised §6.2/§6.3.1 interval for the next report, in milliseconds.
///
/// Two participants — this one and the peer — because that is what a
/// point-to-point media session is. `we_sent` means what §6.2 means by it:
/// this participant has TRANSMITTED media, and so draws from the senders'
/// quarter of the RTCP bandwidth rather than the receivers' three quarters.
fn schedule(s: &mut RtcpState) -> u64 {
    let base = rtcp_core::rtcp_interval_ms(2, 1, s.have_tx != 0, s.bandwidth_bps);
    let r = next_random(s);
    u64::from(rtcp_randomise_interval(base, r))
}

/// Bind the RTCP endpoint, then learn its id. Same two-step as every datagram
/// consumer here: a BOUND is claimed by PORT match, never by arrival order,
/// because a fanned provider output may carry another module's first.
unsafe fn ensure_bound(s: &mut RtcpState) -> bool {
    let sys = &*s.syscalls;
    if s.bound == 0 {
        if s.net_out < 0 {
            return false;
        }
        let port = s.port.to_le_bytes();
        let payload = [port[0], port[1], 0u8];
        if net_write_frame(
            sys,
            s.net_out,
            DG_CMD_BIND,
            payload.as_ptr(),
            3,
            s.net_buf.as_mut_ptr(),
            NET_BUF,
        ) != 0
        {
            s.bound = 1;
        }
        return false;
    }
    if s.ep_id == 0xFF {
        if s.net_in < 0 {
            return false;
        }
        let poll = (sys.channel_poll)(s.net_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let (msg_type, plen) = net_read_frame(sys, s.net_in, s.net_buf.as_mut_ptr(), NET_BUF);
            if msg_type == DG_MSG_BOUND && plen >= 3 {
                let (ep, port) = abi::contracts::net::datagram::dg_bound_parts(
                    core::slice::from_raw_parts(s.net_buf.as_ptr().add(NET_FRAME_HDR), plen),
                );
                if port == s.port {
                    s.ep_id = ep;
                }
            }
        }
        return false;
    }
    true
}

/// Take reception stats from `rtp` and fold them into what we will report.
///
/// Arrival is stamped HERE, from this module's clock, because `rtp` reads none
/// (it is attested `agnostic`). §A.8 takes a difference of differences, so the
/// constant offset between `rtp` seeing a packet and this module reading the
/// record cancels; what would not cancel is a varying one, which is why the
/// records are consumed every step rather than in batches on a timer.
unsafe fn pump_stats(s: &mut RtcpState) {
    if s.stats_in < 0 {
        return;
    }
    let sys = &*s.syscalls;
    for _ in 0..16 {
        let poll = (sys.channel_poll)(s.stats_in, POLL_IN);
        if poll <= 0 || (poll as u32) & POLL_IN == 0 {
            return;
        }
        // Tag first, then exactly the body that tag declares. A record whose
        // length cannot be known from its tag cannot be skipped either, so an
        // unknown one stops the drain rather than desynchronising every record
        // behind it.
        let mut rec = [0u8; RTCP_STAT_MAX_LEN];
        if (sys.channel_read)(s.stats_in, rec.as_mut_ptr(), 1) < 1 {
            return;
        }
        let Some(len) = rtcp_stat_len(rec[0]) else {
            return;
        };
        if (sys.channel_read)(s.stats_in, rec.as_mut_ptr().add(1), len - 1) < (len - 1) as i32 {
            return;
        }
        match parse_rtcp_stat(&rec[..len]) {
            Some(RtcpStat::Rx { seq, rtp_ts }) => {
                // Arrival in the stream's own timestamp units — §A.8
                // subtracts one from the other, so they share a unit or the
                // result is a number that means nothing.
                let arrival = ms_to_rtp_units(dev_millis(sys) as u32, s.clock_rate_hz);
                s.stats.on_packet(seq, rtp_ts, arrival);
                s.stats_seen = 1;
            }
            Some(RtcpStat::Tx {
                packets,
                octets,
                rtp_ts,
            }) => {
                s.tx_packets = packets;
                s.tx_octets = octets;
                s.tx_rtp_ts = rtp_ts;
                s.have_tx = 1;
            }
            None => return,
        }
    }
}

/// Send one compound: a report, then `SDES(CNAME)` — the minimum §6.1 admits.
///
/// The report is a SENDER report when `rtp` has published transmit counters,
/// and a receiver report otherwise. That distinction is the whole of §6.4's
/// split: only a participant that has sent media has an NTP/RTP pair to
/// publish, and publishing one for a stream never sent would hand a receiver a
/// timestamp mapping for nothing.
unsafe fn send_report(s: &mut RtcpState, now: u64) {
    if s.ep_id == 0xFF || s.net_out < 0 || s.peer_ip == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut out = [0u8; MSG_BUF];

    // A report block only when there is a source to describe. A participant
    // that has heard nothing sends an empty report, which is exactly what
    // §6.4.2 wants: presence, without a claim about a stream it never saw.
    let mut blocks = [RtcpReportBlock::default(); 1];
    let n_blocks = if s.stats_seen != 0 {
        let (last_sr, delay) = if s.have_last_sr != 0 {
            // §6.4.1 measures the delay in 1/65536 s.
            let d = now.saturating_sub(s.last_sr_at_ms) as u32;
            (s.last_sr_ntp, ms_to_ntp32(d))
        } else {
            (0, 0)
        };
        blocks[0] = s.stats.report_block(last_sr, delay);
        1
    } else {
        0
    };

    let built = if s.have_tx != 0 {
        let info = RtcpSenderInfo {
            ntp: ms_to_ntp64(now, s.ntp_epoch_offset_s),
            rtp_timestamp: s.tx_rtp_ts,
            packet_count: s.tx_packets,
            octet_count: s.tx_octets,
        };
        rtcp_write_sr(s.ssrc, &info, &blocks[..n_blocks], &mut out)
    } else {
        rtcp_write_rr(s.ssrc, &blocks[..n_blocks], &mut out)
    };
    let Some(mut at) = built else {
        return;
    };

    // §6.1 requires a CNAME in every compound: SSRCs collide and change, and
    // the CNAME is the only stable name for a participant across both.
    let cname_len = s.cname_len as usize;
    let mut cname = [0u8; CNAME_BUF];
    let cname = if cname_len == 0 {
        cname[..7].copy_from_slice(b"wave@rt");
        &cname[..7]
    } else {
        cname[..cname_len].copy_from_slice(&s.cname[..cname_len]);
        &cname[..cname_len]
    };
    let Some(added) = rtcp_write_sdes_cname(s.ssrc, cname, &mut out[at..]) else {
        return;
    };
    at += added;

    let sent = dev_dg_send_to_v4(
        sys,
        s.net_out,
        s.ep_id,
        s.peer_ip,
        s.peer_port,
        out.as_ptr(),
        at,
        s.net_buf.as_mut_ptr(),
        NET_BUF,
    );
    if sent != 0 {
        s.reports_sent = s.reports_sent.wrapping_add(1);
    }
    // The interval advances either way. A refused write is backpressure, and
    // retrying it inside the same interval would turn one report into a spin.
    s.next_report_ms = now.wrapping_add(schedule(s));
}

/// Decode a compound the peer sent and keep what it says about US.
unsafe fn on_compound(s: &mut RtcpState, len: usize, now: u64) {
    let mut copy = [0u8; MSG_BUF];
    copy[..len].copy_from_slice(&s.msg[..len]);
    let mut pkts = [RtcpPacket {
        payload_type: 0,
        count: 0,
        at: 0,
        len: 0,
    }; MAX_COMPOUND];
    let Ok(n) = rtcp_parse_compound(&copy[..len], &mut pkts) else {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    };
    s.reports_received = s.reports_received.wrapping_add(1);

    for p in pkts.iter().take(n) {
        match p.payload_type {
            RTCP_PT_SR => {
                // The NTP/RTP pair, kept so our next report can tell the peer
                // how long we sat on it — which is what makes their round-trip
                // calculation possible at all.
                if let Some(info) = rtcp_parse_sender_info(&copy[..len], p.at) {
                    s.last_sr_ntp = ntp_middle_32(info.ntp);
                    s.last_sr_at_ms = now;
                    s.have_last_sr = 1;
                }
                take_blocks_about_us(s, &copy[..len], p, now);
            }
            RTCP_PT_RR => take_blocks_about_us(s, &copy[..len], p, now),
            RTCP_PT_BYE => s.byes = s.byes.wrapping_add(1),
            _ => {}
        }
        // The first source we hear becomes the one we report on. A second
        // SSRC is a third participant, which is a session this module does not
        // model — counted, not silently folded into the first one's numbers.
        if matches!(p.payload_type, RTCP_PT_SR | RTCP_PT_RR) {
            if let Some(ssrc) = rtcp_packet_ssrc(&copy[..len], p.at) {
                if s.stats.ssrc == 0 {
                    s.stats.ssrc = ssrc;
                } else if s.stats.ssrc != ssrc {
                    s.dropped = s.dropped.wrapping_add(1);
                }
            }
        }
    }
}

/// Keep the report block addressed to our own SSRC — the peer telling us how
/// our stream arrived, which is the only channel that carries that.
unsafe fn take_blocks_about_us(s: &mut RtcpState, buf: &[u8], p: &RtcpPacket, now: u64) {
    let first = rtcp_first_block_at(p.payload_type, p.at);
    for i in 0..p.count as usize {
        let at = first + i * rtcp_core::RTCP_REPORT_BLOCK_SIZE;
        if at + rtcp_core::RTCP_REPORT_BLOCK_SIZE > p.at + p.len {
            return;
        }
        let Some(b) = rtcp_parse_report_block(buf, at) else {
            return;
        };
        if b.ssrc != s.ssrc {
            continue;
        }
        // now, in 1/65536 s, as the middle 32 bits of an NTP timestamp.
        let now_ntp = ms_to_ntp32(now as u32);
        let rtt = rtcp_round_trip(now_ntp, &b);
        emit_report(s, &b, rtt);
    }
}

/// Stage one report record for `reports_out`.
///
/// One slot, drained by [`flush_report`] on the next step, so under an
/// ordinary consumer every report the peer sends is handed over.
///
/// When the channel IS refusing, the slot is overwritten rather than held.
/// Loss, jitter and round trip describe the link as it is now, so a consumer
/// that has not drained within a reporting interval — five seconds at the
/// RFC's floor — is better served by the current measurement than by the one
/// it missed.
unsafe fn emit_report(s: &mut RtcpState, b: &RtcpReportBlock, rtt: Option<u32>) {
    if s.reports_out < 0 {
        return;
    }
    let mut r = [0u8; REPORT_REC];
    // Round trip in milliseconds, from the 1/65536 s the wire carries.
    if write_rtcp_report_record(b, rtt.map(ntp32_to_ms), &mut r).is_none() {
        return;
    }
    s.report = r;
    s.report_owed = 1;
}

unsafe fn flush_report(s: &mut RtcpState) {
    if s.report_owed == 0 || s.reports_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.reports_out, POLL_OUT);
    if poll <= 0 || (poll as u32) & POLL_OUT == 0 {
        return;
    }
    let staged = s.report;
    if (sys.channel_write)(s.reports_out, staged.as_ptr(), REPORT_REC) == REPORT_REC as i32 {
        s.report_owed = 0;
    }
}

/// Read one RTCP datagram.
unsafe fn pump_net(s: &mut RtcpState, now: u64) {
    if s.net_in < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.net_in, POLL_IN);
    if poll <= 0 || (poll as u32) & POLL_IN == 0 {
        return;
    }
    let (msg_type, plen) = net_read_frame(sys, s.net_in, s.net_buf.as_mut_ptr(), NET_BUF);
    if msg_type != DG_MSG_RX_FROM {
        return;
    }
    let Some((_ep, ip, port, data_ptr, raw_len)) = parse_dg_rx_from_v4(s.net_buf.as_ptr(), plen)
    else {
        return;
    };
    // Only the peer this session was configured for. An RTCP endpoint is
    // reachable by anyone, and a report from a stranger would otherwise be
    // read as this session's loss and jitter.
    if ip != s.peer_ip || port != s.peer_port {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    let data_len = raw_len.min(MSG_BUF);
    core::ptr::copy_nonoverlapping(data_ptr, s.msg.as_mut_ptr(), data_len);
    if !rtcp_is_plausible(&s.msg[..data_len]) {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    on_compound(s, data_len, now);
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut RtcpState);
        if s.syscalls.is_null() {
            return -1;
        }
        if !ensure_bound(s) {
            return 0;
        }
        let now = dev_millis(&*s.syscalls);
        pump_stats(s);
        pump_net(s, now);
        if now >= s.next_report_ms && s.draining == 0 {
            send_report(s, now);
        }
        flush_report(s);
        if s.draining == 1 && s.report_owed == 0 {
            return 1;
        }
        0
    }
}
