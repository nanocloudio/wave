//! `jitter` — the RTP-family reorder and depacketize adapter.
//!
//! Validated RTP payloads in, the fluxor encoded-media record stream out
//! (`abi::contracts::encoded`). The reorder window is
//! `modules/common/jitter_core.rs` and the payload formats are
//! `modules/common/rtp_payload.rs`, both mounted verbatim; this file is the
//! pump — records in, in-order release, a bounded wait for holes, backpressure
//! out.
//!
//! It decides nothing about the call. `sip` decides when media starts and
//! stops and says so on the same control records it drives the `rtp`
//! transmitter with; this module obeys START/STOP and ignores SET_ENDPOINT,
//! which addresses the transmitter.
//!
//! It conceals nothing. A packet that never arrives is waited for at most
//! `max_hold_ms`, then skipped, and the next unit carries `DISCONTINUITY` so the
//! decoder conceals — concealment is codec work. Playout pacing is not here
//! either: presenting media on time belongs to the sink that owns the clock.
//!
//! Ports:
//!   in[0]  `rx_in`      — receive records from `rtp.packets` (`rtp_wire.rs`).
//!   in[1]  `media_ctrl` — the shared media-control records (START/STOP).
//!   out[0] `audio_out`  — `AudioEncoded` records, for an audio stream.
//!   out[1] `video_out`  — `VideoEncoded` records, for a video stream.
#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    reason = "the SDK is path-mounted into every module, so each compile sees \
              the whole ABI surface while using a subset"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the module ABI entry points take raw state and syscall pointers \
              whose validity is the runtime's half of the contract, and the \
              signature is fixed by that contract rather than chosen here"
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::contracts::encoded as enc;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// The reorder window — the single implementation, shared with the host
// vectors (tests/harness/tests/jitter.rs).
#[cfg(not(feature = "host-test"))]
#[path = "../../common/jitter_core.rs"]
mod jitter_core;
#[cfg(feature = "host-test")]
#[path = "../../common/jitter_core.rs"]
pub mod jitter_core;
use jitter_core::{JitterBuffer, JitterPacketMeta, JITTER_SLOT_SIZE};

// RTP payload formats → encoded-media records.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtp_payload.rs"]
mod rtp_payload;
#[cfg(feature = "host-test")]
#[path = "../../common/rtp_payload.rs"]
pub mod rtp_payload;
use rtp_payload::{depacketized_max, Depacketizer, Received};

// The receive-record seam from `rtp` — one owner for the layout.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtp_wire.rs"]
mod rtp_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/rtp_wire.rs"]
pub mod rtp_wire;
use rtp_wire::{
    parse_rtp_rx_meta, parse_rtp_rx_meta_mid, REC_RTP_RX_META, REC_RTP_RX_META_MID,
    RTP_RX_META_LEN, RTP_RX_META_MID_LEN,
};

/// The shared media-control records (`sip.rtp_ctrl`, fanned here and to the
/// transmitter). SET_ENDPOINT addresses the transmitter and is ignored.
const CTRL_SET_ENDPOINT: u8 = 0x01;
const CTRL_START: u8 = 0x02;
const CTRL_STOP: u8 = 0x03;
const CTRL_MSG_SIZE: usize = 8;

/// Records consumed from `rx_in` per step — bounds the drain loop while
/// outrunning any admitted cadence.
const RX_DRAIN_BUDGET: u32 = 4;

/// Packets released per step.
const RELEASE_BUDGET: u32 = 8;

/// Staged output: the most records one packet produces, plus the close of a
/// stream (a truncated unit end and `END`) appended on STOP.
const PENDING_MAX: usize = depacketized_max(JITTER_SLOT_SIZE) + enc::UNIT_HEADER + enc::END_LEN;

/// One receive record with its NetProto envelope.
const RX_BUF_SIZE: usize = NET_FRAME_HDR + RTP_RX_META_MID_LEN + JITTER_SLOT_SIZE;

#[repr(C)]
struct JitterState {
    syscalls: *const SyscallTable,
    rx_in: i32,
    ctrl_in: i32,
    audio_out: i32,
    video_out: i32,
    /// The output the current stream's records go to.
    stream_out: i32,
    jitter: JitterBuffer,
    depack: Depacketizer,
    playing: u8,
    max_hold_ms: u16,
    /// When the head hole was first seen; `None` while there is none.
    hole_since_ms: Option<u64>,
    /// Records for a stream whose medium has no wired output. Counted, never
    /// silent.
    unrouted: u32,
    pending_len: u16,
    pending: [u8; PENDING_MAX],
    rx_buf: [u8; RX_BUF_SIZE],
}

impl JitterState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.rx_in = -1;
        self.ctrl_in = -1;
        self.audio_out = -1;
        self.video_out = -1;
        self.stream_out = -1;
        self.jitter = JitterBuffer::new();
        self.depack = Depacketizer::new();
        self.playing = 0;
        self.max_hold_ms = 60;
        self.hole_since_ms = None;
        self.unrouted = 0;
        self.pending_len = 0;
        self.pending = [0; PENDING_MAX];
        self.rx_buf = [0; RX_BUF_SIZE];
    }
}

mod params_def {
    use super::JitterState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u8};

    define_params! {
        JitterState;
        // Tags 1 and 2 are closed; the next allocation is 4.
        3, max_hold_ms, u16, 60 => |s, d, len| { s.max_hold_ms = p_u16(d, len, 0, 60); };
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<JitterState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

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
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<JitterState>() {
            return -5;
        }
        let s = &mut *(state as *mut JitterState);
        s.init(syscalls as *const SyscallTable);
        let sys = &*s.syscalls;

        s.rx_in = in_chan;
        s.audio_out = out_chan;
        s.video_out = dev_channel_port(sys, 1, 1);
        s.ctrl_in = dev_channel_port(sys, 0, 1);

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        dev_log(sys, 3, b"[jit] ready".as_ptr(), 11);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut JitterState);
        if s.syscalls.is_null() {
            return -1;
        }
        step_ctrl(s);
        step_rx(s);
        step_release(s);
        0
    }
}

/// Obey the fanned media-control records. START resets the window and arms
/// release; STOP closes the stream downstream with `END` and clears.
unsafe fn step_ctrl(s: &mut JitterState) {
    let sys = &*s.syscalls;
    if s.ctrl_in < 0 {
        return;
    }
    loop {
        let poll = (sys.channel_poll)(s.ctrl_in, POLL_IN);
        if poll <= 0 || (poll as u32) & POLL_IN == 0 {
            return;
        }
        let mut m = [0u8; CTRL_MSG_SIZE];
        let read = (sys.channel_read)(s.ctrl_in, m.as_mut_ptr(), CTRL_MSG_SIZE);
        if read < CTRL_MSG_SIZE as i32 {
            return;
        }
        match m[0] {
            CTRL_START => {
                s.jitter.reset();
                s.depack.reset();
                s.hole_since_ms = None;
                s.playing = 1;
                dev_log(sys, 3, b"[jit] start".as_ptr(), 11);
            }
            CTRL_STOP => {
                if s.playing != 0 {
                    // Close the stream after anything still staged: a decoder
                    // must see END to flush what it holds.
                    let at = s.pending_len as usize;
                    let n = s.depack.finish(&mut s.pending[at..]);
                    s.pending_len += n as u16;
                }
                s.playing = 0;
                s.jitter.reset();
                s.hole_since_ms = None;
                dev_log(sys, 3, b"[jit] stop".as_ptr(), 10);
            }
            CTRL_SET_ENDPOINT => {}
            _ => {}
        }
    }
}

/// Drain `rx_in` records into the reorder window. Always — an undrained leg of
/// a fan-out stalls its producer; a record that arrives while stopped is
/// consumed and dropped, which is the STOP semantics, not a loss.
unsafe fn step_rx(s: &mut JitterState) {
    let sys = &*s.syscalls;
    if s.rx_in < 0 {
        return;
    }
    let mut budget = RX_DRAIN_BUDGET;
    while budget > 0 {
        budget -= 1;
        let poll = (sys.channel_poll)(s.rx_in, POLL_IN);
        if poll <= 0 || (poll as u32) & POLL_IN == 0 {
            return;
        }
        let (msg_type, plen) = net_read_frame(sys, s.rx_in, s.rx_buf.as_mut_ptr(), s.rx_buf.len());
        if msg_type == 0 {
            return;
        }
        if s.playing == 0 {
            continue;
        }
        let record = &s.rx_buf[NET_FRAME_HDR..NET_FRAME_HDR + plen];
        let parsed = match msg_type {
            REC_RTP_RX_META => parse_rtp_rx_meta(record).map(|m| (m, RTP_RX_META_LEN)),
            REC_RTP_RX_META_MID => {
                parse_rtp_rx_meta_mid(record).map(|(m, _, _)| (m, RTP_RX_META_MID_LEN))
            }
            _ => None,
        };
        // An unknown frame or a runt is consumed whole — the framing keeps the
        // FIFO aligned — and dropped.
        let Some((meta, at)) = parsed else {
            continue;
        };
        s.jitter.insert(
            meta.seq,
            &record[at..],
            JitterPacketMeta {
                timestamp: meta.timestamp,
                ssrc: meta.ssrc,
                payload_type: meta.payload_type,
                marker: meta.marker,
                codec: meta.codec,
            },
        );
    }
}

/// Offer the staged records; `false` while the output is full.
unsafe fn flush_pending(s: &mut JitterState) -> bool {
    let len = s.pending_len as usize;
    if len == 0 {
        return true;
    }
    if s.stream_out < 0 {
        s.unrouted = s.unrouted.wrapping_add(1);
        s.pending_len = 0;
        return true;
    }
    let sys = &*s.syscalls;
    // All-or-nothing: a refused write leaves the stream intact to re-offer.
    if (sys.channel_write)(s.stream_out, s.pending.as_ptr(), len) < 0 {
        return false;
    }
    s.pending_len = 0;
    true
}

/// Release in-order packets as records, waiting at most `max_hold_ms` on a
/// hole before skipping it.
unsafe fn step_release(s: &mut JitterState) {
    let sys = &*s.syscalls;
    let mut budget = RELEASE_BUDGET;
    while budget > 0 {
        budget -= 1;
        if !flush_pending(s) {
            return;
        }
        if s.playing == 0 {
            return;
        }
        if let Some(pkt) = s.jitter.peek() {
            s.stream_out = if enc::is_video(pkt.meta.codec) {
                s.video_out
            } else {
                s.audio_out
            };
            let n = s.depack.packet(
                Received {
                    codec: pkt.meta.codec,
                    timestamp: pkt.meta.timestamp,
                    marker: pkt.meta.marker,
                    lost_before: pkt.lost_before,
                    payload: pkt.payload,
                },
                &mut s.pending,
            );
            s.pending_len = n as u16;
            s.jitter.release();
            s.hole_since_ms = None;
            continue;
        }
        if !s.jitter.waiting_on_hole() {
            s.hole_since_ms = None;
            return;
        }
        // The one clock this module reads, and the reason it attests
        // `wall_clock`: how long a hole is waited for is real time, not steps.
        let now = dev_millis(sys);
        match s.hole_since_ms {
            None => {
                s.hole_since_ms = Some(now);
                return;
            }
            Some(since) if now.wrapping_sub(since) < u64::from(s.max_hold_ms) => return,
            Some(_) => {
                s.jitter.skip_hole();
                s.hole_since_ms = None;
            }
        }
    }
}
