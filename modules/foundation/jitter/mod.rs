//! `jitter` — the RTP-family reorder/playout adapter.
//!
//! The minimum receive-side buffering the realtime family owns
//! (rfc_hardening §9.6): validated RTP payloads in, loss-concealed playout
//! out, at the codec's frame cadence. The data structure and both operations
//! are `modules/common/jitter_core.rs`, mounted verbatim; this file is the
//! pump — records in, a wall clock for pacing, backpressure out.
//!
//! It decides nothing about the call. `sip` decides when media starts and
//! stops and says so on the same control records it drives the `rtp`
//! transmitter with; this module obeys START/STOP and ignores SET_ENDPOINT,
//! which addresses the transmitter. Adaptive playout, clock recovery and
//! topology-aware buffering are Grove's, not Wave's.
//!
//! Ports:
//!   in[0]  `rx_in`    — `[seq: u16 LE][payload…]` records, one validated RTP
//!                       payload per record (`rtp.packets`).
//!   in[1]  `ctrl`     — the shared media-control records (START/STOP).
//!   out[0] `ulaw_out` — playout µ-law at `ptime` cadence.
#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    clippy::missing_safety_doc,
    reason = "the fluxor module ABI entry points take raw state/syscall pointers whose validity is the ABI's contract"
)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the \
              runtime owns these pointers and their validity is the ABI's contract, and the \
              signature is fixed by that contract rather than chosen here."
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// The reorder window and loss-concealing playout ring — the single
// implementation, shared with the host vectors
// (tests/harness/tests/sip_jitter_vectors.rs).
#[cfg(not(feature = "host-test"))]
#[path = "../../common/jitter_core.rs"]
mod jitter_core;
#[cfg(feature = "host-test")]
#[path = "../../common/jitter_core.rs"]
pub mod jitter_core;
use jitter_core::JitterBuffer;

// The receive-record seam from `rtp` — one owner for the layout.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtp_wire.rs"]
mod rtp_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/rtp_wire.rs"]
pub mod rtp_wire;
use rtp_wire::{rtp_rx_seq, REC_RTP_RX, RTP_RX_SEQ_LEN};

/// The shared media-control records (`sip.rtp_ctrl`, fanned here and to the
/// transmitter). SET_ENDPOINT addresses the transmitter and is ignored.
const CTRL_SET_ENDPOINT: u8 = 0x01;
const CTRL_START: u8 = 0x02;
const CTRL_STOP: u8 = 0x03;
const CTRL_MSG_SIZE: usize = 8;

/// Playout scratch: one ptime frame of 8 kHz G.711.
const PLAYOUT_BUF: usize = jitter_core::JITTER_SLOT_SIZE;

/// Records consumed from `rx_in` per step — bounds the drain loop while
/// outrunning any admitted cadence (a 50/s stream against 4/step at a 1 ms
/// tick).
const RX_DRAIN_BUDGET: u32 = 4;

#[repr(C)]
struct JitterState {
    syscalls: *const SyscallTable,
    rx_in: i32,
    ctrl_in: i32,
    ulaw_out: i32,
    jitter: JitterBuffer,
    playing: u8,
    ptime: u8,
    target_fill: u16,
    last_playout_ms: u64,
    playout_buf: [u8; PLAYOUT_BUF],
    rx_buf: [u8; 512],
}

impl JitterState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.rx_in = -1;
        self.ctrl_in = -1;
        self.ulaw_out = -1;
        self.jitter = JitterBuffer::new();
        self.playing = 0;
        self.ptime = 20;
        self.target_fill = 3;
        self.last_playout_ms = 0;
        self.playout_buf = [0; PLAYOUT_BUF];
        self.rx_buf = [0; 512];
    }
}

mod params_def {
    use super::JitterState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u8};

    define_params! {
        JitterState;
        1, ptime, u8, 20 => |s, d, len| { let v = p_u8(d, len, 0, 20); s.ptime = if v == 0 { 20 } else { v }; };
        2, target_fill, u16, 3 => |s, d, len| { s.target_fill = p_u16(d, len, 0, 3); };
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
        s.ulaw_out = out_chan;
        let ch = dev_channel_port(sys, 0, 1); // in[1]: ctrl
        if ch >= 0 {
            s.ctrl_in = ch;
        }

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
        step_playout(s);
        0
    }
}

/// Obey the fanned media-control records. START resets the ring and arms
/// playout; STOP disarms and clears. SET_ENDPOINT addresses the transmitter.
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
                s.playing = 1;
                s.last_playout_ms = dev_millis(sys);
                dev_log(sys, 3, b"[jit] start".as_ptr(), 11);
            }
            CTRL_STOP => {
                s.playing = 0;
                s.jitter.reset();
                dev_log(sys, 3, b"[jit] stop".as_ptr(), 10);
            }
            CTRL_SET_ENDPOINT => {}
            _ => {}
        }
    }
}

/// Drain `rx_in` records into the reorder ring. Always — an undrained leg of
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
        if msg_type != REC_RTP_RX || plen < RTP_RX_SEQ_LEN {
            // Unknown frame or a runt too short for a sequence: consumed
            // whole (the framing keeps the FIFO aligned) and dropped.
            if msg_type == 0 {
                return;
            }
            continue;
        }
        if s.playing == 0 {
            continue;
        }
        let payload = &s.rx_buf[NET_FRAME_HDR..NET_FRAME_HDR + plen];
        let seq = rtp_rx_seq(payload);
        s.jitter.insert(seq, &payload[RTP_RX_SEQ_LEN..]);
    }
}

/// Loss-concealing playout at `ptime` cadence — the one clock this module
/// reads, and the reason it attests `wall_clock`: a relaxed scheduler tick
/// must stretch scheduling, never the audio.
unsafe fn step_playout(s: &mut JitterState) {
    let sys = &*s.syscalls;
    if s.playing == 0 || s.ulaw_out < 0 {
        return;
    }
    if s.jitter.fill_count() < s.target_fill && s.last_playout_ms != 0 {
        // Still pre-buffering before first playout.
    }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_playout_ms) < s.ptime as u64 {
        return;
    }
    let out_poll = (sys.channel_poll)(s.ulaw_out, POLL_OUT);
    if out_poll <= 0 || (out_poll as u32) & POLL_OUT == 0 {
        return;
    }
    let out_len = (s.ptime as usize * 8).min(PLAYOUT_BUF);
    if s.jitter.playout(out_len, &mut s.playout_buf).is_some() {
        let _ = (sys.channel_write)(s.ulaw_out, s.playout_buf.as_ptr(), out_len);
        s.last_playout_ms = now;
    }
}
