//! Echo worker for `foundation/http`'s session anchor.
//!
//! A conformance fixture, not a product module — see `manifest.toml` for why
//! it sits in `modules/fixtures/`. It is the far side of the `WsFrame` seam
//! that a worker swap moves: `modules/common/ws_session_worker.rs` answers
//! SessionCtrlV1 for it, and what this file adds is the least application
//! state that makes a swap observable and the boundary rule testable.
//!
//! Per session it keeps a message count and the partial message being
//! accumulated from `fin = 0` fragments. A complete message is answered on the
//! same connection as `<tag>:<count>:<message>` — so a client watching one
//! connection sees which worker answered and that the count carried across.
//! A drain is answered only at a message boundary: a worker holding half a
//! message declares nothing until the other half arrives.
//!
//! The exported blob is `[magic "WSE1":4][count:4 LE][acc_len:2 LE][acc…]`.
//! Opaque to the anchor, which relays it; meaningful only to another instance
//! of this module.
//!
//! # Parameters (TLV)
//!
//! | Tag | Name | Type | Default | Description                                   |
//! |-----|------|------|---------|-----------------------------------------------|
//! | 1   | tag  | str  | `A`     | Prefix on every reply, naming this worker.    |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unsafe_code,
    reason = "PIC module: ABI shim and zero-copy buffer plumbing"
)]
#![deny(clippy::unwrap_used)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the runtime owns these pointers and their validity is the ABI's contract"
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::contracts::net::session_ctrl as sc;
use abi::contracts::net::ws_frame;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/cores/session_handoff.rs");
include!("../../common/ws_session_worker.rs");

/// Sessions this worker holds at once.
const SESSIONS: usize = 8;
/// Longest message accumulated per session.
const ACC_MAX: usize = 256;
/// Blob: magic + count + acc_len + accumulator.
const BLOB_HDR: usize = 4 + 4 + 2;
const BLOB_MAX: usize = BLOB_HDR + ACC_MAX;
const BLOB_MAGIC: [u8; 4] = *b"WSE1";
/// Export chunk: small enough that a chunk frame is well under the anchor's
/// control ceiling, and small enough that a blob usually crosses in several,
/// which is the reassembly the gates want exercised.
const EXPORT_CHUNK: u32 = 64;
/// Largest control frame read or written.
const CTRL_MAX: usize = 1024 + NET_FRAME_HDR;
/// Longest reply: tag + ':' + 10 digits + ':' + the message.
const TAG_MAX: usize = 16;
const REPLY_MAX: usize = TAG_MAX + 1 + 10 + 1 + ACC_MAX;
const MON_BUF_SIZE: usize = 192;
const STEP_DID_WORK: i32 = 2;

/// The application's state for one session: what the blob carries.
#[repr(C)]
#[derive(Clone, Copy)]
struct App {
    count: u32,
    acc_len: u16,
    _pad: [u8; 2],
    acc: [u8; ACC_MAX],
}

impl App {
    const fn new() -> Self {
        Self {
            count: 0,
            acc_len: 0,
            _pad: [0; 2],
            acc: [0; ACC_MAX],
        }
    }
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    ctrl_in: i32,
    ctrl_out: i32,
    data_in: i32,
    data_out: i32,
    tag: [u8; TAG_MAX],
    tag_len: u8,
    self_idx: u8,
    _pad: [u8; 2],
    /// Envelopes for a connection no session claims, dropped. A worker that
    /// keeps writing after it was detached shows up here rather than being
    /// answered, which is the fixture's half of the anchor's
    /// `ws_envelopes_misowned`.
    unclaimed: u32,
    /// Bytes of `frame_buf` holding an envelope read for a session that
    /// could not consume it yet; 0 when none.
    held_len: u16,
    _pad2: [u8; 2],
    worker: WsSessionWorker<SESSIONS, BLOB_MAX>,
    apps: [App; SESSIONS],
    ctrl_buf: [u8; CTRL_MAX],
    frame_buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    reply_buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    mon_buf: [u8; MON_BUF_SIZE],
}

mod params_def {
    use super::State;
    use super::SCHEMA_MAX;
    use super::TAG_MAX;

    define_params! {
        State;

        1, tag, str, 0
            => |s, d, len| {
                let n = len.min(TAG_MAX);
                if n > 0 {
                    // SAFETY: `d` points at `len` readable bytes (the TLV value).
                    unsafe { core::ptr::copy_nonoverlapping(d, s.tag.as_mut_ptr(), n); }
                    s.tag_len = n as u8;
                }
            };
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
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
    if state.is_null() || state_size < core::mem::size_of::<State>() || syscalls.is_null() {
        return -1;
    }
    let sys = syscalls as *const SyscallTable;
    // SAFETY: `sys` is non-null (checked above) and points at this instance's
    // kernel syscall table.
    let sys_ref = unsafe { &*sys };
    // SAFETY: `state` was null- and size-checked above; the kernel
    // zero-initialised at least `size_of::<State>()` bytes.
    let s = unsafe { &mut *(state as *mut State) };
    s.syscalls = sys;
    s.ctrl_in = in_chan;
    s.ctrl_out = out_chan;
    // SAFETY: `dev_channel_port` is a syscall-table wrapper; each (kind, index)
    // pair is declared in `manifest.toml`.
    s.data_in = unsafe { dev_channel_port(sys_ref, 0, 1) };
    // SAFETY: as above.
    s.data_out = unsafe { dev_channel_port(sys_ref, 1, 1) };
    s.tag = [0; TAG_MAX];
    s.tag[0] = b'A';
    s.tag_len = 1;
    s.self_idx = 0xFF;
    s.unclaimed = 0;
    s.held_len = 0;
    // SAFETY: `params` is either null or `params_len` readable bytes.
    let is_tlv = unsafe {
        !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01
    };
    if is_tlv {
        // SAFETY: as above; the TLV walker bounds every read by `params_len`.
        unsafe { params_def::parse_tlv(s, params, params_len) };
    }
    let mut worker_id = *b"WAVEWK-?";
    worker_id[7] = s.tag[0];
    s.worker = WsSessionWorker::new(worker_id, EXPORT_CHUNK);
    s.apps = [App::new(); SESSIONS];
    0
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: the kernel passes the same `state` buffer it validated in
    // `module_new`, and this module is stepped single-threaded.
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return -1;
    }
    let mut did_work = false;
    // SAFETY: every helper below dereferences only the syscall table set in
    // `module_new` and buffers owned by `s`.
    unsafe {
        did_work |= pump_ctrl(s);
        did_work |= pump_data(s);
        did_work |= flush_ctrl(s);
    }
    if did_work {
        STEP_DID_WORK
    } else {
        0
    }
}

// ── Control plane ─────────────────────────────────────────────────────────

/// Read up to a few commands from the anchor and act on their events.
unsafe fn pump_ctrl(s: &mut State) -> bool {
    if s.ctrl_in < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let mut did = false;
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.ctrl_in, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let buf = s.ctrl_buf.as_mut_ptr();
        let (msg, len) = net_read_frame(sys, s.ctrl_in, buf, CTRL_MAX);
        if msg == 0 {
            break;
        }
        did = true;
        let payload = core::slice::from_raw_parts(buf.add(NET_FRAME_HDR), len);
        let ev = s.worker.handle_ctrl(msg, payload);
        act(s, ev);
    }
    did
}

/// Act on a core event.
unsafe fn act(s: &mut State, ev: WswEvent) {
    match ev {
        WswEvent::Attached(i) => {
            s.apps[i] = App::new();
            mon(s, i, MON_EV_ATTACHED, b"", b"ok");
        }
        WswEvent::ExportRequested(i) => {
            let n = serialise(&s.apps[i], s.worker.blob_mut(i));
            s.worker.export_committed(i, n);
            mon(s, i, MON_EV_DRAINED, b"", b"");
            mon(s, i, MON_EV_EXPORTED, b"", b"");
        }
        WswEvent::Imported(i) => {
            let ok = restore(s.worker.blob(i), &mut s.apps[i]);
            mon(
                s,
                i,
                MON_EV_IMPORTED,
                b"",
                if ok { b"ok" } else { b"corrupt" },
            );
        }
        WswEvent::Resumed(i) => {
            mon(s, i, MON_EV_RESUMED, b"", b"ok");
        }
        WswEvent::Detached(i) => {
            mon(s, i, MON_EV_DETACHED, b"normal", b"");
            s.apps[i] = App::new();
        }
        WswEvent::None => {}
    }
}

/// Write the control frames the core owes, as far as the channel takes them.
unsafe fn flush_ctrl(s: &mut State) -> bool {
    if s.ctrl_out < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let mut did = false;
    loop {
        let poll = (sys.channel_poll)(s.ctrl_out, POLL_OUT);
        if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
            break;
        }
        let mut payload = [0u8; CTRL_MAX];
        let Some((msg, len)) = s.worker.next_out(&mut payload) else {
            break;
        };
        let scratch = s.ctrl_buf.as_mut_ptr();
        if net_write_frame(
            sys,
            s.ctrl_out,
            msg,
            payload.as_ptr(),
            len,
            scratch,
            CTRL_MAX,
        ) == 0
        {
            break;
        }
        did = true;
    }
    did
}

// ── Data plane ────────────────────────────────────────────────────────────

/// One envelope in, at most one reply out; then the drain-to-dry check.
unsafe fn pump_data(s: &mut State) -> bool {
    if s.data_in < 0 || s.data_out < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let mut did = false;
    // A reply is written in the same step as the message that earns it, so
    // an envelope is read only when there is room to answer it.
    let out_ready = {
        let p = (sys.channel_poll)(s.data_out, POLL_OUT);
        p > 0 && (p as u32 & POLL_OUT) != 0
    };
    let in_ready = {
        let p = (sys.channel_poll)(s.data_in, POLL_IN);
        p > 0 && (p as u32 & POLL_IN) != 0
    };
    // An envelope read for a session that could not consume it at the time
    // (drained, half-imported) is held here, ahead of anything still in the
    // channel, until the session can. A mailbox cannot be peeked, so the
    // envelope has to be read to learn whose it is; holding it is what keeps
    // that read from being a loss. The anchor holds such a session's frames
    // anyway, so this is the defensive half of that rule.
    if s.held_len != 0 {
        let total = s.held_len as usize;
        let conn = ws_frame::conn_id(&s.frame_buf);
        match s.worker.session_for_conn(conn) {
            Some(i) if s.worker.may_consume(i) => {
                if out_ready {
                    s.held_len = 0;
                    s.worker.on_inbound(i, total);
                    consume(s, i, total);
                    did = true;
                }
            }
            Some(_) => {}
            None => {
                // The session went away while its frame waited.
                s.held_len = 0;
                s.unclaimed = s.unclaimed.wrapping_add(1);
            }
        }
    } else if in_ready && out_ready {
        let n = (sys.channel_read)(
            s.data_in,
            s.frame_buf.as_mut_ptr(),
            abi::CHANNEL_BUFFER_SIZE,
        );
        if n >= ws_frame::FRAME_HDR as i32 {
            did = true;
            let total = ws_frame::FRAME_HDR + ws_frame::payload_len(&s.frame_buf) as usize;
            if (n as usize) >= total {
                let conn = ws_frame::conn_id(&s.frame_buf);
                match s.worker.session_for_conn(conn) {
                    Some(i) if s.worker.may_consume(i) => {
                        s.worker.on_inbound(i, total);
                        consume(s, i, total);
                    }
                    Some(_) => s.held_len = total as u16,
                    None => s.unclaimed = s.unclaimed.wrapping_add(1),
                }
            }
        }
    }
    if !in_ready && s.held_len == 0 {
        // Dry: a draining session at a message boundary exports now.
        let ev = s.worker.data_idle();
        if ev != WswEvent::None {
            did = true;
            act(s, ev);
        }
    }
    did
}

/// Fold one envelope into session `i`'s message; answer at the boundary.
unsafe fn consume(s: &mut State, i: usize, total: usize) {
    let opcode = ws_frame::opcode(&s.frame_buf);
    let fin = ws_frame::fin(&s.frame_buf) != 0;
    let plen = total - ws_frame::FRAME_HDR;
    // Control frames never reach a worker; anything else is message data.
    let _ = opcode;
    {
        let app = &mut s.apps[i];
        let room = ACC_MAX - app.acc_len as usize;
        let take = plen.min(room);
        app.acc[app.acc_len as usize..app.acc_len as usize + take]
            .copy_from_slice(&s.frame_buf[ws_frame::FRAME_HDR..ws_frame::FRAME_HDR + take]);
        app.acc_len += take as u16;
    }
    s.worker.set_message_open(i, !fin);
    if !fin {
        return;
    }
    let count = s.apps[i].count.wrapping_add(1);
    s.apps[i].count = count;
    let conn = s.worker.sessions[i].conn;
    let mut reply = [0u8; REPLY_MAX];
    let mut p = 0usize;
    reply[..s.tag_len as usize].copy_from_slice(&s.tag[..s.tag_len as usize]);
    p += s.tag_len as usize;
    reply[p] = b':';
    p += 1;
    p += dec(count, &mut reply[p..]);
    reply[p] = b':';
    p += 1;
    let n = s.apps[i].acc_len as usize;
    reply[p..p + n].copy_from_slice(&s.apps[i].acc[..n]);
    p += n;
    s.apps[i].acc_len = 0;

    ws_frame::put_header(&mut s.reply_buf, conn, 0x1, 1, p as u16);
    s.reply_buf[ws_frame::FRAME_HDR..ws_frame::FRAME_HDR + p].copy_from_slice(&reply[..p]);
    let out_total = ws_frame::FRAME_HDR + p;
    let sys = &*s.syscalls;
    if (sys.channel_write)(s.data_out, s.reply_buf.as_ptr(), out_total) > 0 {
        s.worker.on_outbound(i, out_total);
    }
}

/// Decimal render; returns the digits written.
fn dec(mut v: u32, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 10];
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for k in 0..n {
        out[k] = tmp[n - 1 - k];
    }
    n
}

// ── The blob ──────────────────────────────────────────────────────────────

fn serialise(app: &App, blob: &mut [u8; BLOB_MAX]) -> usize {
    blob[..4].copy_from_slice(&BLOB_MAGIC);
    blob[4..8].copy_from_slice(&app.count.to_le_bytes());
    blob[8..10].copy_from_slice(&app.acc_len.to_le_bytes());
    let n = app.acc_len as usize;
    blob[BLOB_HDR..BLOB_HDR + n].copy_from_slice(&app.acc[..n]);
    BLOB_HDR + n
}

fn restore(blob: &[u8], app: &mut App) -> bool {
    if blob.len() < BLOB_HDR || blob[..4] != BLOB_MAGIC {
        return false;
    }
    let count = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    let acc_len = u16::from_le_bytes([blob[8], blob[9]]) as usize;
    if acc_len > ACC_MAX || blob.len() < BLOB_HDR + acc_len {
        return false;
    }
    app.count = count;
    app.acc_len = acc_len as u16;
    app.acc[..acc_len].copy_from_slice(&blob[BLOB_HDR..BLOB_HDR + acc_len]);
    true
}

// ── Telemetry ─────────────────────────────────────────────────────────────

unsafe fn mon(s: &mut State, i: usize, event: u8, reason: &[u8], status: &[u8]) {
    let sys = s.syscalls;
    if s.self_idx == 0xFF {
        let idx = dev_self_index(&*sys);
        if idx >= 0 {
            s.self_idx = idx as u8;
        }
    }
    let sess = &s.worker.sessions[i];
    let sid = sess.session_id;
    let anchor = sess.anchor_id;
    let epoch = sess.epoch;
    let worker_id = s.worker.worker_id;
    let mon_ptr = s.mon_buf.as_mut_ptr();
    let _ = dev_mon_session(
        &*sys,
        s.self_idx,
        event,
        sid.as_ptr(),
        epoch,
        anchor.as_ptr(),
        worker_id.as_ptr(),
        reason,
        status,
        mon_ptr,
        MON_BUF_SIZE,
    );
}

// ── Host-test surface ─────────────────────────────────────────────────────

#[cfg(feature = "host-test")]
/// Envelopes dropped because no session claimed the connection they named.
///
/// # Safety
/// `state` must point to an initialised `State`.
pub unsafe fn test_unclaimed(state: *mut u8) -> u32 {
    (*(state as *const State)).unclaimed
}

#[cfg(feature = "host-test")]
/// `(phase, epoch, count, acc_len)` of the session serving `conn`.
///
/// # Safety
/// `state` must point to an initialised `State`.
pub unsafe fn test_session(state: *mut u8, conn: u32) -> Option<(u8, u32, u32, u16)> {
    let s = &*(state as *const State);
    let i = s.worker.session_for_conn(conn)?;
    let sess = &s.worker.sessions[i];
    Some((
        sess.phase as u8,
        sess.epoch,
        s.apps[i].count,
        s.apps[i].acc_len,
    ))
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
