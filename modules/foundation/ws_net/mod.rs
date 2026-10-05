//! `net_proto` over a server-side WebSocket.
//!
//! A WebSocket route is a place connections arrive, so what sits above one is
//! a `net_proto` provider: the contract `linux_net` implements for TCP and
//! `tls` speaks on its clear side. Modelling it that way is what lets a
//! connection-bearing consumer — `foundation/remote_channel` above all —
//! ride a WebSocket with its session semantics intact. Handed a bare byte
//! stream such a consumer has to assume a session around it, which is the one
//! assumption a carrier binding an authenticated peer must not make.
//!
//! `ws_stream` remains the adapter for consumers that want bytes and nothing
//! more. The difference between the two is not framing but whether
//! connections exist: this module reports when one opens and when it closes.
//!
//! ```text
//! browser → http.ws_out → rx_in  (WsFrame)  → net_out (NetProto) → consumer
//! consumer → net_in (NetProto) → tx_out (WsFrame) → http.ws_in  → browser
//! ```
//!
//! ## Connection ids pass through
//!
//! The `ws_frame` envelope's `conn` is the transport connection id widened to
//! u32, and `http` stamps it from the `MSG_ACCEPTED` its own slot was opened
//! with. An id here is therefore the same id `tls` reported on
//! `peer_identity` for that connection, and a consumer can join the two.
//! Renumbering would break exactly that join, so this module allocates
//! nothing: every id it reports is one it was given.
//!
//! One consequence is worth stating. `http` owns the id space, so the
//! `net_proto` release rule — a transport holds a closed id back from the
//! next accept — is not this module's to enforce. It needs nothing from it:
//! `CMD_CLOSE` for an id no longer live is a no-op, which the contract
//! already allows, and a data frame for an id that is not live is a new
//! connection whatever the id was used for before.
//!
//! ## Dialling
//!
//! There is no outbound side to a served route, so `CMD_CONNECT_TO` is
//! answered `MSG_ERROR` ENOSYS on the requester tag rather than ignored. A
//! provider that silently dropped a dial would leave its consumer waiting out
//! a deadline for a connection nothing had attempted.
//!
//! ## Backpressure
//!
//! Each direction holds at most one frame in flight, and new input is read
//! only once both are clear. A WebSocket payload larger than one `MSG_DATA`
//! may carry ([`net_proto::MAX_DATA_FRAGMENT`]) is emitted across several
//! frames from the same held buffer. Nothing is dropped: a write that cannot
//! land leaves the buffer as it was and the step returns.

#![cfg_attr(not(feature = "host-test"), no_std)]
// PIC library code must not panic; surface errors through the ABI.
#![deny(clippy::unwrap_used)]
#![allow(
    dead_code,
    unused_imports,
    reason = "the SDK is path-mounted into every module, so each compile sees \
              the whole ABI surface while using a subset"
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

// Both envelope layouts come from their contracts rather than being restated:
// the WsFrame header and its u32 conn id from `ws_frame`, the frame header and
// every opcode from `net_proto`.
use abi::contracts::net::{net_proto, ws_frame};
use ws_frame::FRAME_HDR as WS_FRAME_HDR;

// The WebSocket lifecycle record is Wave's own, and `ws_admit` owns it.
#[path = "../../common/ws_admit.rs"]
mod ws_admit;

const FRAME_BUF_BYTES: usize = abi::CHANNEL_BUFFER_SIZE;

/// `module_step` return code for "did work, step me again".
const STEP_DID_WORK: i32 = 2;

const WS_OPCODE_CONTINUATION: u8 = 0x0;
const WS_OPCODE_TEXT: u8 = 0x1;
const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_CLOSE: u8 = 0x8;

/// Connections carried at once. `http`'s own fan-out serves one WebSocket
/// session per route, so this is headroom for a client reconnecting before
/// the close of its predecessor has been seen, not a routing table.
const MAX_CONNS: usize = 8;

/// No connection in this slot. The id space is `http`'s and a real id fits
/// u16, so the all-ones u32 cannot collide with one — and 0 is a valid id.
const NO_CONN: u32 = ws_frame::CONN_UNCLAIMED;

/// `ENOSYS`, as a `net_proto` error byte.
const ERRNO_NOSYS: i8 = -38;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    net_in: i32,
    rx_in: i32,
    event_in: i32,
    net_out: i32,
    tx_out: i32,
    tlm: TlmCounters,
    tlm_last_ms: u64,

    /// The port the consumer bound, echoed on every `MSG_ACCEPTED` so a
    /// multi-anchor consumer can claim its own connections. There is no
    /// socket to bind: the route is the bind, and this is what the consumer
    /// asked it to be called.
    bound_port: u16,
    bound: bool,

    /// Connections seen and not yet closed.
    conns: [u32; MAX_CONNS],

    /// One `net_proto` frame toward the consumer, waiting on `net_out`.
    net_pending: [u8; FRAME_BUF_BYTES],
    net_pending_len: usize,

    /// One `WsFrame` toward `http`, waiting on `tx_out`.
    tx_pending: [u8; FRAME_BUF_BYTES],
    tx_pending_len: usize,

    /// An inbound payload being handed over as `MSG_DATA`, which takes more
    /// than one frame when it is longer than `MAX_DATA_FRAGMENT`.
    data_conn: u32,
    data_buf: [u8; FRAME_BUF_BYTES],
    data_len: usize,
    data_off: usize,

    /// Read scratch for one envelope off either input.
    scratch: [u8; FRAME_BUF_BYTES],
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
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || state_size < core::mem::size_of::<State>() || syscalls.is_null() {
        return -1;
    }
    let sys = syscalls as *const SyscallTable;
    // SAFETY: `sys` is non-null (checked at fn entry) and points at the
    // kernel's syscall table for this module instance.
    let sys_ref = unsafe { &*sys };
    // SAFETY: `state` was null- and size-checked at fn entry; the kernel
    // zero-initialised `state_size >= sizeof::<State>()` bytes.
    let s = unsafe { &mut *(state as *mut State) };
    s.syscalls = sys;
    // SAFETY: `dev_channel_port` is a syscall-table wrapper; `sys_ref`
    // outlives the call and each `(port_kind, port_index)` pair is the one
    // the manifest declares.
    s.net_in = unsafe { dev_channel_port(sys_ref, 0, 0) };
    // SAFETY: as above.
    s.rx_in = unsafe { dev_channel_port(sys_ref, 0, 1) };
    // SAFETY: as above.
    s.event_in = unsafe { dev_channel_port(sys_ref, 0, 2) };
    // SAFETY: as above.
    s.net_out = unsafe { dev_channel_port(sys_ref, 1, 0) };
    // SAFETY: as above.
    s.tx_out = unsafe { dev_channel_port(sys_ref, 1, 1) };
    s.tlm = TlmCounters::new();
    s.tlm_last_ms = 0;
    s.bound_port = 0;
    s.bound = false;
    s.conns = [NO_CONN; MAX_CONNS];
    s.net_pending_len = 0;
    s.tx_pending_len = 0;
    s.data_conn = NO_CONN;
    s.data_len = 0;
    s.data_off = 0;
    0
}

/// Module-scope telemetry: cumulative `bytes_in` / `bytes_out` to the kernel
/// telemetry ring (no-op when no consumer is subscribed), at a ~5s wallclock
/// cadence. Metric ids follow `[observability].metrics` order: 0 = bytes_in,
/// 1 = bytes_out. Counter semantics are monotonic, so nothing is reset here.
#[inline(never)]
fn maybe_emit_telemetry(s: &mut State) {
    // SAFETY: `s.syscalls` was null-checked by `module_step` before this
    // helper runs; the kernel-owned table outlives the call, and every `dev_*`
    // wrapper below is a syscall-table call with no aliasing.
    unsafe {
        let sys = &*s.syscalls;
        if !dev_telemetry_enabled(sys) {
            return;
        }
        let now = dev_millis(sys);
        if now.wrapping_sub(s.tlm_last_ms) < 5000 {
            return;
        }
        s.tlm_last_ms = now;
        let me = dev_self_index(sys);
        if me < 0 {
            return;
        }
        let midx = me as u16;
        let t = dev_micros(sys);
        let counter = abi::contracts::telemetry::METRIC_COUNTER;
        dev_telemetry_metric(sys, -1, midx, t, counter, 0, s.tlm.bytes_in as u64);
        dev_telemetry_metric(sys, -1, midx, t, counter, 1, s.tlm.bytes_out as u64);
    }
}

/// The id a CONSUMER sees, from the one the transport uses.
///
/// `net_proto` carries a connection id in sixteen bits
/// ([`net_proto::CONN_ID_LEN`]) and the `ws_frame` envelope carries thirty-two.
/// The extra half is not padding: with `tls` in front of `http` it holds the
/// session generation, so the id `http` stamps on a frame and the id a consumer
/// can name are DIFFERENT NUMBERS for the same connection.
///
/// So this module keeps the transport's whole id and looks it up by the half a
/// consumer can say. Comparing the two directly is the mistake that hides
/// behind a fallback: on a TLS-fronted chain every outbound frame fails to
/// match, and whatever the fallback resolves to receives it instead.
fn conn_key(conn: u32) -> u32 {
    conn & 0xFFFF
}

/// Is `conn` a connection this module has reported and not yet closed?
fn conn_live(s: &State, conn: u32) -> bool {
    conn_resolve(s, conn).is_some()
}

/// The transport's whole id for the connection a consumer named, which is what
/// an outbound envelope has to carry.
fn conn_resolve(s: &State, conn: u32) -> Option<u32> {
    s.conns
        .iter()
        .copied()
        .find(|c| *c != NO_CONN && conn_key(*c) == conn_key(conn))
}

/// Record `conn` as live. Returns false when every slot is taken, which is a
/// connection this module will not report rather than one it reports wrongly.
fn conn_add(s: &mut State, conn: u32) -> bool {
    if let Some(slot) = s.conns.iter_mut().find(|c| **c == NO_CONN) {
        *slot = conn;
        return true;
    }
    false
}

fn conn_remove(s: &mut State, conn: u32) {
    if let Some(slot) = s
        .conns
        .iter_mut()
        .find(|c| **c != NO_CONN && conn_key(**c) == conn_key(conn))
    {
        *slot = NO_CONN;
    }
}

/// Stage one `net_proto` frame for `net_out`. The caller has checked that
/// `net_pending` is clear.
fn stage_net(s: &mut State, msg: u8, payload: &[u8]) -> bool {
    let total = net_proto::FRAME_HDR + payload.len();
    if total > FRAME_BUF_BYTES {
        return false;
    }
    s.net_pending[0] = msg;
    let Ok(len) = u16::try_from(payload.len()) else {
        return false;
    };
    s.net_pending[1..3].copy_from_slice(&len.to_le_bytes());
    s.net_pending[net_proto::FRAME_HDR..total].copy_from_slice(payload);
    s.net_pending_len = total;
    true
}

/// Stage one `WsFrame` for `tx_out`, addressed to `conn`. The caller has
/// checked that `tx_pending` is clear.
///
/// A frame is staged only for a connection this module currently holds, and a
/// frame for any other id is DROPPED rather than redirected.
///
/// The alternative is [`ws_frame::CONN_UNCLAIMED`], which `http` resolves to
/// whichever fan-out slot is active — and "active" is not "the one this frame
/// is for". A consumer closing the session it has finished with names that
/// connection; resolved against the active slot, the close lands on the
/// connection that replaced it, and a second session dies at the moment the
/// first one is tidied up. The same substitution on a data frame is worse
/// still: it delivers one session's bytes to another.
///
/// Naming the id is always possible here. `http` reports every connection it
/// commits on `ws_event_out`, so a live connection is one this module was told
/// about — and an id it holds nothing for is one with nowhere to send to, which
/// is a no-op and not a reason to pick a different destination.
fn stage_ws(s: &mut State, conn: u32, opcode: u8, payload: &[u8]) -> bool {
    // Resolved rather than taken as given: a consumer names sixteen bits and
    // the envelope carries thirty-two. See [`conn_key`].
    let Some(conn) = conn_resolve(s, conn) else {
        return false;
    };
    let total = WS_FRAME_HDR + payload.len();
    if total > FRAME_BUF_BYTES {
        return false;
    }
    let Ok(len) = u16::try_from(payload.len()) else {
        return false;
    };
    ws_frame::put_header(&mut s.tx_pending, conn, opcode, 1, len);
    s.tx_pending[WS_FRAME_HDR..total].copy_from_slice(payload);
    s.tx_pending_len = total;
    true
}

/// Pull exactly ONE record off `chan` into `scratch`, and return its whole
/// length.
///
/// Two channel kinds reach this module and they need opposite things.
///
/// A FIFO edge is a byte stream. Writes onto it are all-or-nothing, so every
/// record in the ring is whole, but several can be waiting at once and a read
/// sized to the buffer takes as many as happen to be there. A reader that then
/// acts on the first record silently discards whatever followed it, and
/// nothing reports the loss: the producer's write succeeded and the consumer
/// raised no error, so a frame simply never arrives. Reading the fixed header
/// and then exactly the body it declares leaves the remainder for the next
/// step.
///
/// A mailbox edge (an edge given a `buffer_group`) carries one record per
/// buffer and releases it all or not at all, so a read that offers less than
/// the whole record is REFUSED rather than served short. Nothing can be packed
/// behind that record either, so the whole-buffer read is both necessary and
/// sufficient there.
///
/// Which kind a port is depends on how the graph wired it, not on this module,
/// so the kind is discovered rather than assumed: a header-sized read that
/// comes back `EINVAL` is a mailbox saying the record is bigger than the
/// buffer offered.
///
/// `body_len` reads the body's length out of the header, which is the one
/// thing that differs between the three envelopes this module carries.
///
/// # Safety
///
/// `sys` must be a valid syscall table per the module ABI.
unsafe fn read_record(
    sys: &SyscallTable,
    chan: i32,
    scratch: &mut [u8; FRAME_BUF_BYTES],
    hdr_len: usize,
    body_len: fn(&[u8]) -> usize,
) -> Option<usize> {
    // The loop is defence, not the expected path: because FIFO writes are
    // whole and this reader never stops mid-record, the ring always begins at
    // a record boundary, so a header that has started has arrived.
    let mut have = 0usize;
    while have < hdr_len {
        let n = (sys.channel_read)(chan, scratch.as_mut_ptr().add(have), hdr_len - have);
        if n == abi::errno::EINVAL && have == 0 {
            // A mailbox refusing a header-sized read. It releases a record
            // whole or not at all, so nothing has been consumed and the whole
            // buffer can be offered from the start.
            let n = (sys.channel_read)(chan, scratch.as_mut_ptr(), FRAME_BUF_BYTES);
            return if n >= hdr_len as i32 {
                Some(n as usize)
            } else {
                None
            };
        }
        if n <= 0 {
            return None;
        }
        have += n as usize;
    }
    let total = hdr_len + body_len(&scratch[..hdr_len]);
    if total > FRAME_BUF_BYTES {
        // No conforming producer can have written this: the record is larger
        // than the ring that carried it. The header is already consumed, so
        // the stream is off its boundaries — flushing is what puts it back on
        // one, rather than reading a body length out of the next record's
        // header for the rest of the session.
        dev_channel_ioctl(sys, chan, IOCTL_FLUSH, core::ptr::null_mut(), 0);
        return None;
    }
    while have < total {
        let n = (sys.channel_read)(chan, scratch.as_mut_ptr().add(have), total - have);
        if n <= 0 {
            return None;
        }
        have += n as usize;
    }
    Some(total)
}

/// Write a staged buffer to `chan`, clearing it only once it has landed.
///
/// # Safety
///
/// `sys` is the live syscall table and `chan` a port this module owns.
unsafe fn flush(sys: &SyscallTable, chan: i32, buf: &[u8], len: &mut usize) -> bool {
    if *len == 0 {
        return true;
    }
    if chan < 0 {
        // Unwired: nothing can ever take it, so holding the buffer would
        // wedge the direction for good.
        *len = 0;
        return true;
    }
    // A write that cannot land returns non-positive and consumes nothing, so
    // the buffer is left exactly as it was and offered again next step.
    if (sys.channel_write)(chan, buf.as_ptr(), *len) <= 0 {
        return false;
    }
    *len = 0;
    true
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: `state` is non-null (checked above) and `module_new`
    // initialised it; the kernel hands the same instance arena every step.
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return -1;
    }
    // SAFETY: null-checked immediately above; the table outlives the step.
    let sys = unsafe { &*s.syscalls };
    maybe_emit_telemetry(s);
    let mut worked = false;

    // This module and its carrier are a cyclic edge pair, which is what the
    // graphs declare `accept_cycles` for. A module in a cycle must attempt
    // BOTH directions every step and may never return on back-pressure: if a
    // blocked output stopped it reading the input that feeds the other
    // direction, the carrier could not drain its own output either, and the
    // block would be permanent at any tick rate. So each direction is gated
    // on its OWN staged frame and on nothing else.
    //
    // SAFETY: `sys` is live and both ports belong to this module.
    unsafe {
        let (net_out, tx_out) = (s.net_out, s.tx_out);
        let mut len = s.net_pending_len;
        if len > 0 && flush(sys, net_out, &s.net_pending[..len], &mut len) {
            worked = true;
        }
        s.net_pending_len = len;
        let mut len = s.tx_pending_len;
        if len > 0 && flush(sys, tx_out, &s.tx_pending[..len], &mut len) {
            worked = true;
        }
        s.tx_pending_len = len;
    }

    // ── Toward the browser: `net_in` stages onto `tx_out` ───────────────
    //
    // Read whenever the frame it would stage has somewhere to go. Held back
    // only by its own direction, never by `net_out`.
    if s.tx_pending_len == 0 && s.net_in >= 0 {
        // SAFETY: `sys` is live, `scratch` is module state of its own length.
        let got = unsafe {
            read_record(
                sys,
                s.net_in,
                &mut s.scratch,
                net_proto::FRAME_HDR,
                net_proto::payload_len,
            )
        };
        if let Some(n) = got {
            handle_command(s, n);
            worked = true;
        }
    }

    // ── Toward the consumer: the lifecycle, then frames, stage onto
    // `net_out` ─────────────────────────────────────────────────────────
    if s.net_pending_len == 0 && s.data_off < s.data_len {
        // The tail of an inbound payload too long for one `MSG_DATA`.
        let take = (s.data_len - s.data_off).min(net_proto::MAX_DATA_FRAGMENT);
        let mut payload = [0u8; net_proto::CONN_ID_LEN + net_proto::MAX_DATA_FRAGMENT];
        match u16::try_from(s.data_conn & 0xFFFF) {
            Ok(conn) => {
                net_proto::put_conn_id(&mut payload, conn);
                payload[net_proto::CONN_ID_LEN..net_proto::CONN_ID_LEN + take]
                    .copy_from_slice(&s.data_buf[s.data_off..s.data_off + take]);
                if stage_net(
                    s,
                    net_proto::MSG_DATA,
                    &payload[..net_proto::CONN_ID_LEN + take],
                ) {
                    s.data_off += take;
                    s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(take as u32);
                    worked = true;
                }
            }
            // Not an id this wire can carry; the payload goes nowhere.
            Err(_) => s.data_len = 0,
        }
        if s.data_off >= s.data_len {
            s.data_len = 0;
            s.data_off = 0;
        }
    }

    // A lifecycle fact is read before frames, so a connection is reported
    // before anything that arrives on it.
    if s.net_pending_len == 0 && s.data_len == 0 && s.event_in >= 0 {
        // SAFETY: as above.
        let got = unsafe {
            read_record(
                sys,
                s.event_in,
                &mut s.scratch,
                ws_admit::WS_EVENT_HDR,
                ws_admit::ws_event_reason_len,
            )
        };
        if let Some(n) = got {
            handle_ws_event(s, n);
            worked = true;
        }
    }

    if s.net_pending_len == 0 && s.data_len == 0 && s.rx_in >= 0 {
        // SAFETY: as above.
        let got = unsafe {
            read_record(sys, s.rx_in, &mut s.scratch, WS_FRAME_HDR, |h| {
                usize::from(ws_frame::payload_len(h))
            })
        };
        if let Some(n) = got {
            handle_ws_frame(s, n);
            worked = true;
        }
    }

    if worked {
        STEP_DID_WORK
    } else {
        0
    }
}

/// Act on one `net_proto` command the consumer sent.
fn handle_command(s: &mut State, n: usize) {
    let msg = net_proto::msg_type(&s.scratch);
    let len = net_proto::payload_len(&s.scratch);
    if net_proto::FRAME_HDR + len > n {
        return;
    }
    let body_at = net_proto::FRAME_HDR;
    match msg {
        net_proto::CMD_BIND if len >= 2 => {
            let port = u16::from_le_bytes([s.scratch[body_at], s.scratch[body_at + 1]]);
            s.bound_port = port;
            s.bound = true;
            // SAFETY: `s.syscalls` was null-checked by `module_step`.
            unsafe { dev_log(&*s.syscalls, 3, b"[ws_net] bound".as_ptr(), 14) };
            // The route is the bind, so it has already succeeded. `conn_id` on
            // a `MSG_BOUND` names no connection; the port is what the
            // consumer matches its accepts against.
            let mut payload = [0u8; net_proto::CONN_ID_LEN + 2];
            net_proto::put_conn_id(&mut payload, 0);
            payload[net_proto::CONN_ID_LEN..].copy_from_slice(&port.to_le_bytes());
            stage_net(s, net_proto::MSG_BOUND, &payload);
        }
        net_proto::CMD_SEND if len > net_proto::CONN_ID_LEN => {
            let conn = u32::from(net_proto::conn_id(&s.scratch[body_at..]));
            let from = body_at + net_proto::CONN_ID_LEN;
            let to = body_at + len;
            let mut data = [0u8; FRAME_BUF_BYTES];
            let count = to - from;
            if count > FRAME_BUF_BYTES {
                return;
            }
            data[..count].copy_from_slice(&s.scratch[from..to]);
            if stage_ws(s, conn, WS_OPCODE_BINARY, &data[..count]) {
                s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(count as u32);
            }
        }
        net_proto::CMD_CLOSE if len >= net_proto::CONN_ID_LEN => {
            let conn = u32::from(net_proto::conn_id(&s.scratch[body_at..]));
            // Staged BEFORE the connection is forgotten. Forgetting it first
            // leaves `stage_ws` with an id it holds nothing for, and the close
            // then has no addressee — which used to mean it was sent to the
            // active connection instead, so tidying up one session closed its
            // successor. A close for an id already gone is a no-op, which the
            // `net_proto` contract allows.
            stage_ws(s, conn, WS_OPCODE_CLOSE, &[]);
            conn_remove(s, conn);
        }
        net_proto::CMD_CONNECT | net_proto::CMD_CONNECT_TO => {
            // A served route has no outbound side. Answered rather than
            // dropped so a consumer that dials fails at once, on the tag it
            // dialled with, instead of waiting out a deadline.
            let tag = s.scratch.get(body_at + len - 1).copied().unwrap_or(0);
            let mut payload = [0u8; net_proto::CONN_ID_LEN + 2];
            net_proto::put_conn_id(&mut payload, 0);
            payload[net_proto::CONN_ID_LEN] = ERRNO_NOSYS as u8;
            payload[net_proto::CONN_ID_LEN + 1] = tag;
            stage_net(s, net_proto::MSG_ERROR, &payload);
        }
        _ => {}
    }
}

/// Act on one committed WebSocket lifecycle fact from `http`.
fn handle_ws_event(s: &mut State, n: usize) {
    // `ws_admit` owns this record; its parser validates the op byte and the
    // reason length as well as reading the fields.
    let Some(ev) = ws_admit::parse_ws_event(s.scratch.get(..n).unwrap_or(&[])) else {
        return;
    };
    let conn = ev.conn;
    match ev.event {
        ws_admit::WS_EV_OPENED => accept_conn(s, conn),
        ws_admit::WS_EV_CLOSED => close_conn(s, conn),
        _ => {}
    }
}

/// Report `conn` as accepted, if it is not already live.
fn accept_conn(s: &mut State, conn: u32) {
    if conn_live(s, conn) || !conn_add(s, conn) {
        return;
    }
    let Ok(id) = u16::try_from(conn & 0xFFFF) else {
        return;
    };
    // Port-qualified, so a consumer fanned alongside others claims only the
    // connections accepted on its own bind.
    let mut payload = [0u8; net_proto::CONN_ID_LEN + 2];
    net_proto::put_conn_id(&mut payload, id);
    payload[net_proto::CONN_ID_LEN..].copy_from_slice(&s.bound_port.to_le_bytes());
    stage_net(s, net_proto::MSG_ACCEPTED, &payload);
}

/// Report `conn` as closed, if it was live.
fn close_conn(s: &mut State, conn: u32) {
    if !conn_live(s, conn) {
        return;
    }
    conn_remove(s, conn);
    let Ok(id) = u16::try_from(conn & 0xFFFF) else {
        return;
    };
    let mut payload = [0u8; net_proto::CONN_ID_LEN];
    net_proto::put_conn_id(&mut payload, id);
    stage_net(s, net_proto::MSG_CLOSED, &payload);
}

/// Act on one `WsFrame` from `http`.
fn handle_ws_frame(s: &mut State, n: usize) {
    let conn = ws_frame::conn_id(&s.scratch);
    let opcode = ws_frame::opcode(&s.scratch);
    let plen = usize::from(ws_frame::payload_len(&s.scratch));
    if WS_FRAME_HDR + plen > n {
        return;
    }
    match opcode {
        WS_OPCODE_CLOSE => close_conn(s, conn),
        WS_OPCODE_CONTINUATION | WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
            // The lifecycle event is where a connection is normally
            // reported; this covers one whose `opened` was dropped by a full
            // channel, because no frame may be delivered under an id the
            // consumer has not been told about. The accept is staged and the
            // payload held below, so it still arrives — one step later.
            if !conn_live(s, conn) {
                accept_conn(s, conn);
            }
            if plen == 0 {
                return;
            }
            s.data_conn = conn;
            s.data_len = plen;
            s.data_off = 0;
            s.data_buf[..plen].copy_from_slice(&s.scratch[WS_FRAME_HDR..WS_FRAME_HDR + plen]);
        }
        // Ping and pong are the HTTP server's business; tolerated here.
        _ => {}
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
