//! WsFrame ↔ OctetStream adapter.
//!
//! Sits between `foundation/http`'s WebSocket fan-out ports and any
//! transport-agnostic byte-stream carrier (e.g.
//! `foundation/remote_channel`). The adapter strips/adds the 8-byte
//! `WsFrame` header so the byte-stream layer above doesn't have to
//! know about WebSocket framing.
//!
//! Wire layout (matches `modules/foundation/http/server/ws.rs` ::
//! `ws_emit_fanout_frame`):
//!
//! ```text
//! [conn_id  u32 LE]
//! [opcode   u8 ]
//! [fin      u8 ]
//! [payload_len u16 LE]
//! [payload  payload_len bytes]
//! ```
//!
//! Single-connection model: the adapter latches `active_conn_id`
//! from the most recently observed inbound frame and stamps it on
//! outbound frames. A second connection arriving (different
//! `conn_id`) replaces the latch — its bytes flow, the previous
//! connection's outbound queue starves silently. Multi-client session
//! routing is a layer above this; the adapter is a framing
//! conversion, nothing more.
//!
//! Opcode handling:
//!   - 0x0 continuation, 0x1 text, 0x2 binary → payload forwarded to
//!     `rx_out` as raw bytes (OctetStream consumers don't care which).
//!   - 0x8 close, 0x9 ping, 0xA pong → silently dropped. The http
//!     module handles ping/close at the WS layer; the adapter
//!     tolerates them defensively if any leak through.
//!
//! Outbound frames are always opcode = 0x2 (binary) with fin = 1.
//!
//! ## Same-tick coalescing
//!
//! `rx_in` is a byte-FIFO: a single `channel_read` can return several
//! whole WsFrames concatenated (e.g. two requests written back-to-back
//! within one graph tick). The inbound loop walks a cursor over the
//! whole read buffer and emits every complete frame, so no sibling
//! frame is dropped. (WsFrame writes upstream are atomic, so the buffer
//! contains whole frames; a partial trailing frame is not expected.)
//!
//! ## Backpressure (lossless under steady-state)
//!
//! Both directions own a per-instance retry buffer. The inbound
//! retry holds an in-flight WsFrame's payload that didn't fit in
//! `rx_out`; the outbound retry holds a framed message that
//! didn't fit in `tx_out`. Drained first on the next step before
//! pulling new input. When `rx_out` back-pressures mid-buffer, the
//! remaining whole frames from that read are carried at the front of
//! `scratch` (`rx_scratch_len`) until the retry buffer drains. No bytes
//! are dropped under back-pressure; upstream channel back-pressure
//! applies normally if the retry buffer is held full for a sustained
//! period.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unsafe_code,
    reason = "PIC module: ABI shim and zero-copy buffer plumbing"
)]
// PIC library code must not panic; surface errors through the ABI.
#![deny(clippy::unwrap_used)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

const WS_FRAME_HDR: usize = 8;
const FRAME_BUF_BYTES: usize = abi::CHANNEL_BUFFER_SIZE;
const WS_OPCODE_BINARY: u8 = 0x2;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    tx_in: i32,
    tx_out: i32,
    rx_in: i32,
    rx_out: i32,
    /// Cumulative module-scope byte counters + last-emit wallclock (cadence
    /// gated on `dev_millis` since this adapter has no per-step counter).
    tlm: TlmCounters,
    tlm_last_ms: u64,
    active_conn_id: u32,
    has_conn: bool,
    /// Outbound retry buffer: a fully-framed WsFrame waiting to be
    /// written to `tx_out`. `tx_pending_len == 0` means the buffer
    /// is drained and a new TX read may proceed.
    tx_pending: [u8; FRAME_BUF_BYTES],
    tx_pending_len: usize,
    /// Inbound retry buffer: a WsFrame's payload waiting to be
    /// written to `rx_out`. Same drain-first semantics.
    rx_pending: [u8; FRAME_BUF_BYTES],
    rx_pending_len: usize,
    /// Inbound parse scratch: holds the raw WsFrame bytes as read from
    /// `rx_in`. A single `channel_read` on a byte-FIFO can return
    /// several whole WsFrames concatenated, so the inbound loop parses
    /// every complete frame in the buffer (not just the first).
    scratch: [u8; FRAME_BUF_BYTES],
    /// Count of unparsed whole-frame bytes retained at the FRONT of
    /// `scratch` across steps. Non-zero only when `rx_out` back-pressured
    /// mid-buffer: the current frame's payload tail parks in `rx_pending`
    /// and the following whole frames stay here until `rx_pending` drains.
    /// Always whole frames (frame writes are atomic), never a split tail.
    rx_scratch_len: usize,
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
    // outlives the call and `(port_kind, port_index)` is a valid pair.
    s.tx_in = unsafe { dev_channel_port(sys_ref, 0, 0) };
    // SAFETY: as above; in/out parity covers all four ports.
    s.rx_in = unsafe { dev_channel_port(sys_ref, 0, 1) };
    // SAFETY: as above.
    s.tx_out = unsafe { dev_channel_port(sys_ref, 1, 0) };
    // SAFETY: as above.
    s.rx_out = unsafe { dev_channel_port(sys_ref, 1, 1) };
    s.tlm = TlmCounters::new();
    s.tlm_last_ms = 0;
    // `u32::MAX` is the "unclaimed" sentinel: stamped on outbound
    // envelopes when no inbound frame has arrived yet. The HTTP
    // server's `ws_drain_fanout_input` recognises this sentinel and
    // delivers to the first ws-fan-out slot rather than routing by
    // a default-0 conn_id (which would collide with whatever
    // connection happens to occupy slot 0). Real conn_ids fit in
    // u8 (0..255), so u32::MAX is unambiguously distinguishable.
    s.active_conn_id = u32::MAX;
    s.has_conn = false;
    s.tx_pending = [0u8; FRAME_BUF_BYTES];
    s.tx_pending_len = 0;
    s.rx_pending = [0u8; FRAME_BUF_BYTES];
    s.rx_pending_len = 0;
    s.scratch = [0u8; FRAME_BUF_BYTES];
    s.rx_scratch_len = 0;
    0
}

/// Module-scope telemetry: emit cumulative `bytes_in` / `bytes_out` counters to
/// the kernel telemetry ring (no-op when no consumer is subscribed), at a ~5s
/// wallclock cadence. Metric ids follow `[observability].metrics` order:
/// 0 = bytes_in, 1 = bytes_out. Counter semantics are monotonic, so the deltas
/// are NOT reset here.
#[inline(never)]
fn maybe_emit_telemetry(s: &mut State) {
    // SAFETY: `s.syscalls` was null-checked by the caller (module_step) before
    // this helper runs; the kernel-owned table outlives the call. All the
    // `dev_*` wrappers below are syscall-table calls with no aliasing.
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

/// Shift-compact the leading `consumed` bytes out of `buf[..len]`.
unsafe fn shift_consume(buf: *mut u8, len: usize, consumed: usize) -> usize {
    if consumed == 0 || consumed > len {
        return len;
    }
    let remaining = len - consumed;
    if remaining > 0 {
        core::ptr::copy(buf.add(consumed), buf, remaining);
    }
    remaining
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: `state` non-null (checked above); `module_new` initialised
    // it as `State`. Scheduler serialises module_step so re-borrow unique.
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return -1;
    }
    // SAFETY: `s.syscalls` non-null (checked above); the kernel-owned
    // table outlives this step.
    let sys = unsafe { &*s.syscalls };

    // Module-scope metrics: cumulative byte counters, ~5s cadence, no-op when
    // the telemetry port is unwired.
    maybe_emit_telemetry(s);

    // ── Inbound: rx_in (WsFrame) → rx_out (OctetStream) ──
    if s.rx_in >= 0 && s.rx_out >= 0 {
        // Drain the pending retry buffer first.
        if s.rx_pending_len > 0 {
            // SAFETY: `channel_write` is a syscall taking (chan, *const u8,
            // len); `s.rx_pending_len <= s.rx_pending.len()` by invariant.
            let written =
                unsafe { (sys.channel_write)(s.rx_out, s.rx_pending.as_ptr(), s.rx_pending_len) };
            if written > 0 {
                let w = (written as usize).min(s.rx_pending_len);
                s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(w as u32);
                // SAFETY: `shift_consume` is unsafe over a raw pointer + len;
                // `s.rx_pending` is owned by `s` so the pointer is valid for
                // the whole buffer length.
                s.rx_pending_len =
                    unsafe { shift_consume(s.rx_pending.as_mut_ptr(), s.rx_pending_len, w) };
            }
        }
        // Pull new frames only when the retry buffer is drained. Each
        // `channel_read` may return several whole WsFrames concatenated
        // (byte-FIFO transport), so a cursor walks `scratch[..n]` and
        // emits every complete frame — parsing only the first would drop
        // any same-read siblings.
        while s.rx_pending_len == 0 {
            // Reuse whole frames carried over from a prior back-pressured
            // step (already at the front of `scratch`), else read fresh.
            let n = if s.rx_scratch_len > 0 {
                let carried = s.rx_scratch_len;
                s.rx_scratch_len = 0;
                carried
            } else {
                // SAFETY: `channel_read` takes (chan, *mut u8, max_len); the
                // scratch buffer is owned by `s` and sized to its array length.
                let read =
                    unsafe { (sys.channel_read)(s.rx_in, s.scratch.as_mut_ptr(), s.scratch.len()) };
                if read < WS_FRAME_HDR as i32 {
                    break;
                }
                read as usize
            };

            let mut off = 0usize;
            // `true` once back-pressure parked a frame; stops the outer
            // read loop so `rx_pending` (and any carried siblings) drain
            // on following steps before more bytes are pulled from `rx_in`.
            let mut parked = false;
            while off + WS_FRAME_HDR <= n {
                let conn_id = u32::from_le_bytes([
                    s.scratch[off],
                    s.scratch[off + 1],
                    s.scratch[off + 2],
                    s.scratch[off + 3],
                ]);
                let opcode = s.scratch[off + 4];
                let _fin = s.scratch[off + 5];
                let payload_len =
                    u16::from_le_bytes([s.scratch[off + 6], s.scratch[off + 7]]) as usize;
                if off + WS_FRAME_HDR + payload_len > n {
                    // Incomplete trailing frame. Frame writes upstream are
                    // atomic and the read buffer spans the whole channel,
                    // so this is not expected; drop the tail rather than
                    // carry a split frame.
                    break;
                }
                if s.has_conn && conn_id != s.active_conn_id {
                    // Latch replacement: a new connection takes over the
                    // adapter. Anything still queued outbound belongs to the
                    // dead session — the documented contract is that the
                    // previous connection's queue starves. Without this, the
                    // outbound drain below stamps the old session's bytes with
                    // the NEW conn_id, leaking one session's data into another
                    // (observed live: a stale reply delivered as the first
                    // frame of a fresh surface connection).
                    s.tx_pending_len = 0;
                    s.rx_pending_len = 0;
                    s.rx_scratch_len = 0;
                    if s.tx_in >= 0 {
                        // Drain tx_in dry into the (now idle) tx_pending buffer
                        // and discard: bytes the app wrote before seeing any
                        // input from the new session are addressed to the old
                        // one. `scratch` still holds the new connection's
                        // frames, so it must not be used as the bit-bucket here.
                        loop {
                            // SAFETY: `channel_read` into the owned tx_pending
                            // buffer; `tx_pending_len` is 0 so its contents are
                            // dead and the next outbound read rewrites them.
                            let d = unsafe {
                                (sys.channel_read)(
                                    s.tx_in,
                                    s.tx_pending.as_mut_ptr(),
                                    s.tx_pending.len(),
                                )
                            };
                            if d <= 0 {
                                break;
                            }
                        }
                    }
                }
                s.active_conn_id = conn_id;
                s.has_conn = true;

                let is_data = matches!(opcode, 0x0 | 0x1 | WS_OPCODE_BINARY);
                if !is_data || payload_len == 0 {
                    off += WS_FRAME_HDR + payload_len;
                    continue;
                }
                // Try to write this frame's payload directly.
                // SAFETY: `off + WS_FRAME_HDR + payload_len <= n <=
                // s.scratch.len()` checked above; pointer offset stays in-bounds.
                let written = unsafe {
                    (sys.channel_write)(
                        s.rx_out,
                        s.scratch.as_ptr().add(off + WS_FRAME_HDR),
                        payload_len,
                    )
                };
                // CHAN_EAGAIN (negative return) is back-pressure, not an error.
                // The payload was already pulled from rx_in, so treat any
                // non-positive return as a 0-byte partial write and stash the
                // tail in `rx_pending` rather than dropping bytes.
                let w = if written > 0 {
                    (written as usize).min(payload_len)
                } else {
                    0
                };
                s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(w as u32);
                if w < payload_len {
                    // Stash this frame's unwritten payload tail for the next
                    // step's drain.
                    let tail = payload_len - w;
                    let take = tail.min(s.rx_pending.len());
                    // SAFETY: `take <= rx_pending.len()` and `off + WS_FRAME_HDR
                    // + w + take <= n`; src/dst are disjoint buffers in `s`.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            s.scratch.as_ptr().add(off + WS_FRAME_HDR + w),
                            s.rx_pending.as_mut_ptr(),
                            take,
                        );
                    }
                    s.rx_pending_len = take;
                    // Carry the following whole frames (if any) to the front of
                    // `scratch` so they survive while `rx_pending` drains.
                    let next_off = off + WS_FRAME_HDR + payload_len;
                    if next_off < n {
                        let carry = n - next_off;
                        // SAFETY: overlapping move within `scratch`; `copy`
                        // (memmove) handles overlap. Ranges are in-bounds:
                        // `next_off + carry == n <= scratch.len()`.
                        unsafe {
                            core::ptr::copy(
                                s.scratch.as_ptr().add(next_off),
                                s.scratch.as_mut_ptr(),
                                carry,
                            );
                        }
                        s.rx_scratch_len = carry;
                    }
                    parked = true;
                    break;
                }
                off += WS_FRAME_HDR + payload_len;
            }
            if parked {
                break;
            }
        }
    }

    // ── Outbound: tx_in (OctetStream) → tx_out (WsFrame) ──
    //
    // No `has_conn` gate: producer-first bundles push data outbound
    // before the browser sends anything inbound. Until we observe
    // an inbound frame, `active_conn_id` carries the `u32::MAX`
    // sentinel and the HTTP server's `ws_drain_fanout_input`
    // delivers those envelopes to the first ws-fan-out slot rather
    // than routing by a real id (0 would alias slot 0, which is
    // typically the IP listener and never a fan-out target).
    if s.tx_in >= 0 && s.tx_out >= 0 {
        // Drain the pending framed message first.
        if s.tx_pending_len > 0 {
            // SAFETY: `channel_write` over `s.tx_pending[..tx_pending_len]`;
            // length is an invariant of the retry buffer.
            let written =
                unsafe { (sys.channel_write)(s.tx_out, s.tx_pending.as_ptr(), s.tx_pending_len) };
            if written > 0 {
                let w = (written as usize).min(s.tx_pending_len);
                s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(w as u32);
                // SAFETY: `shift_consume` over an owned buffer pointer; `w`
                // is the just-confirmed write count.
                s.tx_pending_len =
                    unsafe { shift_consume(s.tx_pending.as_mut_ptr(), s.tx_pending_len, w) };
            }
        }
        // Pull new input only when pending drained. Cap per-step reads at
        // 4096 so each WS BINARY envelope handed to the http server fits
        // in a single fast-path send_buf slot (SEND_BUF_SIZE = 4100 in
        // `../fluxor/modules/sdk/abi/config.rs` accommodates a 4096-byte payload + the
        // 4-byte server-to-client WS header). Allowing larger payloads
        // works on a quiescent network but drops chunks under sustained
        // load — we measured ~2 KiB lost per ~10 ms emit interval at
        // 192 kbps audio rates because the http server's send_buf
        // couldn't atomically queue the full envelope.
        let max_payload = (FRAME_BUF_BYTES - WS_FRAME_HDR).min(4096);
        while s.tx_pending_len == 0 {
            // SAFETY: `WS_FRAME_HDR + max_payload <= FRAME_BUF_BYTES`
            // (max_payload = `(FRAME_BUF_BYTES - WS_FRAME_HDR).min(4096)`);
            // pointer offset stays inside `s.tx_pending`.
            let n = unsafe {
                (sys.channel_read)(
                    s.tx_in,
                    s.tx_pending.as_mut_ptr().add(WS_FRAME_HDR),
                    max_payload,
                )
            };
            if n <= 0 {
                break;
            }
            let payload_len = n as usize;
            let conn_le = s.active_conn_id.to_le_bytes();
            s.tx_pending[0] = conn_le[0];
            s.tx_pending[1] = conn_le[1];
            s.tx_pending[2] = conn_le[2];
            s.tx_pending[3] = conn_le[3];
            s.tx_pending[4] = WS_OPCODE_BINARY;
            s.tx_pending[5] = 1;
            let plen_le = (payload_len as u16).to_le_bytes();
            s.tx_pending[6] = plen_le[0];
            s.tx_pending[7] = plen_le[1];
            let total = WS_FRAME_HDR + payload_len;
            // Try direct write first.
            // SAFETY: `total = WS_FRAME_HDR + payload_len`; `payload_len`
            // was just written into `tx_pending` by the channel_read above.
            let written = unsafe { (sys.channel_write)(s.tx_out, s.tx_pending.as_ptr(), total) };
            if written < 0 {
                // tx_out back-pressured. Stash the whole frame and
                // break — looping back to read more from tx_in would
                // shred the stream.
                s.tx_pending_len = total;
                break;
            }
            let w = (written as usize).min(total);
            s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(w as u32);
            if w < total {
                // Hold tail; tx_pending_len remembers what's left.
                // SAFETY: `shift_consume` over owned buffer; `total` is the
                // exact pending byte count.
                s.tx_pending_len = unsafe { shift_consume(s.tx_pending.as_mut_ptr(), total, w) };
                break;
            }
            // Fully sent; loop reads more.
        }
    }

    0
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
