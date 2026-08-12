//! Echo application for `foundation/http`'s `HANDLER_APP` fan-out.
//!
//! A conformance fixture, not a product module — see `manifest.toml` for why it
//! sits in `modules/fixtures/`. It reads one `HttpRequest` envelope, and writes
//! back an `HttpResponse` whose body reflects what it was handed:
//!
//! ```text
//! method=PUT path=/v2/blobs body=hello world
//! ```
//!
//! That shape is chosen so a shell assertion can read it. An E2E that only
//! checked for HTTP 200 would pass against a gateway that answered by itself
//! and never consulted an application at all; echoing the method, the path and
//! the body proves each of the three crossed the port pair intact.
//!
//! Two behaviours exist for the sake of the tests that need them, both keyed
//! off the request path rather than configuration, so one graph exercises all
//! of it:
//!
//!   * `/status/NNN` answers with status NNN — the gateway must forward an
//!     application's status verbatim, including ones it would never choose.
//!   * `/stream` answers across several envelopes with `MORE_BODY` set, which
//!     is the only way a body larger than the connection's send buffer reaches
//!     the wire.

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

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

const BUF_BYTES: usize = abi::CHANNEL_BUFFER_SIZE;
const REQ_HDR: usize = 12;
const RESP_HDR: usize = 12;
const FLAG_MORE_BODY: u8 = 0x01;

/// `module_step` return code for "did work, step me again".
///
/// The kernel reads a step result as `0 = Continue`, `1 = Done`, `2 = Burst`,
/// `3 = Ready` (`../fluxor/src/kernel/module/loader.rs`). `1` would retire the
/// module for the life of the process after its first answer, so a module that
/// serves many requests reports `Burst`.
const STEP_DID_WORK: i32 = 2;

/// Chunks emitted for `/stream`, and the size of each. 4 x 2 KiB exceeds the
/// http module's `SEND_BUF_SIZE` on every target, which is the point: a
/// single-envelope response could not carry it.
const STREAM_CHUNKS: usize = 4;
const STREAM_CHUNK_BYTES: usize = 2048;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    request_in: i32,
    response_out: i32,
    /// Connection and stream of a `/stream` response still being emitted.
    stream_conn: u16,
    stream_id: u16,
    /// Chunks already emitted for it; `0` when no stream is in flight.
    stream_sent: u8,
    stream_active: u8,
    buf: [u8; BUF_BYTES],
    out: [u8; BUF_BYTES],
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
    // SAFETY: `sys` is non-null (checked above) and points at this instance's
    // kernel syscall table.
    let sys_ref = unsafe { &*sys };
    // SAFETY: `state` was null- and size-checked above; the kernel
    // zero-initialised at least `size_of::<State>()` bytes.
    let s = unsafe { &mut *(state as *mut State) };
    s.syscalls = sys;
    // SAFETY: `dev_channel_port` is a syscall-table wrapper; `sys_ref` outlives
    // the call and each (kind, index) pair is declared in `manifest.toml`.
    s.request_in = unsafe { dev_channel_port(sys_ref, 0, 0) };
    // SAFETY: as above.
    s.response_out = unsafe { dev_channel_port(sys_ref, 1, 0) };
    s.stream_active = 0;
    s.stream_sent = 0;
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
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };

    // A `/stream` response in flight takes priority: its chunks must reach the
    // gateway in order and before any later request is answered, because the
    // gateway correlates them by position within the stream, not by index.
    if s.stream_active != 0 {
        return emit_stream_chunk(s, sys);
    }

    if s.request_in < 0 || s.response_out < 0 {
        return 0;
    }
    // Poll before reading. Not an optimisation: the scheduler parks a module
    // that reports idle and wakes it on channel activity, and the poll is what
    // registers this module's interest in `request_in`. A module that reads
    // blind is never woken again once parked.
    let ready = unsafe { (sys.channel_poll)(s.request_in, POLL_IN) };
    if ready <= 0 || (ready as u32 & POLL_IN) == 0 {
        return 0;
    }
    // SAFETY: `buf` is a fixed array in module state; the read is bounded by
    // its length and the channel is a mailbox, so a short read cannot split an
    // envelope.
    let n = unsafe { (sys.channel_read)(s.request_in, s.buf.as_mut_ptr(), BUF_BYTES) };
    if n < REQ_HDR as i32 {
        return 0;
    }
    let n = n as usize;

    let conn_id = u16::from_le_bytes([s.buf[0], s.buf[1]]);
    let stream_id = u16::from_le_bytes([s.buf[2], s.buf[3]]);
    let method = s.buf[4];
    let path_len = u16::from_le_bytes([s.buf[6], s.buf[7]]) as usize;
    let hdr_len = u16::from_le_bytes([s.buf[8], s.buf[9]]) as usize;
    let body_len = u16::from_le_bytes([s.buf[10], s.buf[11]]) as usize;
    if REQ_HDR + path_len + hdr_len + body_len > n {
        // The envelope claims more than it carries. Dropping it leaves the
        // gateway to time the request out, which is the honest outcome for a
        // malformed contract — answering anyway would hide the break.
        return 0;
    }
    let path_at = REQ_HDR;
    let body_at = REQ_HDR + path_len + hdr_len;

    // `/stream`: begin a multi-envelope response. Matched ANYWHERE in the
    // path, not as a prefix: the route this fixture sits behind is mounted
    // (`/app/`), so the path it receives is `/app/stream` — an application
    // never sees its own mount point stripped, and matching on a prefix would
    // silently fall through to the echo instead.
    if contains(&s.buf[path_at..path_at + path_len], b"/stream") {
        s.stream_conn = conn_id;
        s.stream_id = stream_id;
        s.stream_sent = 0;
        s.stream_active = 1;
        return emit_stream_chunk(s, sys);
    }

    // `/status/NNN`: answer with the status the caller named.
    let status = parse_status(&s.buf[path_at..path_at + path_len]).unwrap_or(200);

    // Layout is header, then content type, then body — in that order, because
    // each is written once at its final offset. Building the body first and
    // shifting it aside for the content type would be the same bytes and one
    // more chance to overlap them.
    const CT: &[u8] = b"text/plain";
    let mut o = RESP_HDR;
    o = s.put(o, CT);
    let body_at_out = o;

    o = s.put(o, b"method=");
    o = s.put(o, method_name(method));
    o = s.put(o, b" path=");
    o = s.copy_in(o, path_at, path_len);
    o = s.put(o, b" body=");
    o = s.copy_in(o, body_at, body_len);
    let body_bytes = o - body_at_out;

    s.write_resp_header(conn_id, stream_id, status, CT.len(), body_bytes, false);
    // SAFETY: `out` is a fixed array in module state; `o` never exceeds
    // `BUF_BYTES` because `put`/`copy_in` both clamp to it.
    unsafe {
        (sys.channel_write)(s.response_out, s.out.as_ptr(), o);
    }
    STEP_DID_WORK
}

/// Emit the next chunk of a `/stream` response. Every chunk but the last
/// carries `MORE_BODY`; the gateway ends the response on the one that does not.
fn emit_stream_chunk(s: &mut State, sys: &SyscallTable) -> i32 {
    let idx = s.stream_sent as usize;
    let last = idx + 1 >= STREAM_CHUNKS;
    // Each chunk is filled with a distinct byte so a test can tell chunk order
    // from the body alone — a reassembly that dropped or reordered one would
    // otherwise look identical to a correct transfer.
    let fill = b'a' + idx as u8;

    // Only the FIRST chunk carries a content type; a continuation is body
    // bytes and nothing else, and re-sending the head mid-body would put a
    // second response inside the first.
    let ct: &[u8] = if idx == 0 {
        b"application/octet-stream"
    } else {
        b""
    };
    let mut o = RESP_HDR;
    o = s.put(o, ct);
    let body_at_out = o;
    let mut i = 0usize;
    while i < STREAM_CHUNK_BYTES && o < BUF_BYTES {
        s.out[o] = fill;
        o += 1;
        i += 1;
    }
    let body_bytes = o - body_at_out;

    let (conn, stream) = (s.stream_conn, s.stream_id);
    s.write_resp_header(conn, stream, 200, ct.len(), body_bytes, !last);

    // SAFETY: as `module_step`'s write — `out` is fixed-size and `o` is clamped.
    let wrote = unsafe { (sys.channel_write)(s.response_out, s.out.as_ptr(), o) };
    if wrote <= 0 {
        // Ring full: keep the stream armed and retry next step rather than
        // dropping a chunk the gateway is waiting for.
        return 0;
    }
    s.stream_sent += 1;
    if last {
        s.stream_active = 0;
        s.stream_sent = 0;
    }
    STEP_DID_WORK
}

impl State {
    /// Stamp the fixed response prefix. Called AFTER the content type and body
    /// are in place, because it needs their measured lengths.
    fn write_resp_header(
        &mut self,
        conn_id: u16,
        stream_id: u16,
        status: u16,
        ct_len: usize,
        body_bytes: usize,
        more: bool,
    ) {
        self.out[0..2].copy_from_slice(&conn_id.to_le_bytes());
        self.out[2..4].copy_from_slice(&stream_id.to_le_bytes());
        self.out[4..6].copy_from_slice(&status.to_le_bytes());
        self.out[6] = if more { FLAG_MORE_BODY } else { 0 };
        self.out[7] = ct_len as u8;
        self.out[8..10].copy_from_slice(&0u16.to_le_bytes()); // no extra headers
        self.out[10..12].copy_from_slice(&(body_bytes as u16).to_le_bytes());
    }

    /// Append `src` to `out` at `off`, clamped to the buffer.
    fn put(&mut self, mut off: usize, src: &[u8]) -> usize {
        let mut i = 0usize;
        while i < src.len() && off < BUF_BYTES {
            self.out[off] = src[i];
            off += 1;
            i += 1;
        }
        off
    }

    /// Copy `len` bytes from the request buffer at `at` into `out` at `off`.
    ///
    /// Indexed rather than sliced: `buf` and `out` are fields of the same
    /// struct, so a shared slice of one and a mutable slice of the other
    /// cannot be held at the same time.
    fn copy_in(&mut self, mut off: usize, at: usize, len: usize) -> usize {
        let mut i = 0usize;
        while i < len && off < BUF_BYTES && at + i < BUF_BYTES {
            self.out[off] = self.buf[at + i];
            off += 1;
            i += 1;
        }
        off
    }
}

/// Offset of `needle` in `hay`, if present.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let mut i = 0usize;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

/// Parse a `/status/NNN` segment, returning the status it names. Found
/// anywhere in the path, for the same reason `/stream` is.
fn parse_status(path: &[u8]) -> Option<u16> {
    const MARK: &[u8] = b"/status/";
    let at = find(path, MARK)?;
    let digits = &path[at + MARK.len()..];
    if digits.is_empty() {
        return None;
    }
    let mut v: u16 = 0;
    for c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((*c - b'0') as u16)?;
    }
    Some(v)
}

/// `wire::method::METHOD_*` → token. Duplicated from the http module rather
/// than shared: a fixture that `include!`d the gateway's own table could not
/// detect the gateway encoding a method wrongly, because both sides would be
/// wrong together.
fn method_name(m: u8) -> &'static [u8] {
    match m {
        1 => b"GET",
        2 => b"CONNECT",
        3 => b"POST",
        4 => b"HEAD",
        5 => b"PUT",
        6 => b"PATCH",
        7 => b"DELETE",
        8 => b"OPTIONS",
        _ => b"NONE",
    }
}
