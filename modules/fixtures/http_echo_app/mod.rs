//! Echo application for `foundation/http`'s `HANDLER_APP` fan-out.
//!
//! A conformance fixture, not a product module — see `manifest.toml` for why it
//! sits in `modules/fixtures/`. It answers each exchange with a body that
//! reflects what it was handed:
//!
//! ```text
//! method=PUT path=/v2/blobs body=hello world bytes=11
//! ```
//!
//! That shape is chosen so a shell assertion can read it. An E2E that only
//! checked for HTTP 200 would pass against a gateway that answered by itself
//! and never consulted an application at all; echoing the method, the path and
//! the body proves each of the three crossed the port pair intact. `body=`
//! carries the body's first `ECHO_MAX` bytes and `bytes=` its whole length, so
//! a body of any size streamed across many records is accounted for.
//!
//! Two behaviours exist for the sake of the tests that need them, both keyed
//! off the request path rather than configuration, so one graph exercises all
//! of it:
//!
//!   * `/status/NNN` answers with status NNN — the gateway must forward an
//!     application's status verbatim, including ones it would never choose.
//!   * `/stream` answers across several records with `MORE` set, paced by the
//!     response credit the gateway grants, which is the only way a body larger
//!     than the connection's send buffer reaches the wire.

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

#[path = "../../common/http_app.rs"]
mod http_app;
use http_app::{
    app_flag, app_parse_request, app_write_body, app_write_credit, app_write_response_head, AppId,
    AppRecord, AppResponseHead, APP_RECORD_MAX,
};

/// `module_step` return code for "did work, step me again".
///
/// The kernel reads a step result as `0 = Continue`, `1 = Done`, `2 = Burst`,
/// `3 = Ready` (`../fluxor/src/kernel/module/loader.rs`). `1` would retire the
/// module for the life of the process after its first answer, so a module that
/// serves many requests reports `Burst`.
const STEP_DID_WORK: i32 = 2;

/// Exchanges answered at once. The gateway may open many; one past this waits
/// in the channel until an answer frees a place.
const EXCHANGES: usize = 4;

/// Body bytes echoed back; the rest are counted.
const ECHO_MAX: usize = 1024;

/// Longest path echoed back.
const PATH_MAX: usize = 256;

/// Request-body credit granted at once: everything the request will send.
/// The fixture consumes as it reads, so it has no reason to hold a body back.
const BODY_CREDIT: u32 = 1 << 30;

/// Chunks emitted for `/stream`, and the size of each. 4 x 2 KiB exceeds the
/// http module's `SEND_BUF_SIZE` on every target, which is the point: a
/// single-record response could not carry it.
const STREAM_CHUNKS: u8 = 4;
const STREAM_CHUNK_BYTES: usize = 2048;

#[derive(Clone, Copy)]
struct Exchange {
    used: bool,
    id: AppId,
    method: u8,
    path: [u8; PATH_MAX],
    path_len: usize,
    body: [u8; ECHO_MAX],
    body_len: usize,
    total: u64,
    req_done: bool,
    /// Response-body bytes the gateway still accepts.
    resp_credit: u32,
    /// The body credit grant still owes its way to the gateway.
    credit_owed: bool,
    /// `/stream` chunks sent; `STREAM_CHUNKS` once the response is whole.
    stream_sent: u8,
    streaming: bool,
}

const IDLE: Exchange = Exchange {
    used: false,
    id: AppId {
        origin: 0,
        conn: 0,
        stream: 0,
    },
    method: 0,
    path: [0; PATH_MAX],
    path_len: 0,
    body: [0; ECHO_MAX],
    body_len: 0,
    total: 0,
    req_done: false,
    resp_credit: 0,
    credit_owed: false,
    stream_sent: 0,
    streaming: false,
};

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    request_in: i32,
    response_out: i32,
    /// A record read from `request_in` and not yet taken — no place was free.
    held: bool,
    held_len: usize,
    ex: [Exchange; EXCHANGES],
    buf: [u8; APP_RECORD_MAX],
    out: [u8; APP_RECORD_MAX],
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
    s.held = false;
    s.ex = [IDLE; EXCHANGES];
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
    if s.syscalls.is_null() || s.request_in < 0 || s.response_out < 0 {
        return 0;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    let mut worked = false;

    // Owed writes first: credit grants and answers, each retried until the
    // gateway's channel takes it.
    for i in 0..EXCHANGES {
        worked |= s.advance(sys, i);
    }

    // Then one record in. Poll before reading: the poll is what registers
    // this module's interest in `request_in`, and a module that reads blind is
    // never woken again once parked.
    if !s.held {
        // SAFETY: a syscall-table call on a channel this module owns.
        let ready = unsafe { (sys.channel_poll)(s.request_in, POLL_IN) };
        if ready > 0 && (ready as u32 & POLL_IN) != 0 {
            // SAFETY: `buf` is a fixed array in module state and the read is
            // bounded by its length; the channel is a mailbox, so one read is
            // one whole record.
            let n = unsafe { (sys.channel_read)(s.request_in, s.buf.as_mut_ptr(), APP_RECORD_MAX) };
            if n > 0 {
                s.held = true;
                s.held_len = n as usize;
            }
        }
    }
    if s.held && s.take(sys) {
        s.held = false;
        worked = true;
    }
    if worked {
        STEP_DID_WORK
    } else {
        0
    }
}

impl State {
    /// Take the held record. False when it needs a place none is free for.
    fn take(&mut self, sys: &SyscallTable) -> bool {
        let mut touched = None;
        let raw = &self.buf[..self.held_len];
        let Some(rec) = app_parse_request(raw) else {
            // A record that does not parse is dropped: the gateway's own
            // deadline answers the exchange, which is the honest outcome for
            // a broken contract.
            return true;
        };
        match rec {
            AppRecord::Head(h) => {
                let Some(i) = self.ex.iter().position(|e| !e.used) else {
                    return false;
                };
                let mut e = IDLE;
                e.used = true;
                e.id = h.id;
                e.method = h.method;
                e.path_len = h.target.len().min(PATH_MAX);
                e.path[..e.path_len].copy_from_slice(&h.target[..e.path_len]);
                e.req_done = h.flags & app_flag::MORE == 0;
                e.resp_credit = h.resp_credit;
                e.credit_owed = !e.req_done;
                e.streaming = contains(&e.path[..e.path_len], b"/stream");
                self.ex[i] = e;
                touched = Some(i);
            }
            AppRecord::Body { id, flags, data } => {
                if let Some(i) = self.find(&id) {
                    let e = &mut self.ex[i];
                    let room = ECHO_MAX - e.body_len;
                    let n = data.len().min(room);
                    e.body[e.body_len..e.body_len + n].copy_from_slice(&data[..n]);
                    e.body_len += n;
                    e.total += data.len() as u64;
                    e.req_done = flags & app_flag::MORE == 0;
                    touched = Some(i);
                }
            }
            AppRecord::Credit { id, bytes } => {
                if let Some(i) = self.find(&id) {
                    let e = &mut self.ex[i];
                    e.resp_credit = e.resp_credit.saturating_add(bytes);
                    touched = Some(i);
                }
            }
            AppRecord::Abort { id, .. } => {
                if let Some(i) = self.find(&id) {
                    self.ex[i] = IDLE;
                }
            }
            AppRecord::Datagram { .. } => {}
        }
        if let Some(i) = touched {
            self.advance(sys, i);
        }
        true
    }

    fn find(&self, id: &AppId) -> Option<usize> {
        self.ex.iter().position(|e| e.used && e.id == *id)
    }

    /// Do what exchange `i` owes, as far as the gateway's channel takes it.
    fn advance(&mut self, sys: &SyscallTable, i: usize) -> bool {
        if !self.ex[i].used {
            return false;
        }
        let mut worked = false;
        if self.ex[i].credit_owed {
            let n = app_write_credit(&self.ex[i].id, BODY_CREDIT, &mut self.out).unwrap_or(0);
            if !self.write(sys, n) {
                return false;
            }
            self.ex[i].credit_owed = false;
            worked = true;
        }
        if !self.ex[i].req_done {
            return worked;
        }
        if self.ex[i].streaming {
            while self.ex[i].stream_sent < STREAM_CHUNKS {
                if !self.stream_chunk(sys, i) {
                    return worked;
                }
                worked = true;
            }
            self.ex[i] = IDLE;
            return true;
        }
        if self.answer(sys, i) {
            self.ex[i] = IDLE;
            worked = true;
        }
        worked
    }

    /// Answer exchange `i` whole. False when the channel refused it.
    fn answer(&mut self, sys: &SyscallTable, i: usize) -> bool {
        let e = &self.ex[i];
        let status = parse_status(&e.path[..e.path_len]).unwrap_or(200);
        let mut body = [0u8; ECHO_MAX + PATH_MAX + 64];
        let mut o = 0usize;
        o = put(&mut body, o, b"method=");
        o = put(&mut body, o, method_name(e.method));
        o = put(&mut body, o, b" path=");
        o = put(&mut body, o, &e.path[..e.path_len]);
        o = put(&mut body, o, b" body=");
        o = put(&mut body, o, &e.body[..e.body_len]);
        o = put(&mut body, o, b" bytes=");
        let mut digits = [0u8; 20];
        let dn = decimal(e.total, &mut digits);
        o = put(&mut body, o, &digits[..dn]);
        let head = AppResponseHead {
            id: e.id,
            flags: 0,
            status,
            content_type: b"text/plain",
            headers: &[],
            body: &body[..o],
        };
        let n = app_write_response_head(&head, &mut self.out).unwrap_or(0);
        self.write(sys, n)
    }

    /// Emit the next `/stream` chunk when the gateway has credit for it. Each
    /// chunk is filled with a distinct byte so a test can tell chunk order
    /// from the body alone — a reassembly that dropped or reordered one would
    /// otherwise look identical to a correct transfer.
    fn stream_chunk(&mut self, sys: &SyscallTable, i: usize) -> bool {
        let e = self.ex[i];
        if (e.resp_credit as usize) < STREAM_CHUNK_BYTES {
            return false;
        }
        let fill = b'a' + e.stream_sent;
        let chunk = [fill; STREAM_CHUNK_BYTES];
        let last = e.stream_sent + 1 >= STREAM_CHUNKS;
        let flags = if last { 0 } else { app_flag::MORE };
        let n = if e.stream_sent == 0 {
            // The first record is the head; it carries the content type and
            // the first chunk.
            let head = AppResponseHead {
                id: e.id,
                flags,
                status: 200,
                content_type: b"application/octet-stream",
                headers: &[],
                body: &chunk,
            };
            app_write_response_head(&head, &mut self.out).unwrap_or(0)
        } else {
            app_write_body(&e.id, flags, &chunk, &mut self.out).unwrap_or(0)
        };
        if !self.write(sys, n) {
            return false;
        }
        let e = &mut self.ex[i];
        e.resp_credit -= STREAM_CHUNK_BYTES as u32;
        e.stream_sent += 1;
        true
    }

    /// Write the first `n` bytes of `out` as one record.
    fn write(&mut self, sys: &SyscallTable, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        // SAFETY: `out` is a fixed array in module state and `n` is bounded
        // by the encoder that filled it.
        unsafe { (sys.channel_write)(self.response_out, self.out.as_ptr(), n) > 0 }
    }
}

/// Append `src` at `off`, clamped to the buffer.
fn put(dst: &mut [u8], off: usize, src: &[u8]) -> usize {
    let n = src.len().min(dst.len() - off);
    dst[off..off + n].copy_from_slice(&src[..n]);
    off + n
}

/// `v` in decimal into `out`; its length.
fn decimal(mut v: u64, out: &mut [u8; 20]) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
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

/// Whether `needle` occurs in `hay`. Matched anywhere in the path, not as a
/// prefix: the route this fixture sits behind is mounted (`/app/`), so the
/// path it receives is `/app/stream` — an application never sees its own
/// mount point stripped.
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

/// Every token this fixture knows, end to end. Written independently of the
/// http module's own literal rather than shared: a fixture that `include!`d
/// the gateway's table could not detect the gateway encoding a method
/// wrongly, because both sides would be wrong together.
const TOKENS: &[u8] = b"GETCONNECTPOSTHEADPUTPATCHDELETEOPTIONSNONE";

/// `(offset, length)` into [`TOKENS`] per `wire::method::METHOD_*` value,
/// indexed by the value. Index 0 and anything past the table read as `NONE`.
const TOKEN_SPAN: [(u8, u8); 9] = [
    (39, 4), // METHOD_NONE
    (0, 3),  // GET
    (3, 7),  // CONNECT
    (10, 4), // POST
    (14, 4), // HEAD
    (18, 3), // PUT
    (21, 5), // PATCH
    (26, 6), // DELETE
    (32, 7), // OPTIONS
];

/// `wire::method::METHOD_*` → token.
///
/// Spans of one literal rather than a match returning eight different
/// `&'static [u8]`, for the reason the http module's own table states: that
/// match compiles to a table of pointers the flat `.fmod` image has no way to
/// relocate (`tools/ci/fmod_pic_relocs.sh`).
fn method_name(m: u8) -> &'static [u8] {
    let (off, len) = match TOKEN_SPAN.get(m as usize) {
        Some(&(off, len)) => (off as usize, len as usize),
        None => (39, 4),
    };
    match TOKENS.get(off..off + len) {
        Some(tok) => tok,
        None => &[],
    }
}
