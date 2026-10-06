//! Relay between `foundation/http`'s application fan-out and the `s3`
//! connector.
//!
//! A conformance fixture, not a product module — see `manifest.toml` for why it
//! sits in `modules/fixtures/`. Both sides speak the exchange contract: toward
//! `http` the relay is a provider (`request_in` / `response_out`), toward the
//! connector a requester (`request_out` / `response_in`), and the exchange id
//! `http` chose is the one the connector echoes. So every record passes
//! through unchanged but one: a request HEAD loses the header
//! lines that belong to the inbound connection (`host`, its framing, its
//! `expect`, any signature of its own) and its peer, because the connector
//! writes those for the request it signs and refuses a caller that sends them.
//!
//! That is the whole of it. A client of the graph speaks plain HTTP to `http`
//! and is answered by whatever S3 endpoint the connector dials, which lets an
//! end-to-end test drive the connector with real requests of any size.

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

use abi::contracts::exchange::{
    kind, parse_request, write_request_head, Record, RequestHead, RECORD_MAX,
};

/// `module_step` return code for "did work, step me again".
const STEP_DID_WORK: i32 = 2;

/// Records moved per direction per step.
const RECORDS_PER_STEP: usize = 8;

/// One direction: where it reads, where it writes, and the record read but
/// not yet taken by the far side.
#[repr(C)]
struct Lane {
    from: i32,
    to: i32,
    held_len: usize,
    buf: [u8; RECORD_MAX],
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    /// `http` → connector.
    up: Lane,
    /// Connector → `http`.
    down: Lane,
    /// A rewritten request HEAD, and the header lines it keeps.
    scratch: Scratch,
}

#[repr(C)]
struct Scratch {
    record: [u8; RECORD_MAX],
    kept: [u8; RECORD_MAX],
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
    // SAFETY: `dev_channel_port` is a syscall-table wrapper; each (kind,
    // index) pair is declared in `manifest.toml`, inputs then outputs.
    unsafe {
        s.up.from = dev_channel_port(sys_ref, 0, 0);
        s.down.from = dev_channel_port(sys_ref, 0, 1);
        s.down.to = dev_channel_port(sys_ref, 1, 0);
        s.up.to = dev_channel_port(sys_ref, 1, 1);
    }
    s.up.held_len = 0;
    s.down.held_len = 0;
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
        return 0;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    let mut worked = false;
    for _ in 0..RECORDS_PER_STEP {
        let a = pump(sys, &mut s.up, &mut s.scratch, true);
        let b = pump(sys, &mut s.down, &mut s.scratch, false);
        if !(a || b) {
            break;
        }
        worked = true;
    }
    if worked {
        STEP_DID_WORK
    } else {
        0
    }
}

/// Move one record along `lane`: deliver the held one, or read the next.
/// Request HEADs going up are rewritten on the way. True when a record moved.
fn pump(sys: &SyscallTable, lane: &mut Lane, scratch: &mut Scratch, up: bool) -> bool {
    if lane.from < 0 || lane.to < 0 {
        return false;
    }
    if lane.held_len == 0 {
        // SAFETY: a syscall-table call on a channel this module owns. The
        // poll is what registers interest, so a parked module is woken.
        let ready = unsafe { (sys.channel_poll)(lane.from, POLL_IN) };
        if ready <= 0 || (ready as u32 & POLL_IN) == 0 {
            return false;
        }
        // SAFETY: `buf` is a fixed array in module state and the read is
        // bounded by its length; the channel is a mailbox, so one read is one
        // whole record.
        let n = unsafe { (sys.channel_read)(lane.from, lane.buf.as_mut_ptr(), RECORD_MAX) };
        if n <= 0 {
            return false;
        }
        lane.held_len = n as usize;
        if up && lane.buf[0] == kind::HEAD {
            lane.held_len = strip_head(&lane.buf[..lane.held_len], scratch);
            lane.buf[..lane.held_len].copy_from_slice(&scratch.record[..lane.held_len]);
        }
    }
    if lane.held_len == 0 {
        // A HEAD that did not parse is dropped; `http`'s own deadline
        // answers the exchange.
        return true;
    }
    // The poll registers write interest, which is what wakes this module when
    // the destination drains. Writing without it and reporting no work parks
    // the module holding the record, with nothing left to wake it: the record
    // never moves, the connector cannot hand over the next one, and a
    // response stalls mid-body until a deadline closes the connection.
    //
    // SAFETY: syscalls on channels this module owns; `buf` holds `held_len`
    // bytes of one record.
    let w = unsafe {
        let ready = (sys.channel_poll)(lane.to, POLL_OUT);
        if ready <= 0 || (ready as u32 & POLL_OUT) == 0 {
            return false;
        }
        (sys.channel_write)(lane.to, lane.buf.as_ptr(), lane.held_len)
    };
    if w <= 0 {
        return false;
    }
    lane.held_len = 0;
    true
}

/// Re-encode a request HEAD into `scratch.record` without the inbound
/// connection's own header lines and peer. Its length, 0 when it does not
/// parse.
fn strip_head(rec: &[u8], scratch: &mut Scratch) -> usize {
    let Some(Record::Head(h)) = parse_request(rec) else {
        return 0;
    };
    let mut n = 0usize;
    let mut rest = h.headers;
    while !rest.is_empty() {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .map_or(rest.len(), |e| e + 2);
        let line = &rest[..end];
        rest = &rest[end..];
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        if inbound_only(&line[..colon]) {
            continue;
        }
        scratch.kept[n..n + line.len()].copy_from_slice(line);
        n += line.len();
    }
    // The body the HEAD carried rides on with it: the HEAD only got shorter.
    let head = RequestHead {
        id: h.id,
        flags: h.flags,
        method: h.method,
        target: h.target,
        headers: &scratch.kept[..n],
        peer: &[],
        resp_credit: h.resp_credit,
        body: h.body,
    };
    write_request_head(&head, &mut scratch.record).unwrap_or(0)
}

/// A header that describes the inbound connection or its own signature, which
/// the connector writes afresh for the request it sends.
fn inbound_only(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"authorization")
        || name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"content-encoding")
        || name.eq_ignore_ascii_case(b"expect")
        || name.eq_ignore_ascii_case(b"te")
        || name.eq_ignore_ascii_case(b"upgrade")
        || (name.len() > 6 && name[..6].eq_ignore_ascii_case(b"x-amz-"))
}
