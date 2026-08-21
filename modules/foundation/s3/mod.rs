//! S3 connector — a GENUINE per-protocol Fluxor foundation module that makes a
//! point the others don't: even a STATELESS request/reply protocol needs a
//! compiled module when each request must be cryptographically SIGNED. S3 GET is
//! one round trip, but it carries an `Authorization: AWS4-HMAC-SHA256 …` header
//! whose signature is HMAC-SHA256 over a canonical form of the request. It is not
//! a multi-round-trip that forces a module here — it is the crypto, which a
//! bytecode codec cannot compute.
//!
//! Two modes, chosen by whether `request_in` is wired:
//!
//! **Driven** (`request_in` wired) — the connector performs one S3 operation per
//! `S3Request` record and answers with an `S3Response`: GET / PUT / HEAD /
//! DELETE on `/bucket/key`, each signed with the payload hashed in. This is what
//! lets a graph store what it computes — a pipeline that terminates HTTP on one
//! side and blobs on the other needs a connector it can ASK, not one configured
//! with a single request at build time.
//!
//! **Probe** (`request_in` unwired) — the original behaviour, unchanged: on boot
//! it signs a `GET /` (ListBuckets) and reports the HTTP status (200 = signature
//! accepted; 403 = SignatureDoesNotMatch). A probe graph is this mode,
//! and it stays the cheapest way to prove credentials against a real endpoint.
//!
//! Protocol + crypto in the host-tested `s3_core.rs`; the record layouts in
//! `s3_wire.rs`, with vectors in the consumer's host tests.
//!
//! Ports:  net_in/net_out (transport), status_out (HTTP status),
//!         request_in (S3Request), response_out (S3Response).
//! Params: `endpoint` (hex `[ip:4][port:2 LE]`), `host` (the Host header, e.g.
//!         "127.0.0.1:19000"), `access_key`, `secret`, `region`.

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
              signature is fixed by that contract rather than chosen here. Same allow as \
              the other Wave protocol modules carry."
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

include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../common/s3_core.rs");
include!("../../common/hex_core.rs");

#[path = "../../common/s3_wire.rs"]
mod s3_wire;
use s3_wire::*;

const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;

const NET_BUF: usize = 2048;
/// Signed request staging. Sized to hold the largest signed PUT: the head is a
/// few hundred bytes of SigV4, the rest is payload.
const REQ_BUF: usize = 20 * 1024;
const ACC_BUF: usize = 20 * 1024;
/// Largest object body this connector carries in one request, in or out.
///
/// Bounded because both directions stage through fixed state-owned arrays. A
/// registry layer larger than this needs the chunked form the HTTP fan-out uses
/// (a `MORE_BODY` flag across several records), which is a separate change —
/// what exists here is refused explicitly rather than truncated.
const MAX_OBJECT_BYTES: usize = 16 * 1024;
const NAME_BUF: usize = 128;
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const REPLY_TIMEOUT_MS: u64 = 15_000;

const DISCONNECTED: u8 = 0;
const CONNECTING: u8 = 1;
const AWAIT_RESPONSE: u8 = 2;
const DONE: u8 = 3;

#[repr(C)]
struct S3State {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    status_out: i32,

    ip: [u8; 4],
    port: u16,
    ep_hex: [u8; 16],
    ep_hex_len: u16,
    host: [u8; NAME_BUF],
    host_len: u16,
    access_key: [u8; NAME_BUF],
    access_key_len: u16,
    secret: [u8; NAME_BUF],
    secret_len: u16,
    region: [u8; NAME_BUF],
    region_len: u16,

    phase: u8,
    conn_id: u16,
    /// 1 once `MSG_CONNECTED` established a connection, 0 otherwise. Tracks
    /// connection PRESENCE separately from `conn_id`'s value because the net
    /// stack can legitimately assign `conn_id == 0`; keying "connected" off
    /// `conn_id != 0` would skip the close on every connection that happened
    /// to land in slot 0, leaking a transport slot per failure. Same split the
    /// HTTP client carries for the same reason.
    conn_present: u8,
    tag: u8,
    started_ms: u64,
    draining: u8,

    // ── Driven mode ────────────────────────────────────────────────
    /// Channel handles; `-1` when unwired. `request_in < 0` selects probe mode.
    request_in: i32,
    response_out: i32,
    /// The request being performed: op and correlation id are needed when the
    /// response comes back, long after the record was consumed.
    cur_op: u8,
    cur_cid: u32,
    /// 1 while a driven request is in flight, so the boot probe cannot fire and
    /// a second record is not consumed until this one is answered. Cleared only
    /// once the answering `S3Response` has been accepted by `response_out`, so
    /// an admitted request is never displaced by the next one before its own
    /// terminal outcome has left the module.
    busy: u8,
    /// Staging for inbound `S3Request` records. One `channel_read` on the byte
    /// FIFO can return several whole records, so this holds all of them and the
    /// one being performed stays at the front.
    rec: [u8; REQ_BUF],
    /// Valid bytes in `rec`.
    rec_len: u32,
    /// Length of the record at the front of `rec` that is in flight. Its bytes
    /// are retired only after it has been answered.
    rec_taken: u32,
    /// The encoded `S3Response` awaiting `response_out`. `resp_len == 0` means
    /// nothing is owed. A full output channel parks the record here rather than
    /// discarding it: the request was admitted, so the answer is owed until it
    /// is delivered.
    resp: [u8; REQ_BUF],
    resp_len: u32,

    req: [u8; REQ_BUF],
    req_len: u16,
    req_sent: u16,
    acc: [u8; ACC_BUF],
    acc_len: u32,

    nbuf: [u8; NET_BUF],
    ok: u32,
    errors: u32,
    /// Conservation counters for driven mode. `admitted` counts `S3Request`
    /// records taken off `request_in` and understood; `terminated` counts the
    /// `S3Response` records delivered for them. `admitted == terminated` holds
    /// whenever nothing is in flight. `dropped_unparsable` counts records whose
    /// own header could not be trusted — there is no correlation id to answer
    /// on, so they are never admitted and never owed a response.
    admitted: u32,
    terminated: u32,
    dropped_unparsable: u32,
}

/// Driven-mode conservation snapshot: the admission and terminal-outcome
/// counts, plus whether work is still owed.
#[cfg(feature = "host-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct S3Conservation {
    pub admitted: u32,
    pub terminated: u32,
    pub dropped_unparsable: u32,
    /// 1 while an admitted request has not yet had its response delivered.
    pub in_flight: u8,
    /// 1 while an encoded response is parked waiting for `response_out`.
    pub response_owed: u8,
}

/// # Safety
/// `state` must point to an `S3State` initialised by `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_conservation(state: *mut u8) -> S3Conservation {
    let s = &*(state as *const S3State);
    S3Conservation {
        admitted: s.admitted,
        terminated: s.terminated,
        dropped_unparsable: s.dropped_unparsable,
        in_flight: s.busy,
        response_owed: u8::from(s.resp_len != 0),
    }
}

define_params! {
    S3State;

    1, endpoint, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.ep_hex_len as usize) < 16 {
            s.ep_hex[s.ep_hex_len as usize] = *d.add(i); s.ep_hex_len += 1; i += 1;
        }
    };
    2, host, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.host_len as usize) < NAME_BUF {
            s.host[s.host_len as usize] = *d.add(i); s.host_len += 1; i += 1;
        }
    };
    3, access_key, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.access_key_len as usize) < NAME_BUF {
            s.access_key[s.access_key_len as usize] = *d.add(i); s.access_key_len += 1; i += 1;
        }
    };
    4, secret, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.secret_len as usize) < NAME_BUF {
            s.secret[s.secret_len as usize] = *d.add(i); s.secret_len += 1; i += 1;
        }
    };
    5, region, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.region_len as usize) < NAME_BUF {
            s.region[s.region_len as usize] = *d.add(i); s.region_len += 1; i += 1;
        }
    };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<S3State>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut S3State)).draining = 1;
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
        if state_size < core::mem::size_of::<S3State>() {
            return -2;
        }
        let s = &mut *(state as *mut S3State);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.status_out = dev_channel_port(sys, 1, 1);
        // in[1] / out[2]: the driven-mode pair. Unwired (`-1`) selects the boot
        // probe, so `examples/s3_client/` keeps working untouched.
        s.request_in = dev_channel_port(sys, 0, 1);
        s.response_out = dev_channel_port(sys, 1, 2);
        s.ip = [0u8; 4];
        s.port = 0;
        s.ep_hex_len = 0;
        s.host_len = 0;
        s.access_key_len = 0;
        s.secret_len = 0;
        s.region_len = 0;
        s.phase = DISCONNECTED;
        s.conn_id = 0;
        s.conn_present = 0;
        s.tag = dev_requester_tag(sys);
        s.started_ms = 0;
        s.draining = 0;
        s.req_len = 0;
        s.req_sent = 0;
        s.acc_len = 0;
        s.ok = 0;
        s.errors = 0;
        s.busy = 0;
        s.rec_len = 0;
        s.rec_taken = 0;
        s.resp_len = 0;
        s.admitted = 0;
        s.terminated = 0;
        s.dropped_unparsable = 0;
        parse_tlv(s, params, params_len);
        let mut ep = [0u8; 8];
        if let Some(n) = hex_decode(&s.ep_hex[..s.ep_hex_len as usize], &mut ep) {
            if n >= 6 {
                s.ip = [ep[0], ep[1], ep[2], ep[3]];
                s.port = u16::from_le_bytes([ep[4], ep[5]]);
            }
        }
        // default region
        if s.region_len == 0 {
            s.region[..9].copy_from_slice(b"us-east-1");
            s.region_len = 9;
        }
        dev_log(sys, 3, b"[s3] init".as_ptr(), 9);
        0
    }
}

unsafe fn emit_status(s: &mut S3State, text: &[u8]) {
    let sys = &*s.syscalls;
    if s.status_out >= 0 {
        let poll = (sys.channel_poll)(s.status_out, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            (sys.channel_write)(s.status_out, text.as_ptr(), text.len());
        }
    }
}

/// Abandon the transport. A driven request that was in flight is answered with
/// `status` before the connector goes idle: the record was admitted, so it is
/// owed exactly one outcome whether or not the endpoint ever replied.
unsafe fn fail_driven(s: &mut S3State, status: u16) {
    if s.busy != 0 {
        let sys = &*s.syscalls;
        if s.conn_present != 0 {
            let close = s.conn_id.to_le_bytes();
            net_write_frame(
                sys,
                s.net_out,
                NET_CMD_CLOSE,
                close.as_ptr(),
                2,
                s.nbuf.as_mut_ptr(),
                NET_BUF,
            );
        }
        emit_response(s, status, 0, 0);
        return;
    }
    fail(s);
}

unsafe fn fail(s: &mut S3State) {
    let sys = &*s.syscalls;
    if s.conn_present != 0 {
        let close = s.conn_id.to_le_bytes();
        net_write_frame(
            sys,
            s.net_out,
            NET_CMD_CLOSE,
            close.as_ptr(),
            2,
            s.nbuf.as_mut_ptr(),
            NET_BUF,
        );
    }
    s.conn_id = 0;
    s.conn_present = 0;
    s.errors = s.errors.wrapping_add(1);
    s.phase = DONE;
}

// ── Driven mode ───────────────────────────────────────────────────────────

/// Take one `S3Request` off `request_in` and begin it, if this connector is
/// idle. One at a time: the transport is a single connection and SigV4 signs a
/// specific request, so overlapping two would interleave their bytes on the
/// wire.
///
/// `request_in` is a byte FIFO, so one `channel_read` can return several whole
/// records back to back. The buffer therefore holds everything that read
/// returned, the record being performed stays at the front of it (SigV4 signs
/// out of `rec` long after the read), and its bytes are retired only once it
/// has been answered. Reading again before the buffer is empty would discard
/// records a caller has already handed over.
unsafe fn pump_request(s: &mut S3State, now: u64) {
    if s.busy != 0 || s.phase != DISCONNECTED || s.draining != 0 {
        return;
    }
    let sys = &*s.syscalls;
    // Retire the record just answered, exposing whatever arrived behind it.
    if s.rec_taken > 0 {
        let taken = (s.rec_taken as usize).min(s.rec_len as usize);
        let remaining = s.rec_len as usize - taken;
        if remaining > 0 {
            core::ptr::copy(s.rec.as_ptr().add(taken), s.rec.as_mut_ptr(), remaining);
        }
        s.rec_len = remaining as u32;
        s.rec_taken = 0;
    }
    if s.rec_len == 0 {
        let poll = (sys.channel_poll)(s.request_in, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            return;
        }
        let n = (sys.channel_read)(s.request_in, s.rec.as_mut_ptr(), REQ_BUF);
        if n <= 0 {
            return;
        }
        s.rec_len = n as u32;
    }
    let n = s.rec_len as usize;

    let view = match parse_s3_request(&s.rec[..n]) {
        Some(v) => v,
        // A record shorter than the lengths it declares. There is no cid to
        // answer on — the header itself is what could not be trusted — so it is
        // dropped, exactly as the HTTP fan-out drops a truncated envelope. It
        // is counted rather than admitted: no response is owed for it. The rest
        // of the buffer goes with it: without a trustworthy header there is no
        // record boundary to resume from.
        None => {
            // The counter is host-test surface; the log is what a running
            // deployment gets, and silence is otherwise the only other signal.
            let m = b"[s3] unparsable S3Request - dropped, no cid to answer on";
            dev_log(&*s.syscalls, 2, m.as_ptr(), m.len());
            s.dropped_unparsable = s.dropped_unparsable.wrapping_add(1);
            s.rec_len = 0;
            return;
        }
    };
    // The body is the last field, so its end is the record's end.
    s.rec_taken = (view.body_at + view.body_len) as u32;
    s.admitted = s.admitted.wrapping_add(1);
    // In flight from the moment the record is understood, so a refusal below
    // that back-pressures on `response_out` still blocks the next admission.
    s.busy = 1;
    s.cur_op = view.op;
    s.cur_cid = view.cid;

    if !s3_op_is_known(view.op) {
        // Well-formed, unsupported. Answered rather than dropped, so the caller
        // learns its request was refused instead of waiting out a timeout.
        emit_response(s, 501, 0, 0);
        return;
    }
    if view.body_len > MAX_OBJECT_BYTES {
        // 413: the object exceeds what one record can carry. Explicit, because
        // a truncated PUT would store bytes that are not the object and whose
        // digest would not match.
        emit_response(s, 413, 0, 0);
        return;
    }

    // Build `/bucket/key` and the signed request into `req`, then connect. The
    // signature covers the current wall-clock time, so it is built here rather
    // than at connect time only because the payload is already in hand — the
    // timestamp is re-taken on connect below.
    s.acc_len = 0;
    s.req_len = 0;
    s.req_sent = 0;
    s.phase = CONNECTING;
    s.started_ms = now;

    let mut payload = [0u8; 8];
    payload[0] = SOCK_TYPE_STREAM;
    payload[1] = s.ip[3];
    payload[2] = s.ip[2];
    payload[3] = s.ip[1];
    payload[4] = s.ip[0];
    let port = s.port.to_le_bytes();
    payload[5] = port[0];
    payload[6] = port[1];
    payload[7] = s.tag;
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_CONNECT,
        payload.as_ptr(),
        8,
        s.nbuf.as_mut_ptr(),
        NET_BUF,
    );
}

/// Sign the pending driven request. Split from `pump_request` because SigV4
/// binds the timestamp, and the request must be signed when the connection is
/// UP rather than when it was queued — a signature minted before a slow connect
/// can age past the endpoint's skew window.
unsafe fn sign_pending(s: &mut S3State) -> bool {
    let sys = &*s.syscalls;
    let view = match parse_s3_request(&s.rec[..REQ_BUF]) {
        Some(v) => v,
        None => return false,
    };
    let mut ts = [0u8; 16];
    let mut date = [0u8; 8];
    sigv4_time(dev_unix_millis(sys), &mut ts, &mut date);

    let mut path = [0u8; 512];
    let plen = match s3_object_path(
        &s.rec[view.bucket_at..view.bucket_at + view.bucket_len],
        &s.rec[view.key_at..view.key_at + view.key_len],
        &mut path,
    ) {
        Some(n) => n,
        None => return false,
    };

    // The cores take slices, and `s.rec` is borrowed for the payload while
    // `s.req` is written — distinct fields, so the copies below are only to
    // satisfy the borrow checker on the credential arrays.
    let hl = s.host_len as usize;
    let al = s.access_key_len as usize;
    let sl = s.secret_len as usize;
    let rl = s.region_len as usize;
    let mut host = [0u8; NAME_BUF];
    host[..hl].copy_from_slice(&s.host[..hl]);
    let mut ak = [0u8; NAME_BUF];
    ak[..al].copy_from_slice(&s.access_key[..al]);
    let mut sk = [0u8; NAME_BUF];
    sk[..sl].copy_from_slice(&s.secret[..sl]);
    let mut rg = [0u8; NAME_BUF];
    rg[..rl].copy_from_slice(&s.region[..rl]);

    let mut payload = [0u8; MAX_OBJECT_BYTES];
    let blen = view.body_len.min(MAX_OBJECT_BYTES);
    if blen > 0 {
        payload[..blen].copy_from_slice(&s.rec[view.body_at..view.body_at + blen]);
    }

    let mut out = [0u8; REQ_BUF];
    let n = s3_sign_request(
        s3_op_method(s.cur_op),
        &ak[..al],
        &sk[..sl],
        &rg[..rl],
        &host[..hl],
        &path[..plen],
        &payload[..blen],
        &ts,
        &date,
        &mut out,
    );
    match n {
        Some(n) => {
            s.req[..n].copy_from_slice(&out[..n]);
            s.req_len = n as u16;
            s.req_sent = 0;
            true
        }
        None => false,
    }
}

/// Emit an `S3Response` for the request in flight, and go idle.
///
/// `body_at`/`body_len` name a span inside `acc` (the accumulated HTTP
/// response); `0,0` means no body, which is every op but GET and every failure.
unsafe fn emit_response(s: &mut S3State, status: u16, body_at: usize, body_len: usize) {
    if s.response_out >= 0 {
        let len = body_len
            .min(MAX_OBJECT_BYTES)
            .min(REQ_BUF - S3_RESP_BODY_AT);
        // Encode into the state-owned parking buffer rather than a local: the
        // record must survive a back-pressured `response_out` across steps, and
        // at REQ_BUF it has no business on the stack either way. Not cleared
        // first — `write_s3_response` fills the header and the body span is
        // copied below, so every byte under `resp_len` is written here.
        if len > 0 {
            s.resp[S3_RESP_BODY_AT..S3_RESP_BODY_AT + len]
                .copy_from_slice(&s.acc[body_at..body_at + len]);
        }
        s.resp_len = match write_s3_response(s.cur_op, s.cur_cid, status, len, &mut s.resp) {
            Some(total) => total as u32,
            None => 0,
        };
    }
    if (200..400).contains(&status) {
        s.ok = s.ok.wrapping_add(1);
    } else {
        s.errors = s.errors.wrapping_add(1);
    }
    // `busy` stays set while a response is parked, so `pump_request` cannot
    // admit the next record over the top of an undelivered answer. Nothing is
    // parked when `response_out` is unwired — no consumer asked for an answer,
    // so the request finishes here — nor when the record could not be encoded,
    // which the body caps above make unreachable.
    if s.resp_len == 0 {
        s.busy = 0;
        s.terminated = s.terminated.wrapping_add(1);
    }
    s.cur_op = 0;
    s.cur_cid = 0;
    s.acc_len = 0;
    s.req_len = 0;
    s.req_sent = 0;
    // Back to DISCONNECTED rather than DONE: DONE is the probe's terminal
    // state, and a driven connector must be ready for the next request.
    s.phase = DISCONNECTED;
    s.conn_id = 0;
    s.conn_present = 0;
}

/// Hand the parked `S3Response` to `response_out`, retrying on a later step
/// while the channel refuses it. The channel takes a record whole or not at
/// all, so a rejected write leaves the record intact and nothing is owed twice.
unsafe fn flush_response(s: &mut S3State) {
    if s.resp_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.response_out, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let written = (sys.channel_write)(s.response_out, s.resp.as_ptr(), s.resp_len as usize);
    if written <= 0 {
        return;
    }
    s.resp_len = 0;
    s.busy = 0;
    s.terminated = s.terminated.wrapping_add(1);
}

/// Complete a driven request from the accumulated HTTP response.
unsafe fn finish_driven(s: &mut S3State) {
    let acc_len = s.acc_len as usize;
    let status = http_status_code(&s.acc[..acc_len]).unwrap_or(0);
    // Only GET returns bytes; a body after a HEAD would desynchronise the
    // caller exactly as it would on the server side.
    let (at, len) = if s3_op_expects_body(s.cur_op) && (200..300).contains(&status) {
        match http_body_offset(&s.acc[..acc_len]) {
            Some(at) => (at, acc_len - at),
            None => (0, 0),
        }
    } else {
        (0, 0)
    };
    emit_response(s, status, at, len);
}

/// Emit the response's HTTP status ("s3: <code>\n").
unsafe fn finish_response(s: &mut S3State) {
    match http_status_code(&s.acc[..s.acc_len as usize]) {
        Some(code) => {
            let mut out = [b's', b'3', b':', b' ', 0, 0, 0, b'\n'];
            out[4] = b'0' + ((code / 100) % 10) as u8;
            out[5] = b'0' + ((code / 10) % 10) as u8;
            out[6] = b'0' + (code % 10) as u8;
            emit_status(s, &out);
            s.ok = s.ok.wrapping_add(1);
        }
        None => emit_status(s, b"s3: (no status)\n"),
    }
    s.phase = DONE;
    s.conn_id = 0;
    s.conn_present = 0;
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut S3State);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // Driven mode: take the next request, if any, and start it. Checked
        // before the probe so a wired connector never fires the boot GET.
        if s.request_in >= 0 {
            pump_request(s, now);
        }

        // Connect on boot (one-shot: a signed GET / on connect). PROBE MODE
        // ONLY — `request_in >= 0` means a caller decides what to request, and
        // an unasked-for ListBuckets would answer a record nobody sent.
        if s.request_in < 0 && s.phase == DISCONNECTED && s.draining == 0 && s.access_key_len > 0 {
            let mut payload = [0u8; 8];
            payload[0] = SOCK_TYPE_STREAM;
            payload[1] = s.ip[3];
            payload[2] = s.ip[2];
            payload[3] = s.ip[1];
            payload[4] = s.ip[0];
            let port = s.port.to_le_bytes();
            payload[5] = port[0];
            payload[6] = port[1];
            payload[7] = s.tag;
            net_write_frame(
                sys,
                s.net_out,
                NET_CMD_CONNECT,
                payload.as_ptr(),
                8,
                s.nbuf.as_mut_ptr(),
                NET_BUF,
            );
            s.phase = CONNECTING;
            s.started_ms = now;
        }

        if s.net_in >= 0 {
            loop {
                let poll = (sys.channel_poll)(s.net_in, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 {
                    break;
                }
                let (msg, plen) = net_read_frame(sys, s.net_in, s.nbuf.as_mut_ptr(), NET_BUF);
                if msg == 0 {
                    break;
                }
                let payload = s.nbuf.as_ptr().add(NET_FRAME_HDR);
                match msg {
                    NET_MSG_CONNECTED if s.phase == CONNECTING => {
                        if plen >= 3 && *payload.add(2) == s.tag {
                            s.conn_id = u16::from_le_bytes([*payload, *payload.add(1)]);
                            s.conn_present = 1;
                            if s.busy != 0 {
                                // Driven: sign the caller's request now the
                                // connection is up, so the timestamp SigV4
                                // binds is current rather than aged by a slow
                                // connect.
                                if sign_pending(s) {
                                    s.acc_len = 0;
                                    s.phase = AWAIT_RESPONSE;
                                    s.started_ms = now;
                                } else {
                                    // Could not build the request at all —
                                    // a path or buffer bound. 500 names this
                                    // connector as the failing party.
                                    let close = s.conn_id.to_le_bytes();
                                    net_write_frame(
                                        sys,
                                        s.net_out,
                                        NET_CMD_CLOSE,
                                        close.as_ptr(),
                                        2,
                                        s.nbuf.as_mut_ptr(),
                                        NET_BUF,
                                    );
                                    emit_response(s, 500, 0, 0);
                                }
                                continue;
                            }
                            // Build the signed GET / with the current WALL-CLOCK time.
                            // SigV4 needs Unix-epoch time (dev_unix_millis), not the
                            // monotonic uptime `dev_millis` used for timeouts — a
                            // 1970-relative stamp would be rejected RequestTimeTooSkewed.
                            let mut ts = [0u8; 16];
                            let mut date = [0u8; 8];
                            sigv4_time(dev_unix_millis(sys), &mut ts, &mut date);
                            let hl = s.host_len as usize;
                            let al = s.access_key_len as usize;
                            let sl = s.secret_len as usize;
                            let rl = s.region_len as usize;
                            let mut host = [0u8; NAME_BUF];
                            host[..hl].copy_from_slice(&s.host[..hl]);
                            let mut ak = [0u8; NAME_BUF];
                            ak[..al].copy_from_slice(&s.access_key[..al]);
                            let mut sk = [0u8; NAME_BUF];
                            sk[..sl].copy_from_slice(&s.secret[..sl]);
                            let mut rg = [0u8; NAME_BUF];
                            rg[..rl].copy_from_slice(&s.region[..rl]);
                            let mut out = [0u8; REQ_BUF];
                            if let Some(n) = s3_sign_get(
                                &ak[..al],
                                &sk[..sl],
                                &rg[..rl],
                                &host[..hl],
                                b"/",
                                &ts,
                                &date,
                                &mut out,
                            ) {
                                s.req[..n].copy_from_slice(&out[..n]);
                                s.req_len = n as u16;
                                s.req_sent = 0;
                                s.acc_len = 0;
                                s.phase = AWAIT_RESPONSE;
                                s.started_ms = now;
                            } else {
                                fail(s);
                            }
                        }
                    }
                    NET_MSG_DATA if s.phase == AWAIT_RESPONSE => {
                        if plen > 2 && u16::from_le_bytes([*payload, *payload.add(1)]) == s.conn_id
                        {
                            let data_len = plen - 2;
                            let space = ACC_BUF - s.acc_len as usize;
                            let take = if data_len < space { data_len } else { space };
                            core::ptr::copy_nonoverlapping(
                                payload.add(2),
                                s.acc.as_mut_ptr().add(s.acc_len as usize),
                                take,
                            );
                            s.acc_len += take as u32;
                        }
                    }
                    NET_MSG_CLOSED if s.phase == AWAIT_RESPONSE => {
                        // Connection: close — the response is complete.
                        if plen >= 2 && u16::from_le_bytes([*payload, *payload.add(1)]) == s.conn_id
                        {
                            if s.busy != 0 {
                                finish_driven(s);
                            } else {
                                finish_response(s);
                            }
                        }
                    }
                    NET_MSG_ERROR => {
                        // `[conn_id u16][errno i8][requester_tag u8]` — the tag
                        // sits at offset 3, past the widened conn_id. A
                        // connect-phase failure is matched on the TAG ALONE:
                        // the contract states its `conn_id` is meaningless
                        // (0 when the dial failed before a slot was allocated,
                        // which is indistinguishable from a valid id 0). The
                        // established-connection clause is therefore gated on
                        // `conn_present`, or a peer's failed dial carrying
                        // conn_id 0 would be claimed by this module while its
                        // own `conn_id` is still zero-initialised.
                        let ours = (s.phase == CONNECTING && plen >= 4 && *payload.add(3) == s.tag)
                            || (s.conn_present != 0
                                && plen >= 2
                                && u16::from_le_bytes([*payload, *payload.add(1)]) == s.conn_id);
                        if ours {
                            if s.phase == AWAIT_RESPONSE && s.acc_len > 0 {
                                if s.busy != 0 {
                                    finish_driven(s);
                                } else {
                                    finish_response(s);
                                }
                            } else {
                                // 502: the transport failed, so the endpoint
                                // never got to answer for itself.
                                fail_driven(s, 502);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Send pump.
        if s.conn_present != 0 && s.req_sent < s.req_len {
            let max_chunk = NET_BUF - NET_FRAME_HDR - 1;
            while s.req_sent < s.req_len {
                let poll = (sys.channel_poll)(s.net_out, 0x02);
                if poll <= 0 || (poll as u32 & 0x02) == 0 {
                    break;
                }
                let remaining = (s.req_len - s.req_sent) as usize;
                let chunk = if remaining < max_chunk {
                    remaining
                } else {
                    max_chunk
                };
                let total_payload = chunk + 2;
                let cb = s.conn_id.to_le_bytes();
                s.nbuf[0] = NET_CMD_SEND;
                s.nbuf[1] = (total_payload & 0xff) as u8;
                s.nbuf[2] = (total_payload >> 8) as u8;
                s.nbuf[3] = cb[0];
                s.nbuf[4] = cb[1];
                core::ptr::copy_nonoverlapping(
                    s.req.as_ptr().add(s.req_sent as usize),
                    s.nbuf.as_mut_ptr().add(NET_FRAME_HDR + 2),
                    chunk,
                );
                (sys.channel_write)(s.net_out, s.nbuf.as_ptr(), NET_FRAME_HDR + total_payload);
                s.req_sent += chunk as u16;
            }
        }

        if matches!(s.phase, CONNECTING | AWAIT_RESPONSE) {
            let budget = if s.phase == CONNECTING {
                CONNECT_TIMEOUT_MS
            } else {
                REPLY_TIMEOUT_MS
            };
            if now.wrapping_sub(s.started_ms) > budget {
                if s.phase == AWAIT_RESPONSE && s.acc_len > 0 {
                    if s.busy != 0 {
                        finish_driven(s);
                    } else {
                        finish_response(s);
                    }
                } else {
                    // 504: the endpoint was reachable but silent past the
                    // budget, which is a different fact from a dead transport.
                    fail_driven(s, 504);
                }
            }
        }

        // Retry a parked answer last, so a response produced this step reaches
        // `response_out` without waiting for the next one.
        if s.resp_len != 0 {
            flush_response(s);
        }

        // Drain is complete only at genuine quiescence: no admitted request in
        // flight and no answer still owed. A request taken off `request_in` is
        // never abandoned unreported.
        if s.draining == 1 && s.busy == 0 && matches!(s.phase, DISCONNECTED | DONE) {
            return 1;
        }
        0
    }
}
