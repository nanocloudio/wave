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

#![no_std]
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
    /// a second record is not consumed until this one is answered.
    busy: u8,
    /// Staging for one inbound `S3Request` record.
    rec: [u8; REQ_BUF],

    req: [u8; REQ_BUF],
    req_len: u16,
    req_sent: u16,
    acc: [u8; ACC_BUF],
    acc_len: u32,

    nbuf: [u8; NET_BUF],
    ok: u32,
    errors: u32,
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

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<S3State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut S3State)).draining = 1;
        0
    }
}

#[no_mangle]
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
unsafe fn pump_request(s: &mut S3State, now: u64) {
    if s.busy != 0 || s.phase != DISCONNECTED || s.draining != 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.request_in, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return;
    }
    let n = (sys.channel_read)(s.request_in, s.rec.as_mut_ptr(), REQ_BUF);
    if n <= 0 {
        return;
    }
    let n = n as usize;

    let view = match parse_s3_request(&s.rec[..n]) {
        Some(v) => v,
        // A record shorter than the lengths it declares. There is no cid to
        // answer on — the header itself is what could not be trusted — so it is
        // dropped, exactly as the HTTP fan-out drops a truncated envelope.
        None => return,
    };
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
    s.busy = 1;
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
    let sys = &*s.syscalls;
    if s.response_out >= 0 {
        let mut out = [0u8; REQ_BUF];
        let len = body_len
            .min(MAX_OBJECT_BYTES)
            .min(REQ_BUF - S3_RESP_BODY_AT);
        if len > 0 {
            out[S3_RESP_BODY_AT..S3_RESP_BODY_AT + len]
                .copy_from_slice(&s.acc[body_at..body_at + len]);
        }
        if let Some(total) = write_s3_response(s.cur_op, s.cur_cid, status, len, &mut out) {
            (sys.channel_write)(s.response_out, out.as_ptr(), total);
        }
    }
    if (200..400).contains(&status) {
        s.ok = s.ok.wrapping_add(1);
    } else {
        s.errors = s.errors.wrapping_add(1);
    }
    s.busy = 0;
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

#[no_mangle]
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
                                finish_response(s);
                            } else {
                                fail(s);
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
                    finish_response(s);
                } else {
                    fail(s);
                }
            }
        }

        if s.draining == 1 && matches!(s.phase, DISCONNECTED | DONE) {
            return 1;
        }
        0
    }
}
