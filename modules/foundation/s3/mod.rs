//! S3 connector — a per-protocol Fluxor foundation module that makes a point
//! the others don't: even a STATELESS request/reply protocol needs a compiled
//! module when each request must be cryptographically SIGNED. An S3 operation
//! is one round trip, but it carries an `Authorization: AWS4-HMAC-SHA256 …`
//! header whose signature is HMAC-SHA256 over a canonical form of the request,
//! and a streamed body signs every chunk. It is the crypto, not the round-trip
//! count, that a bytecode codec cannot compute.
//!
//! Two modes, chosen by whether `request_in` is wired:
//!
//! **Driven** (`request_in` wired) — the connector is an exchange provider
//! and performs one exchange at a time: a requester writes a request HEAD
//! (`/bucket/key[?query]`) carrying the body inline when it fits, or streams
//! it in BODY records against the credit the connector grants, and reads the
//! endpoint's response HEAD and body back as records, paced by the credit it
//! grants.
//! Neither body is ever held whole: a request body crosses in signed
//! `aws-chunked` chunks of [`S3_CHUNK`] bytes, a response body is forwarded as
//! it arrives and the transport is not read past what the caller has room for.
//!
//! **Probe** (`request_in` unwired) — on boot it signs a `GET /` (ListBuckets)
//! and reports the HTTP status on `status_out` (200 = signature accepted;
//! 403 = SignatureDoesNotMatch): the cheapest way to prove credentials
//! against a real endpoint.
//!
//! Signing is `sigv4_core.rs`; request composition, `aws-chunked` framing and
//! response framing are `s3_core.rs`; the records are the SDK's exchange
//! contract (`abi::contracts::exchange`).
//!
//! Ports:  net_in/net_out (transport), status_out (probe status),
//!         request_in (ExchangeRequest), response_out (ExchangeResponse).
//! Params: `authority` (`host[:port]`, port 80 when it names none: where the
//!         connector dials and, verbatim, the `Host` SigV4 signs),
//!         `access_key`, `secret`, `region`.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
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
include!("../../common/sigv4_core.rs");
include!("../../common/s3_core.rs");

// The exchange records this connector answers, as a provider.
use abi::contracts::exchange::{
    abort, flag, parse_request, seal_body, write_abort, write_credit, write_response_head,
    ExchangeId, Record, ResponseHead, HDR, METHOD_DELETE, METHOD_GET, METHOD_HEAD, METHOD_POST,
    METHOD_PUT, RECORD_MAX,
};

// The NetProto opcodes and identity accessors come from the owning contract,
// never redeclared locally, so a change to the wire is a compile error here
// rather than a wrong answer.
use abi::contracts::net::net_proto::{
    self, CMD_CLOSE as NET_CMD_CLOSE, CMD_CONNECT_TO as NET_CMD_CONNECT_TO,
    CMD_SEND as NET_CMD_SEND, MSG_CLOSED as NET_MSG_CLOSED, MSG_CONNECTED as NET_MSG_CONNECTED,
    MSG_DATA as NET_MSG_DATA, MSG_ERROR as NET_MSG_ERROR,
};
// The method byte of a request HEAD is the exchange contract's vocabulary.
use abi::contracts::exchange::method_name;

/// The port a dial takes when `authority` names none.
const DEFAULT_PORT: u16 = 80;

/// Construction refused: `authority` is absent, over [`NAME_BUF`] bytes, or
/// not `host[:port]`. The connector has one endpoint and signs requests
/// against it, so an instance that cannot name it is refused rather than
/// left to sign for nowhere.
const E_BAD_AUTHORITY: i32 = -22;
/// Construction refused: a credential parameter past its buffer.
const E_BAD_PARAM: i32 = -22;

/// One transport frame, read or written.
const NET_BUF: usize = 2048;
/// Request bytes per `CMD_SEND` frame: one TCP segment's worth, which keeps
/// every frame within `net_out`'s declared `max_record`.
const SEND_MAX: usize = net_proto::MAX_DATA_FRAGMENT;
/// Longest credential field or authority held.
const NAME_BUF: usize = 128;
/// Longest request target a caller may name. The canonical query is sorted in
/// [`SV4_QUERY_SCRATCH`], which is sized for a target of this length; a
/// longer one is refused with 400 rather than signed over a part of it.
const MAX_TARGET: usize = 2048;
/// Longest block of extra request header lines a caller may supply. Over it,
/// 400.
const MAX_CALLER_HEADERS: usize = 2048;
/// The signed request head. The largest head is the request line with a
/// [`MAX_TARGET`] target, [`MAX_CALLER_HEADERS`] of caller lines, a
/// [`NAME_BUF`] host, access key and region, and the fixed SigV4 fields — all
/// within this. It also stages one `aws-chunked` framing line.
const TX_BUF: usize = 6144;
/// Longest response head (status line and headers) read from the endpoint. A
/// head that does not end within it is answered 502 and the connection
/// closed, rather than parsed in part. Every head that fits also fits one
/// response HEAD record.
const RESP_HEAD_MAX: usize = 4096;
/// Longest `Content-Type` forwarded in its own field; a longer one stays among
/// the forwarded headers.
const CT_MAX: usize = 255;
const CONNECT_TIMEOUT_MS: u64 = 10_000;
/// The endpoint's progress deadline: no byte to or from it for this long
/// while the connector waits on it ends the exchange (504 before any response
/// record, ABORT(STALLED) after).
const REPLY_TIMEOUT_MS: u64 = 15_000;
/// The caller's progress deadline: no record from it, and none of the
/// connector's taken by it, for this long while the exchange waits on the
/// caller ends the exchange with ABORT(STALLED).
const CALLER_TIMEOUT_MS: u64 = 30_000;

// Transport phase.
const DISCONNECTED: u8 = 0;
const CONNECTING: u8 = 1;
const OPEN: u8 = 2;
/// The probe's terminal state.
const DONE: u8 = 3;

// Exchange phase.
const EX_IDLE: u8 = 0;
/// Admitted; the dial is staged or in flight.
const EX_DIAL: u8 = 1;
/// Connected; the request is going out and the response coming back.
const EX_OPEN: u8 = 2;
/// The exchange's terminal record is owed; nothing else is done for it.
const EX_ENDING: u8 = 3;

// Response framing state.
const RS_HEAD: u8 = 0;
const RS_NONE: u8 = 1;
const RS_LENGTH: u8 = 2;
const RS_CHUNKED: u8 = 3;
const RS_CLOSE: u8 = 4;
const RS_DONE: u8 = 5;

#[repr(C)]
struct S3State {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    status_out: i32,
    /// Channel handles; `-1` when unwired. `request_in < 0` selects probe mode.
    request_in: i32,
    response_out: i32,

    /// `host[:port]`: where the connector dials and what SigV4 signs as the
    /// `Host` header, one value.
    authority: [u8; NAME_BUF],
    authority_len: u16,
    /// The authority's port, or [`DEFAULT_PORT`] when it names none.
    port: u16,
    access_key: [u8; NAME_BUF],
    access_key_len: u16,
    secret: [u8; NAME_BUF],
    secret_len: u16,
    region: [u8; NAME_BUF],
    region_len: u16,
    /// A credential parameter longer than its buffer: construction refuses
    /// it rather than sign with a prefix of it.
    credential_over: u8,

    // ── Transport ───────────────────────────────────────────────────
    phase: u8,
    conn_id: u16,
    /// 1 once `MSG_CONNECTED` established a connection. Separate from
    /// `conn_id`'s value because the net stack can assign `conn_id == 0`.
    conn_present: u8,
    tag: u8,
    draining: u8,
    /// The transport command staged for `net_out`, `0` when none is owed. A
    /// command takes effect only once `net_out` has taken the whole frame, so
    /// a refused CONNECT or CLOSE is re-offered next step.
    cmd: u8,
    cmd_payload: [u8; net_proto::CONNECT_TO_MAX],
    cmd_len: u16,
    /// Last moment the exchange (or the probe) made progress: the base of
    /// every deadline.
    progress_ms: u64,
    /// The endpoint closed the connection (`MSG_CLOSED`). Its id stays
    /// reserved until this connector's CLOSE answers it.
    eof: u8,
    /// Scratch for every frame written to `net_out`.
    nbuf: [u8; NET_BUF],
    /// The last frame read from `net_in`. Response bytes not yet forwarded
    /// stay here, between `rx_at` and `rx_end`, and nothing more is read
    /// until they are gone — so a caller without credit holds the endpoint
    /// back through the transport, not through a buffer here.
    rxf: [u8; NET_BUF],
    rx_at: u16,
    rx_end: u16,

    // ── Request side ────────────────────────────────────────────────
    /// The record read from `request_in` and not yet taken: a HEAD that
    /// found [`Self::pend`] occupied. Nothing more is read while it is held.
    inrec: [u8; RECORD_MAX],
    inrec_len: u16,
    /// The next exchange's HEAD, read while one was in flight. It waits here
    /// until the exchange ahead of it ends.
    pend: [u8; RECORD_MAX],
    pend_len: u16,
    /// Response credit granted for the pending exchange before it began.
    pend_credit: u64,
    /// The pending exchange sent body bytes before any credit was granted.
    pend_overrun: u8,

    ex: u8,
    id: ExchangeId,
    method: u8,
    target: [u8; MAX_TARGET],
    target_len: u16,
    caller_hdrs: [u8; MAX_CALLER_HEADERS],
    caller_hdrs_len: u16,
    /// The request has a body: inline in its HEAD, after it, or both.
    has_body: u8,
    /// The body goes out `aws-chunked`.
    streaming: u8,
    /// Declared body length (`content-length`).
    req_len: u64,
    /// Body bytes taken from the caller.
    req_got: u64,
    /// Request-body credit granted and not yet used by the caller.
    req_credit: u64,
    /// Request-body credit owed to the caller, not yet written.
    credit_owed: u32,
    /// The request head is on (or queued for) the wire.
    head_queued: u8,
    /// The final `aws-chunked` chunk is queued.
    final_queued: u8,
    /// Every byte of the request has gone to `net_out`.
    req_sent: u8,
    /// Something was queued for `net_out` since the queue last drained.
    in_queue: u8,

    /// One chunk of request body: filled by the caller's BODY records within
    /// the credit granted, then sent from here.
    chunk: [u8; S3_CHUNK],
    chunk_len: u16,
    /// The bytes queued for `net_out`, sent in order: `tx` (a head or a chunk
    /// framing line), then `chunk[..data_len]`, then `\r\n` when `sfx_len` is
    /// 2. Each cursor advances only once a frame carrying its bytes has been
    /// taken whole.
    tx: [u8; TX_BUF],
    tx_len: u16,
    tx_sent: u16,
    data_len: u16,
    data_sent: u16,
    sfx_len: u8,
    sfx_sent: u8,

    signing_key: [u8; 32],
    amz_date: [u8; 16],
    scope_date: [u8; 8],
    /// The previous signature in the chunk chain (the head's for the first).
    prev_sig: [u8; 64],
    sv4_scratch: [u8; SV4_QUERY_SCRATCH],

    // ── Response side ───────────────────────────────────────────────
    /// Response-body credit the caller has granted and not yet used.
    resp_credit: u64,
    rs: u8,
    resp_remaining: u64,
    chunked: S3Chunked,
    resp_head: [u8; RESP_HEAD_MAX],
    resp_head_len: u16,
    resp_status: u16,
    /// The forwarded `Content-Type` (`fwd[..fwd_ct]`) and header lines
    /// (`fwd[fwd_ct..fwd_ct + fwd_hdr]`).
    fwd: [u8; CT_MAX + RESP_HEAD_MAX],
    fwd_ct: u16,
    fwd_hdr: u16,
    /// The response HEAD record is owed.
    head_owed: u8,
    /// The response HEAD record has gone out: a failure from here on is an
    /// ABORT, not a status.
    head_sent: u8,
    /// The terminal outcome owed once the exchange is ending: a status HEAD
    /// (`status_owed`) or an ABORT (`abort_owed`).
    status_owed: u16,
    abort_owed: u8,

    /// The record staged for `response_out`, `out_len == 0` when none. A
    /// refused write leaves it staged for the next step.
    out: [u8; RECORD_MAX],
    out_len: u16,
    /// The staged record ends the exchange.
    out_terminal: u8,

    /// Conservation counters. `admitted` counts HEADs taken off
    /// `request_in`; `terminated` counts their terminal outcomes — a final
    /// response record or ABORT delivered, or the caller's own ABORT.
    /// `admitted == terminated` whenever nothing is in flight or pending.
    admitted: u32,
    terminated: u32,
    /// Records for no exchange this connector holds (dropped).
    records_stale: u32,
    /// Records that do not parse (dropped).
    records_malformed: u32,
}

/// Driven-mode conservation snapshot.
#[cfg(feature = "host-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct S3Conservation {
    pub admitted: u32,
    pub terminated: u32,
    pub records_stale: u32,
    pub records_malformed: u32,
    /// 1 while an admitted exchange has not had its terminal outcome.
    pub in_flight: u8,
    /// 1 while a record is staged for a `response_out` that has not taken it.
    pub record_owed: u8,
    /// 1 while a transport command is staged for a `net_out` that refused it.
    pub command_owed: u8,
    /// 1 while a HEAD read off `request_in` waits behind the exchange in
    /// flight.
    pub pending: u8,
    /// Response bytes read from `net_in` and not yet forwarded.
    pub rx_held: u16,
}

/// # Safety
/// `state` must point to an `S3State` initialised by `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_conservation(state: *mut u8) -> S3Conservation {
    // SAFETY: the caller's contract above.
    let s = unsafe { &*(state as *const S3State) };
    S3Conservation {
        admitted: s.admitted,
        terminated: s.terminated,
        records_stale: s.records_stale,
        records_malformed: s.records_malformed,
        in_flight: u8::from(s.ex != EX_IDLE),
        record_owed: u8::from(s.out_len != 0),
        command_owed: u8::from(s.cmd != 0),
        pending: u8::from(s.pend_len != 0 || s.inrec_len != 0),
        rx_held: s.rx_end.saturating_sub(s.rx_at),
    }
}

/// Hold a string parameter whole, or flag it as too long. A default (empty)
/// value holds nothing.
///
/// # Safety
/// `d` is valid for `len` bytes.
unsafe fn take_param(
    buf: &mut [u8; NAME_BUF],
    held: &mut u16,
    over: &mut u8,
    d: *const u8,
    len: usize,
) {
    if len > NAME_BUF {
        *over = 1;
        return;
    }
    core::ptr::copy_nonoverlapping(d, buf.as_mut_ptr(), len);
    *held = len as u16;
}

define_params! {
    S3State;

    3, access_key, str, 0 => |s, d, len| {
        take_param(&mut s.access_key, &mut s.access_key_len, &mut s.credential_over, d, len);
    };
    4, secret, str, 0 => |s, d, len| {
        take_param(&mut s.secret, &mut s.secret_len, &mut s.credential_over, d, len);
    };
    5, region, str, 0 => |s, d, len| {
        take_param(&mut s.region, &mut s.region_len, &mut s.credential_over, d, len);
    };
    6, authority, str, 0 => |s, d, len| {
        // Held whole or not at all: a prefix of an authority is a
        // different host, and construction refuses an instance whose
        // authority does not parse.
        let room = NAME_BUF - (s.authority_len as usize);
        if len > room {
            s.authority_len = 0;
        } else {
            let mut i = 0usize;
            while i < len {
                s.authority[s.authority_len as usize] = *d.add(i); s.authority_len += 1; i += 1;
            }
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
    if state.is_null() {
        return -1;
    }
    // SAFETY: the kernel passes the state buffer `module_new` initialised.
    unsafe {
        (*(state as *mut S3State)).draining = 1;
    }
    0
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
    if syscalls.is_null() || state.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<S3State>() {
        return -2;
    }
    // SAFETY: `state` is non-null and at least `size_of::<S3State>()` bytes,
    // zero-initialised by the kernel; every field of `S3State` is valid at
    // all-zero bytes. `syscalls` is non-null and is this instance's table.
    let (s, sys) = unsafe {
        (
            &mut *(state as *mut S3State),
            &*(syscalls as *const SyscallTable),
        )
    };
    s.syscalls = sys;
    s.net_in = in_chan;
    s.net_out = out_chan;
    // SAFETY: syscall-table wrappers over a table that outlives the calls;
    // each (direction, index) is declared in `manifest.toml`.
    unsafe {
        s.status_out = dev_channel_port(sys, 1, 1);
        // in[1] / out[2]: the driven-mode pair. Unwired (`-1`) selects the
        // boot probe.
        s.request_in = dev_channel_port(sys, 0, 1);
        s.response_out = dev_channel_port(sys, 1, 2);
        s.tag = dev_requester_tag(sys);
    }
    s.authority_len = 0;
    s.port = 0;
    s.access_key_len = 0;
    s.secret_len = 0;
    s.region_len = 0;
    s.phase = DISCONNECTED;
    s.conn_present = 0;
    s.cmd = 0;
    s.cmd_len = 0;
    s.draining = 0;
    s.ex = EX_IDLE;
    s.out_len = 0;
    s.inrec_len = 0;
    s.pend_len = 0;
    s.admitted = 0;
    s.terminated = 0;
    s.records_stale = 0;
    s.records_malformed = 0;
    reset_exchange(s);
    // SAFETY: `params` spans `params_len` bytes per the module ABI.
    unsafe {
        parse_tlv(s, params, params_len);
    }
    // The one address this connector has. Refused here rather than at the
    // dial: a request performed against nowhere would time out and blame the
    // endpoint for a fault in the graph.
    let al = (s.authority_len as usize).min(NAME_BUF);
    match net_proto::Target::parse(s.authority.get(..al).unwrap_or(&[])) {
        Some((_, port)) => s.port = port.unwrap_or(DEFAULT_PORT),
        None => {
            let m = b"[s3] authority must be host[:port], at most 128 bytes";
            // SAFETY: logging a static message through the syscall table.
            unsafe { dev_log(sys, 2, m.as_ptr(), m.len()) };
            return E_BAD_AUTHORITY;
        }
    }
    if s.credential_over != 0 {
        let m = b"[s3] access_key, secret and region are each at most 128 bytes";
        // SAFETY: logging a static message through the syscall table.
        unsafe { dev_log(sys, 2, m.as_ptr(), m.len()) };
        return E_BAD_PARAM;
    }
    if s.region_len == 0 {
        s.region[..9].copy_from_slice(b"us-east-1");
        s.region_len = 9;
    }
    // SAFETY: as above.
    unsafe { dev_log(sys, 3, b"[s3] init".as_ptr(), 9) };
    0
}

// ── Small accessors ─────────────────────────────────────────────────────

fn authority(s: &S3State) -> &[u8] {
    s.authority.get(..s.authority_len as usize).unwrap_or(&[])
}

fn rx_empty(s: &S3State) -> bool {
    s.rx_at >= s.rx_end
}

fn rx_discard(s: &mut S3State) {
    s.rx_at = 0;
    s.rx_end = 0;
}

/// Clear everything one exchange holds.
fn reset_exchange(s: &mut S3State) {
    s.ex = EX_IDLE;
    s.id = ExchangeId::NONE;
    s.method = 0;
    s.target_len = 0;
    s.caller_hdrs_len = 0;
    s.has_body = 0;
    s.streaming = 0;
    s.req_len = 0;
    s.req_got = 0;
    s.req_credit = 0;
    s.credit_owed = 0;
    s.head_queued = 0;
    s.final_queued = 0;
    s.req_sent = 0;
    s.in_queue = 0;
    s.chunk_len = 0;
    s.tx_len = 0;
    s.tx_sent = 0;
    s.data_len = 0;
    s.data_sent = 0;
    s.sfx_len = 0;
    s.sfx_sent = 0;
    s.resp_credit = 0;
    s.rs = RS_HEAD;
    s.resp_remaining = 0;
    s.chunked = S3Chunked::new();
    s.resp_head_len = 0;
    s.resp_status = 0;
    s.fwd_ct = 0;
    s.fwd_hdr = 0;
    s.head_owed = 0;
    s.head_sent = 0;
    s.status_owed = 0;
    s.abort_owed = 0;
    s.out_terminal = 0;
    s.eof = 0;
    rx_discard(s);
}

// ── Transport commands ──────────────────────────────────────────────────

/// Stage a transport command for `net_out` and offer it straight away. The
/// staged copy is what makes the command survive a refusal.
fn stage_command(s: &mut S3State, cmd: u8, payload: &[u8], now: u64) {
    let len = payload.len().min(s.cmd_payload.len());
    if let (Some(dst), Some(src)) = (s.cmd_payload.get_mut(..len), payload.get(..len)) {
        dst.copy_from_slice(src);
    }
    s.cmd_len = len as u16;
    s.cmd = cmd;
    flush_command(s, now);
}

/// Stage the `CMD_CONNECT_TO` for this connector's authority, tagged with its
/// requester tag. The authority was parsed at construction.
fn stage_connect(s: &mut S3State, now: u64) {
    let mut payload = [0u8; net_proto::CONNECT_TO_MAX];
    let n = match net_proto::Target::parse(authority(s)) {
        Some((target, _)) => net_proto::write_connect_to(
            &mut payload,
            SOCK_TYPE_STREAM,
            s.port,
            &target,
            Some(s.tag),
        ),
        None => 0,
    };
    stage_command(s, NET_CMD_CONNECT_TO, payload.get(..n).unwrap_or(&[]), now);
}

/// Offer the staged transport command. A CONNECT starts the connect budget
/// only once the frame is on the channel.
fn flush_command(s: &mut S3State, now: u64) {
    if s.cmd == 0 {
        return;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    let len = (s.cmd_len as usize).min(s.cmd_payload.len());
    // SAFETY: `cmd_payload` holds `len` bytes and `nbuf` is `NET_BUF` long;
    // `net_write_frame` refuses a frame larger than the scratch.
    let wrote = unsafe {
        net_write_frame(
            sys,
            s.net_out,
            s.cmd,
            s.cmd_payload.as_ptr(),
            len,
            s.nbuf.as_mut_ptr(),
            NET_BUF,
        )
    };
    if wrote == 0 {
        return;
    }
    if s.cmd == NET_CMD_CONNECT_TO {
        s.phase = CONNECTING;
        s.progress_ms = now;
    }
    s.cmd = 0;
    s.cmd_len = 0;
}

/// Let go of the transport: close an established connection, or withdraw a
/// dial `net_out` has not yet taken.
fn drop_connection(s: &mut S3State, now: u64) {
    if s.cmd == NET_CMD_CONNECT_TO {
        s.cmd = 0;
        s.cmd_len = 0;
    }
    if s.conn_present != 0 {
        let mut close = [0u8; 2];
        net_proto::put_conn_id(&mut close, s.conn_id);
        stage_command(s, NET_CMD_CLOSE, &close, now);
    }
    s.conn_present = 0;
    s.conn_id = 0;
    if s.phase != DONE {
        s.phase = DISCONNECTED;
    }
}

// ── Exchange outcomes ───────────────────────────────────────────────────

/// End the exchange in failure. Before any response record has gone out the
/// caller is answered with `status`; after, with ABORT(`reason`).
fn fail_exchange(s: &mut S3State, status: u16, reason: u8, now: u64) {
    if s.ex == EX_IDLE || s.ex == EX_ENDING {
        return;
    }
    if s.head_sent != 0 {
        s.abort_owed = reason;
    } else {
        s.status_owed = status;
    }
    end_work(s, now);
}

/// End the exchange with ABORT(`reason`) whether or not a response record has
/// gone out: the caller broke the exchange's contract.
fn abort_exchange(s: &mut S3State, reason: u8, now: u64) {
    if s.ex == EX_IDLE || s.ex == EX_ENDING {
        return;
    }
    s.abort_owed = reason;
    end_work(s, now);
}

/// Stop all work on the exchange; only its terminal record remains owed.
fn end_work(s: &mut S3State, now: u64) {
    s.ex = EX_ENDING;
    s.head_owed = 0;
    s.credit_owed = 0;
    s.rs = RS_DONE;
    rx_discard(s);
    drop_connection(s, now);
}

/// The terminal record has been delivered (or the caller aborted): the
/// exchange is over.
fn finish_exchange(s: &mut S3State, now: u64) {
    s.terminated = s.terminated.wrapping_add(1);
    drop_connection(s, now);
    reset_exchange(s);
}

// ── Records to the caller ───────────────────────────────────────────────

/// Hand the staged record to `response_out`. The channel takes a record whole
/// or not at all, so a refused write leaves it intact for the next step.
fn flush_out(s: &mut S3State, now: u64) {
    if s.out_len == 0 {
        return;
    }
    if s.response_out >= 0 {
        // SAFETY: set from a non-null pointer in `module_new`.
        let sys = unsafe { &*s.syscalls };
        // SAFETY: syscalls on a channel this module owns; `out` holds
        // `out_len` bytes.
        let written = unsafe {
            let poll = (sys.channel_poll)(s.response_out, POLL_OUT);
            if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
                return;
            }
            (sys.channel_write)(s.response_out, s.out.as_ptr(), s.out_len as usize)
        };
        if written <= 0 {
            return;
        }
    }
    s.out_len = 0;
    s.progress_ms = now;
    if s.out_terminal != 0 {
        s.out_terminal = 0;
        finish_exchange(s, now);
    }
}

/// Move response body bytes from `rx` into `s.out[at..]`, at most `limit` of
/// them (the caller's credit and the record's room). Returns the bytes
/// written and whether the body is complete; `None` when the chunked framing
/// is malformed.
fn take_body(s: &mut S3State, at: usize, limit: usize) -> Option<(usize, bool)> {
    let src_at = s.rx_at as usize;
    let src_end = s.rx_end as usize;
    let end = at.checked_add(limit)?.min(s.out.len());
    match s.rs {
        RS_NONE => {
            rx_discard(s);
            Some((0, true))
        }
        RS_LENGTH => {
            let avail = src_end.saturating_sub(src_at);
            let n = (s.resp_remaining.min(avail as u64) as usize).min(end.saturating_sub(at));
            s.out
                .get_mut(at..at + n)?
                .copy_from_slice(s.rxf.get(src_at..src_at + n)?);
            s.rx_at += n as u16;
            s.resp_remaining -= n as u64;
            if s.resp_remaining == 0 {
                // Bytes past the declared length are not this response's.
                rx_discard(s);
                return Some((n, true));
            }
            Some((n, false))
        }
        RS_CHUNKED => {
            let input = s.rxf.get(src_at..src_end)?;
            let dst = s.out.get_mut(at..end)?;
            let (used, made) = s.chunked.feed(input, dst)?;
            s.rx_at += used as u16;
            if s.chunked.done() {
                rx_discard(s);
                return Some((made, true));
            }
            Some((made, false))
        }
        RS_CLOSE => {
            let avail = src_end.saturating_sub(src_at);
            let n = avail.min(end.saturating_sub(at));
            s.out
                .get_mut(at..at + n)?
                .copy_from_slice(s.rxf.get(src_at..src_at + n)?);
            s.rx_at += n as u16;
            Some((n, s.eof != 0 && rx_empty(s)))
        }
        _ => Some((0, true)),
    }
}

/// The response body has ended with the record just staged.
fn response_complete(s: &mut S3State, now: u64) {
    s.out_terminal = 1;
    s.rs = RS_DONE;
    s.ex = EX_ENDING;
    s.credit_owed = 0;
    rx_discard(s);
    drop_connection(s, now);
}

/// Stage the next record the exchange owes the caller, if the slot is free.
fn produce(s: &mut S3State, now: u64) {
    if s.out_len != 0 {
        return;
    }
    let id = s.id;
    if s.ex == EX_ENDING {
        let n = if s.abort_owed != 0 {
            write_abort(&id, s.abort_owed, &mut s.out)
        } else {
            // Every owed status is this connector's own: the server's
            // answers go out as the response itself, never through here.
            let head = ResponseHead {
                id,
                flags: flag::RAISED,
                status: s.status_owed,
                content_type: &[],
                headers: &[],
                body: &[],
            };
            write_response_head(&head, &mut s.out)
        };
        s.out_len = n.unwrap_or(0) as u16;
        s.out_terminal = 1;
        if s.out_len == 0 {
            finish_exchange(s, now);
        }
        return;
    }
    if s.ex != EX_OPEN {
        return;
    }
    if s.head_owed != 0 {
        let ct_len = (s.fwd_ct as usize).min(CT_MAX);
        let hdr_end = (ct_len + s.fwd_hdr as usize).min(s.fwd.len());
        let head = ResponseHead {
            id,
            flags: 0,
            status: s.resp_status,
            content_type: s.fwd.get(..ct_len).unwrap_or(&[]),
            headers: s.fwd.get(ct_len..hdr_end).unwrap_or(&[]),
            body: &[],
        };
        let Some(at) = write_response_head(&head, &mut s.out) else {
            fail_exchange(s, 502, abort::FAILED, now);
            return;
        };
        let limit =
            (s.resp_credit.min(RECORD_MAX as u64) as usize).min(RECORD_MAX.saturating_sub(at));
        let Some((made, done)) = take_body(s, at, limit) else {
            fail_exchange(s, 502, abort::MALFORMED, now);
            return;
        };
        let Some(flags) = s.out.get_mut(1) else {
            return;
        };
        *flags = if done { 0 } else { flag::MORE };
        s.resp_credit -= made as u64;
        s.out_len = (at + made) as u16;
        s.head_owed = 0;
        s.head_sent = 1;
        if done {
            response_complete(s, now);
        }
        return;
    }
    if s.credit_owed > 0 {
        s.out_len = write_credit(&id, s.credit_owed, &mut s.out).unwrap_or(0) as u16;
        s.req_credit += s.credit_owed as u64;
        s.credit_owed = 0;
        return;
    }
    if s.head_sent == 0 || s.rs == RS_DONE || s.rs == RS_HEAD {
        return;
    }
    let limit = s.resp_credit.min((RECORD_MAX - HDR) as u64) as usize;
    let Some((made, done)) = take_body(s, HDR, limit) else {
        fail_exchange(s, 502, abort::MALFORMED, now);
        return;
    };
    if made == 0 && !done {
        // Nothing to forward. An endpoint that has gone with the body
        // unfinished has failed the exchange.
        if s.eof != 0 && rx_empty(s) {
            fail_exchange(s, 502, abort::PEER_GONE, now);
        }
        return;
    }
    let flags = if done { 0 } else { flag::MORE };
    s.out_len = seal_body(&id, flags, made, &mut s.out).unwrap_or(0) as u16;
    s.resp_credit -= made as u64;
    s.progress_ms = now;
    if done {
        response_complete(s, now);
    }
}

// ── Records from the caller ─────────────────────────────────────────────

/// Read and take records from `request_in` while there is somewhere to put
/// them. A drain closes the channel to new work: it is read only while an
/// exchange is in flight, because that exchange may still need its caller's
/// body and credit to finish.
fn pump_requests(s: &mut S3State, now: u64) {
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    for _ in 0..8 {
        if s.inrec_len == 0 {
            if s.draining != 0 && s.ex == EX_IDLE && s.pend_len == 0 {
                return;
            }
            // SAFETY: syscalls on a channel this module owns; `inrec` is
            // `RECORD_MAX` bytes, and the channel is a mailbox, so one
            // read is one whole record.
            let n = unsafe {
                let poll = (sys.channel_poll)(s.request_in, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                    return;
                }
                (sys.channel_read)(s.request_in, s.inrec.as_mut_ptr(), RECORD_MAX)
            };
            if n <= 0 {
                return;
            }
            s.inrec_len = n as u16;
        }
        if !take_record(s, now) {
            return;
        }
        s.inrec_len = 0;
        start_pending(s, now);
    }
}

/// What a record read from `request_in` asks for, with its borrows dropped.
enum Taken {
    Head,
    Body {
        id: ExchangeId,
        n: usize,
        last: bool,
    },
    Credit {
        id: ExchangeId,
        bytes: u32,
    },
    Abort {
        id: ExchangeId,
    },
    Other,
}

/// Take the record in `inrec`. False when it must stay held: a HEAD with the
/// pending slot already full.
fn take_record(s: &mut S3State, now: u64) -> bool {
    let len = (s.inrec_len as usize).min(RECORD_MAX);
    let taken = match s.inrec.get(..len).and_then(parse_request) {
        None => {
            s.records_malformed = s.records_malformed.wrapping_add(1);
            return true;
        }
        Some(Record::Head(_)) => Taken::Head,
        Some(Record::Body { id, flags, data }) => Taken::Body {
            id,
            n: data.len(),
            last: flags & flag::MORE == 0,
        },
        Some(Record::Credit { id, bytes }) => Taken::Credit { id, bytes },
        Some(Record::Abort { id, .. }) => Taken::Abort { id },
        Some(Record::Datagram { .. }) | Some(Record::Link { .. }) => Taken::Other,
    };
    let current = |id: &ExchangeId| s.ex != EX_IDLE && *id == s.id;
    let pend_id = pending_id(s);
    match taken {
        Taken::Head => {
            if s.pend_len != 0 {
                return false;
            }
            let (Some(dst), Some(src)) = (s.pend.get_mut(..len), s.inrec.get(..len)) else {
                return true;
            };
            dst.copy_from_slice(src);
            s.pend_len = len as u16;
            s.pend_credit = 0;
            s.pend_overrun = 0;
            s.admitted = s.admitted.wrapping_add(1);
        }
        Taken::Body { id, n, last } if current(&id) => take_body_record(s, n, last, now),
        Taken::Credit { id, bytes } if current(&id) => {
            if s.ex != EX_ENDING {
                s.resp_credit = s.resp_credit.saturating_add(bytes as u64);
                s.progress_ms = now;
            }
        }
        Taken::Abort { id } if current(&id) => {
            // The caller has ended the exchange: nothing further is sent for
            // it, not even a record already staged.
            s.out_len = 0;
            s.out_terminal = 0;
            finish_exchange(s, now);
        }
        Taken::Body { id, .. } if pend_id == Some(id) => s.pend_overrun = 1,
        Taken::Credit { id, bytes } if pend_id == Some(id) => {
            s.pend_credit = s.pend_credit.saturating_add(bytes as u64);
        }
        Taken::Abort { id } if pend_id == Some(id) => {
            s.pend_len = 0;
            s.terminated = s.terminated.wrapping_add(1);
        }
        _ => s.records_stale = s.records_stale.wrapping_add(1),
    }
    true
}

fn pending_id(s: &S3State) -> Option<ExchangeId> {
    if s.pend_len == 0 {
        return None;
    }
    match parse_request(s.pend.get(..s.pend_len as usize)?)? {
        Record::Head(h) => Some(h.id),
        _ => None,
    }
}

/// Take one BODY record of the exchange in flight, held in `inrec`: its
/// payload is the `n` bytes after the prefix.
fn take_body_record(s: &mut S3State, n: usize, last: bool, now: u64) {
    if s.ex == EX_ENDING {
        return;
    }
    s.progress_ms = now;
    let got = s.req_got.saturating_add(n as u64);
    if got > s.req_len || (last && got < s.req_len) {
        // The body must be exactly the length the head declared: the
        // signature and the wire length already cover it.
        abort_exchange(s, abort::MALFORMED, now);
        return;
    }
    if n as u64 > s.req_credit {
        abort_exchange(s, abort::CREDIT_OVERRUN, now);
        return;
    }
    if n == 0 {
        // An empty final record: the body's end, already known from its
        // length.
        return;
    }
    let at = s.chunk_len as usize;
    let (Some(dst), Some(src)) = (s.chunk.get_mut(at..at + n), s.inrec.get(HDR..HDR + n)) else {
        abort_exchange(s, abort::CREDIT_OVERRUN, now);
        return;
    };
    dst.copy_from_slice(src);
    s.chunk_len += n as u16;
    s.req_got = got;
    s.req_credit -= n as u64;
    if s.streaming != 0 {
        if s.chunk_len as usize == S3_CHUNK || s.req_got == s.req_len {
            seal_chunk(s, now);
        }
    } else if s.req_got == s.req_len && !queue_signed_head(s) {
        fail_exchange(s, 500, abort::FAILED, now);
    }
}

/// Begin the pending exchange, if the connector is free for it.
fn start_pending(s: &mut S3State, now: u64) {
    if s.pend_len == 0 || s.ex != EX_IDLE || s.out_len != 0 || s.cmd != 0 {
        return;
    }
    let len = (s.pend_len as usize).min(RECORD_MAX);
    let credit = s.pend_credit;
    let overrun = s.pend_overrun;
    s.pend_len = 0;
    reset_exchange(s);
    let Some(Record::Head(h)) = s.pend.get(..len).and_then(parse_request) else {
        s.terminated = s.terminated.wrapping_add(1);
        return;
    };
    s.ex = EX_DIAL;
    s.id = h.id;
    s.method = h.method;
    s.resp_credit = (h.resp_credit as u64).saturating_add(credit);
    // MORE: BODY records follow, under credit, after what the HEAD carried.
    let more = h.flags & flag::MORE != 0;
    s.progress_ms = now;

    let refuse = |s: &mut S3State, status: u16| {
        s.status_owed = status;
        s.ex = EX_ENDING;
    };
    if s.draining != 0 {
        // Taken before the drain closed the channel, so it is owed an
        // outcome; 503 says the connector is going away without having
        // attempted it.
        refuse(s, 503);
        return;
    }
    if !matches!(
        h.method,
        METHOD_GET | METHOD_PUT | METHOD_HEAD | METHOD_DELETE | METHOD_POST
    ) {
        refuse(s, 400);
        return;
    }
    if h.target.len() > MAX_TARGET || h.headers.len() > MAX_CALLER_HEADERS {
        refuse(s, 413);
        return;
    }
    if !s3_target_ok(h.target, &mut s.sv4_scratch) {
        refuse(s, 400);
        return;
    }
    let declared = match s3_caller_headers(h.headers) {
        Ok(l) => l,
        Err(_) => {
            refuse(s, 400);
            return;
        }
    };
    // The body's length, which S3 needs before its first byte: declared, or —
    // when the HEAD carries the whole body — the bytes it carries.
    let inline = h.body;
    let length = match (declared, more) {
        (Some(n), false) if n != inline.len() as u64 => {
            refuse(s, 400);
            return;
        }
        (Some(n), true) if n < inline.len() as u64 => {
            refuse(s, 400);
            return;
        }
        (Some(n), _) => n,
        (None, false) => inline.len() as u64,
        (None, true) => {
            refuse(s, 400);
            return;
        }
    };
    if let Some(dst) = s.target.get_mut(..h.target.len()) {
        dst.copy_from_slice(h.target);
    }
    s.target_len = h.target.len() as u16;
    if let Some(dst) = s.caller_hdrs.get_mut(..h.headers.len()) {
        dst.copy_from_slice(h.headers);
    }
    s.caller_hdrs_len = h.headers.len() as u16;
    if overrun != 0 {
        s.abort_owed = abort::CREDIT_OVERRUN;
        s.ex = EX_ENDING;
        return;
    }
    // The inline bytes open the first chunk; whatever follows them comes on
    // credit. A record is never longer than a chunk, so they always fit.
    let n = inline.len().min(S3_CHUNK);
    if let Some(dst) = s.chunk.get_mut(..n) {
        dst.copy_from_slice(&inline[..n]);
    }
    s.chunk_len = n as u16;
    s.req_got = n as u64;
    s.has_body = u8::from(length > 0);
    s.req_len = length;
    s.streaming = u8::from(s.has_body != 0 && s.req_len > S3_CHUNK as u64);
    if s.streaming != 0 && s3_aws_chunked_len(s.req_len, S3_CHUNK as u64).is_none() {
        refuse(s, 400);
        return;
    }
    stage_connect(s, now);
}

// ── The request on the wire ─────────────────────────────────────────────

/// Sign and queue the request head. A streamed body's head goes out at once,
/// its chunks behind it; any other body is already whole in `chunk` and goes
/// out behind the head it is hashed into.
fn queue_signed_head(s: &mut S3State) -> bool {
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    // SAFETY: a syscall-table read of the wall clock.
    let unix_ms = unsafe { dev_unix_millis(sys) };
    let mut amz = [0u8; 16];
    let mut day = [0u8; 8];
    sv4_format_amz_date(unix_ms / 1000, &mut amz, &mut day);
    let region_len = (s.region_len as usize).min(NAME_BUF);
    let secret_len = (s.secret_len as usize).min(NAME_BUF);
    let key = sv4_signing_key(
        s.secret.get(..secret_len).unwrap_or(&[]),
        &day,
        s.region.get(..region_len).unwrap_or(&[]),
        S3_SERVICE,
    );
    s.signing_key = key;
    s.amz_date = amz;
    s.scope_date = day;

    let body_len = (s.chunk_len as usize).min(S3_CHUNK);
    let payload_hash = if s.streaming != 0 {
        [0u8; 64]
    } else if body_len == 0 {
        *SV4_EMPTY_SHA256
    } else {
        sv4_sha256_hex(s.chunk.get(..body_len).unwrap_or(&[]))
    };
    let wire_len = if s.streaming != 0 {
        s3_aws_chunked_len(s.req_len, S3_CHUNK as u64)
    } else if s.has_body != 0 || s.method == METHOD_PUT || s.method == METHOD_POST {
        Some(s.req_len)
    } else {
        None
    };
    let ak_len = (s.access_key_len as usize).min(NAME_BUF);
    let host_len = (s.authority_len as usize).min(NAME_BUF);
    let target_len = (s.target_len as usize).min(MAX_TARGET);
    let hdrs_len = (s.caller_hdrs_len as usize).min(MAX_CALLER_HEADERS);
    let params = S3HeadParams {
        method: method_name(s.method),
        target: s.target.get(..target_len).unwrap_or(&[]),
        host: s.authority.get(..host_len).unwrap_or(&[]),
        access_key: s.access_key.get(..ak_len).unwrap_or(&[]),
        region: s.region.get(..region_len).unwrap_or(&[]),
        signing_key: &key,
        amz_date: &amz,
        scope_date: &day,
        payload_hash: if s.streaming != 0 {
            SV4_STREAMING
        } else {
            &payload_hash
        },
        decoded_len: if s.streaming != 0 {
            Some(s.req_len)
        } else {
            None
        },
        content_length: wire_len,
        caller_headers: s.caller_hdrs.get(..hdrs_len).unwrap_or(&[]),
    };
    match s3_compose_head(&params, &mut s.tx, &mut s.sv4_scratch) {
        Ok((n, sig)) => {
            s.tx_len = n as u16;
            s.tx_sent = 0;
            s.prev_sig = sig;
            s.head_queued = 1;
            s.in_queue = 1;
            if s.streaming == 0 {
                s.data_len = body_len as u16;
                s.data_sent = 0;
            }
            true
        }
        // The request could not be built at all.
        Err(_) => false,
    }
}

/// Queue the filled chunk with its signed framing line.
fn seal_chunk(s: &mut S3State, now: u64) {
    let len = (s.chunk_len as usize).min(S3_CHUNK);
    let hash = sha256(s.chunk.get(..len).unwrap_or(&[]));
    let region_len = (s.region_len as usize).min(NAME_BUF);
    let sig = sv4_chunk_signature(
        &s.signing_key,
        &s.amz_date,
        &s.scope_date,
        s.region.get(..region_len).unwrap_or(&[]),
        S3_SERVICE,
        &s.prev_sig,
        &hash,
    );
    s.prev_sig = sig;
    match s3_chunk_header(len as u64, &sig, &mut s.tx) {
        Some(n) => {
            s.tx_len = n as u16;
            s.tx_sent = 0;
            s.data_len = len as u16;
            s.data_sent = 0;
            s.sfx_len = 2;
            s.sfx_sent = 0;
            s.in_queue = 1;
        }
        None => fail_exchange(s, 500, abort::FAILED, now),
    }
}

/// Everything queued has gone to `net_out`: queue what follows, or grant the
/// caller credit for the next chunk.
fn queue_drained(s: &mut S3State, now: u64) {
    // Whether what left carried chunk data, rather than the head alone.
    let carried_chunk = s.data_len != 0;
    s.tx_len = 0;
    s.tx_sent = 0;
    s.data_len = 0;
    s.data_sent = 0;
    s.sfx_len = 0;
    s.sfx_sent = 0;
    if s.streaming == 0 {
        if s.head_queued != 0 {
            s.chunk_len = 0;
            s.req_sent = 1;
        }
        return;
    }
    if s.final_queued != 0 {
        s.req_sent = 1;
        return;
    }
    if s.req_got == s.req_len && s.chunk_len != 0 {
        // The last data chunk is out; the empty chunk ends the body.
        s.chunk_len = 0;
        let region_len = (s.region_len as usize).min(NAME_BUF);
        let sig = sv4_chunk_signature(
            &s.signing_key,
            &s.amz_date,
            &s.scope_date,
            s.region.get(..region_len).unwrap_or(&[]),
            S3_SERVICE,
            &s.prev_sig,
            &sha256(&[]),
        );
        match s3_chunk_header(0, &sig, &mut s.tx) {
            Some(n) => {
                s.tx_len = n as u16;
                s.final_queued = 1;
                s.in_queue = 1;
            }
            None => fail_exchange(s, 500, abort::FAILED, now),
        }
        return;
    }
    // The chunk buffer is free again once the bytes it held have left for
    // the transport; after the head alone it still holds what the HEAD
    // carried inline. Either way the caller may fill the rest of it.
    if carried_chunk {
        s.chunk_len = 0;
    }
    let rest = s.req_len - s.req_got;
    s.credit_owed = rest.min((S3_CHUNK - s.chunk_len as usize) as u64) as u32;
}

/// Bytes queued for `net_out` and not yet taken.
fn queued(s: &S3State) -> usize {
    (s.tx_len.saturating_sub(s.tx_sent) as usize)
        + (s.data_len.saturating_sub(s.data_sent) as usize)
        + (s.sfx_len.saturating_sub(s.sfx_sent) as usize)
}

/// Copy up to `left` bytes of `src` into `dst` at `at`; the bytes copied.
fn gather(dst: &mut [u8], at: usize, left: usize, src: Option<&[u8]>) -> usize {
    let src = src.unwrap_or(&[]);
    let k = src.len().min(left);
    match (dst.get_mut(at..at + k), src.get(..k)) {
        (Some(d), Some(s)) => {
            d.copy_from_slice(s);
            k
        }
        _ => 0,
    }
}

/// The line end after an `aws-chunked` chunk's data.
const CRLF: &[u8; 2] = b"\r\n";

/// Send what is queued, one `CMD_SEND` frame at a time, gathering across the
/// three segments. A frame `net_out` refuses moves no cursor.
fn pump_send(s: &mut S3State, now: u64) {
    if s.conn_present == 0 || s.cmd != 0 || s.eof != 0 {
        return;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    let max = SEND_MAX.min(NET_BUF - NET_FRAME_HDR - 2);
    for _ in 0..16 {
        if queued(s) == 0 {
            if s.in_queue == 0 {
                return;
            }
            s.in_queue = 0;
            queue_drained(s, now);
            continue;
        }
        let mut w = NET_FRAME_HDR + 2;
        let mut left = max;
        let tx_take = gather(
            &mut s.nbuf,
            w,
            left,
            s.tx.get(s.tx_sent as usize..s.tx_len as usize),
        );
        w += tx_take;
        left -= tx_take;
        let data_take = gather(
            &mut s.nbuf,
            w,
            left,
            s.chunk.get(s.data_sent as usize..s.data_len as usize),
        );
        w += data_take;
        left -= data_take;
        let sfx_take = gather(
            &mut s.nbuf,
            w,
            left,
            CRLF.get(s.sfx_sent as usize..s.sfx_len as usize),
        );
        let payload = 2 + tx_take + data_take + sfx_take;
        s.nbuf[0] = NET_CMD_SEND;
        s.nbuf[1] = (payload & 0xff) as u8;
        s.nbuf[2] = (payload >> 8) as u8;
        net_proto::put_conn_id(&mut s.nbuf[NET_FRAME_HDR..], s.conn_id);
        let frame = NET_FRAME_HDR + payload;
        // SAFETY: a syscall on a channel this module owns; `nbuf` holds
        // `frame` bytes.
        let wrote = unsafe { (sys.channel_write)(s.net_out, s.nbuf.as_ptr(), frame) };
        if wrote != frame as i32 {
            // Refused wholesale, so none of these bytes are on the wire.
            return;
        }
        s.tx_sent += tx_take as u16;
        s.data_sent += data_take as u16;
        s.sfx_sent += sfx_take as u8;
        s.progress_ms = now;
    }
}

// ── The response off the wire ───────────────────────────────────────────

/// Move response-head bytes from `rx` into `resp_head` until the head ends.
/// True once a whole head is in.
fn take_head_bytes(s: &mut S3State) -> Result<bool, ()> {
    while !rx_empty(s) {
        let at = s.resp_head_len as usize;
        let Some(&c) = s.rxf.get(s.rx_at as usize) else {
            return Err(());
        };
        let Some(dst) = s.resp_head.get_mut(at) else {
            // A head past the bound is refused, not parsed in part.
            return Err(());
        };
        *dst = c;
        s.rx_at += 1;
        s.resp_head_len += 1;
        if at >= 3 && s.resp_head.get(at - 3..=at) == Some(&b"\r\n\r\n"[..]) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A whole response head is in `resp_head`: decide its framing and what the
/// caller is handed. Interim 1xx heads are skipped.
fn on_head(s: &mut S3State, now: u64) {
    let len = (s.resp_head_len as usize).min(RESP_HEAD_MAX);
    let head = s.resp_head.get(..len).unwrap_or(&[]);
    let Some(status) = s3_status_code(head) else {
        fail_exchange(s, 502, abort::FAILED, now);
        return;
    };
    if (100..200).contains(&status) && status != 101 {
        s.resp_head_len = 0;
        return;
    }
    let Some(body) = s3_response_body(head, status, s.method == METHOD_HEAD) else {
        fail_exchange(s, 502, abort::FAILED, now);
        return;
    };
    let (ct, hdrs) = s.fwd.split_at_mut(CT_MAX);
    let Some((ct_len, hdr_len)) = s3_forward_headers(head, ct, hdrs) else {
        fail_exchange(s, 502, abort::FAILED, now);
        return;
    };
    // The forwarded headers start right after the content type.
    if ct_len < CT_MAX {
        s.fwd.copy_within(CT_MAX..CT_MAX + hdr_len, ct_len);
    }
    s.fwd_ct = ct_len as u16;
    s.fwd_hdr = hdr_len as u16;
    s.resp_status = status;
    s.rs = match body {
        S3Body::None => RS_NONE,
        S3Body::Length(n) => {
            s.resp_remaining = n;
            if n == 0 {
                RS_NONE
            } else {
                RS_LENGTH
            }
        }
        S3Body::Chunked => RS_CHUNKED,
        S3Body::Close => RS_CLOSE,
    };
    s.head_owed = 1;
}

/// Work `rx` for the exchange in flight: head bytes into the head buffer,
/// body bytes out as records.
fn process_rx(s: &mut S3State, now: u64) {
    if s.ex != EX_OPEN {
        rx_discard(s);
        return;
    }
    if s.rs == RS_HEAD {
        match take_head_bytes(s) {
            Ok(true) => on_head(s, now),
            Ok(false) => {}
            Err(()) => fail_exchange(s, 502, abort::FAILED, now),
        }
    }
}

/// Read `net_in` while `rx` is empty, and act on each event.
fn pump_net(s: &mut S3State, now: u64) {
    if s.net_in < 0 {
        return;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    for _ in 0..32 {
        if s.request_in >= 0 {
            process_rx(s, now);
            produce(s, now);
            flush_out(s, now);
            start_pending(s, now);
        } else {
            probe_rx(s, now);
        }
        if !rx_empty(s) {
            return;
        }
        // SAFETY: syscalls on a channel this module owns; `rxf` is `NET_BUF`
        // bytes.
        let (msg, plen) = unsafe {
            let poll = (sys.channel_poll)(s.net_in, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                return;
            }
            net_read_frame(sys, s.net_in, s.rxf.as_mut_ptr(), NET_BUF)
        };
        if msg == 0 {
            return;
        }
        let payload_end = (NET_FRAME_HDR + plen).min(NET_BUF);
        let payload = s.rxf.get(NET_FRAME_HDR..payload_end).unwrap_or(&[]);
        match msg {
            NET_MSG_CONNECTED if plen >= 3 => {
                let (cid, tag) = net_proto::connected_parts(payload);
                if tag != s.tag {
                    continue;
                }
                if s.phase != CONNECTING {
                    // A dial this connector withdrew from completed anyway.
                    if s.cmd == 0 {
                        let mut close = [0u8; 2];
                        net_proto::put_conn_id(&mut close, cid);
                        stage_command(s, NET_CMD_CLOSE, &close, now);
                    }
                    continue;
                }
                s.conn_id = cid;
                s.conn_present = 1;
                s.phase = OPEN;
                s.progress_ms = now;
                on_connected(s, now);
            }
            NET_MSG_DATA if plen > 2 => {
                if s.conn_present == 0 || net_proto::conn_id(payload) != s.conn_id {
                    continue;
                }
                s.rx_at = (NET_FRAME_HDR + 2) as u16;
                s.rx_end = payload_end as u16;
                s.progress_ms = now;
            }
            NET_MSG_CLOSED if plen >= 2 => {
                if s.conn_present == 0 || net_proto::conn_id(payload) != s.conn_id {
                    continue;
                }
                // The id stays reserved for this connector's CLOSE, which the
                // exchange's end sends; nothing more is sent on it meanwhile.
                s.eof = 1;
                on_closed(s, now);
            }
            NET_MSG_ERROR if plen >= 3 => {
                // `[conn_id u16][errno i8][requester_tag u8]`. A connect-phase
                // failure is matched on the tag alone (its conn_id is
                // meaningless); an established connection's on an untagged
                // error naming it.
                let (cid, _errno, tag) = net_proto::error_parts(payload);
                let ours = (s.phase == CONNECTING && tag == s.tag)
                    || (s.conn_present != 0
                        && tag == net_proto::REQUESTER_TAG_NONE
                        && cid == s.conn_id);
                if !ours {
                    continue;
                }
                // The established connection is still the net stack's to
                // release: the failure path closes it.
                on_error(s, now);
            }
            _ => {}
        }
    }
}

fn on_connected(s: &mut S3State, now: u64) {
    if s.request_in < 0 {
        probe_request(s, now);
        return;
    }
    if s.ex != EX_DIAL {
        drop_connection(s, now);
        return;
    }
    s.ex = EX_OPEN;
    if s.streaming != 0 || s.req_got == s.req_len {
        // Signed now the connection is up, so the timestamp SigV4 binds is
        // current rather than aged by a slow connect. A streamed body's
        // first credit follows once the head has left; a body the HEAD
        // carried whole is already in the chunk the head hashes.
        if !queue_signed_head(s) {
            fail_exchange(s, 500, abort::FAILED, now);
        }
    } else {
        // A body of at most one chunk is hashed into the head, so it is
        // taken whole first: the credit is the rest of the chunk buffer.
        s.credit_owed = (s.req_len - s.req_got) as u32;
    }
}

fn on_closed(s: &mut S3State, now: u64) {
    if s.request_in < 0 {
        probe_finish(s, now);
        return;
    }
    match s.ex {
        EX_DIAL => fail_exchange(s, 502, abort::PEER_GONE, now),
        EX_OPEN if s.rs == RS_HEAD => fail_exchange(s, 502, abort::PEER_GONE, now),
        // A body framed by close ends here; any other is judged by `produce`
        // once what was read before the close has gone out.
        _ => {}
    }
}

fn on_error(s: &mut S3State, now: u64) {
    if s.request_in < 0 {
        if s.resp_head_len > 0 {
            probe_finish(s, now);
        } else {
            probe_fail(s, now);
        }
        return;
    }
    // 502: the transport failed, so the endpoint never got to answer for
    // itself.
    fail_exchange(s, 502, abort::PEER_GONE, now);
}

/// Who the exchange is waiting on: true for the caller (its body, its credit,
/// or its reading of a staged record), false for the endpoint.
fn waiting_on_caller(s: &S3State) -> bool {
    if s.out_len != 0 {
        return true;
    }
    if s.ex == EX_OPEN {
        let body_owed = s.has_body != 0 && s.req_got < s.req_len && queued(s) == 0;
        let credit_owed = !rx_empty(s) && s.rs != RS_HEAD && s.resp_credit == 0;
        return body_owed || credit_owed;
    }
    false
}

fn check_deadlines(s: &mut S3State, now: u64) {
    let idle = now.wrapping_sub(s.progress_ms);
    if s.request_in < 0 {
        let budget = if s.phase == CONNECTING {
            CONNECT_TIMEOUT_MS
        } else {
            REPLY_TIMEOUT_MS
        };
        if matches!(s.phase, CONNECTING | OPEN) && idle > budget {
            if s.resp_head_len > 0 {
                probe_finish(s, now);
            } else {
                probe_fail(s, now);
            }
        }
        return;
    }
    match s.ex {
        EX_DIAL if s.phase == CONNECTING && idle > CONNECT_TIMEOUT_MS => {
            // 504: the endpoint did not answer the dial in time.
            fail_exchange(s, 504, abort::STALLED, now);
        }
        EX_OPEN => {
            if waiting_on_caller(s) {
                if idle > CALLER_TIMEOUT_MS {
                    abort_exchange(s, abort::STALLED, now);
                }
            } else if idle > REPLY_TIMEOUT_MS {
                // 504: reachable but silent past the budget, a different fact
                // from a dead transport.
                fail_exchange(s, 504, abort::STALLED, now);
            }
        }
        _ => {}
    }
}

// ── Probe mode ──────────────────────────────────────────────────────────

/// Queue the signed `GET /` (ListBuckets).
fn probe_request(s: &mut S3State, now: u64) {
    s.method = METHOD_GET;
    s.target[0] = b'/';
    s.target_len = 1;
    s.caller_hdrs_len = 0;
    s.req_len = 0;
    s.streaming = 0;
    s.has_body = 0;
    if !queue_signed_head(s) {
        probe_fail(s, now);
    }
}

fn probe_rx(s: &mut S3State, now: u64) {
    if s.phase != OPEN {
        rx_discard(s);
        return;
    }
    match take_head_bytes(s) {
        Ok(true) => probe_finish(s, now),
        Ok(false) => {}
        Err(()) => probe_finish(s, now),
    }
}

/// Report the response's status ("s3: <code>\n") and go idle for good.
fn probe_finish(s: &mut S3State, now: u64) {
    let len = (s.resp_head_len as usize).min(RESP_HEAD_MAX);
    match s3_status_code(s.resp_head.get(..len).unwrap_or(&[])) {
        Some(code) => {
            let mut out = [b's', b'3', b':', b' ', 0, 0, 0, b'\n'];
            out[4] = b'0' + ((code / 100) % 10) as u8;
            out[5] = b'0' + ((code / 10) % 10) as u8;
            out[6] = b'0' + (code % 10) as u8;
            emit_status(s, &out);
        }
        None => emit_status(s, b"s3: (no status)\n"),
    }
    rx_discard(s);
    drop_connection(s, now);
    s.phase = DONE;
}

fn probe_fail(s: &mut S3State, now: u64) {
    rx_discard(s);
    drop_connection(s, now);
    s.phase = DONE;
}

fn emit_status(s: &S3State, text: &[u8]) {
    if s.status_out < 0 {
        return;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let sys = unsafe { &*s.syscalls };
    // SAFETY: syscalls on a channel this module owns.
    unsafe {
        let poll = (sys.channel_poll)(s.status_out, POLL_OUT);
        if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
            (sys.channel_write)(s.status_out, text.as_ptr(), text.len());
        }
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: the kernel passes the state buffer `module_new` initialised,
    // and steps this module single-threaded.
    let s = unsafe { &mut *(state as *mut S3State) };
    if s.syscalls.is_null() {
        return -1;
    }
    // SAFETY: set from a non-null pointer in `module_new`.
    let now = unsafe { dev_millis(&*s.syscalls) };

    // A transport command `net_out` refused earlier goes first, before
    // anything can stage another over it.
    flush_command(s, now);

    if s.request_in >= 0 {
        flush_out(s, now);
        pump_requests(s, now);
        start_pending(s, now);
    } else if s.phase == DISCONNECTED && s.cmd == 0 && s.draining == 0 && s.access_key_len > 0 {
        // The boot probe: one signed GET / on connect. Probe mode only — a
        // wired `request_in` means a caller decides what to request.
        stage_connect(s, now);
    }

    pump_net(s, now);
    if s.request_in >= 0 {
        produce(s, now);
        flush_out(s, now);
    }
    pump_send(s, now);
    check_deadlines(s, now);
    if s.request_in >= 0 {
        produce(s, now);
        flush_out(s, now);
        start_pending(s, now);
    }

    // Drained only at quiescence: no exchange in flight or waiting, no record
    // owed to the caller, no transport command owed to the net stack.
    if s.draining != 0
        && s.ex == EX_IDLE
        && s.pend_len == 0
        && s.inrec_len == 0
        && s.out_len == 0
        && s.cmd == 0
        && matches!(s.phase, DISCONNECTED | DONE)
    {
        return 1;
    }
    0
}
