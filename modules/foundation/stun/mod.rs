//! STUN Binding — both roles over one datagram endpoint.
//!
//! **Server.** Tells a peer the address its packets arrived from. That one
//! fact is what a peer behind a NAT cannot learn any other way, and it is the
//! first thing an ICE agent gathers.
//!
//! **Client.** Asks the same question of a server and reports the answer. The
//! two roles are one module because they are one protocol over one socket: a
//! Binding request and its response differ by two bits of the message type,
//! and splitting them would duplicate the parse, the fingerprint check and the
//! endpoint pump to no end. Setting `server_ip` arms the client; leaving it
//! zero is the server-only module this was before.
//!
//! Message mechanics live in the host-tested `modules/common/stun_core.rs`,
//! and the client's retransmission schedule in `modules/common/stun_txn.rs`;
//! this module is the pump around them.
//!
//! **What this module is not.** It is not an ICE agent. It gathers no
//! candidates, forms no pairs, schedules no connectivity checks and nominates
//! nothing — those are decisions about reachability, and reachability policy
//! belongs to Wormhole rather than to a protocol codec. It answers a question,
//! and asks one; it does not decide what to do with the answer.
//!
//! Ports:  net_in/net_out (the datagram surface), result_out (out[1]) — one
//!         `[status:u8][ip:4 BE][port:u16 LE][code:u16 LE]` per client
//!         transaction, and nothing at all in server-only mode.
//! Params: `port` (UDP port to bind, default 3478), `server_ip`/`server_port`
//!         (the server to ask; `server_ip` non-zero arms the client),
//!         `txn_seed` (varies the transaction-id sequence between instances).

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
              signature is fixed by that contract rather than chosen here."
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

// SHA-1 for MESSAGE-INTEGRITY. Mounted before the core, which calls it by
// bare name — the same arrangement `modules/foundation/http/wire/ws.rs` uses for the WebSocket accept
// value, and for the same reason: the SDK is the repo set's one crypto owner.
mod sdkcrypto {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs");
}
use sdkcrypto::sha1;

// The message mechanics, included FLAT rather than mounted as a submodule.
// The core computes MESSAGE-INTEGRITY and calls `sha1` by bare name, which is
// how `modules/foundation/http/wire/ws.rs` mounts the WebSocket frame core: a
// submodule would put the
// SDK's crypto out of the core's scope.
include!("../../common/stun_core.rs");

// The client's transaction schedule. A plain submodule, unlike `stun_core`:
// it computes no MESSAGE-INTEGRITY and so needs nothing in scope by bare name.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/stun_txn.rs"]
mod stun_txn;
#[cfg(feature = "host-test")]
#[path = "../../common/stun_txn.rs"]
pub mod stun_txn;
use stun_txn::{
    parse_stun_result, stun_txn_id, write_stun_result, StunTxn, StunTxnAction, STUN_RESULT_LEN,
    STUN_RES_ERROR, STUN_RES_NO_ADDRESS, STUN_RES_OK, STUN_RES_TIMEOUT,
};

// `turn_core` is NOT included here. This module answers STUN Binding
// requests and nothing else; TURN's methods, relay attributes and
// ChannelData framing are unused by it, and a codec mounted only so tests
// can reach it presents relay mechanics as functionality of this server
// (rfc_hardening §9.6). The TURN codec's conformance fixture reaches it
// directly in the harness, sharing `stun_core` there exactly as a real
// consumer would.

const NET_BUF: usize = 1600;
const MSG_BUF: usize = 1500;

/// Attributes this responder understands. A comprehension-required attribute
/// outside this set is refused with 420 rather than ignored: answering a
/// request whose terms were not understood claims an agreement that was not
/// reached.
const KNOWN_REQUIRED: &[u16] = &[
    ATTR_USERNAME,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_PRIORITY,
    ATTR_USE_CANDIDATE,
];

#[repr(C)]
struct StunState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,

    port: u16,
    bound: u8,
    ep_id: u8,

    /// The reply this module owes, held until the channel takes it.
    ///
    /// One request is answered at a time: a reply dropped because the channel
    /// was briefly full leaves a peer retransmitting against a responder that
    /// already decided.
    reply: [u8; MSG_BUF],
    reply_len: u16,
    reply_owed: u8,
    reply_ip: u32,
    reply_port: u16,

    msg: [u8; MSG_BUF],
    net_buf: [u8; NET_BUF],

    // ── client role (armed by a non-zero `server_ip`) ────────────────────
    /// out[1]: one result record per transaction. −1 leaves the client silent
    /// about its answers, which is a graph that wired no consumer for them.
    result_out: i32,
    /// The server to ask, big-endian like every other address here. Zero means
    /// server-only: this module then starts no transaction and reports nothing.
    server_ip: u32,
    server_port: u16,
    /// Varies the transaction-id sequence between instances counting from the
    /// same place.
    txn_seed: u32,
    /// The transaction in flight. One at a time: this client asks one server
    /// for one address, and a second concurrent question would be a candidate
    /// gatherer, which is ICE and is not this module.
    txn: StunTxn,
    /// 1 while `txn` is live.
    txn_active: u8,
    /// Transactions started, so ids do not repeat within an instance.
    txn_count: u64,
    /// The result this module owes, held until the channel takes it.
    res: [u8; STUN_RESULT_LEN],
    res_owed: u8,

    requests: u32,
    answered: u32,
    refused: u32,
    dropped: u32,
    /// Client transactions that ended, by outcome.
    resolved: u32,
    timeouts: u32,
    draining: u8,
}

define_params! {
    StunState;

    1, port, u16, 3478
        => |s, d, len| { s.port = p_u16(d, len, 0, 3478); };
    2, server_ip, u32, 0
        => |s, d, len| { s.server_ip = p_u32(d, len, 0, 0); };
    3, server_port, u16, 3478
        => |s, d, len| { s.server_port = p_u16(d, len, 0, 3478); };
    4, txn_seed, u32, 0
        => |s, d, len| { s.txn_seed = p_u32(d, len, 0, 0); };
}

/// Is the client role armed?
///
/// A server address is the whole configuration: there is nothing to ask
/// without one, and asking is the only thing the client does.
fn client_armed(s: &StunState) -> bool {
    s.server_ip != 0
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<StunState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut StunState)).draining = 1;
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
        if state_size < core::mem::size_of::<StunState>() {
            return -2;
        }
        let s = &mut *(state as *mut StunState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.bound = 0;
        s.ep_id = 0xFF;
        s.reply_len = 0;
        s.reply_owed = 0;
        s.reply_ip = 0;
        s.reply_port = 0;
        s.requests = 0;
        s.answered = 0;
        s.refused = 0;
        s.dropped = 0;
        s.resolved = 0;
        s.timeouts = 0;
        s.draining = 0;
        s.result_out = -1;
        s.server_ip = 0;
        s.txn_active = 0;
        s.txn_count = 0;
        s.res_owed = 0;
        set_defaults(s);
        parse_tlv(s, params, params_len);
        if client_armed(s) {
            s.result_out = dev_channel_port(sys, 1, 1);
        }
        dev_log(sys, 3, b"[stun] init".as_ptr(), 11);
        0
    }
}

/// Bind the endpoint, then learn its id.
unsafe fn ensure_bound(s: &mut StunState) -> bool {
    let sys = &*s.syscalls;
    if s.bound == 0 {
        if s.net_out < 0 {
            return false;
        }
        let port = s.port.to_le_bytes();
        let payload = [port[0], port[1], 0u8];
        if net_write_frame(
            sys,
            s.net_out,
            DG_CMD_BIND,
            payload.as_ptr(),
            3,
            s.net_buf.as_mut_ptr(),
            NET_BUF,
        ) != 0
        {
            s.bound = 1;
        }
        return false;
    }
    if s.ep_id == 0xFF {
        if s.net_in < 0 {
            return false;
        }
        let poll = (sys.channel_poll)(s.net_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let (msg_type, plen) = net_read_frame(sys, s.net_in, s.net_buf.as_mut_ptr(), NET_BUF);
            if msg_type == DG_MSG_BOUND && plen >= 3 {
                // Port-matched claim (see dg_bound_parts): on a fanned
                // provider output the first BOUND polled may be another
                // module's endpoint.
                let (ep, port) = abi::contracts::net::datagram::dg_bound_parts(
                    core::slice::from_raw_parts(s.net_buf.as_ptr().add(NET_FRAME_HDR), plen),
                );
                if port == s.port {
                    s.ep_id = ep;
                }
            }
        }
        return false;
    }
    true
}

/// Build the success response for a Binding request from `(ip, port)`.
unsafe fn build_success(s: &mut StunState, header: &StunHeader, ip: u32, port: u16) -> bool {
    let mut out = [0u8; MSG_BUF];
    let Some(mut at) = write_stun_header(STUN_CLASS_SUCCESS, header.method, &header.txn, &mut out)
    else {
        return false;
    };
    // The address the request arrived FROM, which is the whole point of the
    // exchange: after a NAT it is not the address the peer believes it has.
    let Some(next) = append_xor_mapped_address_v4(ip.to_be_bytes(), port, &mut out, at) else {
        return false;
    };
    at = next;
    let Some(next) = append_fingerprint(&mut out, at) else {
        return false;
    };
    at = next;
    s.reply[..at].copy_from_slice(&out[..at]);
    s.reply_len = at as u16;
    s.reply_ip = ip;
    s.reply_port = port;
    s.reply_owed = 1;
    true
}

/// Build an error response.
unsafe fn build_error(
    s: &mut StunState,
    header: &StunHeader,
    code: u16,
    reason: &[u8],
    ip: u32,
    port: u16,
) -> bool {
    let mut out = [0u8; MSG_BUF];
    let Some(mut at) = write_stun_header(STUN_CLASS_ERROR, header.method, &header.txn, &mut out)
    else {
        return false;
    };
    let Some(next) = append_error_code(code, reason, &mut out, at) else {
        return false;
    };
    at = next;
    let Some(next) = append_fingerprint(&mut out, at) else {
        return false;
    };
    at = next;
    s.reply[..at].copy_from_slice(&out[..at]);
    s.reply_len = at as u16;
    s.reply_ip = ip;
    s.reply_port = port;
    s.reply_owed = 1;
    true
}

/// Hand the owed reply to the transport, retrying while it refuses.
unsafe fn flush_reply(s: &mut StunState) {
    if s.reply_owed == 0 || s.net_out < 0 || s.ep_id == 0xFF {
        return;
    }
    let sys = &*s.syscalls;
    let len = s.reply_len as usize;
    let mut staged = [0u8; MSG_BUF];
    staged[..len].copy_from_slice(&s.reply[..len]);
    let sent = dev_dg_send_to_v4(
        sys,
        s.net_out,
        s.ep_id,
        s.reply_ip,
        s.reply_port,
        staged.as_ptr(),
        len,
        s.net_buf.as_mut_ptr(),
        NET_BUF,
    );
    if sent != 0 {
        s.reply_owed = 0;
        s.answered = s.answered.wrapping_add(1);
    }
}

// ── client role ───────────────────────────────────────────────────────────

/// Record the outcome of the transaction in flight and retire it.
///
/// The result is held rather than written here: a channel that is briefly full
/// must not turn into a lost answer, and this module owes exactly one record
/// per transaction it started.
unsafe fn finish_txn(s: &mut StunState, status: u8, ip_be: [u8; 4], port: u16, code: u16) {
    s.txn_active = 0;
    if status == STUN_RES_OK {
        s.resolved = s.resolved.wrapping_add(1);
    } else if status == STUN_RES_TIMEOUT {
        s.timeouts = s.timeouts.wrapping_add(1);
    }
    if s.result_out < 0 || s.res_owed != 0 {
        return;
    }
    let mut out = [0u8; STUN_RESULT_LEN];
    if write_stun_result(status, ip_be, port, code, &mut out).is_some() {
        s.res[..].copy_from_slice(&out[..]);
        s.res_owed = 1;
    }
}

/// Hand the owed result to `result_out`, retrying while it refuses.
unsafe fn flush_result(s: &mut StunState) {
    if s.res_owed == 0 || s.result_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.result_out, POLL_OUT);
    if poll <= 0 || (poll as u32) & POLL_OUT == 0 {
        return;
    }
    let staged = s.res;
    if (sys.channel_write)(s.result_out, staged.as_ptr(), STUN_RESULT_LEN) == STUN_RESULT_LEN as i32
    {
        s.res_owed = 0;
    }
}

/// Start a transaction, or put the next retransmission of one on the wire.
///
/// Everything about WHEN is the transaction core's; everything about WHAT is
/// `stun_core`'s. This decides neither — it moves bytes between them.
unsafe fn pump_client(s: &mut StunState) {
    if !client_armed(s) || s.ep_id == 0xFF || s.net_out < 0 {
        return;
    }
    // One result outstanding at a time, so a transaction cannot retire onto a
    // record the channel has not taken yet.
    if s.res_owed != 0 {
        return;
    }
    let sys = &*s.syscalls;
    let now = dev_millis(sys);

    if s.txn_active == 0 {
        // Draining, or a graph that asked once and was answered: a client that
        // re-asked forever would be a keepalive, which is a policy decision
        // this module has no standing to make.
        if s.draining != 0 || s.txn_count != 0 {
            return;
        }
        s.txn_count += 1;
        s.txn = StunTxn::start(stun_txn_id(s.txn_count, u64::from(s.txn_seed)), now);
        s.txn_active = 1;
    }

    match s.txn.poll(now) {
        StunTxnAction::Wait => {}
        StunTxnAction::TimedOut => {
            dev_log(sys, 3, b"[stun] client timeout".as_ptr(), 21);
            finish_txn(s, STUN_RES_TIMEOUT, [0; 4], 0, 0);
        }
        StunTxnAction::Send { .. } => {
            let mut out = [0u8; MSG_BUF];
            let Some(mut at) =
                write_stun_header(STUN_CLASS_REQUEST, STUN_METHOD_BINDING, &s.txn.id, &mut out)
            else {
                return;
            };
            // A FINGERPRINT on the way out is what lets the server tell this
            // request from whatever else shares its port, and it is what this
            // module demands of a response in return.
            let Some(next) = append_fingerprint(&mut out, at) else {
                return;
            };
            at = next;
            let sent = dev_dg_send_to_v4(
                sys,
                s.net_out,
                s.ep_id,
                s.server_ip,
                s.server_port,
                out.as_ptr(),
                at,
                s.net_buf.as_mut_ptr(),
                NET_BUF,
            );
            // Only a confirmed write advances the schedule. Counting a refused
            // one would burn a transmission the server never had a chance to
            // see, and seven of those retire a transaction that was never
            // actually asked.
            if sent != 0 {
                s.txn.sent_at(now);
            }
        }
    }
}

/// Decide a STUN response against the transaction in flight.
///
/// Returns true when the datagram was consumed as this client's answer, so the
/// server path does not also count it.
unsafe fn client_on_response(
    s: &mut StunState,
    header: &StunHeader,
    buf: &[u8],
    from_ip: u32,
    from_port: u16,
) -> bool {
    if s.txn_active == 0 || !client_armed(s) {
        return false;
    }
    // The source is checked before the transaction id, and both are checked.
    // A response from anywhere else is a stranger answering a question they
    // were not asked — and being told your own address by a stranger is the
    // one thing this exchange must not allow.
    if from_ip != s.server_ip || from_port != s.server_port {
        return false;
    }
    if !s.txn.matches(&header.txn) {
        return false;
    }
    if find_attribute(buf, header, ATTR_FINGERPRINT).is_some() && !verify_fingerprint(buf, header) {
        return false;
    }
    if !s.txn.accept() {
        return true;
    }

    if header.class == STUN_CLASS_ERROR {
        let code = find_attribute(buf, header, ATTR_ERROR_CODE)
            .and_then(|(at, len)| parse_error_code(buf, at, len))
            .unwrap_or(0);
        finish_txn(s, STUN_RES_ERROR, [0; 4], 0, code);
        return true;
    }

    // XOR-MAPPED-ADDRESS is the modern attribute and the one a NAT cannot
    // rewrite in passing; MAPPED-ADDRESS is the RFC 3489 fallback, accepted
    // because a server old enough to send only that is still telling the
    // truth about what it saw.
    let addr = find_attribute(buf, header, ATTR_XOR_MAPPED_ADDRESS)
        .and_then(|(at, len)| parse_xor_mapped_address(buf, at, len, &header.txn))
        .or_else(|| {
            find_attribute(buf, header, ATTR_MAPPED_ADDRESS)
                .and_then(|(at, len)| parse_mapped_address(buf, at, len))
        });
    match addr {
        Some(a) if a.family == STUN_FAMILY_IPV4 => {
            finish_txn(
                s,
                STUN_RES_OK,
                [a.addr[0], a.addr[1], a.addr[2], a.addr[3]],
                a.port,
                0,
            );
        }
        // A success carrying nothing this client can read is not an address,
        // and reporting it as one would put zeroes where a candidate goes.
        _ => finish_txn(s, STUN_RES_NO_ADDRESS, [0; 4], 0, 0),
    }
    true
}

/// Read one datagram and decide what it deserves.
unsafe fn pump(s: &mut StunState) {
    // A reply already owed means the server half cannot take another request.
    // The client half can still take its own response — and must, or a busy
    // responder would starve the transaction sharing its socket.
    if s.net_in < 0 || (s.reply_owed != 0 && !client_armed(s)) {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.net_in, POLL_IN);
    if poll <= 0 || (poll as u32) & POLL_IN == 0 {
        return;
    }
    let (msg_type, plen) = net_read_frame(sys, s.net_in, s.net_buf.as_mut_ptr(), NET_BUF);
    if msg_type != DG_MSG_RX_FROM {
        return;
    }
    // The SDK's own parser rather than hand-read offsets: the datagram surface
    // carries the address big-endian and the port little-endian, and reading
    // the port the same way as the address yields a byte-swapped port that
    // still looks like a port.
    let Some((_ep, ip, port, data_ptr, raw_len)) = parse_dg_rx_from_v4(s.net_buf.as_ptr(), plen)
    else {
        return;
    };
    let data_len = raw_len.min(MSG_BUF);
    core::ptr::copy_nonoverlapping(data_ptr, s.msg.as_mut_ptr(), data_len);

    // Not STUN at all: this endpoint may carry other traffic, and dropping
    // silently is the only correct answer to a datagram that was never
    // addressed to this protocol.
    if !stun_is_plausible(&s.msg[..data_len]) {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    let Some(header) = parse_stun_header(&s.msg[..data_len]) else {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    };
    // A response belongs to a transaction. This module's own, if the client is
    // armed and everything matches; otherwise to one it never started.
    if matches!(header.class, STUN_CLASS_SUCCESS | STUN_CLASS_ERROR) {
        let mut copy = [0u8; MSG_BUF];
        copy[..data_len].copy_from_slice(&s.msg[..data_len]);
        if !client_on_response(s, &header, &copy[..data_len], ip, port) {
            s.dropped = s.dropped.wrapping_add(1);
        }
        return;
    }
    // Only requests are answered; an indication asks for nothing.
    if header.class != STUN_CLASS_REQUEST {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    // A request arriving while a reply is still owed has to wait its turn: the
    // server answers one at a time.
    if s.reply_owed != 0 {
        return;
    }
    s.requests = s.requests.wrapping_add(1);

    if header.method != STUN_METHOD_BINDING {
        s.refused = s.refused.wrapping_add(1);
        build_error(s, &header, 400, b"unsupported method", ip, port);
        return;
    }
    // A fingerprint is optional, but one that is present and wrong means the
    // bytes are not what the sender sent.
    let mut copy = [0u8; MSG_BUF];
    copy[..data_len].copy_from_slice(&s.msg[..data_len]);
    if find_attribute(&copy[..data_len], &header, ATTR_FINGERPRINT).is_some()
        && !verify_fingerprint(&copy[..data_len], &header)
    {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    if let Some(unknown) = first_unknown_required(&copy[..data_len], &header, KNOWN_REQUIRED) {
        let _ = unknown;
        s.refused = s.refused.wrapping_add(1);
        build_error(s, &header, 420, b"unknown attribute", ip, port);
        return;
    }
    build_success(s, &header, ip, port);
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut StunState);
        if s.syscalls.is_null() {
            return -1;
        }
        if !ensure_bound(s) {
            return 0;
        }
        pump(s);
        flush_reply(s);
        pump_client(s);
        flush_result(s);
        // Draining ends when nothing is owed in either direction. A client
        // that learned an address and could not hand it over yet has not
        // finished, however quiet its socket has gone.
        if s.draining == 1 && s.reply_owed == 0 && s.res_owed == 0 {
            return 1;
        }
        0
    }
}
