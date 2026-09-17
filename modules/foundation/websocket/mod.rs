//! WebSocket (RFC 6455) connector — a GENUINE per-protocol Fluxor foundation
//! module for the "protocol upgrade + masked bidirectional framing" class. The
//! connection starts as HTTP: the client sends an Upgrade request with a random
//! Sec-WebSocket-Key and CRYPTOGRAPHICALLY VERIFIES the server's
//! Sec-WebSocket-Accept (= base64(SHA1(key ++ magic))) before switching. After
//! the 101, both sides exchange frames and client frames are masked (payload XOR
//! a per-frame key). A protocol that mutates from HTTP into a masked frame stream
//! and verifies the switch is a stateful session, not request/reply.
//!
//! On boot it upgrades and sends a masked `message`. Thereafter it sends what
//! arrives on `request_in`, one message per chunk, and emits what the server
//! sends on `message_out` as COMPLETE messages — continuation frames are
//! reassembled here, so a consumer never sees half of one. PING is answered
//! with PONG. Protocol + crypto in Wave's shared cores: `b64_core.rs` (Base64),
//! `sha1_core.rs` (SHA-1), `ws_core.rs`.
//!
//! Ports:  net_in/net_out (transport), request_in (messages to send),
//!         message_out (reassembled messages received).
//! Params: `endpoint` (hex `[ip:4][port:2 LE]`), `host`, `path`, `message`,
//!         `request_opcode` (1 = text, the default; 2 = binary).

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
              chronicle's and lattice's PIC modules carry, and required here because \
              `fluxor ci` clippies modules/** directly."
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

// Shared Wave codecs — `include!`d verbatim so the device and the host test
// harness compile identical bytes.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/b64.rs"); // b64_encode
include!("../../common/hex_core.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs"); // sha1
include!("../../common/ws_frame_core.rs");
// The records that drive this connector from outside it, and the number of
// links it carries. Mounted rather than restated: a consumer mounts the same
// file, so neither end can believe in a link the other does not have.
include!("../../../target/fluxor/fluxor-abi/sdk/contracts/net/ws_control.rs");
include!("../../common/utf8_core.rs");
include!("../../common/ws_core.rs");

// The NetProto opcodes and identity accessors come from the owning contract,
// never redeclared locally, so a change to the wire is a compile error here
// rather than a wrong answer.
use abi::contracts::net::net_proto::{
    self, CMD_CLOSE as NET_CMD_CLOSE, CMD_CONNECT as NET_CMD_CONNECT, CMD_SEND as NET_CMD_SEND,
    MSG_CLOSED as NET_MSG_CLOSED, MSG_CONNECTED as NET_MSG_CONNECTED, MSG_DATA as NET_MSG_DATA,
    MSG_ERROR as NET_MSG_ERROR,
};
use abi::contracts::net::ws_frame as wsf;

const NET_BUF: usize = 2048;
const REQ_BUF: usize = 512;
const ACC_BUF: usize = 8192;
const NAME_BUF: usize = 128;
const MESSAGE_MAX: usize = 2048;
/// How many WebSockets one connector carries at once. Four, to match the
/// connection table of the network adapters that sit under it: a consumer
/// that can hold four sockets open should not find the protocol above them
/// the narrower of the two.
const CLOSE_TIMEOUT_MS: u64 = 5000;
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const REPLY_TIMEOUT_MS: u64 = 15_000;

/// The largest `WsFrame` envelope either direction.
const WSF_ENVELOPE_MAX: usize = 8 + MESSAGE_MAX;

#[repr(C)]
struct WsState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    request_in: i32,
    message_out: i32,
    /// The addressed surface, alongside the params-driven one above.
    /// `ws_in`/`ws_out` carry messages as `WsFrame`, whose layout and
    /// accessors Fluxor owns, so neither end of it restates the envelope.
    /// `open_in`/`event_out` carry what a frame has no room for: which
    /// resource to open, and whether a link opened or ended.
    ws_in: i32,
    ws_out: i32,
    open_in: i32,
    event_out: i32,

    ip: [u8; 4],
    port: u16,
    ep_hex: [u8; 16],
    ep_hex_len: u16,
    host: [u8; NAME_BUF],
    host_len: u16,
    message: [u8; NAME_BUF],
    message_len: u16,

    tag: u8,
    draining: u8,
    sent_msg: u8,
    request_opcode: u8,

    links: [Link; WS_LINKS],

    nbuf: [u8; NET_BUF],
    /// One envelope read from `ws_in` and not yet framed onto its link.
    ///
    /// A mailbox channel hands over a whole envelope or nothing, and there is
    /// no peeking at one -- so which link a frame is for is known only after
    /// it has been taken. Taking one for a link that cannot carry it yet and
    /// dropping it would be a hole in that link's stream; leaving it in the
    /// channel is not on offer once it has been read. So it is held here, and
    /// nothing else is read until it has been placed.
    pending: [u8; WSF_ENVELOPE_MAX],
    pending_len: u16,
    frames: u32,
    errors: u32,
}

/// One WebSocket, with everything that belongs to it and nothing that does
/// not.
///
/// The state is held per link even at `WS_LINKS == 1`, which is what
/// ../standards/fluxor-modules.md §6 asks of a component that can serve more
/// than one logical instance: the alternative it forbids is a second module
/// instance with ports of its own, so the identity a consumer addresses has
/// to be carried in the frame. `WsFrame`'s `conn` field is that identity, and
/// it is the index of the link here.
#[repr(C)]
#[derive(Clone, Copy)]
struct Link {
    phase: WsPhase,
    /// 1 while this link is wanted: an open was asked for and no close has
    /// completed. The dial is driven from here rather than from the presence
    /// of an endpoint, so a graph that names no path opens nothing until a
    /// consumer asks -- which is what lets one connector serve a program that
    /// decides at run time whether it wants a socket at all.
    wanted: u8,
    conn_id: u16,
    /// 1 once `MSG_CONNECTED` established a connection, 0 otherwise. Tracks
    /// connection PRESENCE separately from `conn_id`'s value because the net
    /// stack can legitimately assign `conn_id == 0`; keying "connected" off
    /// `conn_id != 0` would skip the close on every connection that happened
    /// to land in slot 0, leaking a transport slot per failure. Same split the
    /// HTTP client carries for the same reason.
    conn_present: u8,
    started_ms: u64,
    /// The resource this link asked for. A param supplies it for a graph that
    /// names one; an open record supplies it otherwise.
    path: [u8; NAME_BUF],
    path_len: u16,

    // The expected Sec-WebSocket-Accept for the key we sent.
    accept: [u8; 32],
    accept_len: u16,

    req: [u8; REQ_BUF],
    req_len: u16,
    req_sent: u16,
    acc: [u8; ACC_BUF],
    acc_len: u32,
    assembled: [u8; MESSAGE_MAX],
    assembled_len: u16,
    assembled_opcode: u8,
    assembled_ready: u8,
    /// 1 closes after sending (peer close/protocol error); 2 awaits peer close.
    closing: u8,
    close_started_ms: u64,
}

impl Link {
    const EMPTY: Link = Link {
        phase: WsPhase::Disconnected,
        wanted: 0,
        conn_id: 0,
        conn_present: 0,
        started_ms: 0,
        path: [0; NAME_BUF],
        path_len: 0,
        accept: [0; 32],
        accept_len: 0,
        req: [0; REQ_BUF],
        req_len: 0,
        req_sent: 0,
        acc: [0; ACC_BUF],
        acc_len: 0,
        assembled: [0; MESSAGE_MAX],
        assembled_len: 0,
        assembled_opcode: 0,
        assembled_ready: 0,
        closing: 0,
        close_started_ms: 0,
    };
}

define_params! {
    WsState;

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
    3, path, str, 0 => |s, d, len| {
        // A path named by the graph belongs to the link the graph opens, which
        // is the first one. A consumer that opens its own names it then.
        let mut i = 0usize;
        while i < len && (s.links[0].path_len as usize) < NAME_BUF {
            s.links[0].path[s.links[0].path_len as usize] = *d.add(i);
            s.links[0].path_len += 1;
            i += 1;
        }
    };
    4, message, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.message_len as usize) < NAME_BUF {
            s.message[s.message_len as usize] = *d.add(i); s.message_len += 1; i += 1;
        }
    };
    5, request_opcode, u8, 1 => |s, d, len| {
        s.request_opcode = p_u8(d, len, 0, ws_op::TEXT);
    };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<WsState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut WsState)).draining = 1;
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
        if state_size < core::mem::size_of::<WsState>() {
            return -2;
        }
        let s = &mut *(state as *mut WsState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.request_in = dev_channel_port(sys, 0, 1);
        s.message_out = dev_channel_port(sys, 1, 1);
        s.ws_in = dev_channel_port(sys, 0, 2);
        s.open_in = dev_channel_port(sys, 0, 3);
        s.ws_out = dev_channel_port(sys, 1, 2);
        s.event_out = dev_channel_port(sys, 1, 3);
        s.ip = [0u8; 4];
        s.port = 0;
        s.ep_hex_len = 0;
        s.host_len = 0;
        s.message_len = 0;
        s.links = [Link::EMPTY; WS_LINKS];
        s.tag = dev_requester_tag(sys);
        s.draining = 0;
        s.sent_msg = 0;
        s.request_opcode = ws_op::TEXT;
        s.frames = 0;
        s.errors = 0;
        parse_tlv(s, params, params_len);
        if !matches!(s.request_opcode, ws_op::TEXT | ws_op::BINARY) {
            return -22;
        }
        let mut ep = [0u8; 8];
        if let Some(n) = hex_decode(&s.ep_hex[..s.ep_hex_len as usize], &mut ep) {
            if n >= 6 {
                s.ip = [ep[0], ep[1], ep[2], ep[3]];
                s.port = u16::from_le_bytes([ep[4], ep[5]]);
            }
        }
        // Who opens a link is settled by the wiring, not by a parameter. A
        // graph that wired `open_in` has a consumer that will say what it
        // wants opened and when, so nothing is opened until it does -- which
        // is what lets one connector serve a program that decides at run time
        // whether it wants a socket at all. A graph that did not wire it is
        // the older shape: it named an endpoint because it wants that link,
        // so the first one is opened on its own, to the path it named or to
        // the root, carrying the message it named.
        if s.open_in < 0 && s.ep_hex_len > 0 {
            if s.links[0].path_len == 0 {
                s.links[0].path[0] = b'/';
                s.links[0].path_len = 1;
            }
            if s.message_len == 0 {
                s.message[..5].copy_from_slice(b"hello");
                s.message_len = 5;
            }
            s.links[0].wanted = 1;
        }
        dev_log(sys, 3, b"[ws] init".as_ptr(), 9);
        0
    }
}

/// Entropy failure never falls back to predictable masks.
unsafe fn next_mask(s: &WsState) -> Option<[u8; 4]> {
    let mut key = [0u8; 4];
    (dev_csprng_fill(&*s.syscalls, key.as_mut_ptr(), key.len()) == 0).then_some(key)
}

/// Keep the connection identity until the transport accepted its close.
unsafe fn close_transport(s: &mut WsState, i: usize) -> bool {
    if s.links[i].conn_present == 0 {
        return true;
    }
    let mut close = [0u8; 2];
    net_proto::put_conn_id(&mut close, s.links[i].conn_id);
    if net_write_frame(
        &*s.syscalls,
        s.net_out,
        NET_CMD_CLOSE,
        close.as_ptr(),
        close.len(),
        s.nbuf.as_mut_ptr(),
        NET_BUF,
    ) == 0
    {
        return false;
    }
    s.links[i].conn_present = 0;
    s.links[i].conn_id = 0;
    true
}

/// Application output is a complete bounded message, retained on refusal.
///
/// Both surfaces are offered it: `message_out` carries the payload alone, for
/// a graph that wired one connector to one endpoint and wants what came back;
/// `ws_out` carries a `WsFrame`, which additionally says which link it arrived
/// on and whether it was text or binary -- the two things a consumer holding
/// several links cannot do without. A wired port that refuses leaves the
/// message staged, so neither surface loses one.
unsafe fn emit_message(s: &mut WsState, i: usize) -> bool {
    if s.links[i].assembled_ready == 0 {
        return true;
    }
    let len = s.links[i].assembled_len as usize;
    if s.message_out >= 0
        && len > 0
        && ((*s.syscalls).channel_write)(s.message_out, s.links[i].assembled.as_ptr(), len)
            != len as i32
    {
        return false;
    }
    if s.ws_out >= 0 && len > 0 {
        let total = wsf::FRAME_HDR + len;
        if total > NET_BUF {
            // Longer than the envelope may carry. Dropping it would be a hole
            // in the stream a consumer cannot see, so the link ends instead.
            s.links[i].assembled_ready = 0;
            s.links[i].assembled_len = 0;
            s.links[i].assembled_opcode = 0;
            protocol_close(s, i, 1009, dev_millis(&*s.syscalls));
            return true;
        }
        wsf::put_header(
            &mut s.nbuf,
            i as u32,
            s.links[i].assembled_opcode,
            1,
            len as u16,
        );
        core::ptr::copy_nonoverlapping(
            s.links[i].assembled.as_ptr(),
            s.nbuf.as_mut_ptr().add(wsf::FRAME_HDR),
            len,
        );
        if ((*s.syscalls).channel_write)(s.ws_out, s.nbuf.as_ptr(), total) != total as i32 {
            return false;
        }
    }
    s.frames = s.frames.wrapping_add(1);
    s.links[i].assembled_ready = 0;
    s.links[i].assembled_len = 0;
    s.links[i].assembled_opcode = 0;
    true
}

/// Say what became of a link. Nothing waits on this: a consumer that is not
/// wired for events is a consumer that does not need them.
unsafe fn emit_event(s: &mut WsState, i: usize, kind: u8, code: u16) {
    if s.event_out < 0 {
        return;
    }
    let mut record = [0u8; event::LEN];
    let Some(length) = write_event(i as u8, kind, code, &mut record) else {
        return;
    };
    ((*s.syscalls).channel_write)(s.event_out, record.as_ptr(), length);
}

unsafe fn stage(s: &mut WsState, i: usize, n: usize) {
    s.links[i].req_len = n as u16;
    s.links[i].req_sent = 0;
}

unsafe fn control(s: &mut WsState, i: usize, opcode: u8, payload: &[u8], now: u64) -> bool {
    if s.links[i].req_sent < s.links[i].req_len {
        return false;
    }
    let Some(mask) = next_mask(s) else {
        feed(s, i, &*s.syscalls, WsEv::NetError, now);
        return false;
    };
    let Some(n) = ws_frame(opcode, payload, mask, &mut s.links[i].req) else {
        return false;
    };
    stage(s, i, n);
    true
}

unsafe fn protocol_close(s: &mut WsState, i: usize, code: u16, now: u64) {
    if control(s, i, ws_op::CLOSE, &code.to_be_bytes(), now) {
        s.links[i].closing = 1;
        s.links[i].close_started_ms = now;
        s.errors = s.errors.wrapping_add(1);
        s.links[i].acc_len = 0;
    }
}

fn valid_close(payload: &[u8]) -> Result<(), u16> {
    if payload.len() == 1 {
        return Err(1002);
    }
    if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999) {
            return Err(1002);
        }
        if !valid_utf8(&payload[2..]) {
            return Err(1007);
        }
    }
    Ok(())
}

unsafe fn drain_messages(s: &mut WsState, i: usize, now: u64) {
    if s.links[i].phase != WsPhase::Ready || s.links[i].closing == 1 || !emit_message(s, i) {
        return;
    }
    // Fixed work budget even when a peer pipelines zero-length control frames.
    for _ in 0..16 {
        let h = match ws_decode_header(&s.links[i].acc[..s.links[i].acc_len as usize]) {
            WsHeaderParse::Incomplete => return,
            WsHeaderParse::Invalid => {
                protocol_close(s, i, 1002, now);
                return;
            }
            WsHeaderParse::Header(h) => h,
        };
        if h.masked {
            protocol_close(s, i, 1002, now);
            return;
        }
        if h.payload_len > MESSAGE_MAX as u64 {
            protocol_close(s, i, 1009, now);
            return;
        }
        let total = h.header_len + h.payload_len as usize;
        if total > s.links[i].acc_len as usize {
            return;
        }
        if h.opcode == ws_op::CLOSE {
            let mut payload = [0u8; 125];
            let n = h.payload_len as usize;
            payload[..n].copy_from_slice(&s.links[i].acc[h.header_len..total]);
            if let Err(code) = valid_close(&payload[..n]) {
                protocol_close(s, i, code, now);
                return;
            }
            if s.links[i].closing == 2 {
                s.links[i].closing = 1;
            } else if control(s, i, ws_op::CLOSE, &payload[..n], now) {
                s.links[i].closing = 1;
                s.links[i].close_started_ms = now;
            } else {
                return;
            }
        } else if h.opcode == ws_op::PING {
            if s.links[i].closing == 0 {
                let mut payload = [0u8; 125];
                let n = h.payload_len as usize;
                payload[..n].copy_from_slice(&s.links[i].acc[h.header_len..total]);
                if !control(s, i, ws_op::PONG, &payload[..n], now) {
                    return;
                }
            }
        } else if matches!(h.opcode, ws_op::TEXT | ws_op::BINARY | ws_op::CONT)
            && s.links[i].closing == 0
        {
            if (h.opcode == ws_op::CONT) != (s.links[i].assembled_opcode != 0) {
                protocol_close(s, i, 1002, now);
                return;
            }
            if h.opcode != ws_op::CONT {
                s.links[i].assembled_opcode = h.opcode;
            }
            let have = s.links[i].assembled_len as usize;
            let n = h.payload_len as usize;
            if have + n > MESSAGE_MAX {
                protocol_close(s, i, 1009, now);
                return;
            }
            s.links[i].assembled[have..have + n]
                .copy_from_slice(&s.links[i].acc[h.header_len..total]);
            s.links[i].assembled_len = (have + n) as u16;
            if h.fin {
                if s.links[i].assembled_opcode == ws_op::TEXT
                    && !valid_utf8(&s.links[i].assembled[..have + n])
                {
                    protocol_close(s, i, 1007, now);
                    return;
                }
                s.links[i].assembled_ready = 1;
            }
        }
        s.links[i]
            .acc
            .copy_within(total..s.links[i].acc_len as usize, 0);
        s.links[i].acc_len -= total as u32;
        if s.links[i].closing != 0 || !emit_message(s, i) {
            return;
        }
    }
}

unsafe fn feed(s: &mut WsState, i: usize, sys: &SyscallTable, ev: WsEv, now: u64) {
    let (action, next) = ws_transition(s.links[i].phase, ev);
    match action {
        WsAct::Connect => {
            s.links[i].assembled_len = 0;
            s.links[i].assembled_opcode = 0;
            s.links[i].assembled_ready = 0;
            s.links[i].closing = 0;
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
            if net_write_frame(
                sys,
                s.net_out,
                NET_CMD_CONNECT,
                payload.as_ptr(),
                8,
                s.nbuf.as_mut_ptr(),
                NET_BUF,
            ) == 0
            {
                // Refused: stay where we are so the same CONNECT is offered
                // again next step. The deadline has not started, because
                // nothing has been asked of the peer yet.
                return;
            }
            s.links[i].started_ms = now;
        }
        WsAct::SendUpgrade => {
            let mut raw = [0u8; 16];
            if dev_csprng_fill(sys, raw.as_mut_ptr(), raw.len()) != 0 {
                feed(s, i, sys, WsEv::NetError, now);
                return;
            }
            let mut key_b64 = [0u8; 24];
            let kn = b64_encode(&raw, &mut key_b64).unwrap_or(0);
            if let Some(an) = ws_accept(&key_b64[..kn], &mut s.links[i].accept) {
                s.links[i].accept_len = an as u16;
            }
            let hl = s.host_len as usize;
            let pl = s.links[i].path_len as usize;
            let mut host = [0u8; NAME_BUF];
            host[..hl].copy_from_slice(&s.host[..hl]);
            let mut path = [0u8; NAME_BUF];
            path[..pl].copy_from_slice(&s.links[i].path[..pl]);
            let mut out = [0u8; REQ_BUF];
            if let Some(n) = ws_upgrade_request(&host[..hl], &path[..pl], &key_b64[..kn], &mut out)
            {
                s.links[i].req[..n].copy_from_slice(&out[..n]);
                stage(s, i, n);
                s.links[i].started_ms = now;
                s.links[i].acc_len = 0;
            } else {
                feed(s, i, sys, WsEv::NetError, now);
                return;
            }
        }
        WsAct::Fail => {
            let _ = close_transport(s, i);
            s.links[i].acc_len = 0;
            s.links[i].req_len = 0;
            s.links[i].req_sent = 0;
            s.errors = s.errors.wrapping_add(1);
        }
        WsAct::None => {}
    }
    if next == WsPhase::Ready && s.links[i].phase != WsPhase::Ready {
        emit_event(s, i, event::OPEN, 0);
    }
    if next == WsPhase::Disconnected && s.links[i].phase != WsPhase::Disconnected {
        // Which of the two it is turns on whether the link ever carried
        // messages: one that did has ended, one that did not never opened,
        // and a consumer waiting to send has to be able to tell those apart.
        let (kind, code) = if s.links[i].phase == WsPhase::Ready {
            (event::CLOSED, 1006u16)
        } else {
            (event::FAILED, 0u16)
        };
        s.links[i].wanted = 0;
        emit_event(s, i, kind, code);
    }
    // The configured message belongs to the link the graph opened, and only
    // to the first upgrade on it: a link a consumer opened sends what the
    // consumer sends and nothing of its own.
    if next == WsPhase::Ready && s.links[i].phase != WsPhase::Ready && s.message_len > 0 {
        let ml = s.message_len as usize;
        let mut msg = [0u8; NAME_BUF];
        msg[..ml].copy_from_slice(&s.message[..ml]);
        let Some(mask) = next_mask(s) else {
            feed(s, i, &*s.syscalls, WsEv::NetError, now);
            return;
        };
        let mut out = [0u8; REQ_BUF];
        if let Some(n) = ws_frame(ws_op::TEXT, &msg[..ml], mask, &mut out) {
            s.links[i].req[..n].copy_from_slice(&out[..n]);
            stage(s, i, n);
            s.sent_msg = 1;
        }
        // The upgrade reader retained any coalesced WebSocket bytes.
        // They belong to the new session and must survive this transition.
    }
    s.links[i].phase = next;
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut WsState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // The transport lane is shared by every link, so it is drained once
        // and each frame is given to the link it belongs to. The send lane is
        // shared for the same reason and drained the same way.
        pump_net_in(s, sys, now);
        pump_ws_in(s, sys, now);

        // Finished means every link is, not any of them. A link that was
        // never opened reports itself done the moment the graph drains, and
        // taking the greater of the verdicts would retire the module while
        // another link was still waiting for its close to be answered.
        let mut done = true;
        let mut i = 0usize;
        while i < WS_LINKS {
            if pump_link(s, i, sys, now) == 0 {
                done = false;
            }
            i += 1;
        }
        i32::from(done)
    }
}

/// Which link a transport frame belongs to.
///
/// `MSG_CONNECTED` and a tagged `MSG_ERROR` answer a dial, and the requester
/// tag names this module rather than one of its links -- so they are matched
/// to the dial in flight, and only one link dials at a time (`dialling`) so
/// that there is only ever one to match. Everything else carries a connection
/// id, which is the link's own.
unsafe fn link_for(s: &WsState, msg: u8, payload: &[u8], plen: usize) -> Option<usize> {
    match msg {
        NET_MSG_CONNECTED if plen >= 3 => {
            let (_cid, tag) = net_proto::connected_parts(payload);
            (tag == s.tag).then(|| dialling(s)).flatten()
        }
        NET_MSG_ERROR if plen >= 3 => {
            let (cid, _errno, tag) = net_proto::error_parts(payload);
            if tag == s.tag {
                dialling(s)
            } else if tag == net_proto::REQUESTER_TAG_NONE {
                established(s, cid)
            } else {
                None
            }
        }
        NET_MSG_DATA | NET_MSG_CLOSED if plen >= 2 => established(s, net_proto::conn_id(payload)),
        _ => None,
    }
}

/// The link waiting on a dial, if one is.
fn dialling(s: &WsState) -> Option<usize> {
    (0..WS_LINKS).find(|&i| s.links[i].phase == WsPhase::Connecting)
}

/// Whether every link has room for whatever the next transport frame turns
/// out to be. A frame is routed only after it is read, so the room that has
/// to be there is the least of them.
fn room_for_a_frame(s: &WsState) -> bool {
    (0..WS_LINKS)
        .all(|i| s.links[i].closing != 1 && ACC_BUF - (s.links[i].acc_len as usize) >= NET_BUF)
}

/// The link holding an established connection by that id.
fn established(s: &WsState, id: u16) -> Option<usize> {
    (0..WS_LINKS).find(|&i| {
        s.links[i].phase != WsPhase::Disconnected
            && s.links[i].conn_present != 0
            && s.links[i].conn_id == id
    })
}

/// Take at most one message to send, and place it on the link it names.
///
/// One at a time, and nothing new until the last is placed: see `pending`.
unsafe fn pump_ws_in(s: &mut WsState, sys: &SyscallTable, now: u64) {
    if s.ws_in < 0 || s.draining != 0 {
        return;
    }
    if s.pending_len == 0 {
        if (sys.channel_poll)(s.ws_in, 1) & 1 == 0 {
            return;
        }
        let n = (sys.channel_read)(s.ws_in, s.pending.as_mut_ptr(), WSF_ENVELOPE_MAX);
        if n < wsf::FRAME_HDR as i32 {
            return;
        }
        s.pending_len = n as u16;
    }
    let held = s.pending_len as usize;
    let i = wsf::conn_id(&s.pending) as usize;
    if i >= WS_LINKS {
        s.pending_len = 0;
        return;
    }
    // Not ready to carry it: keep it and come back. The link may be mid-send,
    // still opening, or already closing.
    if s.links[i].phase != WsPhase::Ready
        || s.links[i].closing != 0
        || s.links[i].req_sent != s.links[i].req_len
    {
        // A link that will never be ready would hold this forever, so one
        // that has gone releases it instead.
        if s.links[i].phase == WsPhase::Disconnected && s.links[i].wanted == 0 {
            s.pending_len = 0;
        }
        return;
    }
    let opcode = wsf::opcode(&s.pending);
    let len = (wsf::payload_len(&s.pending) as usize).min(held - wsf::FRAME_HDR);
    let mut body = [0u8; MESSAGE_MAX];
    let take = len.min(MESSAGE_MAX);
    body[..take].copy_from_slice(&s.pending[wsf::FRAME_HDR..wsf::FRAME_HDR + take]);
    s.pending_len = 0;
    if opcode == ws_op::CLOSE {
        protocol_close(s, i, 1000, now);
        return;
    }
    if opcode == ws_op::TEXT && !valid_utf8(&body[..take]) {
        protocol_close(s, i, 1007, now);
        return;
    }
    let Some(mask) = next_mask(s) else {
        feed(s, i, sys, WsEv::NetError, now);
        return;
    };
    let mut out = [0u8; REQ_BUF];
    if let Some(n) = ws_frame(opcode, &body[..take], mask, &mut out) {
        s.links[i].req[..n].copy_from_slice(&out[..n]);
        stage(s, i, n);
    }
}

/// Drain the shared transport lane, giving each frame to its link.
unsafe fn pump_net_in(s: &mut WsState, sys: &SyscallTable, now: u64) {
    if s.net_in >= 0 {
        for _ in 0..8 {
            // Leave the next transport event in its channel until every
            // link has room for it. Which link it is for is not known
            // until it has been read, and a frame read without room is a
            // frame truncated under pressure -- so the room that has to be
            // there is the room of the link with the least of it.
            if !room_for_a_frame(s) {
                break;
            }
            let poll = (sys.channel_poll)(s.net_in, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg, plen) = net_read_frame(sys, s.net_in, s.nbuf.as_mut_ptr(), NET_BUF);
            if msg == 0 {
                break;
            }
            let payload = core::slice::from_raw_parts(s.nbuf.as_ptr().add(NET_FRAME_HDR), plen);
            // One transport lane carries every link's traffic, so the
            // frame says which link it is for -- by connection id, or by
            // the dial in flight for the frames that answer a connect.
            let Some(i) = link_for(s, msg, payload, plen) else {
                continue;
            };
            match msg {
                NET_MSG_CONNECTED => {
                    let (cid, _tag) = net_proto::connected_parts(payload);
                    s.links[i].conn_id = cid;
                    s.links[i].conn_present = 1;
                    feed(s, i, sys, WsEv::Connected, now);
                }
                NET_MSG_DATA => {
                    if plen > 2 {
                        let data_len = plen - 2;
                        let space = ACC_BUF - s.links[i].acc_len as usize;
                        let take = if data_len < space { data_len } else { space };
                        core::ptr::copy_nonoverlapping(
                            payload.as_ptr().add(2),
                            s.links[i].acc.as_mut_ptr().add(s.links[i].acc_len as usize),
                            take,
                        );
                        s.links[i].acc_len += take as u32;
                        if s.links[i].phase == WsPhase::AwaitUpgrade {
                            let al = s.links[i].accept_len as usize;
                            let mut acc = [0u8; 32];
                            acc[..al].copy_from_slice(&s.links[i].accept[..al]);
                            if let Some(ok) = ws_verify_upgrade(
                                &s.links[i].acc[..s.links[i].acc_len as usize],
                                &acc[..al],
                            ) {
                                // Consume the header block; keep any trailing frame bytes.
                                let mut at = 0;
                                let mut hend = s.links[i].acc_len as usize;
                                while at + 3 < s.links[i].acc_len as usize {
                                    if &s.links[i].acc[at..at + 4] == b"\r\n\r\n" {
                                        hend = at + 4;
                                        break;
                                    }
                                    at += 1;
                                }
                                let rem = s.links[i].acc_len as usize - hend;
                                let mut k = 0;
                                while k < rem {
                                    s.links[i].acc[k] = s.links[i].acc[hend + k];
                                    k += 1;
                                }
                                s.links[i].acc_len = rem as u32;
                                feed(
                                    s,
                                    i,
                                    sys,
                                    if ok {
                                        WsEv::Upgraded
                                    } else {
                                        WsEv::UpgradeFailed
                                    },
                                    now,
                                );
                            }
                        }
                        drain_messages(s, i, now);
                    }
                }
                NET_MSG_CLOSED => {
                    feed(s, i, sys, WsEv::PeerClosed, now);
                }
                NET_MSG_ERROR => {
                    // `link_for` has already decided this error is this
                    // link's: a tagged one answers its dial, an untagged
                    // one names its established connection. The contract
                    // states a tagged error's conn_id is meaningless, which
                    // is why the two are told apart by the tag and not by
                    // the id.
                    feed(s, i, sys, WsEv::NetError, now);
                }
                _ => {}
            }
        }
    }
}

/// One link's own work: its dial, its frames, its close.
unsafe fn pump_link(s: &mut WsState, i: usize, sys: &SyscallTable, now: u64) -> i32 {
    unsafe {
        if s.links[i].phase == WsPhase::Disconnected && !close_transport(s, i) {
            return 0;
        }
        // A dial is answered by a frame carrying this module's requester tag
        // and nothing finer, so only one link may have one outstanding.
        if s.links[i].phase == WsPhase::Disconnected
            && s.draining == 0
            && s.links[i].wanted != 0
            && s.ep_hex_len > 0
            && dialling(s).is_none()
        {
            feed(s, i, sys, WsEv::Start, now);
        }
        // Re-offer anything a full `message_out` refused earlier, without
        // waiting for the peer to send more.
        drain_messages(s, i, now);

        // An open names the link and the resource. It is taken only when that
        // link is free, so a record is never dropped for arriving while the
        // link it names is busy -- it waits in the channel instead.
        if s.open_in >= 0 && s.draining == 0 {
            let mut record = [0u8; NAME_BUF + 1];
            let peek = (sys.channel_poll)(s.open_in, 1);
            if peek > 0 && (peek as u32 & 1) != 0 {
                let n = (sys.channel_read)(s.open_in, record.as_mut_ptr(), record.len());
                if n >= 2 {
                    let Some((want, path)) = parse_open(record.get(..n as usize).unwrap_or(&[]))
                    else {
                        return 0;
                    };
                    let len = path.len().min(NAME_BUF);
                    if s.links[want].wanted == 0 {
                        s.links[want] = Link::EMPTY;
                        s.links[want].path[..len].copy_from_slice(&path[..len]);
                        s.links[want].path_len = len as u16;
                        s.links[want].wanted = 1;
                    } else {
                        // The link is already spoken for. Saying so is better
                        // than opening a second one the consumer will address
                        // as the first.
                        emit_event(s, want, event::FAILED, 0);
                    }
                }
            }
        }

        // A channel is an octet stream: each bounded read becomes one message.
        // Do not consume another chunk until the transport accepts this frame.
        if s.links[i].phase == WsPhase::Ready
            && s.draining == 0
            && s.links[i].closing == 0
            && s.links[i].req_sent == s.links[i].req_len
            && s.request_in >= 0
            && (sys.channel_poll)(s.request_in, 1) & 1 != 0
        {
            let Some(mask) = next_mask(s) else {
                feed(s, i, sys, WsEv::NetError, now);
                return 0;
            };
            let mut payload = [0u8; REQ_BUF - 8];
            let n = (sys.channel_read)(s.request_in, payload.as_mut_ptr(), payload.len());
            if n > 0 {
                if s.request_opcode == ws_op::TEXT && !valid_utf8(&payload[..n as usize]) {
                    protocol_close(s, i, 1007, now);
                    return 0;
                }
                if let Some(len) = ws_frame(
                    s.request_opcode,
                    &payload[..n as usize],
                    mask,
                    &mut s.links[i].req,
                ) {
                    stage(s, i, len);
                }
            }
        }

        if s.links[i].conn_present != 0 && s.links[i].req_sent < s.links[i].req_len {
            let max_chunk = 1600 - NET_FRAME_HDR - 2;
            while s.links[i].req_sent < s.links[i].req_len {
                let poll = (sys.channel_poll)(s.net_out, 0x02);
                if poll <= 0 || (poll as u32 & 0x02) == 0 {
                    break;
                }
                let remaining = (s.links[i].req_len - s.links[i].req_sent) as usize;
                let chunk = if remaining < max_chunk {
                    remaining
                } else {
                    max_chunk
                };
                let total_payload = chunk + 2;
                s.nbuf[0] = NET_CMD_SEND;
                s.nbuf[1] = (total_payload & 0xff) as u8;
                s.nbuf[2] = (total_payload >> 8) as u8;
                net_proto::put_conn_id(&mut s.nbuf[NET_FRAME_HDR..], s.links[i].conn_id);
                core::ptr::copy_nonoverlapping(
                    s.links[i].req.as_ptr().add(s.links[i].req_sent as usize),
                    s.nbuf.as_mut_ptr().add(NET_FRAME_HDR + 2),
                    chunk,
                );
                // All-or-nothing: the offset advances only over bytes the
                // channel actually took. A short or refused write that still
                // advanced it would skip those bytes forever, and the peer
                // would see a truncated HTTP upgrade or WS frame.
                let total = NET_FRAME_HDR + total_payload;
                if (sys.channel_write)(s.net_out, s.nbuf.as_ptr(), total) != total as i32 {
                    break;
                }
                s.links[i].req_sent += chunk as u16;
            }
        }

        if matches!(
            s.links[i].phase,
            WsPhase::Connecting | WsPhase::AwaitUpgrade
        ) {
            let budget = if s.links[i].phase == WsPhase::Connecting {
                CONNECT_TIMEOUT_MS
            } else {
                REPLY_TIMEOUT_MS
            };
            if now.wrapping_sub(s.links[i].started_ms) > budget {
                feed(s, i, sys, WsEv::NetError, now);
            }
        }

        if s.draining != 0
            && s.links[i].phase == WsPhase::Ready
            && s.links[i].closing == 0
            && s.links[i].req_sent == s.links[i].req_len
            && control(s, i, ws_op::CLOSE, &1000u16.to_be_bytes(), now)
        {
            s.links[i].closing = 2;
            s.links[i].close_started_ms = now;
        }
        if s.links[i].closing != 0
            && s.links[i].req_sent == s.links[i].req_len
            && (s.links[i].closing == 1
                || now.wrapping_sub(s.links[i].close_started_ms) >= CLOSE_TIMEOUT_MS)
        {
            if !close_transport(s, i) {
                return 0;
            }
            s.links[i].phase = WsPhase::Disconnected;
            // The close is over, so this link is no longer holding one open.
            // `room_for_a_frame` reads that flag across every link before any
            // transport bytes are taken, so a link that left it set would stop
            // the other three being read from for as long as it stayed down.
            s.links[i].closing = 0;
            s.draining = 1;
        }
        if s.draining != 0 && s.links[i].phase == WsPhase::Disconnected {
            return if close_transport(s, i) { 1 } else { 0 };
        }
        0
    }
}
