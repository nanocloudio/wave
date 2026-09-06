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

const NET_BUF: usize = 2048;
const REQ_BUF: usize = 512;
const ACC_BUF: usize = 8192;
const NAME_BUF: usize = 128;
const MESSAGE_MAX: usize = 2048;
const CLOSE_TIMEOUT_MS: u64 = 5000;
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const REPLY_TIMEOUT_MS: u64 = 15_000;

#[repr(C)]
struct WsState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    request_in: i32,
    message_out: i32,

    ip: [u8; 4],
    port: u16,
    ep_hex: [u8; 16],
    ep_hex_len: u16,
    host: [u8; NAME_BUF],
    host_len: u16,
    path: [u8; NAME_BUF],
    path_len: u16,
    message: [u8; NAME_BUF],
    message_len: u16,

    phase: WsPhase,
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
    sent_msg: u8,
    request_opcode: u8,

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

    nbuf: [u8; NET_BUF],
    frames: u32,
    errors: u32,
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
        let mut i = 0usize;
        while i < len && (s.path_len as usize) < NAME_BUF {
            s.path[s.path_len as usize] = *d.add(i); s.path_len += 1; i += 1;
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
        s.ip = [0u8; 4];
        s.port = 0;
        s.ep_hex_len = 0;
        s.host_len = 0;
        s.path_len = 0;
        s.message_len = 0;
        s.phase = WsPhase::Disconnected;
        s.conn_id = 0;
        s.conn_present = 0;
        s.tag = dev_requester_tag(sys);
        s.started_ms = 0;
        s.draining = 0;
        s.sent_msg = 0;
        s.request_opcode = ws_op::TEXT;
        s.accept_len = 0;
        s.req_len = 0;
        s.req_sent = 0;
        s.acc_len = 0;
        s.assembled_len = 0;
        s.assembled_opcode = 0;
        s.assembled_ready = 0;
        s.closing = 0;
        s.close_started_ms = 0;
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
        if s.path_len == 0 {
            s.path[0] = b'/';
            s.path_len = 1;
        }
        if s.message_len == 0 {
            s.message[..5].copy_from_slice(b"hello");
            s.message_len = 5;
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
unsafe fn close_transport(s: &mut WsState) -> bool {
    if s.conn_present == 0 {
        return true;
    }
    let mut close = [0u8; 2];
    net_proto::put_conn_id(&mut close, s.conn_id);
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
    s.conn_present = 0;
    s.conn_id = 0;
    true
}

/// Application output is a complete bounded message, retained on refusal.
unsafe fn emit_message(s: &mut WsState) -> bool {
    if s.assembled_ready == 0 {
        return true;
    }
    let len = s.assembled_len as usize;
    if s.message_out >= 0
        && len > 0
        && ((*s.syscalls).channel_write)(s.message_out, s.assembled.as_ptr(), len) != len as i32
    {
        return false;
    }
    s.frames = s.frames.wrapping_add(1);
    s.assembled_ready = 0;
    s.assembled_len = 0;
    s.assembled_opcode = 0;
    true
}

unsafe fn stage(s: &mut WsState, n: usize) {
    s.req_len = n as u16;
    s.req_sent = 0;
}

unsafe fn control(s: &mut WsState, opcode: u8, payload: &[u8], now: u64) -> bool {
    if s.req_sent < s.req_len {
        return false;
    }
    let Some(mask) = next_mask(s) else {
        feed(s, &*s.syscalls, WsEv::NetError, now);
        return false;
    };
    let Some(n) = ws_frame(opcode, payload, mask, &mut s.req) else {
        return false;
    };
    stage(s, n);
    true
}

unsafe fn protocol_close(s: &mut WsState, code: u16, now: u64) {
    if control(s, ws_op::CLOSE, &code.to_be_bytes(), now) {
        s.closing = 1;
        s.close_started_ms = now;
        s.errors = s.errors.wrapping_add(1);
        s.acc_len = 0;
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

unsafe fn drain_messages(s: &mut WsState, now: u64) {
    if s.phase != WsPhase::Ready || s.closing == 1 || !emit_message(s) {
        return;
    }
    // Fixed work budget even when a peer pipelines zero-length control frames.
    for _ in 0..16 {
        let h = match ws_decode_header(&s.acc[..s.acc_len as usize]) {
            WsHeaderParse::Incomplete => return,
            WsHeaderParse::Invalid => {
                protocol_close(s, 1002, now);
                return;
            }
            WsHeaderParse::Header(h) => h,
        };
        if h.masked {
            protocol_close(s, 1002, now);
            return;
        }
        if h.payload_len > MESSAGE_MAX as u64 {
            protocol_close(s, 1009, now);
            return;
        }
        let total = h.header_len + h.payload_len as usize;
        if total > s.acc_len as usize {
            return;
        }
        if h.opcode == ws_op::CLOSE {
            let mut payload = [0u8; 125];
            let n = h.payload_len as usize;
            payload[..n].copy_from_slice(&s.acc[h.header_len..total]);
            if let Err(code) = valid_close(&payload[..n]) {
                protocol_close(s, code, now);
                return;
            }
            if s.closing == 2 {
                s.closing = 1;
            } else if control(s, ws_op::CLOSE, &payload[..n], now) {
                s.closing = 1;
                s.close_started_ms = now;
            } else {
                return;
            }
        } else if h.opcode == ws_op::PING {
            if s.closing == 0 {
                let mut payload = [0u8; 125];
                let n = h.payload_len as usize;
                payload[..n].copy_from_slice(&s.acc[h.header_len..total]);
                if !control(s, ws_op::PONG, &payload[..n], now) {
                    return;
                }
            }
        } else if matches!(h.opcode, ws_op::TEXT | ws_op::BINARY | ws_op::CONT) && s.closing == 0 {
            if (h.opcode == ws_op::CONT) != (s.assembled_opcode != 0) {
                protocol_close(s, 1002, now);
                return;
            }
            if h.opcode != ws_op::CONT {
                s.assembled_opcode = h.opcode;
            }
            let have = s.assembled_len as usize;
            let n = h.payload_len as usize;
            if have + n > MESSAGE_MAX {
                protocol_close(s, 1009, now);
                return;
            }
            s.assembled[have..have + n].copy_from_slice(&s.acc[h.header_len..total]);
            s.assembled_len = (have + n) as u16;
            if h.fin {
                if s.assembled_opcode == ws_op::TEXT && !valid_utf8(&s.assembled[..have + n]) {
                    protocol_close(s, 1007, now);
                    return;
                }
                s.assembled_ready = 1;
            }
        }
        s.acc.copy_within(total..s.acc_len as usize, 0);
        s.acc_len -= total as u32;
        if s.closing != 0 || !emit_message(s) {
            return;
        }
    }
}

unsafe fn feed(s: &mut WsState, sys: &SyscallTable, ev: WsEv, now: u64) {
    let (action, next) = ws_transition(s.phase, ev);
    match action {
        WsAct::Connect => {
            s.assembled_len = 0;
            s.assembled_opcode = 0;
            s.assembled_ready = 0;
            s.closing = 0;
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
            s.started_ms = now;
        }
        WsAct::SendUpgrade => {
            let mut raw = [0u8; 16];
            if dev_csprng_fill(sys, raw.as_mut_ptr(), raw.len()) != 0 {
                feed(s, sys, WsEv::NetError, now);
                return;
            }
            let mut key_b64 = [0u8; 24];
            let kn = b64_encode(&raw, &mut key_b64).unwrap_or(0);
            if let Some(an) = ws_accept(&key_b64[..kn], &mut s.accept) {
                s.accept_len = an as u16;
            }
            let hl = s.host_len as usize;
            let pl = s.path_len as usize;
            let mut host = [0u8; NAME_BUF];
            host[..hl].copy_from_slice(&s.host[..hl]);
            let mut path = [0u8; NAME_BUF];
            path[..pl].copy_from_slice(&s.path[..pl]);
            let mut out = [0u8; REQ_BUF];
            if let Some(n) = ws_upgrade_request(&host[..hl], &path[..pl], &key_b64[..kn], &mut out)
            {
                s.req[..n].copy_from_slice(&out[..n]);
                stage(s, n);
                s.started_ms = now;
                s.acc_len = 0;
            } else {
                feed(s, sys, WsEv::NetError, now);
                return;
            }
        }
        WsAct::Fail => {
            let _ = close_transport(s);
            s.acc_len = 0;
            s.req_len = 0;
            s.req_sent = 0;
            s.errors = s.errors.wrapping_add(1);
        }
        WsAct::None => {}
    }
    if next == WsPhase::Ready && s.phase != WsPhase::Ready {
        // On upgrade, send the configured message as a masked text frame.
        let ml = s.message_len as usize;
        let mut msg = [0u8; NAME_BUF];
        msg[..ml].copy_from_slice(&s.message[..ml]);
        let Some(mask) = next_mask(s) else {
            feed(s, &*s.syscalls, WsEv::NetError, now);
            return;
        };
        let mut out = [0u8; REQ_BUF];
        if let Some(n) = ws_frame(ws_op::TEXT, &msg[..ml], mask, &mut out) {
            s.req[..n].copy_from_slice(&out[..n]);
            stage(s, n);
            s.sent_msg = 1;
        }
        // The upgrade reader retained any coalesced WebSocket bytes.
        // They belong to the new session and must survive this transition.
    }
    s.phase = next;
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut WsState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        if s.phase == WsPhase::Disconnected && !close_transport(s) {
            return 0;
        }
        if s.phase == WsPhase::Disconnected && s.draining == 0 && s.ep_hex_len > 0 {
            feed(s, sys, WsEv::Start, now);
        }

        if s.net_in >= 0 {
            for _ in 0..8 {
                drain_messages(s, now);
                // Leave the next transport event in its channel until there is
                // room for it. Accepted frames are never truncated under pressure.
                if s.closing == 1 || ACC_BUF - (s.acc_len as usize) < NET_BUF {
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
                match msg {
                    NET_MSG_CONNECTED if s.phase == WsPhase::Connecting => {
                        if plen >= 3 {
                            let (cid, tag) = net_proto::connected_parts(payload);
                            if tag == s.tag {
                                s.conn_id = cid;
                                s.conn_present = 1;
                                feed(s, sys, WsEv::Connected, now);
                            }
                        }
                    }
                    NET_MSG_DATA if s.phase != WsPhase::Disconnected => {
                        if plen > 2 && net_proto::conn_id(payload) == s.conn_id {
                            let data_len = plen - 2;
                            let space = ACC_BUF - s.acc_len as usize;
                            let take = if data_len < space { data_len } else { space };
                            core::ptr::copy_nonoverlapping(
                                payload.as_ptr().add(2),
                                s.acc.as_mut_ptr().add(s.acc_len as usize),
                                take,
                            );
                            s.acc_len += take as u32;
                            if s.phase == WsPhase::AwaitUpgrade {
                                let al = s.accept_len as usize;
                                let mut acc = [0u8; 32];
                                acc[..al].copy_from_slice(&s.accept[..al]);
                                if let Some(ok) =
                                    ws_verify_upgrade(&s.acc[..s.acc_len as usize], &acc[..al])
                                {
                                    // Consume the header block; keep any trailing frame bytes.
                                    let mut i = 0;
                                    let mut hend = s.acc_len as usize;
                                    while i + 3 < s.acc_len as usize {
                                        if &s.acc[i..i + 4] == b"\r\n\r\n" {
                                            hend = i + 4;
                                            break;
                                        }
                                        i += 1;
                                    }
                                    let rem = s.acc_len as usize - hend;
                                    let mut k = 0;
                                    while k < rem {
                                        s.acc[k] = s.acc[hend + k];
                                        k += 1;
                                    }
                                    s.acc_len = rem as u32;
                                    feed(
                                        s,
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
                            drain_messages(s, now);
                        }
                    }
                    NET_MSG_CLOSED if s.phase != WsPhase::Disconnected => {
                        if plen >= 2 && net_proto::conn_id(payload) == s.conn_id {
                            feed(s, sys, WsEv::PeerClosed, now);
                        }
                    }
                    NET_MSG_ERROR => {
                        // A connect-phase failure is matched on the TAG ALONE:
                        // the contract states its `conn_id` is meaningless (0
                        // when the dial failed before a slot was allocated,
                        // indistinguishable from a valid id 0). The
                        // established-connection clause is gated on
                        // `conn_present` AND on the error being UNTAGGED — a
                        // tagged error is some module's connect failure, and
                        // its meaningless conn_id colliding with ours must not
                        // read as our established connection failing.
                        let ours = if plen >= 3 {
                            let (cid, _errno, tag) = net_proto::error_parts(payload);
                            (s.phase == WsPhase::Connecting && tag == s.tag)
                                || (s.conn_present != 0
                                    && tag == net_proto::REQUESTER_TAG_NONE
                                    && cid == s.conn_id)
                        } else {
                            false
                        };
                        if ours {
                            feed(s, sys, WsEv::NetError, now);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Re-offer anything a full `message_out` refused earlier, without
        // waiting for the peer to send more.
        drain_messages(s, now);

        // A channel is an octet stream: each bounded read becomes one message.
        // Do not consume another chunk until the transport accepts this frame.
        if s.phase == WsPhase::Ready
            && s.draining == 0
            && s.closing == 0
            && s.req_sent == s.req_len
            && s.request_in >= 0
            && (sys.channel_poll)(s.request_in, 1) & 1 != 0
        {
            let Some(mask) = next_mask(s) else {
                feed(s, sys, WsEv::NetError, now);
                return 0;
            };
            let mut payload = [0u8; REQ_BUF - 8];
            let n = (sys.channel_read)(s.request_in, payload.as_mut_ptr(), payload.len());
            if n > 0 {
                if s.request_opcode == ws_op::TEXT && !valid_utf8(&payload[..n as usize]) {
                    protocol_close(s, 1007, now);
                    return 0;
                }
                if let Some(len) =
                    ws_frame(s.request_opcode, &payload[..n as usize], mask, &mut s.req)
                {
                    stage(s, len);
                }
            }
        }

        if s.conn_present != 0 && s.req_sent < s.req_len {
            let max_chunk = 1600 - NET_FRAME_HDR - 2;
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
                s.nbuf[0] = NET_CMD_SEND;
                s.nbuf[1] = (total_payload & 0xff) as u8;
                s.nbuf[2] = (total_payload >> 8) as u8;
                net_proto::put_conn_id(&mut s.nbuf[NET_FRAME_HDR..], s.conn_id);
                core::ptr::copy_nonoverlapping(
                    s.req.as_ptr().add(s.req_sent as usize),
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
                s.req_sent += chunk as u16;
            }
        }

        if matches!(s.phase, WsPhase::Connecting | WsPhase::AwaitUpgrade) {
            let budget = if s.phase == WsPhase::Connecting {
                CONNECT_TIMEOUT_MS
            } else {
                REPLY_TIMEOUT_MS
            };
            if now.wrapping_sub(s.started_ms) > budget {
                feed(s, sys, WsEv::NetError, now);
            }
        }

        if s.draining != 0
            && s.phase == WsPhase::Ready
            && s.closing == 0
            && s.req_sent == s.req_len
            && control(s, ws_op::CLOSE, &1000u16.to_be_bytes(), now)
        {
            s.closing = 2;
            s.close_started_ms = now;
        }
        if s.closing != 0
            && s.req_sent == s.req_len
            && (s.closing == 1 || now.wrapping_sub(s.close_started_ms) >= CLOSE_TIMEOUT_MS)
        {
            if !close_transport(s) {
                return 0;
            }
            s.phase = WsPhase::Disconnected;
            s.draining = 1;
        }
        if s.draining != 0 && s.phase == WsPhase::Disconnected {
            return if close_transport(s) { 1 } else { 0 };
        }
        0
    }
}
