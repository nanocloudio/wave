//! Migrated from Chronicle (`modules/foundation/websocket`) per
//! `rfc_connector_strategy.md` §10.1: an RFC-6455 HTTP/1.1 ws CLIENT. Fluxor has
//! only server-side `ws_stream` + a WS-over-HTTP/2 client, so this filled a real
//! gap and is NOT a duplicate. Wave now owns RFC 6455 byte semantics for both
//! roles — this client, `ws_stream`'s `WsFrame` adapter, and the `http` server's
//! upgrade path — over Fluxor transports.
//!
//! WebSocket (RFC 6455) connector — a GENUINE per-protocol Fluxor foundation
//! module for the "protocol upgrade + masked bidirectional framing" class. The
//! connection starts as HTTP: the client sends an Upgrade request with a random
//! Sec-WebSocket-Key and CRYPTOGRAPHICALLY VERIFIES the server's
//! Sec-WebSocket-Accept (= base64(SHA1(key ++ magic))) before switching. After
//! the 101, both sides exchange frames and client frames are masked (payload XOR
//! a per-frame key). A protocol that mutates from HTTP into a masked frame stream
//! and verifies the switch is a stateful session, not request/reply.
//!
//! On boot it upgrades, sends a masked text `message`, and emits every server
//! frame's payload on `message_out` (answering PING with PONG). Protocol +
//! crypto in Wave's shared cores: `b64_core.rs` (Base64), `sha1_core.rs`
//! (SHA-1), `ws_core.rs`.
//!
//! Ports:  net_in/net_out (transport), message_out (received frame payloads).
//! Params: `endpoint` (hex `[ip:4][port:2 LE]`), `host`, `path`, `message`.

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
              chronicle's and lattice's PIC modules carry. Newly required because \
              `fluxor ci` clippies modules/** directly now that Wave has no root manifest \
              for it to lint instead."
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
// harness compile identical bytes (rfc_connector_strategy.md §9).
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/b64.rs"); // b64_encode
include!("../../common/hex_core.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs"); // sha1
include!("../../common/ws_frame_core.rs");
include!("../../common/ws_core.rs");

// The NetProto opcodes and identity accessors come from the owning contract
// — never redeclared locally, so a wire change there is a compile change here
// (rfc_hardening.md §5.2).
use abi::contracts::net::net_proto::{
    self, CMD_CLOSE as NET_CMD_CLOSE, CMD_CONNECT as NET_CMD_CONNECT, CMD_SEND as NET_CMD_SEND,
    MSG_CLOSED as NET_MSG_CLOSED, MSG_CONNECTED as NET_MSG_CONNECTED, MSG_DATA as NET_MSG_DATA,
    MSG_ERROR as NET_MSG_ERROR,
};

const NET_BUF: usize = 2048;
const REQ_BUF: usize = 512;
const ACC_BUF: usize = 8192;
const NAME_BUF: usize = 128;
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
    mask_ctr: u32,
    sent_msg: u8,

    // The expected Sec-WebSocket-Accept for the key we sent.
    accept: [u8; 32],
    accept_len: u16,

    req: [u8; REQ_BUF],
    req_len: u16,
    req_sent: u16,
    acc: [u8; ACC_BUF],
    acc_len: u32,

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
        s.mask_ctr = 0;
        s.sent_msg = 0;
        s.accept_len = 0;
        s.req_len = 0;
        s.req_sent = 0;
        s.acc_len = 0;
        s.frames = 0;
        s.errors = 0;
        parse_tlv(s, params, params_len);
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

/// Derive a 4-byte frame mask from time/tag/counter.
unsafe fn next_mask(s: &mut WsState, now: u64) -> [u8; 4] {
    s.mask_ctr = s.mask_ctr.wrapping_add(1);
    let mut x = now ^ ((s.tag as u64) << 40) ^ ((s.mask_ctr as u64).wrapping_mul(0x9E37_79B9));
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    (x as u32).to_le_bytes()
}

/// Hand one received application message to `message_out`.
///
/// Returns whether the caller may consume the frame that carried it. `false`
/// means `message_out` refused the write, and the frame must stay in `acc` so
/// the identical bytes are offered again next step — a message the peer sent
/// successfully is not ours to drop because a downstream reader is briefly
/// behind.
///
/// An unwired `message_out` returns `true`: nobody asked for the data, so
/// there is nothing to deliver and nothing to retry.
#[must_use]
unsafe fn emit_message(s: &mut WsState, start: usize, end: usize) -> bool {
    if s.message_out < 0 {
        s.frames = s.frames.wrapping_add(1);
        return true;
    }
    if end > s.acc_len as usize || end < start {
        return true;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.message_out, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let len = end - start;
    if (sys.channel_write)(s.message_out, s.acc.as_ptr().add(start), len) != len as i32 {
        return false;
    }
    s.frames = s.frames.wrapping_add(1);
    true
}

unsafe fn stage(s: &mut WsState, n: usize) {
    s.req_len = n as u16;
    s.req_sent = 0;
}

/// Drive one FSM transition.
///
/// The phase advances only when the action it carries actually reached the
/// transport. `net_write_frame` returns 0 on backpressure precisely so a caller
/// can retry rather than treat a dropped frame as committed; advancing anyway
/// left this client waiting in `Connecting` for a reply to a CONNECT the
/// channel had refused, until the connect deadline failed the exchange.
/// Parse and deliver whatever complete frames the accumulator holds.
///
/// Called once per step rather than only when new bytes arrive: a frame the
/// consumer refused stays in `acc`, and if this ran only on fresh input it
/// would sit there until the peer happened to send something else — which,
/// for a peer waiting on a reply, is never.
unsafe fn drain_messages(s: &mut WsState, now: u64) {
    if s.phase != WsPhase::Ready {
        return;
    }
    while let Some(f) = ws_parse_frame(&s.acc[..s.acc_len as usize]) {
        if f.opcode == ws_op::TEXT || f.opcode == ws_op::BINARY {
            // Refused downstream: leave the frame in `acc` and stop draining.
            // It is re-parsed and re-offered next step.
            if !emit_message(s, f.payload_start, f.payload_end) {
                return;
            }
        } else if f.opcode == ws_op::PING {
            // answer with a masked PONG
            let mask = next_mask(s, now);
            let mut out = [0u8; 128];
            let pl2 = (f.payload_end - f.payload_start).min(120);
            let mut body = [0u8; 120];
            body[..pl2].copy_from_slice(&s.acc[f.payload_start..f.payload_start + pl2]);
            if let Some(n) = ws_frame(ws_op::PONG, &body[..pl2], mask, &mut out) {
                s.req[..n].copy_from_slice(&out[..n]);
                stage(s, n);
            }
        }
        let total = f.total;
        let rem = s.acc_len as usize - total;
        let mut k = 0;
        while k < rem {
            s.acc[k] = s.acc[total + k];
            k += 1;
        }
        s.acc_len = rem as u32;
        if s.acc_len == 0 {
            return;
        }
    }
}

unsafe fn feed(s: &mut WsState, sys: &SyscallTable, ev: WsEv, now: u64) {
    let (action, next) = ws_transition(s.phase, ev);
    match action {
        WsAct::Connect => {
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
            // Random 16-byte key -> base64; remember the expected accept.
            let mask = next_mask(s, now);
            let mask2 = next_mask(s, now ^ 0x5555);
            let mut raw = [0u8; 16];
            raw[..4].copy_from_slice(&mask);
            raw[4..8].copy_from_slice(&mask2);
            raw[8..12].copy_from_slice(&next_mask(s, now ^ 0xAAAA));
            raw[12..16].copy_from_slice(&next_mask(s, now ^ 0x1234));
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
            }
        }
        WsAct::Fail => {
            if s.conn_present != 0 {
                let mut close = [0u8; 2];
                net_proto::put_conn_id(&mut close, s.conn_id);
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
        let mask = next_mask(s, now);
        let mut out = [0u8; REQ_BUF];
        if let Some(n) = ws_frame(ws_op::TEXT, &msg[..ml], mask, &mut out) {
            s.req[..n].copy_from_slice(&out[..n]);
            stage(s, n);
            s.sent_msg = 1;
        }
        s.acc_len = 0;
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

        if s.phase == WsPhase::Disconnected && s.draining == 0 && s.ep_hex_len > 0 {
            feed(s, sys, WsEv::Start, now);
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

        // Drain reports finished only once the CLOSE has actually been taken
        // by the transport. Reporting on an unconfirmed write drops the
        // connection locally while the peer's socket stays open: the instance
        // is torn down, the CLOSE never goes out, and the far end waits on a
        // half of a connection nobody owns any more. A refused CLOSE simply
        // retries next step.
        if s.draining == 1 && matches!(s.phase, WsPhase::Disconnected | WsPhase::Ready) {
            if s.conn_present != 0 {
                let mut close = [0u8; 2];
                net_proto::put_conn_id(&mut close, s.conn_id);
                if net_write_frame(
                    sys,
                    s.net_out,
                    NET_CMD_CLOSE,
                    close.as_ptr(),
                    2,
                    s.nbuf.as_mut_ptr(),
                    NET_BUF,
                ) == 0
                {
                    return 0;
                }
                s.conn_id = 0;
                s.conn_present = 0;
            }
            return 1;
        }
        0
    }
}
