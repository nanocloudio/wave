//! SMTP connector — a GENUINE per-protocol Fluxor foundation module for mail
//! SUBMISSION: the lockstep ESMTP conversation
//!   220 greeting -> EHLO/250 -> MAIL FROM/250 -> RCPT TO/250 -> DATA/354
//!   -> <message>.CRLF/250 -> QUIT/221
//! where each command waits on the 3-digit code of the previous multi-line
//! reply, and the message body is RFC 5321 dot-stuffed and terminated by
//! `\r\n.\r\n`. A reply-code-driven, multi-round-trip session over a
//! server-chosen greeting is not a stateless codec, so it is a compiled module.
//!
//! Protocol logic in the host-tested `modules/common/smtp_core.rs`; this file is the
//! I/O pump:
//! connect -> await greeting -> walk the command sequence -> emit a status.
//!
//! Ports:  net_in/net_out (transport), status_out (delivery result).
//! Params: `endpoint` (hex `[ip:4][port:2 LE]`), `helo` (EHLO domain),
//!         `mail_from`, `rcpt_to`, `body` (message headers+body).
//! Scope:  unauthenticated submission (no STARTTLS / AUTH) — the class most
//!         relay/sink deployments use behind a trusted boundary.

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

// Protocol logic + hex codec from `modules/common` — the same sources the host
// vector tests exercise, path-mounted exactly as `sip` mounts `sip_core`.
// Public under host-test only, so this module's lane-1 vectors
// (`tests/harness/tests/smtp_core.rs`) pin the same bytes the
// device compiles; private off host-test, so the firmware's symbol surface is
// unchanged.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/smtp_core.rs"]
mod smtp_core;
#[cfg(feature = "host-test")]
#[path = "../../common/smtp_core.rs"]
pub mod smtp_core;
use smtp_core::{
    smtp_body, smtp_data, smtp_ehlo, smtp_mail_from, smtp_on_reply, smtp_quit, smtp_rcpt_to,
    smtp_reply_line, SmtpCmd, SmtpPhase,
};

#[path = "../../common/hex_core.rs"]
mod hex_core;
use hex_core::hex_decode;

const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;

const NET_BUF: usize = 2048;
const REQ_BUF: usize = 4096;
/// Longest delivery-result line (`smtp: connection closed\n` is the longest
/// today); parked in state, so it is sized for the class rather than the
/// current maximum.
const STATUS_BUF: usize = 64;
const ACC_BUF: usize = 2048;
const NAME_BUF: usize = 128;
const BODY_BUF: usize = 2048;
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const REPLY_TIMEOUT_MS: u64 = 15_000;

#[repr(C)]
struct SmtpState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    status_out: i32,

    ip: [u8; 4],
    port: u16,
    ep_hex: [u8; 16],
    ep_hex_len: u16,
    helo: [u8; NAME_BUF],
    helo_len: u16,
    mail_from: [u8; NAME_BUF],
    mail_from_len: u16,
    rcpt_to: [u8; NAME_BUF],
    rcpt_to_len: u16,
    body: [u8; BODY_BUF],
    body_len: u16,

    phase: SmtpPhase,
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

    req: [u8; REQ_BUF],
    req_len: u16,
    req_sent: u16,
    acc: [u8; ACC_BUF],
    acc_len: u32,

    nbuf: [u8; NET_BUF],
    delivered: u32,
    errors: u32,
    /// The one delivery result this session owes, held until `status_out`
    /// accepts it. `status_len == 0` means nothing is owed.
    ///
    /// The module's contract is exactly one result per submission, and a
    /// channel that is briefly full is not a reason to break it: the previous
    /// behaviour polled, skipped the write when there was no room, and let the
    /// FSM go terminal anyway — so a caller waiting for the outcome of a
    /// message that had in fact been delivered waited forever.
    status: [u8; STATUS_BUF],
    status_len: u32,
}

define_params! {
    SmtpState;

    1, endpoint, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.ep_hex_len as usize) < 16 {
            s.ep_hex[s.ep_hex_len as usize] = *d.add(i); s.ep_hex_len += 1; i += 1;
        }
    };
    2, helo, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.helo_len as usize) < NAME_BUF {
            s.helo[s.helo_len as usize] = *d.add(i); s.helo_len += 1; i += 1;
        }
    };
    3, mail_from, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.mail_from_len as usize) < NAME_BUF {
            s.mail_from[s.mail_from_len as usize] = *d.add(i); s.mail_from_len += 1; i += 1;
        }
    };
    4, rcpt_to, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.rcpt_to_len as usize) < NAME_BUF {
            s.rcpt_to[s.rcpt_to_len as usize] = *d.add(i); s.rcpt_to_len += 1; i += 1;
        }
    };
    5, body, str, 0 => |s, d, len| {
        let mut i = 0usize;
        while i < len && (s.body_len as usize) < BODY_BUF {
            s.body[s.body_len as usize] = *d.add(i); s.body_len += 1; i += 1;
        }
    };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SmtpState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut SmtpState)).draining = 1;
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
        if state_size < core::mem::size_of::<SmtpState>() {
            return -2;
        }
        let s = &mut *(state as *mut SmtpState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.status_out = dev_channel_port(sys, 1, 1);
        s.ip = [0u8; 4];
        s.port = 0;
        s.ep_hex_len = 0;
        s.helo_len = 0;
        s.mail_from_len = 0;
        s.rcpt_to_len = 0;
        s.body_len = 0;
        s.phase = SmtpPhase::Disconnected;
        s.conn_id = 0;
        s.conn_present = 0;
        s.tag = dev_requester_tag(sys);
        s.started_ms = 0;
        s.draining = 0;
        s.req_len = 0;
        s.req_sent = 0;
        s.acc_len = 0;
        s.delivered = 0;
        s.status_len = 0;
        s.errors = 0;
        parse_tlv(s, params, params_len);
        let mut ep = [0u8; 8];
        if let Some(n) = hex_decode(&s.ep_hex[..s.ep_hex_len as usize], &mut ep) {
            if n >= 6 {
                s.ip = [ep[0], ep[1], ep[2], ep[3]];
                s.port = u16::from_le_bytes([ep[4], ep[5]]);
            }
        }
        // Default the EHLO domain when none was supplied.
        if s.helo_len == 0 {
            let def = b"localhost";
            s.helo[..def.len()].copy_from_slice(def);
            s.helo_len = def.len() as u16;
        }
        dev_log(sys, 3, b"[smtp] init".as_ptr(), 11);
        0
    }
}

/// Record the session's delivery result, to be handed to `status_out` as soon
/// as it will take it.
///
/// First writer wins. Exactly one result is owed per submission, and where a
/// later event would overwrite an earlier one the earlier is the outcome —
/// "delivered" followed by the connection closing describes a delivery, not a
/// connection failure.
unsafe fn emit_status(s: &mut SmtpState, text: &[u8]) {
    if s.status_out < 0 || s.status_len != 0 {
        return;
    }
    let n = text.len().min(STATUS_BUF);
    s.status[..n].copy_from_slice(&text[..n]);
    s.status_len = n as u32;
}

/// Hand the parked delivery result to `status_out`, retrying on a later step
/// while the channel refuses it. The channel takes a record whole or not at
/// all, so a rejected write leaves it intact and nothing is reported twice.
unsafe fn flush_status(s: &mut SmtpState) {
    if s.status_len == 0 || s.status_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.status_out, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let len = s.status_len as usize;
    if (sys.channel_write)(s.status_out, s.status.as_ptr(), len) != len as i32 {
        return;
    }
    s.status_len = 0;
}

/// Stage `bytes` as the outbound command to send (chunked in module_step).
unsafe fn stage_req(s: &mut SmtpState, bytes: &[u8], now: u64) {
    let n = bytes.len().min(REQ_BUF);
    s.req[..n].copy_from_slice(&bytes[..n]);
    s.req_len = n as u16;
    s.req_sent = 0;
    s.started_ms = now;
}

/// Build the command for `cmd` into a scratch buffer and stage it.
unsafe fn stage_cmd(s: &mut SmtpState, cmd: SmtpCmd, now: u64) {
    let mut out = [0u8; REQ_BUF];
    let built = match cmd {
        SmtpCmd::SendEhlo => {
            let hl = s.helo_len as usize;
            let mut h = [0u8; NAME_BUF];
            h[..hl].copy_from_slice(&s.helo[..hl]);
            smtp_ehlo(&h[..hl], &mut out)
        }
        SmtpCmd::SendMailFrom => {
            let fl = s.mail_from_len as usize;
            let mut f = [0u8; NAME_BUF];
            f[..fl].copy_from_slice(&s.mail_from[..fl]);
            smtp_mail_from(&f[..fl], &mut out)
        }
        SmtpCmd::SendRcptTo => {
            let rl = s.rcpt_to_len as usize;
            let mut r = [0u8; NAME_BUF];
            r[..rl].copy_from_slice(&s.rcpt_to[..rl]);
            smtp_rcpt_to(&r[..rl], &mut out)
        }
        SmtpCmd::SendData => smtp_data(&mut out),
        SmtpCmd::SendBody => {
            let bl = s.body_len as usize;
            let mut b = [0u8; BODY_BUF];
            b[..bl].copy_from_slice(&s.body[..bl]);
            smtp_body(&b[..bl], &mut out)
        }
        SmtpCmd::SendQuit => smtp_quit(&mut out),
        SmtpCmd::Complete | SmtpCmd::Fail => None,
    };
    if let Some(n) = built {
        stage_req(s, &out[..n], now);
    }
}

/// Advance the conversation on a FINAL reply `code`.
unsafe fn on_reply(s: &mut SmtpState, code: u16, now: u64) {
    let (cmd, next) = smtp_on_reply(s.phase, code);
    s.phase = next;
    match cmd {
        SmtpCmd::Complete => {
            s.delivered = s.delivered.wrapping_add(1);
            emit_status(s, b"smtp: delivered\n");
        }
        SmtpCmd::Fail => {
            s.errors = s.errors.wrapping_add(1);
            emit_status(s, b"smtp: rejected\n");
            if s.conn_present != 0 {
                let close = s.conn_id.to_le_bytes();
                net_write_frame(
                    &*s.syscalls,
                    s.net_out,
                    NET_CMD_CLOSE,
                    close.as_ptr(),
                    2,
                    s.nbuf.as_mut_ptr(),
                    NET_BUF,
                );
                s.conn_id = 0;
                s.conn_present = 0;
            }
        }
        other => stage_cmd(s, other, now),
    }
}

/// Drain complete reply lines out of `acc`; act on the FINAL line of each reply,
/// skipping the intermediate lines of a multi-line reply.
unsafe fn drain_replies(s: &mut SmtpState, now: u64) {
    loop {
        if matches!(s.phase, SmtpPhase::Done | SmtpPhase::Failed) {
            break;
        }
        let (code, is_final, len) = match smtp_reply_line(&s.acc[..s.acc_len as usize]) {
            Some(v) => v,
            None => break,
        };
        // Consume the line.
        let rem = s.acc_len as usize - len;
        let mut k = 0usize;
        while k < rem {
            s.acc[k] = s.acc[len + k];
            k += 1;
        }
        s.acc_len = rem as u32;
        if is_final {
            on_reply(s, code, now);
        }
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut SmtpState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // Connect once params are present (endpoint + envelope). Nothing to send
        // yet — the server speaks first (220 greeting), which flips us to Greet.
        if s.phase == SmtpPhase::Disconnected
            && s.draining == 0
            && s.mail_from_len > 0
            && s.rcpt_to_len > 0
        {
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
            // Enter `Connecting` only once the dial has actually been taken.
            // `net_write_frame` returns 0 on backpressure so a caller can
            // retry; advancing anyway started the connect deadline against a
            // CONNECT the channel had refused, and the exchange failed on a
            // timeout for a dial that was never made.
            if net_write_frame(
                sys,
                s.net_out,
                NET_CMD_CONNECT,
                payload.as_ptr(),
                8,
                s.nbuf.as_mut_ptr(),
                NET_BUF,
            ) != 0
            {
                s.phase = SmtpPhase::Connecting;
                s.started_ms = now;
            }
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
                    NET_MSG_CONNECTED if s.phase == SmtpPhase::Connecting => {
                        if plen >= 3 && *payload.add(2) == s.tag {
                            s.conn_id = u16::from_le_bytes([*payload, *payload.add(1)]);
                            s.conn_present = 1;
                            s.phase = SmtpPhase::Greet; // await 220
                            s.started_ms = now;
                        }
                    }
                    NET_MSG_DATA
                        if !matches!(s.phase, SmtpPhase::Disconnected | SmtpPhase::Connecting) =>
                    {
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
                            drain_replies(s, now);
                        }
                    }
                    NET_MSG_CLOSED if !matches!(s.phase, SmtpPhase::Disconnected) => {
                        if plen >= 2
                            && u16::from_le_bytes([*payload, *payload.add(1)]) == s.conn_id
                            && !matches!(s.phase, SmtpPhase::Done)
                        {
                            s.phase = SmtpPhase::Failed;
                            s.errors = s.errors.wrapping_add(1);
                            emit_status(s, b"smtp: connection closed\n");
                            s.conn_id = 0;
                            s.conn_present = 0;
                        }
                    }
                    NET_MSG_ERROR => {
                        // A connect-phase failure is matched on the TAG ALONE:
                        // the contract states its `conn_id` is meaningless (0
                        // when the dial failed before a slot was allocated,
                        // indistinguishable from a valid id 0). The
                        // established-connection clause is gated on
                        // `conn_present`, not on the phase — during
                        // `Connecting` this module's `conn_id` is still
                        // zero-initialised, so a peer's failed dial carrying
                        // conn_id 0 would otherwise be claimed here.
                        let ours = (s.phase == SmtpPhase::Connecting
                            && plen >= 4
                            && *payload.add(3) == s.tag)
                            || (s.conn_present != 0
                                && plen >= 2
                                && u16::from_le_bytes([*payload, *payload.add(1)]) == s.conn_id);
                        if ours && !matches!(s.phase, SmtpPhase::Done | SmtpPhase::Failed) {
                            s.phase = SmtpPhase::Failed;
                            s.errors = s.errors.wrapping_add(1);
                            emit_status(s, b"smtp: network error\n");
                        }
                    }
                    _ => {}
                }
            }
        }

        // Send any staged command, chunked, when the transport is writable.
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
                // All-or-nothing: the offset advances only over committed
                // bytes. Advancing past a refused write would send the server
                // a truncated command, which ESMTP answers with a syntax
                // error for a command this client believes it sent correctly.
                let total = NET_FRAME_HDR + total_payload;
                if (sys.channel_write)(s.net_out, s.nbuf.as_ptr(), total) != total as i32 {
                    break;
                }
                s.req_sent += chunk as u16;
            }
        }

        if !matches!(
            s.phase,
            SmtpPhase::Disconnected | SmtpPhase::Done | SmtpPhase::Failed
        ) {
            let budget = if s.phase == SmtpPhase::Connecting {
                CONNECT_TIMEOUT_MS
            } else {
                REPLY_TIMEOUT_MS
            };
            if now.wrapping_sub(s.started_ms) > budget {
                s.phase = SmtpPhase::Failed;
                s.errors = s.errors.wrapping_add(1);
                emit_status(s, b"smtp: timeout\n");
            }
        }

        // Hand over the delivery result before anything else can end the step,
        // so a result produced this step does not wait for the next one.
        flush_status(s);

        // Quiescence means the result has been delivered and the CLOSE has been
        // taken — not merely that the FSM reached a terminal phase. Reporting
        // earlier tears the instance down with the one outcome it promised
        // still in its own buffer, and with a CLOSE the peer never receives.
        if s.draining == 1
            && s.status_len == 0
            && matches!(
                s.phase,
                SmtpPhase::Disconnected | SmtpPhase::Done | SmtpPhase::Failed
            )
        {
            if s.conn_present != 0 {
                let close = s.conn_id.to_le_bytes();
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
