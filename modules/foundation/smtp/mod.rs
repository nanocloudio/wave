//! SMTP connector — a GENUINE per-protocol Fluxor foundation module for mail
//! SUBMISSION: the lockstep ESMTP conversation
//!   220 greeting -> EHLO/250 -> MAIL FROM/250 -> RCPT TO/250 -> DATA/354
//!   -> <message>.CRLF/250 -> QUIT/221
//! where each command waits on the 3-digit code of the previous multi-line
//! reply, and the message body is RFC 5321 dot-stuffed and terminated by
//! `\r\n.\r\n`. A reply-code-driven, multi-round-trip session over a
//! server-chosen greeting is not a stateless codec, so it is a compiled module.
//!
//! Protocol logic in the host-tested `modules/common/smtp_core.rs` and the
//! record layouts in `modules/common/smtp_wire.rs`; this file is the I/O pump:
//! take a submission -> connect -> walk the command sequence -> report exactly
//! one result.
//!
//! **Driven.** A submission arrives as an `SmtpRequest` on `request_in` and is
//! answered with exactly one `SmtpResult` on `result_out`, correlated by the
//! caller's `cid`. One long-running instance performs many submissions without
//! its graph being rebuilt.
//!
//! **Configured.** Params may instead describe a single submission, which is
//! performed once at startup as if its record had arrived on `request_in`. A
//! graph whose only job is one message — a boot notification, an alert — needs
//! no node to drive it.
//!
//! **What a result claims.** The 250 answering end-of-data is the server taking
//! responsibility for the message, and it is latched the moment it arrives. The
//! QUIT that follows is graceful cleanup: a QUIT that fails, times out, or
//! never completes does not un-accept a message the server already holds, and
//! reporting otherwise would have a caller deliver it twice. Nothing here
//! translates acceptance into human delivery or presentation — that meaning
//! belongs above this module.
//!
//! Ports:  net_in/net_out (transport), status_out (human-readable status),
//!         request_in (submissions), result_out (one result each).
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
    smtp_body, smtp_body_chunk, smtp_body_end, smtp_data, smtp_ehlo, smtp_mail_from, smtp_on_reply,
    smtp_phase_code, smtp_quit, smtp_rcpt_to, smtp_reply_accepts, smtp_reply_line, smtp_reply_text,
    SmtpCmd, SmtpPhase,
};

#[cfg(not(feature = "host-test"))]
#[path = "../../common/smtp_wire.rs"]
mod smtp_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/smtp_wire.rs"]
pub mod smtp_wire;
use smtp_wire::{
    parse_smtp_request, smtp_classify_code, smtp_enhanced_status, smtp_op_is_known,
    write_smtp_result, SmtpResultHead, SMTP_FLAG_MORE_BODY, SMTP_OP_BODY, SMTP_OP_CANCEL,
    SMTP_OP_SUBMIT, SMTP_OUT_ACCEPTED, SMTP_OUT_CANCELLED, SMTP_OUT_CLOSED,
    SMTP_OUT_CONNECT_FAILED, SMTP_OUT_MALFORMED, SMTP_OUT_PROTOCOL_ERROR, SMTP_OUT_TIMEOUT,
    SMTP_REQ_HDR, SMTP_RES_HDR,
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
/// Raw body bytes held between arriving on `request_in` and reaching the wire.
/// One record's worth: the next body record is not read until this one has been
/// sent, which is what bounds the module's memory against a message of any size.
const CHUNK_BUF: usize = 4096;
/// Staged outbound bytes. Sized for a dot-stuffed `CHUNK_BUF`: transparency can
/// double a chunk in the worst case (every line a lone `.`), and a staged
/// command that did not fit would be sent truncated.
const REQ_BUF: usize = 2 * CHUNK_BUF + 64;
/// Longest delivery-result line (`smtp: connection closed\n` is the longest
/// today); parked in state, so it is sized for the class rather than the
/// current maximum.
const STATUS_BUF: usize = 64;
const ACC_BUF: usize = 2048;
const NAME_BUF: usize = 256;
/// Bounded reply text kept for the result. A server explaining a refusal in
/// more words than this has its explanation truncated, not the module's buffers
/// grown by whatever it chose to send.
const TEXT_BUF: usize = 256;
/// Inbound `SmtpRequest` staging. Holds a whole record plus whatever arrived
/// behind it on the byte FIFO.
const REC_BUF: usize = 2 * (SMTP_REQ_HDR + 2 * NAME_BUF + CHUNK_BUF);
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const REPLY_TIMEOUT_MS: u64 = 15_000;

#[repr(C)]
struct SmtpState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    status_out: i32,
    request_in: i32,
    result_out: i32,

    ip: [u8; 4],
    port: u16,
    ep_hex: [u8; 16],
    ep_hex_len: u16,
    helo: [u8; NAME_BUF],
    helo_len: u16,

    // ── the submission in flight ──────────────────────────────────────────
    /// 1 while a submission is in flight. One at a time: the transport is a
    /// single connection and SMTP is lockstep, so overlapping two would
    /// interleave their commands on the wire.
    op_active: u8,
    cid: u32,
    mail_from: [u8; NAME_BUF],
    mail_from_len: u16,
    rcpt_to: [u8; NAME_BUF],
    rcpt_to_len: u16,

    /// Raw body bytes awaiting dot-stuffing and transmission.
    chunk: [u8; CHUNK_BUF],
    chunk_len: u32,
    /// 1 while further body records are expected for this submission.
    more_body: u8,
    /// Dot-stuffing carry: whether the next byte begins a line. A chunk
    /// boundary in the middle of a line must not re-arm transparency.
    at_line_start: u8,
    /// Whether the message bytes so far ended with CRLF, so the terminator
    /// knows whether to supply one.
    ends_crlf: u8,
    /// 1 once the end-of-data marker has been staged.
    body_terminated: u8,

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
    req_len: u32,
    req_sent: u32,
    acc: [u8; ACC_BUF],
    acc_len: u32,

    nbuf: [u8; NET_BUF],

    // ── the one result this submission owes ───────────────────────────────
    /// 1 once the end-of-data 250 arrived. Latched: no later event may
    /// downgrade it, because the server already holds the message.
    accepted: u8,
    /// 1 once a result has been decided for this submission. Exactly one is
    /// owed per submission, so the first decision is the only one.
    res_produced: u8,
    /// 1 while the decided result still has to be handed to `result_out`.
    res_owed: u8,
    res_outcome: u8,
    res_phase: u8,
    res_code: u16,
    res_enh_class: u8,
    res_enh_subject: u16,
    res_enh_detail: u16,
    res_text: [u8; TEXT_BUF],
    res_text_len: u16,

    /// The human-readable status line, held until `status_out` takes it.
    status: [u8; STATUS_BUF],
    status_len: u32,
    /// 1 once a status line has been decided for this submission. Separate
    /// from `status_len`, which returns to 0 as soon as the line is handed
    /// over: without it a later event would emit a second line for the same
    /// submission once the first had flushed.
    status_produced: u8,

    /// Inbound record staging, and how much of its front has been consumed.
    rec: [u8; REC_BUF],
    rec_len: u32,
    rec_taken: u32,

    delivered: u32,
    errors: u32,
    admitted: u32,
    dropped_unparsable: u32,
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
        while i < len && (s.chunk_len as usize) < CHUNK_BUF {
            s.chunk[s.chunk_len as usize] = *d.add(i); s.chunk_len += 1; i += 1;
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
        s.request_in = dev_channel_port(sys, 0, 1);
        s.result_out = dev_channel_port(sys, 1, 2);
        s.ip = [0u8; 4];
        s.port = 0;
        s.ep_hex_len = 0;
        s.helo_len = 0;
        s.op_active = 0;
        s.cid = 0;
        s.mail_from_len = 0;
        s.rcpt_to_len = 0;
        s.chunk_len = 0;
        s.more_body = 0;
        s.at_line_start = 1;
        s.ends_crlf = 0;
        s.body_terminated = 0;
        s.phase = SmtpPhase::Disconnected;
        s.conn_id = 0;
        s.conn_present = 0;
        s.tag = dev_requester_tag(sys);
        s.started_ms = 0;
        s.draining = 0;
        s.req_len = 0;
        s.req_sent = 0;
        s.acc_len = 0;
        s.accepted = 0;
        s.res_produced = 0;
        s.res_owed = 0;
        s.res_outcome = 0;
        s.res_phase = 0;
        s.res_code = 0;
        s.res_enh_class = 0;
        s.res_enh_subject = 0;
        s.res_enh_detail = 0;
        s.res_text_len = 0;
        s.status_len = 0;
        s.status_produced = 0;
        s.rec_len = 0;
        s.rec_taken = 0;
        s.delivered = 0;
        s.errors = 0;
        s.admitted = 0;
        s.dropped_unparsable = 0;
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
        // A params-described submission is performed once, as if its record had
        // arrived on `request_in`. A statically configured graph keeps working
        // and there is only one path through the pump.
        if s.mail_from_len > 0 && s.rcpt_to_len > 0 {
            s.op_active = 1;
            s.more_body = 0;
        }
        dev_log(sys, 3, b"[smtp] init".as_ptr(), 11);
        0
    }
}

// ── the human-readable status line ────────────────────────────────────────

/// Record the session's status line, to be handed to `status_out` as soon as it
/// will take it.
///
/// First writer wins, for the same reason the result does: "delivered" followed
/// by the connection closing describes a delivery, not a connection failure.
unsafe fn emit_status(s: &mut SmtpState, text: &[u8]) {
    if s.status_out < 0 || s.status_produced != 0 {
        return;
    }
    s.status_produced = 1;
    let n = text.len().min(STATUS_BUF);
    s.status[..n].copy_from_slice(&text[..n]);
    s.status_len = n as u32;
}

/// Hand the parked status line to `status_out`, retrying on a later step while
/// the channel refuses it. The channel takes a record whole or not at all, so a
/// rejected write leaves it intact and nothing is reported twice.
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

// ── the one result ────────────────────────────────────────────────────────

/// Decide this submission's result.
///
/// Exactly one result is owed per submission, so the first decision stands:
/// later events describe what happened after the outcome, not a different
/// outcome. Acceptance in particular is never revisited — a QUIT that fails
/// after the server took the message does not make the message undelivered.
unsafe fn emit_result(s: &mut SmtpState, outcome: u8, reached: SmtpPhase) {
    if s.res_produced != 0 {
        return;
    }
    s.res_produced = 1;
    s.res_owed = 1;
    s.res_outcome = outcome;
    // The phase the conversation REACHED, not the terminal state it landed
    // in. Every failure lands in `Failed`, which tells a caller nothing;
    // which command was outstanding when it failed tells them where to look.
    s.res_phase = smtp_phase_code(reached);
}

/// Hand the decided result to `result_out`, retrying while the channel refuses
/// it. Built afresh each attempt from the fields already in state, so a refused
/// write costs nothing but the rebuild.
unsafe fn flush_result(s: &mut SmtpState) {
    if s.res_owed == 0 || s.result_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.result_out, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let text_len = s.res_text_len as usize;
    let head = SmtpResultHead {
        cid: s.cid,
        outcome: s.res_outcome,
        phase: s.res_phase,
        code: s.res_code,
        enhanced: if s.res_enh_class == 0 {
            None
        } else {
            Some(smtp_wire::SmtpEnhanced {
                class: s.res_enh_class,
                subject: s.res_enh_subject,
                detail: s.res_enh_detail,
            })
        },
        peer_ip: s.ip,
        peer_port: s.port,
        text_len,
    };
    let mut out = [0u8; SMTP_RES_HDR + TEXT_BUF];
    let total = match write_smtp_result(&head, &mut out) {
        Some(n) => n,
        None => {
            s.res_owed = 0;
            return;
        }
    };
    out[SMTP_RES_HDR..SMTP_RES_HDR + text_len].copy_from_slice(&s.res_text[..text_len]);
    if (sys.channel_write)(s.result_out, out.as_ptr(), total) != total as i32 {
        return;
    }
    s.res_owed = 0;
}

/// Keep the reply code, its enhanced status and its bounded text for the
/// result, so the caller learns what the server actually said rather than a
/// classification of it.
unsafe fn record_reply(s: &mut SmtpState, code: u16, text: &[u8]) {
    s.res_code = code;
    let n = text.len().min(TEXT_BUF);
    s.res_text[..n].copy_from_slice(&text[..n]);
    s.res_text_len = n as u16;
    match smtp_enhanced_status(text) {
        Some(enhanced) => {
            s.res_enh_class = enhanced.class;
            s.res_enh_subject = enhanced.subject;
            s.res_enh_detail = enhanced.detail;
        }
        None => {
            s.res_enh_class = 0;
            s.res_enh_subject = 0;
            s.res_enh_detail = 0;
        }
    }
}

// ── outbound staging ──────────────────────────────────────────────────────

/// Stage `bytes` as the outbound command to send (chunked in module_step).
unsafe fn stage_req(s: &mut SmtpState, bytes: &[u8], now: u64) {
    let n = bytes.len().min(REQ_BUF);
    s.req[..n].copy_from_slice(&bytes[..n]);
    s.req_len = n as u32;
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
        // The body is streamed rather than built in one piece; entering `Body`
        // is what starts that, in `pump_body`.
        SmtpCmd::SendBody => None,
        SmtpCmd::SendQuit => smtp_quit(&mut out),
        SmtpCmd::Complete | SmtpCmd::Fail => None,
    };
    if let Some(n) = built {
        stage_req(s, &out[..n], now);
    }
}

/// Move the message towards the wire while the server is waiting for it.
///
/// Only runs in `Body`, and only when nothing is already staged: the chunk in
/// hand is dot-stuffed and staged whole, and the next body record is not read
/// until that has gone out. That is what keeps a message of any size inside
/// `CHUNK_BUF` here and in the caller.
unsafe fn pump_body(s: &mut SmtpState, now: u64) {
    if s.phase != SmtpPhase::Body || s.req_sent < s.req_len {
        return;
    }
    if s.chunk_len > 0 {
        let mut out = [0u8; REQ_BUF];
        let chunk_len = s.chunk_len as usize;
        let mut raw = [0u8; CHUNK_BUF];
        raw[..chunk_len].copy_from_slice(&s.chunk[..chunk_len]);
        if let Some((n, at_line_start)) =
            smtp_body_chunk(&raw[..chunk_len], s.at_line_start != 0, &mut out)
        {
            s.at_line_start = u8::from(at_line_start);
            s.ends_crlf = u8::from(
                chunk_len >= 2 && raw[chunk_len - 2] == b'\r' && raw[chunk_len - 1] == b'\n',
            );
            s.chunk_len = 0;
            stage_req(s, &out[..n], now);
        }
        return;
    }
    // The chunk in hand has gone. Either more of the message is coming, or the
    // message is complete and owes its end-of-data marker.
    if s.more_body == 0 && s.body_terminated == 0 {
        let mut out = [0u8; 8];
        if let Some(n) = smtp_body_end(s.ends_crlf != 0, &mut out) {
            s.body_terminated = 1;
            stage_req(s, &out[..n], now);
        }
    }
}

// ── reply handling ────────────────────────────────────────────────────────

/// Advance the conversation on a FINAL reply `code`.
unsafe fn on_reply(s: &mut SmtpState, code: u16, now: u64) {
    // Acceptance is decided against the phase the reply answers, before the
    // machine moves on from it.
    let answered = s.phase;
    if smtp_reply_accepts(answered, code) {
        s.accepted = 1;
        s.delivered = s.delivered.wrapping_add(1);
        emit_result(s, SMTP_OUT_ACCEPTED, answered);
        emit_status(s, b"smtp: delivered\n");
    }
    let (cmd, next) = smtp_on_reply(s.phase, code);
    s.phase = next;
    match cmd {
        SmtpCmd::Complete => {
            // The 221 to QUIT. The message was already accounted for at
            // end-of-data; this only completes the cleanup.
            emit_status(s, b"smtp: delivered\n");
        }
        SmtpCmd::Fail => {
            s.errors = s.errors.wrapping_add(1);
            emit_result(s, smtp_classify_code(code), answered);
            emit_status(s, b"smtp: rejected\n");
            close_connection(s);
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
        if is_final {
            if let Some((at, text_len)) = smtp_reply_text(&s.acc[..s.acc_len as usize], len) {
                let mut text = [0u8; TEXT_BUF];
                let take = text_len.min(TEXT_BUF);
                text[..take].copy_from_slice(&s.acc[at..at + take]);
                record_reply(s, code, &text[..take]);
            } else {
                record_reply(s, code, b"");
            }
        }
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

/// Close the transport connection, if one is open.
unsafe fn close_connection(s: &mut SmtpState) {
    if s.conn_present == 0 {
        return;
    }
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

/// Retire a finished submission so the next one can start.
///
/// Only once its result has actually been handed over: tearing the operation
/// down with the one outcome it promised still in its own buffer is how a
/// caller ends up waiting forever for a message that was in fact delivered.
unsafe fn finish_op(s: &mut SmtpState) {
    if s.res_owed != 0 || s.status_len != 0 {
        return;
    }
    close_connection(s);
    s.op_active = 0;
    s.cid = 0;
    s.mail_from_len = 0;
    s.rcpt_to_len = 0;
    s.chunk_len = 0;
    s.more_body = 0;
    s.at_line_start = 1;
    s.ends_crlf = 0;
    s.body_terminated = 0;
    s.phase = SmtpPhase::Disconnected;
    s.req_len = 0;
    s.req_sent = 0;
    s.acc_len = 0;
    s.accepted = 0;
    s.res_produced = 0;
    s.res_outcome = 0;
    s.res_phase = 0;
    s.res_code = 0;
    s.res_enh_class = 0;
    s.res_enh_subject = 0;
    s.res_enh_detail = 0;
    s.res_text_len = 0;
    s.status_produced = 0;
}

// ── inbound records ───────────────────────────────────────────────────────

/// What the front of `rec` holds, once the bytes read so far are in.
enum Front {
    /// Fewer bytes than a record needs — either the fixed header has not all
    /// arrived, or it has and the fields it declares have not. Both are the
    /// caller mid-write, not a caller in error.
    Partial,
    /// A whole record, ready to perform.
    Whole,
    /// A header declaring a record longer than `REC_BUF`. No later read
    /// completes it, so it is decided now rather than waited on.
    Impossible,
}

/// Total length the record at the front of `buf` declares, in `u64` so a
/// declared chunk of up to `u32::MAX` cannot overflow the arithmetic on a
/// 32-bit target.
fn declared_len(buf: &[u8]) -> Option<u64> {
    if buf.len() < SMTP_REQ_HDR {
        return None;
    }
    let from_len = u16::from_le_bytes([buf[6], buf[7]]) as u64;
    let rcpt_len = u16::from_le_bytes([buf[8], buf[9]]) as u64;
    let chunk_len = u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]) as u64;
    Some(SMTP_REQ_HDR as u64 + from_len + rcpt_len + chunk_len)
}

/// Classify the front of the request buffer.
fn front_status(buf: &[u8]) -> Front {
    match declared_len(buf) {
        None => Front::Partial,
        Some(need) if need > REC_BUF as u64 => Front::Impossible,
        Some(need) if (buf.len() as u64) < need => Front::Partial,
        Some(_) => Front::Whole,
    }
}

/// Correlation id of the record at the front of `rec`.
fn front_cid(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]])
}

/// Answer a record this connector will not perform, so a caller learns its
/// request was refused instead of waiting out a timeout.
unsafe fn refuse_record(s: &mut SmtpState, cid: u32, outcome: u8) {
    // Only safe to borrow the result fields when nothing else owes one.
    if s.res_owed != 0 {
        return;
    }
    s.cid = cid;
    s.res_text_len = 0;
    s.res_code = 0;
    s.res_enh_class = 0;
    s.res_produced = 0;
    emit_result(s, outcome, SmtpPhase::Disconnected);
    // Nothing was started, so nothing is retired by `finish_op`.
    s.res_produced = 0;
}

/// Take at most one record off `request_in`.
///
/// One per step, deliberately: every record either starts a submission, feeds
/// the one in flight, ends it, or is refused, and each of those needs the rest
/// of the step to act on it before another is taken.
///
/// `request_in` is a byte FIFO, so one `channel_read` can return several whole
/// records back to back and end part-way through the next. The buffer holds
/// everything the reads returned; the record being performed stays at the front
/// until it has been consumed, and a trailing fragment is topped up by later
/// reads until it is whole. Both are bytes the caller can no longer hand to
/// anything else, so discarding either loses the request with no event to
/// explain it.
unsafe fn pump_requests(s: &mut SmtpState, now: u64) {
    let sys = &*s.syscalls;
    if s.request_in < 0 {
        return;
    }
    // Retire the record just consumed, exposing whatever arrived behind it.
    if s.rec_taken > 0 {
        let taken = (s.rec_taken as usize).min(s.rec_len as usize);
        let remaining = s.rec_len as usize - taken;
        if remaining > 0 {
            core::ptr::copy(s.rec.as_ptr().add(taken), s.rec.as_mut_ptr(), remaining);
        }
        s.rec_len = remaining as u32;
        s.rec_taken = 0;
    }
    // Whether the record at the front can be taken is decided per record,
    // below: a cancel must be readable while a submission is in flight,
    // which a gate on "is this connector idle" would prevent. A record
    // that cannot be taken yet stays at the front until it can.
    //
    // A submission queued behind another is not reachable until the one in
    // front is taken, which is what a FIFO means; a caller that needs a
    // cancel honoured promptly sends it before queueing more work.
    let wants_submit = s.op_active == 0 && s.draining == 0;
    let wants_body = s.op_active != 0 && s.more_body != 0 && s.chunk_len == 0;
    while s.draining == 0 && matches!(front_status(&s.rec[..s.rec_len as usize]), Front::Partial) {
        let at = s.rec_len as usize;
        if at >= REC_BUF {
            break;
        }
        let poll = (sys.channel_poll)(s.request_in, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let n = (sys.channel_read)(s.request_in, s.rec.as_mut_ptr().add(at), REC_BUF - at);
        if n <= 0 {
            break;
        }
        s.rec_len = (at + n as usize) as u32;
    }
    let n = s.rec_len as usize;
    match front_status(&s.rec[..n]) {
        Front::Whole => {}
        Front::Partial => return,
        Front::Impossible => {
            // Nothing later completes it. It names a correlation id, so it
            // is refused rather than dropped, and the buffer is cleared:
            // its remaining bytes belong to a record that cannot be read.
            let cid = front_cid(&s.rec[..n]);
            refuse_record(s, cid, SMTP_OUT_MALFORMED);
            s.dropped_unparsable = s.dropped_unparsable.wrapping_add(1);
            s.rec_len = 0;
            return;
        }
    }
    let view = match parse_smtp_request(&s.rec[..n]) {
        Some(v) => v,
        None => return,
    };
    let total = SMTP_REQ_HDR + view.from_len + view.rcpt_len + view.chunk_len;

    if !smtp_op_is_known(view.op) {
        refuse_record(s, view.cid, SMTP_OUT_MALFORMED);
        s.rec_taken = total as u32;
        s.dropped_unparsable = s.dropped_unparsable.wrapping_add(1);
        return;
    }

    match view.op {
        SMTP_OP_SUBMIT if wants_submit => {
            if view.from_len == 0
                || view.rcpt_len == 0
                || view.from_len > NAME_BUF
                || view.rcpt_len > NAME_BUF
                || view.chunk_len > CHUNK_BUF
            {
                refuse_record(s, view.cid, SMTP_OUT_MALFORMED);
                s.rec_taken = total as u32;
                return;
            }
            s.cid = view.cid;
            s.mail_from_len = view.from_len as u16;
            s.mail_from[..view.from_len]
                .copy_from_slice(&s.rec[view.from_at..view.from_at + view.from_len]);
            s.rcpt_to_len = view.rcpt_len as u16;
            s.rcpt_to[..view.rcpt_len]
                .copy_from_slice(&s.rec[view.rcpt_at..view.rcpt_at + view.rcpt_len]);
            s.chunk_len = view.chunk_len as u32;
            s.chunk[..view.chunk_len]
                .copy_from_slice(&s.rec[view.chunk_at..view.chunk_at + view.chunk_len]);
            s.more_body = u8::from(view.more_body());
            s.at_line_start = 1;
            s.ends_crlf = 0;
            s.body_terminated = 0;
            s.op_active = 1;
            s.admitted = s.admitted.wrapping_add(1);
            s.rec_taken = total as u32;
            let _ = now;
        }
        SMTP_OP_BODY if wants_body && view.cid == s.cid => {
            if view.chunk_len > CHUNK_BUF {
                refuse_record(s, view.cid, SMTP_OUT_MALFORMED);
                s.rec_taken = total as u32;
                return;
            }
            s.chunk_len = view.chunk_len as u32;
            s.chunk[..view.chunk_len]
                .copy_from_slice(&s.rec[view.chunk_at..view.chunk_at + view.chunk_len]);
            s.more_body = u8::from(view.more_body());
            s.rec_taken = total as u32;
        }
        SMTP_OP_CANCEL if s.op_active != 0 && view.cid == s.cid => {
            emit_result(s, SMTP_OUT_CANCELLED, s.phase);
            emit_status(s, b"smtp: cancelled\n");
            close_connection(s);
            s.phase = SmtpPhase::Failed;
            s.rec_taken = total as u32;
        }
        _ => {
            // A body or cancel for a submission this connector is not
            // performing, or a submission while one is in flight. Leave it
            // where it is when it may yet become current; refuse it when it
            // never can.
            if view.op == SMTP_OP_SUBMIT {
                return;
            }
            refuse_record(s, view.cid, SMTP_OUT_MALFORMED);
            s.rec_taken = total as u32;
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

        pump_requests(s, now);

        // Connect once a submission is in hand. Nothing to send yet — the
        // server speaks first (220 greeting), which flips us to Greet.
        if s.op_active != 0 && s.phase == SmtpPhase::Disconnected && s.res_produced == 0 {
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
                            // Never over an acceptance: a server that closes
                            // after taking the message has still taken it.
                            emit_result(s, SMTP_OUT_CLOSED, s.phase);
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
                        let connecting = s.phase == SmtpPhase::Connecting
                            && plen >= 4
                            && *payload.add(3) == s.tag;
                        let established = s.conn_present != 0
                            && plen >= 2
                            && u16::from_le_bytes([*payload, *payload.add(1)]) == s.conn_id;
                        if (connecting || established)
                            && !matches!(s.phase, SmtpPhase::Done | SmtpPhase::Failed)
                        {
                            let outcome = if connecting {
                                SMTP_OUT_CONNECT_FAILED
                            } else {
                                SMTP_OUT_CLOSED
                            };
                            let reached = s.phase;
                            s.phase = SmtpPhase::Failed;
                            s.errors = s.errors.wrapping_add(1);
                            emit_result(s, outcome, reached);
                            emit_status(s, b"smtp: network error\n");
                        }
                    }
                    _ => {}
                }
            }
        }

        // Feed the message to the wire while the server waits for it.
        pump_body(s, now);

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
                s.req_sent += chunk as u32;
            }
        }

        if s.op_active != 0
            && !matches!(
                s.phase,
                SmtpPhase::Disconnected | SmtpPhase::Done | SmtpPhase::Failed
            )
        {
            let budget = if s.phase == SmtpPhase::Connecting {
                CONNECT_TIMEOUT_MS
            } else {
                REPLY_TIMEOUT_MS
            };
            if now.wrapping_sub(s.started_ms) > budget {
                let reached = s.phase;
                s.phase = SmtpPhase::Failed;
                s.errors = s.errors.wrapping_add(1);
                emit_result(s, SMTP_OUT_TIMEOUT, reached);
                emit_status(s, b"smtp: timeout\n");
            }
        }

        // Hand over the outcome before anything else can end the step, so a
        // result produced this step does not wait for the next one.
        flush_result(s);
        flush_status(s);

        // A finished submission frees the instance for the next one.
        if s.op_active != 0 && matches!(s.phase, SmtpPhase::Done | SmtpPhase::Failed) {
            finish_op(s);
        }

        // Quiescence means every result has been delivered and the CLOSE has
        // been taken — not merely that the FSM reached a terminal phase.
        // Reporting earlier tears the instance down with the one outcome it
        // promised still in its own buffer, and with a CLOSE the peer never
        // receives.
        if s.draining == 1 && s.res_owed == 0 && s.status_len == 0 && s.op_active == 0 {
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
