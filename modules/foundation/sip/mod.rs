//! SIP voice-signalling PIC module — the two-party call user-agent.
//!
//! Composes the tested `modules/common` logic with datagram I/O:
//!   * `sip_core` formats/parses the INVITE/ACK/BYE/200-OK messages and SDP;
//!   * `sip_dialog` is the UAC/UAS transaction FSM.
//!
//! Signalling ONLY: it owns the SIP datagram endpoint
//! and drives the media path — the separate `rtp` module and the `jitter`
//! reorder/playout adapter — over shared control records on `rtp_ctrl`. It
//! holds no media socket, no jitter state and no playout clock: the media path
//! is `rtp`'s and the reorder ring is `jitter`'s, so a graph that needs
//! signalling without media pays for neither.
//!
//! This module is the endpoint and orchestration wrapper. The message and
//! dialog mechanics it drives are the shared cores, which is where their
//! behaviour is pinned.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
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

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// Tested logic cores, mounted by `#[path]` so the module and host tests compile
// the same bytes. Public under host-test only, on the same precedent as http's
// `wire_h2` / `qpack`: the vector suites in `tests/harness/tests/` pin these
// directly, and the firmware's symbol surface is unchanged because the mods are
// private off host-test. `modules/**` has a hard inline-test ban
// (../standards/tests.md §1), so reaching them through the rlib is the only route.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/sip_core.rs"]
mod sip_core;
#[cfg(feature = "host-test")]
#[path = "../../common/sip_core.rs"]
pub mod sip_core;
#[cfg(not(feature = "host-test"))]
#[path = "../../common/sip_dialog.rs"]
mod sip_dialog;
#[cfg(feature = "host-test")]
#[path = "../../common/sip_dialog.rs"]
pub mod sip_dialog;
#[cfg(not(feature = "host-test"))]
#[path = "../../common/sip_wire.rs"]
mod sip_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/sip_wire.rs"]
pub mod sip_wire;

use sip_core::SipDialog;
use sip_dialog::{MediaCmd, SipDialogFsm, SipEvent, SipSend, SipState};
use sip_wire::{
    parse_sip_command, sip_cmd_is_known, write_sip_event, SIP_CMD_ACCEPT, SIP_CMD_CANCEL,
    SIP_CMD_DIAL, SIP_CMD_HANGUP, SIP_CMD_LEN, SIP_CMD_REJECT, SIP_EVENT_HDR, SIP_EV_DECLINED,
    SIP_EV_ESTABLISHED, SIP_EV_FAILED, SIP_EV_LOCAL_CLOSED, SIP_EV_OFFERED, SIP_EV_PROVISIONAL,
    SIP_EV_REJECTED, SIP_EV_REMOTE_HANGUP, SIP_EV_TIMEOUT,
};

const NET_BUF_SIZE: usize = 600;
const SIP_TX_BUF_SIZE: usize = 512;
const SIP_RX_BUF_SIZE: usize = 512;
const CALL_ID_SIZE: usize = 16;

// Control-channel protocol to the `rtp` transmitter (8-byte messages).
const CTRL_SET_ENDPOINT: u8 = 0x01;
const CTRL_START: u8 = 0x02;
const CTRL_STOP: u8 = 0x03;
/// Depth of the ordered media-control queue.
const CTRL_QUEUE: usize = 4;
const CTRL_MSG_SIZE: usize = 8;

const T1_MS: u64 = 500;

#[repr(C)]
struct SipModState {
    syscalls: *const SyscallTable,

    // Ports.
    sip_net_in: i32,   // in[0]
    sip_net_out: i32,  // out[0]
    rtp_ctrl_out: i32, // out[3]: control to the rtp transmitter
    call_ctrl_in: i32, // ctrl: local call/hangup trigger
    command_in: i32,   // in[2]: SipCommand records
    event_out: i32,    // out[4]: SipEvent records

    // Datagram endpoint ids (0xFF = unallocated).
    sip_ep_id: u8,
    sip_bound: u8,

    // Config.
    local_ip: u32,
    peer_ip: u32,
    local_sip_port: u16,
    peer_sip_port: u16,
    rtp_port: u16,
    auto_answer: u8,
    ptime: u8,
    sip_active: u8,
    _pad0: u8,

    // Negotiated remote RTP endpoint (from SDP).
    peer_rtp_ip: u32,
    peer_rtp_port: u16,
    _pad1: u16,

    /// The call this module is currently working on. Zero when idle.
    cid: u32,
    /// Source of call ids for calls that arrive rather than being placed.
    cid_counter: u32,
    /// 1 while an offered call is held awaiting an accept or reject.
    ///
    /// The INVITE is NOT given to the dialog machine while this is set: a
    /// machine that had already answered would leave nothing to decide.
    offer_pending: u8,
    /// 1 while a decided event still owes `event_out`.
    event_owed: u8,
    /// The staged event record.
    event_buf: [u8; SIP_EVENT_HDR + 64],
    event_len: u16,

    // TEMPORARY diagnosis counters (rig): datagrams seen on sip_net_in, SIP
    // messages among them, and the last heartbeat time.
    dbg_rx: u16,
    dbg_sip: u16,
    dbg_last_ms: u64,

    // Dialog data.
    cseq: u32,
    call_id_counter: u16,
    from_tag: u16,
    to_tag: u16,
    branch: u16,
    call_id_len: u8,
    _pad2: u8,

    // FSM + retransmit (from cores).
    fsm: SipDialogFsm,
    last_retransmit_ms: u64,
    /// Ordered media-control commands awaiting the transmitter's channel.
    /// Depth covers the longest run this module emits (`SET_ENDPOINT` then
    /// `START`) with room for a `STOP` behind them.
    ctrl_queue: [u8; CTRL_QUEUE],
    ctrl_len: u8,
    _pad3: u8,

    // Buffers.
    call_id: [u8; CALL_ID_SIZE],
    sip_tx_buf: [u8; SIP_TX_BUF_SIZE],
    sip_tx_len: u16,
    /// 1 while the staged datagram in `sip_tx_buf` still owes a send.
    ///
    /// Separate from `sip_tx_len` because that buffer is RETAINED after a
    /// successful send: `SipSend::Retransmit` re-flushes it unchanged for T1.
    /// Clearing the length on send would have destroyed the retransmission
    /// buffer; this flag is what a refused write leaves set instead.
    sip_tx_pending: u8,
    _pad4: u16,
    sip_rx_buf: [u8; SIP_RX_BUF_SIZE],
    net_buf: [u8; NET_BUF_SIZE],
}

impl SipModState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.sip_net_in = -1;
        self.sip_net_out = -1;
        self.rtp_ctrl_out = -1;
        self.call_ctrl_in = -1;
        self.command_in = -1;
        self.event_out = -1;
        self.cid = 0;
        self.cid_counter = 0;
        self.offer_pending = 0;
        self.event_owed = 0;
        self.event_len = 0;
        self.sip_ep_id = 0xFF;
        self.sip_bound = 0;
        self.local_ip = 0;
        self.peer_ip = 0;
        self.local_sip_port = 5060;
        self.peer_sip_port = 5060;
        self.rtp_port = 5004;
        self.auto_answer = 1;
        self.ptime = 20;
        self.sip_active = 0;
        self.peer_rtp_ip = 0;
        self.peer_rtp_port = 0;
        self.cseq = 1;
        self.call_id_counter = 0;
        self.from_tag = 0;
        self.to_tag = 0;
        self.branch = 0;
        self.call_id_len = 0;
        self.fsm = SipDialogFsm::new();
        self.last_retransmit_ms = 0;
        self.sip_tx_len = 0;
        self.sip_tx_pending = 0;
        self.ctrl_queue = [0; CTRL_QUEUE];
        self.ctrl_len = 0;
    }
}

/// Write a `u16` as exactly four lowercase hex digits into `dst`.
fn write_hex16(dst: &mut [u8], v: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    dst[0] = HEX[((v >> 12) & 0xF) as usize];
    dst[1] = HEX[((v >> 8) & 0xF) as usize];
    dst[2] = HEX[((v >> 4) & 0xF) as usize];
    dst[3] = HEX[(v & 0xF) as usize];
}

// ---------------------------------------------------------------------------
// SIP signalling
// ---------------------------------------------------------------------------

/// Format `msg` into the TX buffer via the appropriate `sip_core` builder.
unsafe fn build(s: &mut SipModState, msg: SipSend) {
    if msg == SipSend::Retransmit {
        return; // keep the last-staged buffer unchanged
    }
    // Copy Call-ID to a local so the immutable dialog view does not borrow `s`
    // while the builder writes `s.sip_tx_buf`.
    let clen = s.call_id_len as usize;
    let mut cid = [0u8; CALL_ID_SIZE];
    cid[..clen].copy_from_slice(&s.call_id[..clen]);
    let d = SipDialog {
        local_ip: s.local_ip,
        peer_ip: s.peer_ip,
        local_port: s.local_sip_port,
        peer_port: s.peer_sip_port,
        rtp_port: s.rtp_port,
        cseq: s.cseq,
        from_tag: s.from_tag,
        to_tag: s.to_tag,
        branch: s.branch,
        call_id: &cid[..clen],
    };
    let r = match msg {
        SipSend::Invite => sip_core::build_invite(&d, &mut s.sip_tx_buf),
        SipSend::Ok => sip_core::build_invite_ok(&d, &mut s.sip_tx_buf),
        SipSend::Ack => sip_core::build_ack(&d, &mut s.sip_tx_buf),
        SipSend::Bye => sip_core::build_bye(&d, &mut s.sip_tx_buf),
        SipSend::ByeOk => sip_core::build_bye_ok(&d, &mut s.sip_tx_buf),
        SipSend::Retransmit => None,
    };
    if let Some(n) = r {
        s.sip_tx_len = n as u16;
    }
}

/// Stage a final response refusing the offered `INVITE`.
unsafe fn build_refusal(s: &mut SipModState, code: u16) {
    let clen = s.call_id_len as usize;
    let mut cid = [0u8; CALL_ID_SIZE];
    cid[..clen].copy_from_slice(&s.call_id[..clen]);
    let d = SipDialog {
        local_ip: s.local_ip,
        peer_ip: s.peer_ip,
        local_port: s.local_sip_port,
        peer_port: s.peer_sip_port,
        rtp_port: s.rtp_port,
        cseq: s.cseq,
        from_tag: s.from_tag,
        to_tag: s.to_tag,
        branch: s.branch,
        call_id: &cid[..clen],
    };
    if let Some(n) = sip_core::build_invite_status(&d, code, &mut s.sip_tx_buf) {
        s.sip_tx_len = n as u16;
    }
}

/// Send the staged SIP message to the signalling peer.
unsafe fn sip_flush(s: &mut SipModState) {
    if s.sip_tx_pending == 0 || s.sip_tx_len == 0 || s.sip_net_out < 0 || s.sip_ep_id == 0xFF {
        return;
    }
    let sys = &*s.syscalls;
    let data_len = s.sip_tx_len as usize;
    let frame_payload = DG_V4_PREFIX + data_len;
    if frame_payload + NET_FRAME_HDR > NET_BUF_SIZE {
        return;
    }
    let b = s.net_buf.as_mut_ptr();
    *b = DG_CMD_SEND_TO;
    *b.add(1) = (frame_payload & 0xFF) as u8;
    *b.add(2) = ((frame_payload >> 8) & 0xFF) as u8;
    *b.add(NET_FRAME_HDR) = s.sip_ep_id;
    *b.add(NET_FRAME_HDR + 1) = DG_AF_INET;
    let ip = s.peer_ip.to_be_bytes();
    *b.add(NET_FRAME_HDR + 2) = ip[0];
    *b.add(NET_FRAME_HDR + 3) = ip[1];
    *b.add(NET_FRAME_HDR + 4) = ip[2];
    *b.add(NET_FRAME_HDR + 5) = ip[3];
    let port = s.peer_sip_port.to_le_bytes();
    *b.add(NET_FRAME_HDR + 6) = port[0];
    *b.add(NET_FRAME_HDR + 7) = port[1];
    core::ptr::copy_nonoverlapping(
        s.sip_tx_buf.as_ptr(),
        b.add(NET_FRAME_HDR + DG_V4_PREFIX),
        data_len,
    );
    let total = NET_FRAME_HDR + frame_payload;
    if (sys.channel_write)(s.sip_net_out, b, total) == total as i32 {
        s.sip_tx_pending = 0;
    }
    // On refusal `sip_tx_pending` stays set and the step loop retries.
    // Signalling is not media: a dropped SIP datagram is a lost transaction,
    // and only requests are covered by T1 retransmission — a refused 200 OK
    // would never be sent again.
    //
    // `sip_tx_len` is deliberately NOT cleared. It is the retransmission
    // buffer: `SipSend::Retransmit` re-flushes it unchanged, which is why the
    // pending flag is separate from the buffer's length.
}

/// Act on one application command.
unsafe fn handle_command(s: &mut SipModState, cmd: &sip_wire::SipCommandView) {
    match cmd.op {
        SIP_CMD_DIAL if s.fsm.state() == SipState::Ready && s.offer_pending == 0 => {
            // The peer and media endpoints travel with the command: a
            // connector that can only ever call one address is not one.
            if cmd.peer_port != 0 {
                s.peer_ip = u32::from_be_bytes(cmd.peer_ip);
                s.peer_sip_port = cmd.peer_port;
            }
            if cmd.media_port != 0 {
                s.rtp_port = cmd.media_port;
            }
            s.cid = cmd.cid;
            s.call_id_counter = s.call_id_counter.wrapping_add(1);
            write_hex16(&mut s.call_id, s.call_id_counter ^ s.from_tag);
            s.call_id_len = 4;
            s.cseq = 1;
            s.to_tag = 0;
            s.branch = s.branch.wrapping_add(1);
            let step = s.fsm.on_event(SipEvent::LocalInvite);
            apply(s, step);
        }
        SIP_CMD_ACCEPT if s.offer_pending != 0 => {
            if cmd.media_port != 0 {
                s.rtp_port = cmd.media_port;
            }
            s.offer_pending = 0;
            // Only now does the dialog machine see the INVITE, with an answer
            // it was given rather than one it assumed.
            let step = s.fsm.on_event(SipEvent::RxInvite { answer: true });
            apply(s, step);
        }
        SIP_CMD_REJECT if s.offer_pending != 0 => {
            s.offer_pending = 0;
            let code = if cmd.code == 0 { 603 } else { cmd.code };
            build_refusal(s, code);
            s.sip_tx_pending = 1;
            sip_flush(s);
            emit_event(s, SIP_EV_DECLINED, code);
            s.cid = 0;
        }
        SIP_CMD_HANGUP if s.fsm.state() == SipState::Active => {
            s.cseq += 1;
            s.branch = s.branch.wrapping_add(1);
            emit_event(s, SIP_EV_LOCAL_CLOSED, 0);
            let step = s.fsm.on_event(SipEvent::LocalBye);
            apply(s, step);
        }
        SIP_CMD_CANCEL if s.fsm.state() == SipState::Inviting => {
            // Abandoning a call that was never answered. The transaction is
            // dropped locally and reported; a CANCEL request on the wire is a
            // later profile, and claiming one was sent would be a lie.
            emit_event(s, SIP_EV_LOCAL_CLOSED, 0);
            s.fsm = SipDialogFsm::new();
            media_stop(s);
            s.cid = 0;
        }
        _ => {
            // A command that does not apply in this state is reported rather
            // than dropped: a caller waiting on an outcome for a call it
            // thinks it started would otherwise wait forever.
            let cid_before = s.cid;
            s.cid = cmd.cid;
            emit_event(s, SIP_EV_FAILED, 0);
            if cid_before != 0 {
                s.cid = cid_before;
            }
        }
    }
}

/// Stage the one event this transition owes.
///
/// First writer wins per transition, and the record is retried until the
/// channel takes it: an event dropped because the channel was briefly full
/// would leave a caller holding a call that had in fact ended.
unsafe fn emit_event(s: &mut SipModState, event: u8, code: u16) {
    if s.event_owed != 0 || s.event_out < 0 {
        return;
    }
    let media_ip = s.peer_rtp_ip.to_be_bytes();
    // 0 (PCMU) is the only payload this module carries; 0xFF says none is
    // settled, which is the honest answer before an answer SDP has arrived.
    let payload = if s.peer_rtp_port != 0 { 0u8 } else { 0xFF };
    let mut out = [0u8; SIP_EVENT_HDR + 64];
    if let Some(total) = write_sip_event(
        s.cid,
        event,
        code,
        media_ip,
        s.peer_rtp_port,
        payload,
        &[],
        &mut out,
    ) {
        s.event_buf[..total].copy_from_slice(&out[..total]);
        s.event_len = total as u16;
        s.event_owed = 1;
    }
}

/// Hand the staged event to `event_out`, retrying while the channel refuses.
unsafe fn flush_event(s: &mut SipModState) {
    if s.event_owed == 0 || s.event_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.event_out, POLL_OUT);
    if poll <= 0 || (poll as u32) & POLL_OUT == 0 {
        return;
    }
    let len = s.event_len as usize;
    if (sys.channel_write)(s.event_out, s.event_buf.as_ptr(), len) == len as i32 {
        s.event_owed = 0;
    }
}

/// Whether an application is driving this module.
///
/// When one is, `auto_answer` does not apply: a graph that wired a decision
/// port and also let the module answer on its own would answer twice, and the
/// first answer would be the one nobody authorised.
unsafe fn application_driven(s: &SipModState) -> bool {
    s.command_in >= 0
}

/// Classify a received datagram into a dialog event and extract its facts.
unsafe fn classify_and_extract(s: &mut SipModState, len: usize) -> Option<SipEvent> {
    let msg = &s.sip_rx_buf[..len];
    if msg.starts_with(b"INVITE ") {
        let ep = sip_core::parse_sdp_endpoint(msg)?;
        s.peer_rtp_ip = ep.ip.unwrap_or(s.peer_ip);
        s.peer_rtp_port = ep.port;
        if let Some(cid) = sip_core::find_call_id(msg) {
            let n = cid.len().min(CALL_ID_SIZE);
            s.call_id[..n].copy_from_slice(&cid[..n]);
            s.call_id_len = n as u8;
        }
        s.to_tag = sip_core::parse_from_tag(msg).wrapping_add(1);
        s.branch = s.branch.wrapping_add(1);
        if application_driven(s) {
            // The call is held: nothing is answered until a decision names
            // it. Ringing a caller and then having nobody able to accept is
            // a worse outcome than a refusal.
            if s.offer_pending == 0 && s.fsm.state() == SipState::Ready {
                s.cid_counter = s.cid_counter.wrapping_add(1);
                s.cid = s.cid_counter;
                s.offer_pending = 1;
                emit_event(s, SIP_EV_OFFERED, 0);
            }
            return None;
        }
        return Some(SipEvent::RxInvite {
            answer: s.auto_answer != 0,
        });
    }
    if msg.starts_with(b"ACK ") {
        // The ACK completes an answer this end sent: the call is up.
        if s.fsm.state() == SipState::WaitAck {
            emit_event(s, SIP_EV_ESTABLISHED, 200);
        }
        return Some(SipEvent::RxAck);
    }
    if msg.starts_with(b"BYE ") {
        emit_event(s, SIP_EV_REMOTE_HANGUP, 0);
        return Some(SipEvent::RxBye);
    }
    let code = sip_core::parse_status_code(msg);
    if code >= 100 {
        // A 2xx to our INVITE carries the answer SDP + remote tag.
        if (200..300).contains(&code) && s.fsm.state() == SipState::Inviting {
            if let Some(ep) = sip_core::parse_sdp_endpoint(msg) {
                s.peer_rtp_ip = ep.ip.unwrap_or(s.peer_ip);
                s.peer_rtp_port = ep.port;
            }
            s.to_tag = sip_core::parse_to_tag(msg);
        }
        // Report what the response means for the call. A provisional response
        // is progress and not an outcome; a final one that is not a 2xx ended
        // it, and says with which code.
        if s.fsm.state() == SipState::Inviting {
            if (100..200).contains(&code) {
                emit_event(s, SIP_EV_PROVISIONAL, code);
            } else if (200..300).contains(&code) {
                emit_event(s, SIP_EV_ESTABLISHED, code);
            } else {
                emit_event(s, SIP_EV_REJECTED, code);
            }
        }
        return Some(SipEvent::RxResponse { code });
    }
    None
}

/// Apply an FSM step: send any message and drive the media path.
unsafe fn apply(s: &mut SipModState, step: sip_dialog::SipStep) {
    if let Some(msg) = step.send {
        build(s, msg);
        s.sip_tx_pending = 1;
        sip_flush(s);
    }
    match step.media {
        MediaCmd::Start => media_start(s),
        MediaCmd::Stop => media_stop(s),
        MediaCmd::None => {}
    }
    if step.reset_timer {
        s.last_retransmit_ms = dev_millis(&*s.syscalls);
    }
}

/// Bounded state beat: `[sip] s=<state> rx=<n> sip=<n>` once a second, so a
/// rig capture can see whether the module is stepping, whether datagrams reach
/// it at all, and what the dialog thinks its state is. Rate-limited to one
/// line per second and carrying counters and an FSM state only — never message
/// bodies, peer credentials or media.
unsafe fn dbg_beat(s: &mut SipModState) {
    let sys = &*s.syscalls;
    let now = dev_millis(sys);
    if now.wrapping_sub(s.dbg_last_ms) < 1000 {
        return;
    }
    s.dbg_last_ms = now;
    // `b=` carries the signalling bind flag and `ep=` its endpoint id —
    // startup and bind evidence must ride the beat, because one-shot records
    // at module_new are emitted before DHCP binds and never leave the board
    // over UDP telemetry (rig run 2026-08-26). Media bind evidence lives with
    // the modules that own media now: `[rtp]`'s beat and `[jit]`'s records.
    let mut line = [0u8; 42];
    line[..8].copy_from_slice(b"[sip] s=");
    write_hex16(&mut line[8..12], s.fsm.state() as u16);
    line[12..16].copy_from_slice(b" rx=");
    write_hex16(&mut line[16..20], s.dbg_rx);
    line[20..25].copy_from_slice(b" sip=");
    write_hex16(&mut line[25..29], s.dbg_sip);
    line[29..32].copy_from_slice(b" b=");
    line[32] = b'0' + s.sip_bound;
    line[33..37].copy_from_slice(b" ep=");
    write_hex16(&mut line[37..41], s.sip_ep_id as u16);
    dev_log(sys, 3, line.as_ptr(), 41);
}

unsafe fn step_sip(s: &mut SipModState) {
    let sys = &*s.syscalls;
    dbg_beat(s);

    // Bind the SIP endpoint once.
    if s.sip_bound == 0 {
        if s.sip_net_out < 0 {
            return;
        }
        let port = s.local_sip_port.to_le_bytes();
        let payload = [port[0], port[1], 0u8];
        let wrote = net_write_frame(
            sys,
            s.sip_net_out,
            DG_CMD_BIND,
            payload.as_ptr(),
            3,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
        if wrote != 0 {
            s.sip_bound = 1;
            // Bind evidence: the request left this module.
            // Its absence isolates a wiring/backpressure fault before the IP
            // module; the `ep=` line below isolates one after it.
            let mut l = [0u8; 20];
            l[..15].copy_from_slice(b"[sip] bind sip=");
            write_hex16(&mut l[15..19], s.local_sip_port);
            dev_log(sys, 3, l.as_ptr(), 19);
        }
        return;
    }
    if s.sip_ep_id == 0xFF {
        if s.sip_net_in < 0 {
            return;
        }
        let poll = (sys.channel_poll)(s.sip_net_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let (msg_type, plen) =
                net_read_frame(sys, s.sip_net_in, s.net_buf.as_mut_ptr(), NET_BUF_SIZE);
            if msg_type == DG_MSG_BOUND && plen >= 3 {
                // A fanned provider output delivers every BOUND to every
                // leg. Claim ONLY the bind we asked for, by port — grabbing
                // the first BOUND polled claims another module's endpoint
                // and then filters every later datagram against the wrong
                // identity (Pi 5 rig, 2026-08-26).
                let (ep, port) = abi::contracts::net::datagram::dg_bound_parts(
                    core::slice::from_raw_parts(s.net_buf.as_ptr().add(NET_FRAME_HDR), plen),
                );
                if port == s.local_sip_port {
                    s.sip_ep_id = ep;
                    let mut l = [0u8; 18];
                    l[..13].copy_from_slice(b"[sip] sip ep=");
                    write_hex16(&mut l[13..17], s.sip_ep_id as u16);
                    dev_log(sys, 3, l.as_ptr(), 17);
                }
            }
        }
        return;
    }

    // Application commands take precedence over the one-byte trigger below, so
    // a graph that wires both is driven by the surface that can express which
    // call it means and why.
    if s.command_in >= 0 && s.event_owed == 0 {
        let poll = (sys.channel_poll)(s.command_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let mut b = [0u8; SIP_CMD_LEN];
            if (sys.channel_read)(s.command_in, b.as_mut_ptr(), SIP_CMD_LEN) > 0 {
                if let Some(cmd) = parse_sip_command(&b) {
                    if sip_cmd_is_known(cmd.op) {
                        handle_command(s, &cmd);
                        return;
                    }
                }
            }
        }
    }

    // Local call / hangup trigger.
    if s.call_ctrl_in >= 0 {
        let poll = (sys.channel_poll)(s.call_ctrl_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let mut b = [0u8; 1];
            if (sys.channel_read)(s.call_ctrl_in, b.as_mut_ptr(), 1) > 0 {
                let ev = match s.fsm.state() {
                    SipState::Ready => {
                        s.call_id_counter = s.call_id_counter.wrapping_add(1);
                        write_hex16(&mut s.call_id, s.call_id_counter ^ s.from_tag);
                        s.call_id_len = 4;
                        s.cseq = 1;
                        s.to_tag = 0;
                        s.branch = s.branch.wrapping_add(1);
                        Some(SipEvent::LocalInvite)
                    }
                    SipState::Active => {
                        s.cseq += 1;
                        s.branch = s.branch.wrapping_add(1);
                        Some(SipEvent::LocalBye)
                    }
                    _ => None,
                };
                if let Some(ev) = ev {
                    let step = s.fsm.on_event(ev);
                    apply(s, step);
                    return;
                }
            }
        }
    }

    // Retransmit timer for in-transaction states.
    let now = dev_millis(sys);
    if matches!(
        s.fsm.state(),
        SipState::Inviting | SipState::WaitAck | SipState::ByeSent
    ) && now.wrapping_sub(s.last_retransmit_ms) >= T1_MS
    {
        let before = s.fsm.state();
        let step = s.fsm.on_event(SipEvent::Timeout);
        // A transaction that gave up rather than retransmitting again has
        // ended the call, and the layer above is told which way.
        if step.send.is_none() && s.fsm.state() != before {
            emit_event(s, SIP_EV_TIMEOUT, 0);
        }
        apply(s, step);
    }

    // Inbound signalling.
    if s.sip_net_in >= 0 {
        let poll = (sys.channel_poll)(s.sip_net_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let (msg_type, plen) =
                net_read_frame(sys, s.sip_net_in, s.net_buf.as_mut_ptr(), NET_BUF_SIZE);
            if msg_type == DG_MSG_RX_FROM && plen > DG_V4_PREFIX {
                // The signalling ring is one leg of the ingress fan-out, so
                // it also carries RTP addressed to the media endpoints.
                // Filter by endpoint id BEFORE parsing: media bytes are not
                // SIP, and `dbg_rx` counts signalling-endpoint traffic only,
                // so the beat's evidence names this endpoint unambiguously.
                if *s.net_buf.as_ptr().add(NET_FRAME_HDR) == s.sip_ep_id {
                    let data_len = (plen - DG_V4_PREFIX).min(SIP_RX_BUF_SIZE);
                    core::ptr::copy_nonoverlapping(
                        s.net_buf.as_ptr().add(NET_FRAME_HDR + DG_V4_PREFIX),
                        s.sip_rx_buf.as_mut_ptr(),
                        data_len,
                    );
                    s.dbg_rx = s.dbg_rx.wrapping_add(1);
                    if data_len > 4 && (s.sip_rx_buf[0] as char).is_ascii_uppercase() {
                        s.dbg_sip = s.dbg_sip.wrapping_add(1);
                    }
                    if let Some(ev) = classify_and_extract(s, data_len) {
                        // Bounded, payload-free: a stable class code for the
                        // classified event (1=INVITE, 2=ACK, 3=BYE, else the
                        // response status), not the message bytes: the event is a fact
                        // about the dialogue, and the payload never leaves this module.
                        let code: u16 = match ev {
                            SipEvent::RxInvite { .. } => 1,
                            SipEvent::RxAck => 2,
                            SipEvent::RxBye => 3,
                            SipEvent::RxResponse { code } => code,
                            _ => 0,
                        };
                        let mut l = [0u8; 16];
                        l[..9].copy_from_slice(b"[sip] ev=");
                        write_hex16(&mut l[9..13], code);
                        dev_log(sys, 3, l.as_ptr(), 13);
                        let step = s.fsm.on_event(ev);
                        apply(s, step);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Media control — drive the rtp transmitter and the jitter adapter over
// the shared control records (fanned by the graph).
// ---------------------------------------------------------------------------

/// Queue an ordered media-control command for the RTP transmitter.
///
/// Queued rather than written directly because these commands are RELIABLE and
/// ORDERED in a way media is not. `SET_ENDPOINT` names where to send and
/// `START` begins sending, so a dropped one leaves the transmitter stopped, or
/// aimed at a previous call's endpoint, while this module believes a call is
/// up — silence in one direction with nothing reporting a fault. Losing an RTP
/// packet is acceptable; losing the instruction that says where the packets go
/// is not.
unsafe fn queue_rtp_ctrl(s: &mut SipModState, cmd: u8) {
    if s.rtp_ctrl_out < 0 {
        return;
    }
    if (s.ctrl_len as usize) < CTRL_QUEUE {
        s.ctrl_queue[s.ctrl_len as usize] = cmd;
        s.ctrl_len += 1;
    }
    flush_rtp_ctrl(s);
}

/// Hand queued control commands to the transmitter, in order, stopping at the
/// first refusal so ordering is preserved across steps.
unsafe fn flush_rtp_ctrl(s: &mut SipModState) {
    while s.ctrl_len > 0 {
        if !send_rtp_ctrl(s, s.ctrl_queue[0]) {
            return;
        }
        let n = s.ctrl_len as usize;
        let mut i = 1;
        while i < n {
            s.ctrl_queue[i - 1] = s.ctrl_queue[i];
            i += 1;
        }
        s.ctrl_len -= 1;
    }
}

/// Write one control command. Returns whether the channel took it whole.
unsafe fn send_rtp_ctrl(s: &mut SipModState, cmd: u8) -> bool {
    if s.rtp_ctrl_out < 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let mut m = [0u8; CTRL_MSG_SIZE];
    m[0] = cmd;
    if cmd == CTRL_SET_ENDPOINT {
        let port = s.peer_rtp_port.to_le_bytes();
        m[2] = port[0];
        m[3] = port[1];
        let ip = s.peer_rtp_ip.to_le_bytes();
        m[4] = ip[0];
        m[5] = ip[1];
        m[6] = ip[2];
        m[7] = ip[3];
    }
    (sys.channel_write)(s.rtp_ctrl_out, m.as_ptr(), CTRL_MSG_SIZE) == CTRL_MSG_SIZE as i32
}

unsafe fn media_start(s: &mut SipModState) {
    queue_rtp_ctrl(s, CTRL_SET_ENDPOINT);
    queue_rtp_ctrl(s, CTRL_START);
}

unsafe fn media_stop(s: &mut SipModState) {
    queue_rtp_ctrl(s, CTRL_STOP);
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

mod params_def {
    use super::SipModState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32, p_u8};

    define_params! {
        SipModState;
        1, local_ip, u32, 0 => |s, d, len| { s.local_ip = p_u32(d, len, 0, 0); };
        2, local_sip_port, u16, 5060 => |s, d, len| { s.local_sip_port = p_u16(d, len, 0, 5060); };
        3, peer_ip, u32, 0 => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0); };
        4, peer_sip_port, u16, 5060 => |s, d, len| { s.peer_sip_port = p_u16(d, len, 0, 5060); };
        5, rtp_port, u16, 5004 => |s, d, len| { s.rtp_port = p_u16(d, len, 0, 5004); };
        6, auto_answer, u8, 1 => |s, d, len| { s.auto_answer = p_u8(d, len, 0, 1); };
        8, ptime, u8, 20 => |s, d, len| { let v = p_u8(d, len, 0, 20); s.ptime = if v == 0 { 20 } else { v }; };
    }
}

// ---------------------------------------------------------------------------
// PIC interface
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SipModState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<SipModState>() {
            return -5;
        }
        let s = &mut *(state as *mut SipModState);
        s.init(syscalls as *const SyscallTable);
        let sys = &*s.syscalls;

        s.sip_net_in = in_chan;
        s.sip_net_out = out_chan;
        s.call_ctrl_in = ctrl_chan;
        // in[1] = command_in, out[1] = rtp_ctrl, out[2] = event_out. The
        // media ports belong to the media modules, not to signalling.
        s.command_in = dev_channel_port(sys, 0, 1);
        let ch = dev_channel_port(sys, 1, 1);
        if ch >= 0 {
            s.rtp_ctrl_out = ch;
        }
        s.event_out = dev_channel_port(sys, 1, 2);

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        if s.local_ip != 0 && s.peer_ip != 0 {
            s.sip_active = 1;
            let now = dev_millis(sys) as u16;
            s.from_tag = now ^ 0x5349;
            s.branch = now;
        }

        // Startup evidence: the record a rig capture keys
        // on to distinguish "module never instantiated" from every later
        // failure class. Local ports and the active flag only.
        let mut line = [0u8; 34];
        line[..13].copy_from_slice(b"[sip] new sp=");
        write_hex16(&mut line[13..17], s.local_sip_port);
        line[17..21].copy_from_slice(b" rp=");
        write_hex16(&mut line[21..25], s.rtp_port);
        line[25..28].copy_from_slice(b" a=");
        line[28] = b'0' + s.sip_active;
        dev_log(sys, 3, line.as_ptr(), 29);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut SipModState);
        if s.syscalls.is_null() {
            return -1;
        }
        if s.sip_active != 0 {
            step_sip(s);
            // Retry anything a full channel refused: a staged SIP datagram and
            // any queued media-control command.
            sip_flush(s);
            flush_rtp_ctrl(s);
            // And the one event the last transition owes.
            flush_event(s);
        }
        0
    }
}

include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
