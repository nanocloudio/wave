//! HTTP/2 client (h2c, cleartext) — single-stream fetch / submit.
//!
//! Connects, sends the connection preface and an empty SETTINGS frame,
//! ACKs the server's SETTINGS, then issues exactly one request on
//! stream id 1:
//!
//! - GET (no body): HEADERS with END_STREAM.
//! - POST (`request_body` set): HEADERS without END_STREAM, followed
//!   by DATA frames until the body is exhausted; the last DATA carries
//!   END_STREAM.
//! - WebSocket bootstrap (`websocket = 1`): extended CONNECT
//!   (RFC 8441) + `:protocol = websocket`. Once the server replies 200
//!   HEADERS the stream tunnels RFC 6455 frames inside DATA frames in
//!   both directions.
//! - gRPC unary (`grpc = 1`): a POST that sends `content-type:
//!   application/grpc` + `te: trailers` instead of a plain body. The
//!   caller supplies the gRPC Length-Prefixed-Message
//!   (`[compressed:1][len:4 BE][message]`) as `request_body`; the
//!   response DATA (the reply LPM) is forwarded like any body, and the
//!   trailing HEADERS' `grpc-status` is surfaced — a non-zero (non-OK)
//!   status fails the transfer even though the HTTP `:status` is 200.
//!
//! Response body is forwarded to the module's data output channel
//! until END_STREAM — for a server-streaming method that is every DATA
//! frame's payload concatenated (N gRPC messages), closed by the
//! trailers. Connection-level recv flow control honours
//! `RECV_WINDOW_THRESHOLD` — a WINDOW_UPDATE goes out automatically when
//! the window depletes so the server keeps streaming. Peer PING frames
//! are answered with a PING ACK (§6.7); gRPC servers withhold a stream's
//! closing trailers until their keepalive/BDP PING is acknowledged.
//!
//! # Scope
//!
//! - HPACK encodes literal-without-indexing entries.
//! - Stream id is hardcoded to 1.
//! - No Huffman on send (inbound Huffman strings are decoded); no
//!   PUSH; no CONTINUATION.
//! - h2c only on this surface; h2-over-TLS arrives via the `tls`
//!   module wrapping the cleartext channel.

use super::super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_CLOSE, NET_CMD_CONNECT, NET_CMD_SEND, NET_MSG_CLOSED,
    NET_MSG_CONNECTED, NET_MSG_DATA, NET_MSG_ERROR,
};
use super::super::wire::h2 as h2w;
use super::super::wire::ws;
use super::super::HttpState;
use super::super::{
    dev_csprng_fill, dev_log, dev_millis, dev_requester_tag, net_read_frame,
    net_read_frame_aligned, net_write_frame, E_AGAIN, NET_FRAME_HDR, POLL_IN, POLL_OUT,
    SOCK_TYPE_STREAM,
};
use super::{
    send_close_frame, Phase as H1Phase, E_CONNECT_FAILED, E_NET_FAILED, E_SEND_FAILED,
    E_WRITE_FAILED, RECV_BUF_SIZE, REQUEST_BUF_SIZE,
};

const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const STREAM_ID: u32 = 1;
/// Spec default initial recv window (RFC 7540 §6.9.2).
const RECV_WINDOW_INITIAL: i32 = 65535;
/// Below this we proactively queue a WINDOW_UPDATE to refill so the
/// server keeps streaming response body without stalling.
const RECV_WINDOW_THRESHOLD: i32 = 32768;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum H2Phase {
    Init = 0,
    Connecting = 1,
    WaitConnect = 2,
    SendPreface = 3,  // request_buf holds preface + SETTINGS, drain to net_out
    WaitSettings = 4, // receive server SETTINGS, ack, then queue HEADERS
    SendRequest = 5,  // request_buf holds (ACK +) HEADERS, draining
    SendBody = 6,     // POST body — frame `request_body` into DATA frames
    WaitResponse = 7, // peek h2 frames out of recv_buf; HEADERS / DATA / control
    Writing = 8,      // current DATA frame's payload is being forwarded to out_chan
    /// WebSocket-over-h2 active. After the server's 200 HEADERS the
    /// stream tunnels RFC 6455 frames inside h2 DATA frames. The
    /// minimal client sends `request_body` once as a TEXT frame, waits
    /// for the echo, sends CLOSE, and exits.
    WsActive = 9,
    Done = 10,
    Error = 255,
}

#[inline]
fn phase(s: &HttpState) -> H2Phase {
    // safe: u8 → H2Phase only ever set by this module
    let v = s.client.h2_phase;
    match v {
        0 => H2Phase::Init,
        1 => H2Phase::Connecting,
        2 => H2Phase::WaitConnect,
        3 => H2Phase::SendPreface,
        4 => H2Phase::WaitSettings,
        5 => H2Phase::SendRequest,
        6 => H2Phase::SendBody,
        7 => H2Phase::WaitResponse,
        8 => H2Phase::Writing,
        9 => H2Phase::WsActive,
        10 => H2Phase::Done,
        _ => H2Phase::Error,
    }
}

#[inline]
fn set_phase(s: &mut HttpState, p: H2Phase) {
    s.client.h2_phase = p as u8;
}

#[inline(always)]
unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

/// Emit `[http] transfer done bytes=NNN` once the response body has
/// been fully delivered (or silently consumed when no sink is wired).
unsafe fn log_done(s: &HttpState) {
    let mut buf = [0u8; 40];
    let prefix = b"[http] transfer done bytes=";
    let mut o = 0usize;
    while o < prefix.len() {
        buf[o] = prefix[o];
        o += 1;
    }
    let n = super::super::fmt_u32_raw(buf.as_mut_ptr().add(o), s.client.bytes_received);
    o += n;
    dev_log(&*s.syscalls, 3, buf.as_ptr(), o);
}

/// Emit `[http] grpc-status=N` when a gRPC call closes with a `grpc-status`
/// trailer (RFC: the definitive per-call status; 0 = OK, non-zero = failure).
unsafe fn log_grpc_status(s: &HttpState, status: u32) {
    let mut buf = [0u8; 32];
    let prefix = b"[http] grpc-status=";
    let mut o = 0usize;
    while o < prefix.len() {
        buf[o] = prefix[o];
        o += 1;
    }
    o += super::super::fmt_u32_raw(buf.as_mut_ptr().add(o), status);
    dev_log(&*s.syscalls, 3, buf.as_ptr(), o);
}

/// Drive one tick. Returns 0 (idle), 1 (done), or a negative error.
pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    // The h1 step machine uses `client.phase`; the h2 path uses
    // `client.h2_phase`. The two never run interleaved (mode dispatch
    // in mod.rs picks one at module_step). The h1 phase is left at
    // `Init` so post_params() doesn't trip it.
    if s.client.phase != H1Phase::Init {
        s.client.phase = H1Phase::Init;
    }

    loop {
        match phase(s) {
            H2Phase::Init => {
                log(s, b"[http] connecting (h2c)");
                set_phase(s, H2Phase::Connecting);
                continue;
            }

            H2Phase::Connecting => {
                if s.net_out_chan < 0 {
                    set_phase(s, H2Phase::Error);
                    return E_NET_FAILED;
                }
                let sys = &*s.syscalls;
                let chan = s.net_out_chan;
                let buf = s.net_buf.as_mut_ptr();
                let mut payload = [0u8; 8];
                payload[0] = SOCK_TYPE_STREAM;
                let ip = s.client.host_ip.to_le_bytes();
                payload[1] = ip[0];
                payload[2] = ip[1];
                payload[3] = ip[2];
                payload[4] = ip[3];
                payload[5] = (s.client.port & 0xFF) as u8;
                payload[6] = (s.client.port >> 8) as u8;
                // requester tag = our module index (see client.rs).
                payload[7] = dev_requester_tag(sys);
                let wrote = net_write_frame(
                    sys,
                    chan,
                    NET_CMD_CONNECT,
                    payload.as_ptr(),
                    8,
                    buf,
                    NET_BUF_SIZE,
                );
                if wrote == 0 {
                    return 0;
                }
                s.client.connect_start_ms = dev_millis(sys);
                set_phase(s, H2Phase::WaitConnect);
                return 0;
            }

            H2Phase::WaitConnect => {
                if s.net_in_chan < 0 {
                    return 0;
                }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                    let buf = s.net_buf.as_mut_ptr();
                    let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
                    if msg_type == NET_MSG_CONNECTED && payload_len >= 2 {
                        // Claim only our own outbound connection by requester tag
                        // (see client.rs). Untagged or our tag → ours.
                        let (_, tag) = net_proto::connected_parts(core::slice::from_raw_parts(
                            buf.add(NET_FRAME_HDR),
                            payload_len,
                        ));
                        let me = dev_requester_tag(sys);
                        if tag != 0 && tag != me {
                            return 0;
                        }
                        s.client.conn_id = net_proto::conn_id(core::slice::from_raw_parts(
                            buf.add(NET_FRAME_HDR),
                            payload_len,
                        ));
                        s.client.conn_present = 1;
                        log(s, b"[http] connected (h2c)");
                        build_preface(s);
                        set_phase(s, H2Phase::SendPreface);
                        continue;
                    } else if msg_type == NET_MSG_ERROR {
                        // Connect failure carries our tag at payload[3]; ignore
                        // another consumer's error on a fanned net_in.
                        let etag = if payload_len >= 3 {
                            net_proto::error_parts(core::slice::from_raw_parts(
                                buf.add(NET_FRAME_HDR),
                                payload_len,
                            ))
                            .2
                        } else {
                            net_proto::REQUESTER_TAG_NONE
                        };
                        if etag == 0 || etag == dev_requester_tag(sys) {
                            log(s, b"[http] connect error");
                            set_phase(s, H2Phase::Error);
                            return E_CONNECT_FAILED;
                        }
                    }
                }
                if dev_millis(sys).wrapping_sub(s.client.connect_start_ms) >= CONNECT_TIMEOUT_MS {
                    log(s, b"[http] connect timeout");
                    set_phase(s, H2Phase::Error);
                    return E_CONNECT_FAILED;
                }
                return 0;
            }

            H2Phase::SendPreface => {
                if !drain_request_buf(s) {
                    return 0;
                }
                log(s, b"[http] preface sent");
                s.client.recv_len = 0;
                set_phase(s, H2Phase::WaitSettings);
                continue;
            }

            H2Phase::WaitSettings => {
                if !pump_inbound(s) {
                    return 0;
                }
                // Look for the server's first SETTINGS frame (without
                // ACK flag). Drain any other control frames the server
                // sends along with it.
                match consume_until_settings(s) {
                    Some(true) => {
                        // SETTINGS observed and consumed; queue ACK +
                        // HEADERS in request_buf, drive SendRequest.
                        build_request(s);
                        set_phase(s, H2Phase::SendRequest);
                        continue;
                    }
                    Some(false) => {
                        // peer error
                        set_phase(s, H2Phase::Error);
                        return E_NET_FAILED;
                    }
                    None => return 0, // need more bytes
                }
            }

            H2Phase::SendRequest => {
                if !drain_request_buf(s) {
                    return 0;
                }
                // For WS, `request_body` is the initial WS message and
                // is sent later by `WsActive` after the upgrade — we
                // skip the h2 SendBody path here.
                let has_h2_body = s.client.request_body_len > 0 && s.client.websocket == 0;
                if has_h2_body {
                    log(s, b"[http] sending request body (h2c)");
                    s.client.request_body_sent = 0;
                    set_phase(s, H2Phase::SendBody);
                } else {
                    log(s, b"[http] request sent (h2c)");
                    set_phase(s, H2Phase::WaitResponse);
                }
                continue;
            }

            H2Phase::SendBody => {
                if !drain_request_buf(s) {
                    return 0;
                }
                if s.client.request_body_sent >= s.client.request_body_len {
                    log(s, b"[http] request body sent (h2c)");
                    set_phase(s, H2Phase::WaitResponse);
                    continue;
                }
                build_body_frame(s);
                continue;
            }

            H2Phase::WaitResponse => {
                // Flush any queued control frame — a WINDOW_UPDATE we owe, or a
                // PING/SETTINGS ACK queued by process_one_frame — before pulling
                // more inbound bytes. Draining every pass gets a PING ACK onto
                // the wire; a gRPC server-stream withholds its trailers until
                // its PING is acknowledged.
                maybe_queue_window_update(s);
                if !drain_request_buf(s) {
                    return 0;
                }
                // Always try to make progress on inbound bytes first.
                pump_inbound(s);

                let action = process_one_frame(s);
                match action {
                    FrameAction::NeedMore => return 0,
                    FrameAction::Continue => {
                        // For a WS upgrade, the response HEADERS
                        // (status=200) means the stream now tunnels
                        // RFC 6455 frames. Transition before processing
                        // the next frame.
                        if s.client.websocket != 0 && s.client.headers_done != 0 {
                            log(s, b"[http] websocket upgraded (h2c)");
                            s.client.request_body_sent = 0;
                            s.client.ws_done = 0;
                            set_phase(s, H2Phase::WsActive);
                        }
                        continue;
                    }
                    FrameAction::DataPending => {
                        s.client.pending_offset = 0;
                        set_phase(s, H2Phase::Writing);
                        continue;
                    }
                    FrameAction::Done => {
                        log_done(s);
                        let _ = send_close_frame(s);
                        set_phase(s, H2Phase::Done);
                        // A body-less response (204, a bare 200) is still an
                        // answer; an empty payload is not a refusal.
                        #[cfg(feature = "exchange")]
                        super::exchange::complete(s);
                        return 1;
                    }
                    FrameAction::Error => {
                        set_phase(s, H2Phase::Error);
                        return E_NET_FAILED;
                    }
                }
            }

            H2Phase::WsActive => {
                // Drain any pending outbound bytes (the initial WS
                // frame or a queued CLOSE).
                if s.client.request_sent < s.client.request_len && !drain_request_buf(s) {
                    return 0;
                }
                // First action after the upgrade: send `request_body`
                // as a masked WS TEXT frame inside an h2 DATA frame.
                if s.client.request_body_sent == 0
                    && s.client.request_body_len > 0
                    && s.client.ws_done == 0
                {
                    build_ws_frame(
                        s,
                        ws::OP_TEXT,
                        s.client.request_body.as_ptr(),
                        s.client.request_body_len as usize,
                        false,
                    );
                    s.client.request_body_sent = s.client.request_body_len;
                    continue;
                }
                // Peer's CLOSE echo arrived — exit cleanly.
                if s.client.ws_done == 2 {
                    log_done(s);
                    let _ = send_close_frame(s);
                    set_phase(s, H2Phase::Done);
                    #[cfg(feature = "exchange")]
                    super::exchange::complete(s);
                    return 1;
                }
                // Bidirectional mode: if `in[1]` is wired and has
                // outgoing data, wrap and queue it. HUP queues a
                // CLOSE so the session terminates cleanly.
                if s.client.data_in_chan >= 0 && s.client.ws_done == 0 && pump_data_in(s).is_some()
                {
                    continue;
                }
                // If we owe a WINDOW_UPDATE, get it onto the wire so
                // the server keeps streaming WS frames.
                if maybe_queue_window_update(s) && !drain_request_buf(s) {
                    return 0;
                }
                // Otherwise pump inbound frames and process WS DATA
                // inline (process_ws_data may queue our own CLOSE).
                pump_inbound(s);
                let action = process_one_frame(s);
                match action {
                    FrameAction::NeedMore => return 0,
                    FrameAction::Continue => continue,
                    FrameAction::DataPending => continue,
                    FrameAction::Done => {
                        log_done(s);
                        let _ = send_close_frame(s);
                        set_phase(s, H2Phase::Done);
                        // A body-less response (204, a bare 200) is still an
                        // answer; an empty payload is not a refusal.
                        #[cfg(feature = "exchange")]
                        super::exchange::complete(s);
                        return 1;
                    }
                    FrameAction::Error => {
                        set_phase(s, H2Phase::Error);
                        return E_NET_FAILED;
                    }
                }
            }

            H2Phase::Writing => {
                // Graph-driven: a reply is ONE frame, so the body is
                // accumulated rather than streamed to `file_ctrl`. Same rule
                // as h1 — the protocols differ in where the bytes come from,
                // not in what an exchange does with them.
                #[cfg(feature = "exchange")]
                if super::exchange::busy(s) {
                    let plen = data_frame_payload_len(s);
                    let end = data_frame_end_stream(s);
                    let n = plen.min(super::RECV_BUF_SIZE - h2w::FRAME_HEADER_LEN);
                    let src = s.client.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN);
                    super::exchange::accumulate(s, src, n);
                    s.client.bytes_received += plen as u32;
                    consume_data_frame(s);
                    if end {
                        log_done(s);
                        let _ = send_close_frame(s);
                        set_phase(s, H2Phase::Done);
                        super::exchange::complete(s);
                        return 1;
                    }
                    set_phase(s, H2Phase::WaitResponse);
                    continue;
                }

                if s.client.out_chan < 0 {
                    // No data sink — drop the body silently and resume.
                    let plen = data_frame_payload_len(s);
                    let end = data_frame_end_stream(s);
                    s.client.bytes_received += plen as u32;
                    consume_data_frame(s);
                    if end {
                        log_done(s);
                        let _ = send_close_frame(s);
                        set_phase(s, H2Phase::Done);
                        #[cfg(feature = "exchange")]
                        super::exchange::complete(s);
                        return 1;
                    }
                    set_phase(s, H2Phase::WaitResponse);
                    continue;
                }
                let sys = &*s.syscalls;
                let out_chan = s.client.out_chan;
                let poll = (sys.channel_poll)(out_chan, POLL_OUT);
                if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
                    return 0;
                }

                let payload_len = data_frame_payload_len(s);
                let pending = s.client.pending_offset as usize;
                if pending >= payload_len {
                    // Whole frame already drained — shift it off and
                    // resume frame parsing.
                    let end_stream = data_frame_end_stream(s);
                    consume_data_frame(s);
                    if end_stream {
                        log_done(s);
                        let _ = send_close_frame(s);
                        set_phase(s, H2Phase::Done);
                        #[cfg(feature = "exchange")]
                        super::exchange::complete(s);
                        return 1;
                    }
                    set_phase(s, H2Phase::WaitResponse);
                    continue;
                }
                let src = s
                    .client
                    .recv_buf
                    .as_ptr()
                    .add(h2w::FRAME_HEADER_LEN + pending);
                let remaining = payload_len - pending;
                let written = (sys.channel_write)(out_chan, src, remaining);
                if written < 0 {
                    if written == E_AGAIN {
                        return 0;
                    }
                    log(s, b"[http] write failed");
                    set_phase(s, H2Phase::Error);
                    return E_WRITE_FAILED;
                }
                s.client.pending_offset += written as u16;
                s.client.bytes_received += written as u32;
                return 0;
            }

            H2Phase::Done => {
                let _ = send_close_frame(s);
                #[cfg(feature = "exchange")]
                super::exchange::complete(s);
                return 1;
            }

            H2Phase::Error => {
                let _ = send_close_frame(s);
                // No silent drops: a failed exchange is answered.
                #[cfg(feature = "exchange")]
                super::exchange::fail(s);
                return -1;
            }
        }
    }
}

// ── Frame-level helpers ───────────────────────────────────────────────────

enum FrameAction {
    NeedMore,
    Continue,
    DataPending,
    Done,
    Error,
}

unsafe fn process_one_frame(s: &mut HttpState) -> FrameAction {
    let len = s.client.recv_len as usize;
    let hdr = match h2w::parse_header(s.client.recv_buf.as_ptr(), len) {
        Some(h) => h,
        None => return FrameAction::NeedMore,
    };
    let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
    if total > RECV_BUF_SIZE {
        // Server announced a frame larger than we can buffer — bail
        // before we'd otherwise wait forever for the rest.
        return FrameAction::Error;
    }
    if total > len {
        return FrameAction::NeedMore;
    }

    match hdr.ftype {
        h2w::FRAME_HEADERS => {
            // Response HEADERS — decode :status only. Body follows in
            // DATA frames; we don't expose other headers to the
            // consumer in this slice.
            let block_ptr = s.client.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN);
            let (block_off, block_len) =
                match h2w::headers_block_extent(block_ptr, hdr.length, hdr.flags) {
                    Ok(x) => x,
                    Err(_) => return FrameAction::Error,
                };
            let blk = block_ptr.add(block_off);
            let mut status: u16 = 0;
            let st_ptr = &mut status as *mut u16;
            // gRPC per-call status: -1 = absent (defaults to 0/OK per spec),
            // >= 0 = the `grpc-status` trailer value. Carried in trailing
            // HEADERS, or (Trailers-Only response) in the first HEADERS.
            let mut grpc_status: i32 = -1;
            let gs_ptr = &mut grpc_status as *mut i32;
            let dec = super::super::wire::hpack::decode_block(blk, block_len, |name, value| {
                if name == b":status" && value.len() <= 4 {
                    let mut v: u16 = 0;
                    for &c in value {
                        if !c.is_ascii_digit() {
                            return;
                        }
                        v = v.saturating_mul(10) + (c - b'0') as u16;
                    }
                    *st_ptr = v;
                } else if name == b"grpc-status" && !value.is_empty() && value.len() <= 4 {
                    let mut v: i32 = 0;
                    for &c in value {
                        if !c.is_ascii_digit() {
                            return;
                        }
                        v = v.saturating_mul(10) + (c - b'0') as i32;
                    }
                    *gs_ptr = v;
                }
            });
            if dec.is_err() {
                return FrameAction::Error;
            }
            // A HEADERS frame after the initial response headers is a
            // trailing header block (HTTP trailers / gRPC grpc-status).
            // Trailers carry no `:status`, so only the FIRST HEADERS is
            // required to have one; trailers just close the stream.
            let is_trailers = s.client.headers_done != 0;
            if !is_trailers {
                if status == 0 {
                    return FrameAction::Error;
                }
                log(s, b"[http] headers done (h2c)");
                s.client.headers_done = 1;
                s.client.content_length = status as u32;
            }

            let end_stream = (hdr.flags & h2w::FLAG_END_STREAM) != 0;
            shift_consume(s, total);
            // In gRPC mode the definitive per-call outcome is `grpc-status`,
            // NOT the HTTP `:status` (a failed RPC is still HTTP 200). Surface
            // it and fail the transfer on any non-zero (non-OK) status.
            if s.client.grpc != 0 && grpc_status >= 0 {
                log_grpc_status(s, grpc_status as u32);
                if grpc_status != 0 {
                    return FrameAction::Error;
                }
            }
            if end_stream {
                return FrameAction::Done;
            }
            FrameAction::Continue
        }

        h2w::FRAME_DATA => {
            // Account for received bytes against connection-level
            // recv window first, regardless of WS or non-WS handling.
            // Padding counts against flow control in full (§6.1).
            consume_recv_window(s, hdr.length);

            // Strip DATA padding (§6.1) in place: drop the pad-length
            // octet and the trailing pad, shrink the frame header, and
            // close the gap so later frames stay contiguous. Both the
            // WS parser and the Writing forward path (which re-parses
            // the header) must see real payload bytes only.
            let mut total = total;
            let mut flags = hdr.flags;
            let mut dlen = hdr.length as usize;
            if (flags & h2w::FLAG_PADDED) != 0 {
                let p = s.client.recv_buf.as_mut_ptr();
                if dlen == 0 {
                    return FrameAction::Error; // pad-length octet missing
                }
                let pad = *p.add(h2w::FRAME_HEADER_LEN) as usize;
                if pad + 1 > dlen {
                    // §6.1: padding >= remaining payload → PROTOCOL_ERROR.
                    return FrameAction::Error;
                }
                let new_len = dlen - 1 - pad;
                let mut i = 0;
                while i < new_len {
                    *p.add(h2w::FRAME_HEADER_LEN + i) = *p.add(h2w::FRAME_HEADER_LEN + 1 + i);
                    i += 1;
                }
                let new_total = h2w::FRAME_HEADER_LEN + new_len;
                let tail = len - total;
                let mut j = 0;
                while j < tail {
                    *p.add(new_total + j) = *p.add(total + j);
                    j += 1;
                }
                flags &= !h2w::FLAG_PADDED;
                h2w::write_header(p, new_len as u32, h2w::FRAME_DATA, flags, hdr.stream_id);
                s.client.recv_len -= (1 + pad) as u16;
                total = new_total;
                dlen = new_len;
            }

            // WS-over-h2: DATA payload is a stream of RFC 6455 frames.
            // Parse and process inline; never go through the Writing
            // body-forward path.
            if s.client.websocket != 0 {
                let payload_ptr = s.client.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN);
                process_ws_data(s, payload_ptr, dlen);
                let end_stream = (flags & h2w::FLAG_END_STREAM) != 0;
                shift_consume(s, total);
                if end_stream {
                    return FrameAction::Done;
                }
                return FrameAction::Continue;
            }
            if dlen == 0 {
                let end_stream = (flags & h2w::FLAG_END_STREAM) != 0;
                shift_consume(s, total);
                if end_stream {
                    return FrameAction::Done;
                }
                return FrameAction::Continue;
            }
            // Leave the frame in recv_buf for Writing to drain; signal
            // body bytes pending to the caller.
            FrameAction::DataPending
        }

        h2w::FRAME_SETTINGS => {
            if (hdr.flags & h2w::FLAG_ACK) == 0 {
                // Mid-stream SETTINGS — ack into request_buf if free,
                // otherwise drop on the floor (we don't act on values).
                if s.client.request_len == s.client.request_sent {
                    let n = h2w::write_settings_ack(s.client.request_buf.as_mut_ptr());
                    s.client.request_len = n as u16;
                    s.client.request_sent = 0;
                }
            }
            shift_consume(s, total);
            FrameAction::Continue
        }

        h2w::FRAME_GOAWAY => {
            // Peer is closing.
            shift_consume(s, total);
            FrameAction::Done
        }

        h2w::FRAME_PING => {
            // Reply to a peer PING with a PING ACK echoing the 8 opaque bytes
            // (RFC 7540 §6.7). gRPC servers send BDP-estimation / keepalive
            // PINGs and withhold stream completion (the closing trailers) until
            // the ACK — so a server-stream stalls after the data frames without
            // it. Queue the ACK into request_buf (drained by the response loop);
            // if request_buf is busy, drop it (the peer re-pings).
            if hdr.stream_id != 0 || hdr.length != 8 {
                // §6.7: PING is connection-scoped with a fixed 8-byte
                // payload; anything else is a connection error. The check
                // also guarantees the 8-byte echo below stays inside the
                // received frame.
                return FrameAction::Error;
            }
            if (hdr.flags & h2w::FLAG_ACK) == 0 && s.client.request_len == s.client.request_sent {
                let opaque = s.client.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN);
                let n = h2w::write_ping_ack(s.client.request_buf.as_mut_ptr(), opaque);
                s.client.request_len = n as u16;
                s.client.request_sent = 0;
            }
            shift_consume(s, total);
            FrameAction::Continue
        }

        h2w::FRAME_WINDOW_UPDATE | h2w::FRAME_PRIORITY | h2w::FRAME_RST_STREAM => {
            shift_consume(s, total);
            FrameAction::Continue
        }

        _ => {
            // Unknown frame types must be ignored per §5.5.
            shift_consume(s, total);
            FrameAction::Continue
        }
    }
}

unsafe fn data_frame_payload_len(s: &HttpState) -> usize {
    match h2w::parse_header(s.client.recv_buf.as_ptr(), s.client.recv_len as usize) {
        Some(h) => h.length as usize,
        None => 0,
    }
}

unsafe fn data_frame_end_stream(s: &HttpState) -> bool {
    match h2w::parse_header(s.client.recv_buf.as_ptr(), s.client.recv_len as usize) {
        Some(h) => (h.flags & h2w::FLAG_END_STREAM) != 0,
        None => false,
    }
}

unsafe fn consume_data_frame(s: &mut HttpState) {
    let len = data_frame_payload_len(s);
    shift_consume(s, h2w::FRAME_HEADER_LEN + len);
    s.client.pending_offset = 0;
}

unsafe fn shift_consume(s: &mut HttpState, total: usize) {
    let len = s.client.recv_len as usize;
    let leftover = len - total;
    if leftover > 0 {
        let p = s.client.recv_buf.as_mut_ptr();
        let mut i = 0;
        while i < leftover {
            *p.add(i) = *p.add(total + i);
            i += 1;
        }
    }
    s.client.recv_len = leftover as u16;
}

// ── Request building ──────────────────────────────────────────────────────

unsafe fn build_preface(s: &mut HttpState) {
    let buf = s.client.request_buf.as_mut_ptr();
    let mut o = 0usize;
    // 24-byte preface
    let mut i = 0;
    while i < PREFACE.len() {
        *buf.add(o + i) = PREFACE[i];
        i += 1;
    }
    o += PREFACE.len();
    // Empty SETTINGS frame so the server gets it before we send HEADERS.
    let n = h2w::write_settings(buf.add(o), &[]);
    o += n;
    s.client.request_len = o as u16;
    s.client.request_sent = 0;
}

unsafe fn build_request(s: &mut HttpState) {
    let buf = s.client.request_buf.as_mut_ptr();
    let mut o = 0usize;
    let is_ws = s.client.websocket != 0;
    let has_body = !is_ws && s.client.request_body_len > 0;

    // 1) ACK the server's SETTINGS frame.
    let n = h2w::write_settings_ack(buf.add(o));
    o += n;

    // 2) Build the HEADERS frame.
    let block_start = o + h2w::FRAME_HEADER_LEN;
    let mut bo = block_start;
    let method: &[u8] = if is_ws {
        b"CONNECT"
    } else if has_body {
        b"POST"
    } else {
        b"GET"
    };
    bo += super::super::wire::hpack::encode_header(
        buf.add(bo),
        REQUEST_BUF_SIZE - bo,
        b":method",
        method,
    );
    bo += super::super::wire::hpack::encode_header(
        buf.add(bo),
        REQUEST_BUF_SIZE - bo,
        b":scheme",
        b"http",
    );
    let plen = s.client.path_len as usize;
    let path = s.client.path.as_ptr();
    bo += super::super::wire::hpack::encode_header(
        buf.add(bo),
        REQUEST_BUF_SIZE - bo,
        b":path",
        core::slice::from_raw_parts(path, plen),
    );
    let mut authority = [0u8; 21]; // "255.255.255.255:65535"
    let auth_len = format_authority(s.client.host_ip, s.client.port, authority.as_mut_ptr());
    bo += super::super::wire::hpack::encode_header(
        buf.add(bo),
        REQUEST_BUF_SIZE - bo,
        b":authority",
        core::slice::from_raw_parts(authority.as_ptr(), auth_len),
    );

    if is_ws {
        // RFC 8441 §4 — extended CONNECT pseudo-header bootstraps WS.
        bo += super::super::wire::hpack::encode_header(
            buf.add(bo),
            REQUEST_BUF_SIZE - bo,
            b":protocol",
            b"websocket",
        );
    }

    if has_body {
        let is_grpc = s.client.grpc != 0;
        bo += super::super::wire::hpack::encode_header(
            buf.add(bo),
            REQUEST_BUF_SIZE - bo,
            b"content-type",
            if is_grpc {
                b"application/grpc" as &[u8]
            } else {
                b"application/octet-stream"
            },
        );
        if is_grpc {
            // gRPC-over-HTTP/2 (§ gRPC spec) requires `te: trailers` so the
            // server may send grpc-status/grpc-message in trailing HEADERS.
            // No content-length: gRPC bodies are DATA-framed and END_STREAM
            // delimited, and the framed body may exceed the initial buffer.
            bo += super::super::wire::hpack::encode_header(
                buf.add(bo),
                REQUEST_BUF_SIZE - bo,
                b"te",
                b"trailers",
            );
        } else {
            let mut clen = [0u8; 11];
            let n = super::super::fmt_u32_raw(clen.as_mut_ptr(), s.client.request_body_len as u32);
            bo += super::super::wire::hpack::encode_header(
                buf.add(bo),
                REQUEST_BUF_SIZE - bo,
                b"content-length",
                core::slice::from_raw_parts(clen.as_ptr(), n),
            );
        }
    }

    let block_len = bo - block_start;
    // GET → END_STREAM + END_HEADERS. POST / WS-CONNECT → END_HEADERS
    // only; DATA frames carry the body / WS frames and the last one
    // sets END_STREAM.
    let end_stream = !has_body && !is_ws;
    h2w::write_headers_frame_header(buf.add(o), block_len, STREAM_ID, end_stream, true);
    o = bo;

    s.client.request_len = o as u16;
    s.client.request_sent = 0;
}

/// Frame the next chunk of `request_body` into a DATA frame in
/// `request_buf`. Sets END_STREAM on the chunk that exhausts the body.
unsafe fn build_body_frame(s: &mut HttpState) {
    let buf = s.client.request_buf.as_mut_ptr();
    let body_remaining = (s.client.request_body_len - s.client.request_body_sent) as usize;
    let max_chunk = REQUEST_BUF_SIZE - h2w::FRAME_HEADER_LEN;
    let chunk = body_remaining.min(max_chunk);
    let end_stream = s.client.request_body_sent + chunk as u16 >= s.client.request_body_len;

    let src = s
        .client
        .request_body
        .as_ptr()
        .add(s.client.request_body_sent as usize);
    core::ptr::copy_nonoverlapping(src, buf.add(h2w::FRAME_HEADER_LEN), chunk);
    h2w::write_data_frame_header(buf, chunk, STREAM_ID, end_stream);

    s.client.request_len = (h2w::FRAME_HEADER_LEN + chunk) as u16;
    s.client.request_sent = 0;
    s.client.request_body_sent += chunk as u16;
}

// ── Flow-control helpers ──────────────────────────────────────────────────

unsafe fn consume_recv_window(s: &mut HttpState, n: u32) {
    s.client.recv_window = s.client.recv_window.saturating_sub(n as i32);
    if s.client.recv_window <= RECV_WINDOW_THRESHOLD {
        s.client.window_update_pending = 1;
    }
}

/// If we owe a connection-level WINDOW_UPDATE and `request_buf` is
/// free, queue it. Returns true when a frame was queued; the caller
/// should then drain `request_buf` before resuming reads.
unsafe fn maybe_queue_window_update(s: &mut HttpState) -> bool {
    if s.client.window_update_pending == 0 {
        return false;
    }
    if s.client.request_sent < s.client.request_len {
        return false; // request_buf busy
    }
    let delta = (RECV_WINDOW_INITIAL - s.client.recv_window) as u32;
    if delta == 0 {
        s.client.window_update_pending = 0;
        return false;
    }
    let n = h2w::write_window_update(s.client.request_buf.as_mut_ptr(), 0, delta);
    s.client.request_len = n as u16;
    s.client.request_sent = 0;
    s.client.recv_window = RECV_WINDOW_INITIAL;
    s.client.window_update_pending = 0;
    true
}

// ── WebSocket-over-h2 helpers ─────────────────────────────────────────────

/// Wrap an RFC 6455 frame inside an h2 DATA frame in `request_buf`.
/// The WS frame is masked per RFC 6455 §5.3 (client→server).
unsafe fn build_ws_frame(
    s: &mut HttpState,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    end_stream: bool,
) {
    let buf = s.client.request_buf.as_mut_ptr();
    let dst = buf.add(h2w::FRAME_HEADER_LEN);
    let cap = REQUEST_BUF_SIZE - h2w::FRAME_HEADER_LEN;

    let mut mask_key = [0u8; 4];
    dev_csprng_fill(&*s.syscalls, mask_key.as_mut_ptr(), 4);

    let written = ws::write_frame_masked(dst, cap, true, opcode, payload, payload_len, &mask_key);
    h2w::write_data_frame_header(buf, written, STREAM_ID, end_stream);
    s.client.request_len = (h2w::FRAME_HEADER_LEN + written) as u16;
    s.client.request_sent = 0;
}

/// Parse an unmasked server WS frame from a DATA frame payload and
/// dispatch on its opcode. TEXT/BINARY: forward payload to `out_chan`
/// (if wired). One-shot mode (no `data_in_chan` wired) auto-closes
/// after the first echo so the session exits cleanly. Bidirectional
/// mode (`data_in_chan` wired) leaves the session open until the
/// in-channel HUPs.
unsafe fn process_ws_data(s: &mut HttpState, payload: *const u8, plen: usize) {
    let frame = match ws::parse_frame(payload, plen) {
        Ok(Some(f)) => f,
        _ => return,
    };
    let total = frame.header_len as usize + frame.payload_len as usize;
    if total > plen {
        return;
    }
    let pl_ptr = payload.add(frame.header_len as usize);

    match frame.opcode {
        ws::OP_TEXT | ws::OP_BINARY => {
            if s.client.out_chan >= 0 && frame.payload_len > 0 {
                let sys = &*s.syscalls;
                (sys.channel_write)(s.client.out_chan, pl_ptr, frame.payload_len as usize);
            }
            s.client.bytes_received += frame.payload_len;
            // One-shot mode: no `in[1]` wired → close after first echo.
            // Bidirectional mode: keep the session open; pump_data_in
            // drives both outbound traffic and the eventual CLOSE.
            if s.client.data_in_chan < 0 && s.client.ws_done == 0 {
                let close_payload = [
                    (ws::CLOSE_NORMAL >> 8) as u8,
                    (ws::CLOSE_NORMAL & 0xFF) as u8,
                ];
                build_ws_frame(s, ws::OP_CLOSE, close_payload.as_ptr(), 2, true);
                s.client.ws_done = 1;
            }
        }
        ws::OP_CLOSE => {
            // Server's CLOSE echo. End-of-session.
            s.client.ws_done = 2;
        }
        _ => {
            // PING / PONG / CONTINUATION ignored in this minimal impl.
        }
    }
}

/// Read up to one chunk of outbound WS payload from `data_in_chan`,
/// wrap it as a masked WS TEXT frame inside an h2 DATA frame, and
/// queue it in `request_buf`. On HUP, queue a WS CLOSE instead.
/// Returns `Some(())` when something was queued (caller should drain
/// before resuming reads), `None` if the channel was idle.
unsafe fn pump_data_in(s: &mut HttpState) -> Option<()> {
    if s.client.data_in_chan < 0 {
        return None;
    }
    if s.client.request_sent < s.client.request_len {
        // Outbound buffer still draining; don't queue another frame.
        return None;
    }
    let sys = &*s.syscalls;
    let chan = s.client.data_in_chan;
    let poll = (sys.channel_poll)(chan, POLL_IN | super::super::POLL_HUP);
    if poll <= 0 {
        return None;
    }
    let p = poll as u32;
    if (p & POLL_IN) != 0 {
        // Read up to a chunk that fits our request_buf with framing
        // overhead (h2 DATA hdr 9 + WS hdr+mask 8 = 17, plus slack).
        const CHUNK_CAP: usize = 200;
        let mut tmp = [0u8; CHUNK_CAP];
        let n = (sys.channel_read)(chan, tmp.as_mut_ptr(), CHUNK_CAP);
        if n > 0 {
            build_ws_frame(s, ws::OP_TEXT, tmp.as_ptr(), n as usize, false);
            return Some(());
        }
    }
    if (p & super::super::POLL_HUP) != 0 && s.client.ws_done == 0 {
        // Producer is done — close the WS session cleanly.
        let close_payload = [
            (ws::CLOSE_NORMAL >> 8) as u8,
            (ws::CLOSE_NORMAL & 0xFF) as u8,
        ];
        build_ws_frame(s, ws::OP_CLOSE, close_payload.as_ptr(), 2, true);
        s.client.ws_done = 1;
        return Some(());
    }
    None
}

unsafe fn format_authority(host: u32, port: u16, dst: *mut u8) -> usize {
    let mut o = 0usize;
    let bytes = host.to_le_bytes();
    for &b in &bytes {
        o += super::super::fmt_u32_raw(dst.add(o), b as u32);
        *dst.add(o) = b'.';
        o += 1;
    }
    o = o.saturating_sub(1); // strip trailing '.'
    *dst.add(o) = b':';
    o += 1;
    o += super::super::fmt_u32_raw(dst.add(o), port as u32);
    o
}

// ── Network I/O ───────────────────────────────────────────────────────────

unsafe fn drain_request_buf(s: &mut HttpState) -> bool {
    if s.net_out_chan < 0 {
        return false;
    }
    while s.client.request_sent < s.client.request_len {
        let sys = &*s.syscalls;
        let out_chan = s.net_out_chan;
        let conn_id = s.client.conn_id;
        let remaining = (s.client.request_len - s.client.request_sent) as usize;
        let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 2;
        let to_send = remaining.min(max_data);
        let scratch = s.net_buf.as_mut_ptr();
        let payload_len = 2 + to_send;
        let mut cb = [0u8; 2];
        net_proto::put_conn_id(&mut cb, conn_id);
        *scratch = NET_CMD_SEND;
        *scratch.add(1) = (payload_len & 0xFF) as u8;
        *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
        *scratch.add(3) = cb[0];
        *scratch.add(4) = cb[1];
        let src = s
            .client
            .request_buf
            .as_ptr()
            .add(s.client.request_sent as usize);
        core::ptr::copy_nonoverlapping(src, scratch.add(5), to_send);
        let total = NET_FRAME_HDR + payload_len;
        let written = (sys.channel_write)(out_chan, scratch, total);
        if written < total as i32 {
            return false;
        }
        s.client.request_sent += to_send as u16;
    }
    s.client.request_len = 0;
    s.client.request_sent = 0;
    true
}

/// Pump one NET_MSG_DATA into recv_buf. Returns true if any progress
/// was made (bytes appended OR connection-level event consumed).
unsafe fn pump_inbound(s: &mut HttpState) -> bool {
    if s.net_in_chan < 0 {
        return false;
    }
    // Backpressure: refuse to pump if recv_buf can't hold a worst-case
    // MSG_DATA payload. The bound is the net_proto fragment CAP, NOT the (much
    // larger) outbound scratch `NET_BUF_SIZE` — using the latter against a
    // 2048-byte recv_buf would refuse forever (h2 inbound stalls on aarch64).
    // The channel queue then absorbs the backlog and ultimately TCP slows the peer.
    let worst_case = super::super::connection::MAX_DATA_FRAGMENT;
    if s.client.recv_len as usize + worst_case > RECV_BUF_SIZE {
        return false;
    }
    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    let poll = (sys.channel_poll)(chan, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return false;
    }
    let buf = s.net_buf.as_mut_ptr();
    // Alignment-safe: per the net_proto cap a MSG_DATA frame fits our buffer,
    // but a misbehaving producer's oversized frame is drained rather than left
    // to desync the FIFO.
    let (msg_type, payload_len, _full) = net_read_frame_aligned(sys, chan, buf, NET_BUF_SIZE);
    // Established-stream isolation: ignore DATA/CLOSED/ERROR frames for other
    // connections sharing a fanned net_in (e.g. an OTLP exporter).
    if matches!(msg_type, NET_MSG_DATA | NET_MSG_CLOSED | NET_MSG_ERROR)
        && payload_len >= 2
        && net_proto::conn_id(core::slice::from_raw_parts(
            buf.add(NET_FRAME_HDR),
            payload_len,
        )) != s.client.conn_id
    {
        return false;
    }
    if msg_type == NET_MSG_CLOSED {
        // Peer hung up; treat as end of body.
        log(s, b"[http] premature close");
        return true;
    }
    if msg_type != NET_MSG_DATA || payload_len < 2 {
        return false;
    }
    let data_ptr = buf.add(NET_FRAME_HDR + 2);
    let data_len = payload_len - 2;
    let cur = s.client.recv_len as usize;
    let space = RECV_BUF_SIZE - cur;
    let to_copy = data_len.min(space);
    if to_copy > 0 {
        core::ptr::copy_nonoverlapping(data_ptr, s.client.recv_buf.as_mut_ptr().add(cur), to_copy);
        s.client.recv_len += to_copy as u16;
    }
    true
}

/// Walk frames in recv_buf until we see and consume a SETTINGS frame
/// without ACK. Returns Some(true) when consumed, Some(false) on
/// unrecoverable error, None if more bytes are needed.
unsafe fn consume_until_settings(s: &mut HttpState) -> Option<bool> {
    loop {
        let len = s.client.recv_len as usize;
        let hdr = h2w::parse_header(s.client.recv_buf.as_ptr(), len)?;
        let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
        if total > len {
            return None;
        }
        if hdr.ftype == h2w::FRAME_SETTINGS && (hdr.flags & h2w::FLAG_ACK) == 0 {
            shift_consume(s, total);
            return Some(true);
        }
        if hdr.ftype == h2w::FRAME_GOAWAY {
            return Some(false);
        }
        // Skip anything else that arrived ahead of SETTINGS (per spec
        // SETTINGS is first, but be liberal with PING / WINDOW_UPDATE).
        shift_consume(s, total);
    }
}
