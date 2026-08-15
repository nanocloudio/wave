//! HTTP/1.1 — the slot lifecycle, and every phase that serves a request over it.
//!
//! `step_active_slot` is one `match` over `Phase` and is the whole file. It runs
//! once per ready slot per tick, advances that slot by at most one phase, and
//! returns without blocking: the module is cooperatively scheduled, so a phase
//! that cannot make progress yields and is re-entered next tick rather than
//! looping.
//!
//! # Why the bind and accept phases live here
//!
//! `Init` → `Binding` → `WaitBound` → `WaitAccept` are not HTTP/1-specific in
//! their bytes, but they are HTTP/1-specific in their MODEL: one connection,
//! served to completion, then reused or closed. That model is what `ConnSlot`
//! implements, and h2 and h3 both reach their own front ends *through* it —
//! `Phase::H2Active` hands off to `super::h2::step` after the upgrade or the
//! ALPN preface is seen, and an h3 stream is dispatched against a slot this
//! machine allocated. So the accept path is h1's, and the other generations
//! borrow it; inverting that — a generation-neutral "accept" file with h1's
//! phases elsewhere — would split one state machine across two files for the
//! sake of a boundary that does not exist in the code.
//!
//! Everything a phase needs beyond the slot itself comes from a subsystem:
//! `super::routes` to match, `super::cache` to fill, `super::body` to render and
//! emit, `super::response` to stage a head, `super::ws` to upgrade,
//! `super::proxy` to relay. This file owns the ORDER, not the work.

use super::super::connection::{
    NET_BUF_SIZE, NET_CMD_BIND, NET_CMD_CLOSE, NET_CMD_SEND, NET_MSG_ACCEPTED, NET_MSG_BOUND,
    NET_MSG_CLOSED, NET_MSG_DATA, NET_MSG_ERROR, NET_MSG_TRACE_CTX,
};
use super::super::wire;
use super::body::{
    finish_response, parse_file_index, render_index_into, render_static_into,
    render_template_route_into, step_legacy_file_dispatch, step_send_file, step_send_fs_file,
    step_send_index, step_send_static, step_send_template,
};
use super::cache::{
    cache_alloc, cache_evict_all, cache_fetch_step, cache_lookup, cache_release_for_route,
    cache_retain_for_route, cache_try_or_fetch, drain_variables, CacheLookup, CacheStepResult,
    CACHE_COMPLETE,
};
use super::listeners::{fill_bind_payload, is_listen_port};
use super::proxy::{
    begin_proxy, proxy_build_forward_head, proxy_connect_failed, proxy_dial, proxy_relay_step,
    try_begin_dyn_proxy, PROXY_CONNECT_TIMEOUT_MS,
};
use super::response::{
    build_error, build_error_416, build_header, build_header_fs_full, build_header_fs_partial,
    build_header_with_len,
};
#[cfg(feature = "app")]
use super::routes::HANDLER_APP;
use super::routes::{
    content_type_from_path, match_route, Route, HANDLER_FILE, HANDLER_FS_FILE, HANDLER_FS_LIST,
    HANDLER_GRPC, HANDLER_PROXY, HANDLER_STATIC, HANDLER_STREAM, HANDLER_TEMPLATE,
    HANDLER_WEBSOCKET, HANDLER_WEBSOCKET_FANOUT, HANDLER_WEBSOCKET_SESSION,
};
use super::ws::{
    begin_ws_upgrade, retain_capture_envelope, ws_begin_close, ws_drain_fanout_input,
    ws_emit_next_fragment, ws_process_inbound, ws_queue_envelope_on_active, ws_queue_frame,
    ws_queue_frame_fin, RETAINED_ENVELOPE_HDR, RETAIN_RESET_TICKS,
};
// The h2 helpers are gated with the state they touch: `http-web` links no
// `H2State`, so importing them unconditionally breaks that variant while the
// all-features host build stays green.
#[cfg(feature = "app")]
use super::app;
use super::reqbody;
use super::{
    active_slot_count, alloc_free_slot, close_net_conn, cur_conn_id, cur_fs_fd, cur_fs_sent,
    cur_fs_total, cur_matched_route, cur_phase, cur_recv_buf_mut_ptr, cur_recv_buf_ptr,
    cur_recv_len, cur_send_buf_mut_ptr, cur_send_buf_ptr, cur_send_len, cur_send_offset, cur_slot,
    cur_slot_mut, cur_ws_fan_out, current_slot_index, dev_channel_ioctl, dev_log, dev_micros,
    dev_millis, dev_telemetry_enabled, find_slot_by_conn_id, free_slot, hex_val, log,
    net_read_frame, net_send, net_send_conn, net_write_frame, ready_clear, ready_set,
    release_file_chan, reset_connection, set_cur_phase, try_acquire_file_chan, HttpState, Phase,
    IOCTL_FLUSH, IOCTL_NOTIFY, IOCTL_POLL_NOTIFY, MAX_CONCURRENT_CONNS, MAX_CONTENT_TYPE,
    MAX_FS_PATH, MAX_PATH, NET_FRAME_HDR, POLL_HUP, POLL_IN, POLL_OUT, RECV_BUF_SIZE,
    SEND_BUF_SIZE, SOCK_TYPE_STREAM,
};
#[cfg(feature = "h2")]
use super::{cur_h2_mut, ensure_h2_state};

/// Stage `HTTP/1.1 100 Continue` in `send_buf` and mark the slot so
/// `Phase::RecvBody` flushes it before reading a byte of body.
///
/// An interim response is not a response: it does not end the request, carries
/// no body, and is followed by the real status line on the same connection
/// (RFC 9110 §15.2). So it is written straight into `send_buf` rather than
/// through `build_header*`, none of which can express "more to follow".
unsafe fn stage_interim_continue(s: &mut HttpState) {
    const INTERIM: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
    let dst = cur_send_buf_mut_ptr(s);
    if dst.is_null() {
        return;
    }
    let n = INTERIM.len().min(SEND_BUF_SIZE);
    core::ptr::copy_nonoverlapping(INTERIM.as_ptr(), dst, n);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = n as u16;
        cur.body_continue = 1;
    }
}

pub(crate) unsafe fn step_active_slot(s: &mut HttpState) -> i32 {
    drain_variables(s);

    // Application responses are drained once per step, before any slot runs.
    // Deliberately NOT per-slot: `resp_in` is one channel feeding every
    // connection in `Phase::AwaitApp`, so a per-slot read would let whichever
    // slot stepped first consume an envelope addressed to a different one.
    // `drain_responses` routes by `(conn_id, stream_id)` and composes onto the
    // slot that asked, whichever slot happens to be current.
    #[cfg(feature = "app")]
    app::drain_responses(s);

    // Background-drain inbound network messages during phases that
    // don't already poll `net_in_chan` themselves. Without this the
    // channel buffer fills up while the server is mid-response and
    // the upstream network module stops `accept()`ing new TCP
    // connections — TCP wedges from the outside even though the
    // scheduler keeps ticking. WaitBound / WaitAccept / RecvRequest /
    // WsActive are excluded because their per-phase handlers consume
    // the same channel directly with phase-specific semantics.
    // Inbound channel drain happens once per `step()` call via
    // `demux_inbound` (sibling of this function), which routes
    // every frame to the right slot. Per-slot ticks no longer poll
    // the channel themselves.

    // If MSG_CLOSED has fired for the current conn, any outbound-write
    // phase will spin against a closed slot — IP accepts CMD_SEND on
    // CloseWait but the bytes never reach the wire, so `send_offset`
    // never advances. Short-circuit to CloseConn so WaitAccept gets
    // ticks again.
    //
    // RecvRequest / H2Active included so a connect-then-close client
    // (peer_closed=1 with recv_len=0) doesn't leak the slot:
    //   - RecvRequest at the bottom of this match returns 0 when
    //     `recv_len == 0`, with no peer_closed check; without this
    //     preemption the slot stays in RecvRequest forever.
    //   - H2Active hands off to `h2::step`, which doesn't see the
    //     close (demux consumed it) so it can stall on stream-init
    //     waits the peer will never satisfy.
    if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
        match cur_phase(s) {
            Phase::RecvRequest
            | Phase::H2Active
            | Phase::SendHeaders
            | Phase::SendBody
            | Phase::DrainSend
            | Phase::FetchContent
            | Phase::CacheStream
            | Phase::WsHandshake
            | Phase::WsClose
            | Phase::AwaitFsStat
            | Phase::ProxyConnect
            | Phase::ProxyWaitConnect
            | Phase::ProxySendRequest
            | Phase::ProxyRelayHeaders
            | Phase::ProxyRelayBody => {
                if cur_fs_fd(s) >= 0 {
                    ((*s.syscalls).provider_call)(
                        cur_fs_fd(s),
                        0x0903, // FS_CLOSE
                        core::ptr::null_mut(),
                        0,
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_fd = -1;
                    }
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
            }
            _ => {}
        }
    }

    match cur_phase(s) {
        Phase::Init | Phase::Binding => {
            if s.net_out_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_out_chan;
            let buf = s.net_buf.as_mut_ptr();
            let mut payload = [0u8; 4];
            let plen = fill_bind_payload(sys, s.server.port, &mut payload);
            let wrote = net_write_frame(
                sys,
                chan,
                NET_CMD_BIND,
                payload.as_ptr(),
                plen,
                buf,
                NET_BUF_SIZE,
            );
            if wrote == 0 {
                return 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::WaitBound;
            }
            return 2;
        }

        Phase::WaitBound => {
            if s.net_in_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_in_chan;
            let poll = (sys.channel_poll)(chan, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                return 0;
            }

            let buf = s.net_buf.as_mut_ptr();
            let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
            match msg_type {
                // Multi-anchor demux: on a shared `net_in` fan IP emits one
                // MSG_BOUND per anchor's CMD_BIND. Treat only the bound for
                // OUR listener port as ours (a port-less legacy frame is
                // accepted). Ignoring a neighbour's bound here prevents this
                // server from flipping to WaitAccept / `bound` on someone
                // else's listen completing first.
                NET_MSG_BOUND
                    if payload_len < 4 || {
                        let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                        let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 3);
                        ((lo as u16) | ((hi as u16) << 8)) == s.server.port
                    } =>
                {
                    log(s, b"[http] bound, waiting for connections");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::WaitAccept;
                    }
                    // Slot 0's bind-sequence work is done; demux now
                    // owns its lifecycle like any other slot. Drop
                    // it from the ready bitmap so idle ticks are
                    // free, and flip the global bound flag so the
                    // demux can run from now on.
                    if let Some(idx) = current_slot_index(s) {
                        ready_clear(s, idx);
                    }
                    s.server.bound = 1;
                    return 2;
                }
                NET_MSG_ERROR => {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::Error;
                    }
                    return -1;
                }
                NET_MSG_ACCEPTED if payload_len >= 2 => {
                    // A connection accepted by linux_net while we were
                    // still binding. Allocate a slot directly — the
                    // slot table is the queue. Multi-anchor demux: claim
                    // only accepts on our bound port (see the demux path).
                    let conn = u16::from_le_bytes([
                        *s.net_buf.as_ptr().add(NET_FRAME_HDR),
                        *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1),
                    ]);
                    let ours = payload_len < 4 || {
                        let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                        let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 3);
                        ((lo as u16) | ((hi as u16) << 8)) == s.server.port
                    };
                    if ours {
                        if let Some(idx) = alloc_free_slot(s, conn) {
                            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                            slot.phase = Phase::RecvRequest;
                        } else {
                            close_net_conn(s, conn);
                        }
                    }
                    return 2;
                }
                NET_MSG_DATA if payload_len > 2 => {
                    // Append directly to the owning slot's `recv_buf`.
                    let conn = u16::from_le_bytes([
                        *s.net_buf.as_ptr().add(NET_FRAME_HDR),
                        *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1),
                    ]);
                    let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                    let data_len = payload_len - 2;
                    if let Some(idx) = find_slot_by_conn_id(s, conn) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        if slot.recv_buf.is_null() {
                            // Slot freed mid-stream; drop the data.
                            return 2;
                        }
                        let space = slot.recv_cap as usize - slot.recv_len as usize;
                        let to_copy = data_len.min(space);
                        if to_copy > 0 {
                            let dst = slot.recv_buf.add(slot.recv_len as usize);
                            core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                            slot.recv_len += to_copy as u16;
                        }
                    }
                    // Else: orphan — drop.
                    return 2;
                }
                NET_MSG_CLOSED if payload_len >= 2 => {
                    let conn = u16::from_le_bytes([
                        *s.net_buf.as_ptr().add(NET_FRAME_HDR),
                        *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1),
                    ]);
                    if let Some(idx) = find_slot_by_conn_id(s, conn) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        slot.peer_closed = 1;
                    }
                    return 2;
                }
                NET_MSG_TRACE_CTX
                    if payload_len
                        >= super::super::abi::contracts::net::net_proto::TRACE_CTX_LEN =>
                {
                    // Observability: the upstream (IP via TLS) trace context for
                    // this connection — `[conn_id][trace_id 16][tls_span_id 8]`.
                    // Store as the connection default; each request without its
                    // own `traceparent` parents `http.server.request` under it.
                    if dev_telemetry_enabled(&*s.syscalls) {
                        let p = s.net_buf.as_ptr().add(NET_FRAME_HDR);
                        let conn = u16::from_le_bytes([*p, *p.add(1)]);
                        if let Some(idx) = find_slot_by_conn_id(s, conn) {
                            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                            core::ptr::copy_nonoverlapping(
                                p.add(2),
                                slot.conn_trace_id.as_mut_ptr(),
                                16,
                            );
                            core::ptr::copy_nonoverlapping(
                                p.add(18),
                                slot.conn_parent_id.as_mut_ptr(),
                                8,
                            );
                            slot.conn_flags = *p.add(26);
                        }
                    }
                    return 2;
                }
                _ => return 2,
            }
        }

        Phase::WaitAccept => {
            // No-op — `demux_inbound` allocates this slot directly
            // when MSG_ACCEPTED arrives, transitioning it to
            // RecvRequest without any per-slot channel poll here.
        }

        Phase::RecvRequest => {
            // Inbound bytes are routed to this slot's `recv_buf` by
            // `demux_inbound` at the top of `step()`. If nothing's
            // buffered, the slot is genuinely idle — yield this tick.
            if cur_recv_len(s) == 0 {
                return 0;
            }

            let len = cur_recv_len(s) as usize;

            // Detect the HTTP/2 cleartext (h2c) preface — 24 bytes
            // beginning with `PRI`. We check before the h1 request
            // parse so a misdirected h1 client doesn't accidentally
            // hit the same path. The preface is a fixed string; first
            // few bytes are sufficient to disambiguate. Without the
            // h2 feature the whole detect is compiled out and a `PRI`
            // request falls through to h1 parsing (which 400s it) —
            // fail-visible rather than silently half-speaking h2.
            let recv_parsed = cur_slot(s).map(|c| c.recv_parsed).unwrap_or(0);
            #[cfg(feature = "h2")]
            if recv_parsed == 0 && len >= 1 && *cur_recv_buf_ptr(s) == b'P' {
                if len < wire::h2::PREFACE.len() {
                    return 0; // wait for the rest of the preface
                }
                let mut prefix_match = true;
                let mut i = 0;
                let recv_buf = cur_recv_buf_ptr(s);
                while i < wire::h2::PREFACE.len() {
                    if *recv_buf.add(i) != wire::h2::PREFACE[i] {
                        prefix_match = false;
                        break;
                    }
                    i += 1;
                }
                if prefix_match {
                    // Drop the preface from recv_buf and hand off to
                    // the h2 state machine. Any frames that arrived in
                    // the same MSG_DATA stay queued for it to consume.
                    let pre = wire::h2::PREFACE.len();
                    let leftover = len - pre;
                    let p = cur_recv_buf_mut_ptr(s);
                    let mut j = 0;
                    while j < leftover {
                        *p.add(j) = *p.add(pre + j);
                        j += 1;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.recv_len = leftover as u16;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.recv_parsed = 0;
                    }
                    if !super::h2::enter(s) {
                        // Heap exhausted: close the conn cleanly.
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::CloseConn;
                        }
                        return 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::H2Active;
                    }
                    return 2;
                }
                // Not the preface; fall through to h1 parsing.
            }

            if recv_parsed == 0 {
                let ptr = cur_recv_buf_ptr(s);
                let mut has_line = false;
                let mut i = 0;
                while i + 1 < len {
                    if *ptr.add(i) == b'\r' && *ptr.add(i + 1) == b'\n' {
                        has_line = true;
                        break;
                    }
                    i += 1;
                }
                if has_line {
                    let recv_buf_ptr = cur_recv_buf_ptr(s);
                    let plen = if let Some(cur) = cur_slot_mut(s) {
                        let recv_len = cur.recv_len as usize;
                        wire::h1::parse_request_line(
                            recv_buf_ptr,
                            recv_len,
                            cur.req_path.as_mut_ptr(),
                            MAX_PATH,
                        )
                    } else {
                        None
                    };
                    match plen {
                        // A well-formed line whose method this server does not
                        // implement is 501, not 400: the request is not
                        // malformed, it asks for something unsupported (RFC
                        // 9110 §9.1). The parser reports the distinction by
                        // returning METHOD_NONE with the path intact.
                        Some((verb, _)) if verb == wire::method::METHOD_NONE => {
                            build_error(s, b"501 Not Implemented", b"Not Implemented\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        Some((verb, n)) => {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.req_method = verb;
                                cur.req_path_len = n as u16;
                                cur.recv_parsed = 1;
                            }
                        }
                        None => {
                            build_error(s, b"400 Bad Request", b"Bad Request\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                    }
                } else if cur_recv_len(s) as usize >= RECV_BUF_SIZE {
                    build_error(s, b"400 Bad Request", b"Bad Request\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                    return 0;
                }
            }

            let recv_parsed = cur_slot(s).map(|c| c.recv_parsed).unwrap_or(0);
            if recv_parsed == 1 {
                let ptr = cur_recv_buf_ptr(s);
                let scan_len = cur_recv_len(s) as usize;
                let mut found_at: Option<usize> = None;
                if scan_len >= 4 {
                    let mut i = 0;
                    while i + 3 < scan_len {
                        if *ptr.add(i) == b'\r'
                            && *ptr.add(i + 1) == b'\n'
                            && *ptr.add(i + 2) == b'\r'
                            && *ptr.add(i + 3) == b'\n'
                        {
                            found_at = Some(i);
                            break;
                        }
                        i += 1;
                    }
                }

                if let Some(crlf_pos) = found_at {
                    // Pin keep-alive disposition before DispatchRoute
                    // so every write_status_line sees the right flag.
                    let head_len = crlf_pos + 4;
                    let head = core::slice::from_raw_parts(ptr, head_len);
                    let keepalive = wire::h1::request_keeps_alive(head);
                    // Observability: stamp the `http.server.request` span start
                    // as the head is parsed. Computed before the slot borrow;
                    // one predicate, no clock read, when the port is unwired.
                    let span_now: u64 = if dev_telemetry_enabled(&*s.syscalls) {
                        let n = dev_micros(&*s.syscalls);
                        if n == 0 {
                            1
                        } else {
                            n
                        }
                    } else {
                        0
                    };
                    // W3C trace-context ingress: when tracing, a `traceparent`
                    // header (the caller's distributed trace) takes precedence;
                    // otherwise fall back to the connection context propagated
                    // in-band by IP/TLS. Resolved per request so a keepalive slot
                    // never inherits a previous request's header.
                    let header_ctx: Option<([u8; 16], [u8; 8], u8)> = if span_now != 0 {
                        wire::h1::find_header(head, b"traceparent")
                            .and_then(super::super::abi::contracts::telemetry::parse_traceparent)
                    } else {
                        None
                    };
                    // Decide the body BEFORE dispatch, because the answer can
                    // be the whole response: contradictory framing is 400, an
                    // over-cap length is 413, and a body-bearing method with no
                    // framing at all is 411. Each of those is a refusal that
                    // must happen without ever routing the request.
                    let plan = reqbody::plan_body(s, head);
                    let refusal: Option<(&[u8], &[u8])> = match plan {
                        reqbody::BodyPlan::Invalid => Some((b"400 Bad Request", b"Bad Request\n")),
                        reqbody::BodyPlan::TooLarge => {
                            Some((b"413 Content Too Large", b"Content Too Large\n"))
                        }
                        reqbody::BodyPlan::LengthRequired => {
                            Some((b"411 Length Required", b"Length Required\n"))
                        }
                        reqbody::BodyPlan::None | reqbody::BodyPlan::Read { .. } => None,
                    };
                    if let Some((status, body)) = refusal {
                        build_error(s, status, body);
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.header_end_off = head_len as u16;
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // The head STAYS in `recv_buf`, and the body reader
                    // consumes from `header_end_off` onward. Shifting the head
                    // away would be simpler arithmetic and would destroy the
                    // one copy of the request headers there is — which
                    // `HANDLER_APP` forwards verbatim to the application, since
                    // a gateway cannot know which of them the application's API
                    // is defined in terms of.
                    let body_follows = matches!(plan, reqbody::BodyPlan::Read { .. });
                    let wants_continue = matches!(
                        plan,
                        reqbody::BodyPlan::Read {
                            continue_first: true
                        }
                    );

                    if let Some(cur) = cur_slot_mut(s) {
                        cur.keepalive = if keepalive { 1 } else { 0 };
                        cur.header_end_off = head_len as u16;
                        cur.phase = if body_follows {
                            Phase::RecvBody
                        } else {
                            Phase::DispatchRoute
                        };
                        let flags = match header_ctx {
                            Some((tid, pid, flags)) => {
                                cur.span_trace_id = tid;
                                cur.span_parent_id = pid;
                                flags
                            }
                            None => {
                                // In-band connection context (all-zero = root).
                                cur.span_trace_id = cur.conn_trace_id;
                                cur.span_parent_id = cur.conn_parent_id;
                                cur.conn_flags
                            }
                        };
                        cur.span_flags = flags;
                        // Head-sampling: a propagated context carries the caller's
                        // bit; a root (all-zero trace) is sampled. Latch the span
                        // start ONLY when sampled, so an unsampled request does NO
                        // end-of-request clock/RNG work (emit returns on start==0).
                        let propagated = cur.span_trace_id != [0u8; 16];
                        let sampled = !propagated
                            || flags & super::super::abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
                                != 0;
                        cur.span_start_us = if sampled { span_now } else { 0 };
                    }
                    // `Expect: 100-continue` — stage the interim response now.
                    // The client is WAITING for it and will not send the body
                    // until it arrives, so deferring this to the body reader
                    // would deadlock: the reader waits for bytes the client is
                    // withholding pending a response the reader has not sent.
                    if wants_continue {
                        stage_interim_continue(s);
                    }
                    return 2;
                } else if cur_recv_len(s) as usize >= RECV_BUF_SIZE {
                    let l = cur_recv_len(s) as usize;
                    if l >= 3 {
                        let p = cur_recv_buf_mut_ptr(s);
                        *p = *p.add(l - 3);
                        *p.add(1) = *p.add(l - 2);
                        *p.add(2) = *p.add(l - 1);
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.recv_len = 3;
                        }
                    }
                }
            }
        }

        Phase::RecvBody => {
            // A staged `100 Continue` must reach the wire before the body is
            // read — see `stage_interim_continue`.
            if cur_slot(s).map(|c| c.body_continue).unwrap_or(0) != 0 {
                let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
                if remaining > 0 {
                    let sent = net_send(
                        s,
                        cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                        remaining,
                    );
                    if sent > 0 {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset += sent as u16;
                        }
                    }
                    return 2;
                }
                // Drained. Clear the interim response out of `send_buf` so the
                // real response is composed into an empty buffer.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.body_continue = 0;
                    cur.send_offset = 0;
                    cur.send_len = 0;
                }
            }

            match reqbody::step_recv_body(s) {
                reqbody::BodyStep::Done => {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DispatchRoute;
                    }
                    return 2;
                }
                reqbody::BodyStep::NeedMore => {
                    // The peer hung up mid-body. The request will never be
                    // complete, so there is nothing to answer — close rather
                    // than dispatch a truncated body as if it were whole.
                    if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::CloseConn;
                        }
                        return 2;
                    }
                    return 0;
                }
                reqbody::BodyStep::Bad => {
                    build_error(s, b"400 Bad Request", b"Bad Request\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.keepalive = 0;
                        cur.phase = Phase::DrainSend;
                    }
                    return 0;
                }
                reqbody::BodyStep::TooLarge => {
                    // Close rather than keep-alive: the rest of the body is
                    // still arriving and this server has stopped reading it,
                    // so there is no way to find the next request boundary.
                    build_error(s, b"413 Content Too Large", b"Content Too Large\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.keepalive = 0;
                        cur.phase = Phase::DrainSend;
                    }
                    return 0;
                }
            }
        }

        #[cfg(not(feature = "app"))]
        Phase::AwaitApp => {
            // Unreachable without the feature (nothing dispatches HANDLER_APP),
            // but the variant is kept so phase numbering stays identical across
            // builds. Fail closed, as H2Active does.
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return 0;
        }
        #[cfg(feature = "app")]
        Phase::AwaitApp => {
            // Responses are drained centrally (`app::drain_responses`, once per
            // step) rather than polled per slot: one channel feeds every
            // waiting connection, and a per-slot read would let whichever slot
            // stepped first consume an envelope addressed to another.
            //
            // So this arm only handles the case the drain cannot: nothing came
            // back in time.
            if let Some(idx) = current_slot_index(s) {
                if app::app_deadline_passed(s, idx) {
                    s.server.app_timeouts = s.server.app_timeouts.wrapping_add(1);
                    // Mid-stream, the response head and part of its body are
                    // already on the wire. A 504 here would append a second
                    // status line INSIDE the first response's body, which the
                    // client would read as content. Closing is the only honest
                    // signal left: it surfaces as the truncated transfer it is.
                    let streaming = cur_slot(s).map(|c| c.app_streaming != 0).unwrap_or(false);
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.app_pending = 0;
                        cur.app_streaming = 0;
                        cur.app_deadline_ms = 0;
                        cur.keepalive = 0;
                    }
                    if streaming {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::CloseConn;
                        }
                        return 2;
                    }
                    build_error(s, b"504 Gateway Timeout", b"Gateway Timeout\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                    return 0;
                }
            }
            // Peer hung up while the application was still thinking: nothing
            // to deliver the answer to.
            if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.app_pending = 0;
                    cur.phase = Phase::CloseConn;
                }
                return 2;
            }
            return 0;
        }

        Phase::DispatchRoute => {
            if s.server.legacy_mode == 2 {
                // Returns false if file_chan was busy; caller stays
                // in DispatchRoute and retries next tick.
                let _ = step_legacy_file_dispatch(s);
                return 0;
            }

            // Diagnostic endpoint `/_fan` — calls the kernel
            // `FAN_DIAG_SNAPSHOT` opcode and serves the resulting ASCII
            // line (fan-out / fan-in pump counters + log_ring state).
            // Available on every http instance without route configuration.
            let (req, plen) = match cur_slot(s) {
                Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
                None => return 0,
            };
            if plen >= 5
                && *req == b'/'
                && *req.add(1) == b'_'
                && *req.add(2) == b'f'
                && *req.add(3) == b'a'
                && *req.add(4) == b'n'
            {
                // Close-delimited (provider body ends at EOF) —
                // keep wire + slot in sync.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.keepalive = 0;
                }
                let buf = cur_send_buf_mut_ptr(s);
                let cap = SEND_BUF_SIZE;
                let mut off = 0usize;
                let header =
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n";
                let mut k = 0;
                while k < header.len() && off < cap {
                    *buf.add(off) = header[k];
                    off += 1;
                    k += 1;
                }
                let room = cap.saturating_sub(off);
                let n = ((*s.syscalls).provider_call)(-1, 0x0C65, buf.add(off), room);
                if n > 0 {
                    off += n as usize;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                    cur.send_len = off as u16;
                    cur.phase = Phase::DrainSend;
                }
                return 0;
            }

            let ri = match_route(s);
            if ri < 0 {
                // No static route — consult the dynamic-route proxy
                // table (§3.2: after the static arena). An empty table
                // falls through to the fixed 404 surface (§7).
                if try_begin_dyn_proxy(s) {
                    return 2;
                }
                build_error(s, b"404 Not Found", b"Not Found\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.matched_route = ri;
            }
            let route = &*s.server.routes.as_ptr().add(ri as usize);
            let handler = route.handler;
            let src_idx = route.source_index;

            match handler {
                HANDLER_STATIC | HANDLER_TEMPLATE => {
                    if src_idx >= 0 && s.server.file_chan >= 0 {
                        let ci = cache_lookup(s, ri as u8);
                        if ci >= 0 {
                            let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
                            s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
                            ce.lru_tick = s.server.cache_tick;
                            // Retain the entry while emission is in
                            // flight. Released at SendBody → DrainSend.
                            ce.retain = ce.retain.saturating_add(1);
                            let r = &mut *s.server.routes.as_mut_ptr().add(ri as usize);
                            r.body_offset = ce.arena_offset;
                            r.body_len = ce.length;
                            // Borrow the route's content_type before
                            // calling build_header (which takes &mut s).
                            let mut ct = [0u8; MAX_CONTENT_TYPE];
                            let ct_len = r.content_type_len as usize;
                            if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                                ct[..ct_len].copy_from_slice(&r.content_type[..ct_len]);
                            }
                            let ct_slice: &[u8] = if ct_len == 0 {
                                b"text/html"
                            } else {
                                &ct[..ct_len]
                            };
                            // Static → Content-Length + keep-alive.
                            // Template → close-delimited.
                            let body_len = r.body_len;
                            if handler == HANDLER_STATIC {
                                build_header_with_len(s, b"200 OK", ct_slice, body_len);
                            } else {
                                build_header(s, b"200 OK", ct_slice);
                            }
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.tmpl_pos = 0;
                                cur.cache_retained = 1;
                            }
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::SendHeaders;
                            }
                        } else {
                            // Cache miss → file_chan fetch. Serialise
                            // across slots so concurrent template
                            // misses don't trample each other's
                            // FLUSH/NOTIFY.
                            if !try_acquire_file_chan(s) {
                                // Another slot owns the channel —
                                // stay in DispatchRoute, retry next
                                // tick. The active route is already
                                // matched on this slot.
                                return 0;
                            }
                            // cache_alloc refuses if another reader
                            // is retaining the existing entry —
                            // defer (release lock, retry next tick).
                            if cache_alloc(s, ri as u8) < 0 {
                                release_file_chan(s);
                                return 0;
                            }
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_FLUSH,
                                core::ptr::null_mut(),
                                0,
                            );
                            let mut pos = src_idx as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_NOTIFY,
                                pos_ptr,
                                4,
                            );
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::FetchContent;
                            }
                        }
                    } else {
                        let mut ct = [0u8; MAX_CONTENT_TYPE];
                        let ct_len = route.content_type_len as usize;
                        if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                            ct[..ct_len].copy_from_slice(&route.content_type[..ct_len]);
                        }
                        let ct_slice: &[u8] = if ct_len == 0 {
                            b"text/html"
                        } else {
                            &ct[..ct_len]
                        };
                        // Static → fixed body_len, emit Content-Length
                        // (enables keep-alive). Template → unknown
                        // total, close-delimited.
                        let body_len = route.body_len;
                        if handler == HANDLER_STATIC {
                            build_header_with_len(s, b"200 OK", ct_slice, body_len);
                        } else {
                            build_header(s, b"200 OK", ct_slice);
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.tmpl_pos = 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                    }
                }
                HANDLER_FILE => {
                    let fi = parse_file_index(s);
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.file_index = fi;
                    }
                    if fi == -1 {
                        if s.server.file_chan >= 0 {
                            let mut count: u32 = 0;
                            let count_ptr = &mut count as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_POLL_NOTIFY,
                                count_ptr,
                                4,
                            );
                            if r >= 0 {
                                if let Some(cur) = cur_slot_mut(s) {
                                    cur.file_count = count as u16;
                                }
                            }
                        }
                        build_header(s, b"200 OK", b"text/plain");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.index_pos = 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                    } else if fi >= 0 {
                        if s.server.file_chan >= 0 {
                            // Serialise: concurrent HANDLER_FILE
                            // requests across slots must not race on
                            // FLUSH/NOTIFY. Stall in DispatchRoute
                            // until the channel is free.
                            if !try_acquire_file_chan(s) {
                                return 0;
                            }
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_FLUSH,
                                core::ptr::null_mut(),
                                0,
                            );
                            let mut pos = fi as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_NOTIFY,
                                pos_ptr,
                                4,
                            );
                            if r < 0 {
                                build_error(s, b"404 Not Found", b"Not Found\n");
                                if let Some(cur) = cur_slot_mut(s) {
                                    cur.phase = Phase::DrainSend;
                                }
                                return 0;
                            }
                            build_header(s, b"200 OK", b"application/octet-stream");
                        } else {
                            build_error(s, b"404 Not Found", b"Not Found\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                    } else {
                        build_error(s, b"400 Bad Request", b"Bad Request\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                }
                HANDLER_STREAM => {
                    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
                    let src_idx = route.source_index;
                    if src_idx < 0 || s.server.file_chan < 0 {
                        build_error(
                            s,
                            b"500 Internal Server Error",
                            b"Stream handler missing source\n",
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // Snapshot the per-route content_type before we
                    // pass `&mut s` to build_header.
                    let mut ct = [0u8; MAX_CONTENT_TYPE];
                    let ct_len = route.content_type_len as usize;
                    if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                        ct[..ct_len].copy_from_slice(&route.content_type[..ct_len]);
                    }
                    let ct_slice: &[u8] = if ct_len == 0 {
                        b"application/octet-stream"
                    } else {
                        &ct[..ct_len]
                    };
                    // Serialise: HANDLER_STREAM body-send reads from
                    // file_chan across multiple step()s. Without this
                    // gate a sibling slot's IOCTL_FLUSH would wipe
                    // our pending notify mid-stream.
                    if !try_acquire_file_chan(s) {
                        return 0;
                    }
                    dev_channel_ioctl(
                        &*s.syscalls,
                        s.server.file_chan,
                        IOCTL_FLUSH,
                        core::ptr::null_mut(),
                        0,
                    );
                    let mut pos = src_idx as u32;
                    let pos_ptr = &mut pos as *mut u32 as *mut u8;
                    let r = dev_channel_ioctl(
                        &*s.syscalls,
                        s.server.file_chan,
                        IOCTL_NOTIFY,
                        pos_ptr,
                        4,
                    );
                    if r < 0 {
                        build_error(s, b"500 Internal Server Error", b"Stream NOTIFY failed\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    build_header(s, b"200 OK", ct_slice);
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::SendHeaders;
                    }
                }
                HANDLER_FS_FILE => {
                    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
                    let n = route.fs_path_len as usize;
                    if n == 0 || n > MAX_FS_PATH {
                        build_error(s, b"500 Internal Server Error", b"FS route missing path\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // Snapshot the path before borrowing &mut s for
                    // header construction. Content-type is re-derived
                    // from `matched_route` in `Phase::AwaitFsStat`
                    // once the response code is decided.
                    let mut fs_path = [0u8; MAX_FS_PATH];
                    fs_path[..n].copy_from_slice(&route.fs_path[..n]);

                    let sys = &*s.syscalls;
                    // FS_OPEN(-1, path, len) → fd or negative errno.
                    // Dispatched through the kernel's FS_VTABLE to
                    // whichever module registered as the FS provider
                    // (fat32 on bare-metal, linux_fs_dispatch on host,
                    // browser-fetch on wasm).
                    let fd = (sys.provider_call)(
                        -1,
                        0x0900, // FS_OPEN
                        fs_path.as_mut_ptr(),
                        n,
                    );
                    if fd < 0 {
                        build_error(s, b"404 Not Found", b"Not Found\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // FS_STAT may pend for async providers, so the
                    // response-line decision happens in
                    // `Phase::AwaitFsStat` once the outcome is known.
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_fd = fd;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_sent = 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_total = 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_stat_ticks = 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::AwaitFsStat;
                    }
                }
                #[cfg(feature = "app")]
                HANDLER_APP => {
                    // Hand the whole request to the application module. The
                    // head is still in `recv_buf` — the body reader consumed
                    // only what followed it — so the headers can be forwarded
                    // verbatim.
                    let head_len = cur_slot(s).map(|c| c.header_end_off as usize).unwrap_or(0);
                    let head = core::slice::from_raw_parts(cur_recv_buf_ptr(s), head_len);
                    match app::emit_request(s, head) {
                        app::EmitResult::Sent => {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.app_pending = 1;
                                // `app_stream_id` is the request generation and
                                // was stamped by `emit_request`; setting it here
                                // would erase the discriminator.

                                cur.phase = Phase::AwaitApp;
                            }
                        }
                        // The ring is momentarily full. Stay in DispatchRoute
                        // and retry — the application is alive, just behind.
                        app::EmitResult::Full => return 0,
                        // Both remaining cases are configuration errors that no
                        // retry will fix: a route declaring HANDLER_APP with
                        // nothing wired to `req_out`, or a `max_body_kib`
                        // larger than the ring that must carry it. 503 names
                        // the server as the broken party, which is accurate.
                        app::EmitResult::Unwired => {
                            build_error(
                                s,
                                b"503 Service Unavailable",
                                b"No application wired to req_out\n",
                            );
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        app::EmitResult::TooLarge => {
                            build_error(
                                s,
                                b"503 Service Unavailable",
                                b"Request exceeds the req_out ring\n",
                            );
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                    }
                }
                HANDLER_FS_LIST => {
                    // Dual-mode: when the request path exactly matches
                    // the route path → emit the JSON directory listing
                    // (the original FS_LIST behaviour). When the
                    // request path is `<route>/<filename>` (matched
                    // via the implicit-prefix rule in
                    // `match_route_path`) → open `<fs_path>/<filename>`
                    // and stream it like HANDLER_FS_FILE.  This dual
                    // mode lets one route serve both the listing AND
                    // every file in the dir, which is what the
                    // scenario synthesiser's `list:` binding emits
                    // (the canonical case is `/api/list` + the gallery
                    // files the host page navigates between).
                    //
                    // The dispatch into the file-serve path falls
                    // through to the HANDLER_FS_FILE Phase::AwaitFsStat
                    // machinery below by setting `cur.fs_fd` after
                    // FS_OPEN-ing the composed path and transitioning
                    // straight to AwaitFsStat — no code duplication.
                    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
                    let route_path_len = route.path_len as usize;
                    let (req_path_ptr_local, req_path_len) = match cur_slot(s) {
                        Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
                        None => (core::ptr::null(), 0usize),
                    };
                    let is_file_request = req_path_len > route_path_len + 1;

                    if is_file_request {
                        // Compose `<fs_path>/<suffix>`. The suffix
                        // already includes its leading '/' (the
                        // separator between route path and filename),
                        // which lets us concat without inserting one.
                        let mut composed = [0u8; MAX_FS_PATH];
                        let dir_len = route.fs_path_len as usize;
                        let suffix_len = req_path_len - route_path_len;
                        if dir_len == 0 || dir_len + suffix_len > MAX_FS_PATH {
                            build_error(
                                s,
                                b"500 Internal Server Error",
                                b"FS_LIST file path too long\n",
                            );
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        composed[..dir_len].copy_from_slice(&route.fs_path[..dir_len]);
                        let req_path_ptr = req_path_ptr_local;
                        // Percent-decode the request suffix so spaces and
                        // other `%XX`-escaped bytes in filenames resolve to
                        // the real on-disk path (browsers encode them).
                        // Decoding only shrinks the length, so the bound
                        // check above stays valid.
                        let mut out = dir_len;
                        let mut k = 0usize;
                        while k < suffix_len {
                            let mut b = *req_path_ptr.add(route_path_len + k);
                            if b == b'%' && k + 3 <= suffix_len {
                                match (
                                    hex_val(*req_path_ptr.add(route_path_len + k + 1)),
                                    hex_val(*req_path_ptr.add(route_path_len + k + 2)),
                                ) {
                                    (Some(h), Some(l)) => {
                                        b = (h << 4) | l;
                                        k += 3;
                                    }
                                    _ => k += 1,
                                }
                            } else {
                                k += 1;
                            }
                            // Reject embedded null / backslash control bytes.
                            if b == 0 || b == b'\\' {
                                build_error(s, b"400 Bad Request", b"bad path\n");
                                if let Some(cur) = cur_slot_mut(s) {
                                    cur.phase = Phase::DrainSend;
                                }
                                return 0;
                            }
                            composed[out] = b;
                            out += 1;
                        }
                        let total = out;
                        // Reject `..` traversal: scan for `/../`,
                        // trailing `/..`, leading `../`, or bare `..`.
                        // Cheap byte-window check rather than a full
                        // canonicaliser — we're guarding the suffix
                        // (already validated for nulls/backslashes
                        // above), and the suffix is provided by the
                        // request URL which we don't trust.
                        let suffix_start = dir_len;
                        let suffix_end = total;
                        let mut k = suffix_start;
                        while k + 1 < suffix_end {
                            if composed[k] == b'.' && composed[k + 1] == b'.' {
                                let before_ok = k == suffix_start || composed[k - 1] == b'/';
                                let after_ok = (k + 2) == suffix_end || composed[k + 2] == b'/';
                                if before_ok && after_ok {
                                    build_error(
                                        s,
                                        b"400 Bad Request",
                                        b"path traversal rejected\n",
                                    );
                                    if let Some(cur) = cur_slot_mut(s) {
                                        cur.phase = Phase::DrainSend;
                                    }
                                    return 0;
                                }
                            }
                            k += 1;
                        }

                        let sys = &*s.syscalls;
                        let fd = (sys.provider_call)(
                            -1,
                            0x0900, // FS_OPEN
                            composed.as_mut_ptr(),
                            total,
                        );
                        if fd < 0 {
                            build_error(s, b"404 Not Found", b"Not Found\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_fd = fd;
                            cur.fs_sent = 0;
                            cur.fs_total = 0;
                            cur.fs_stat_ticks = 0;
                            cur.phase = Phase::AwaitFsStat;
                        }
                        return 0;
                    }

                    // Fall through: exact-match listing path.
                    let n = route.fs_path_len as usize;
                    if n == 0 || n > MAX_FS_PATH {
                        build_error(
                            s,
                            b"500 Internal Server Error",
                            b"FS_LIST route missing path\n",
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // Snapshot path + filter so the FS calls + body
                    // build don't borrow `s` immutably while we later
                    // need it mutable to write send_buf.
                    let mut fs_path = [0u8; MAX_FS_PATH];
                    fs_path[..n].copy_from_slice(&route.fs_path[..n]);
                    let filter_len = route.fs_filter_len as usize;
                    let mut filter = [0u8; 64];
                    filter[..filter_len].copy_from_slice(&route.fs_filter[..filter_len]);

                    let sys = &*s.syscalls;
                    let dir_fd = (sys.provider_call)(
                        -1,
                        0x0907, /* FS_OPENDIR */
                        fs_path.as_mut_ptr(),
                        n,
                    );
                    if dir_fd < 0 {
                        build_error(s, b"404 Not Found", b"Directory not found\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }

                    // Build JSON body into a local scratch then write
                    // headers + body into send_buf together (we need
                    // body_len for Content-Length before writing).
                    let mut body = [0u8; 2048];
                    let mut bp = 0usize;
                    // Opening `{"items":[`.
                    let prefix: &[u8] = b"{\"items\":[";
                    while bp < prefix.len() && bp < body.len() {
                        body[bp] = prefix[bp];
                        bp += 1;
                    }
                    let mut first = true;
                    let mut readdir_buf = [0u8; 1024];
                    loop {
                        let nb = (sys.provider_call)(
                            dir_fd,
                            0x0908, /* FS_READDIR */
                            readdir_buf.as_mut_ptr(),
                            readdir_buf.len(),
                        );
                        if nb <= 0 {
                            break;
                        }
                        let nb = nb as usize;
                        if nb < 2 {
                            break;
                        }
                        let count = u16::from_le_bytes([readdir_buf[0], readdir_buf[1]]) as usize;
                        // Belt-and-braces: some providers may return
                        // `nb=2 count=0` at end-of-dir; honour either.
                        if count == 0 {
                            break;
                        }
                        let mut pos = 2usize;
                        let mut emitted = 0usize;
                        while emitted < count && pos + 2 <= nb {
                            let name_len = readdir_buf[pos] as usize;
                            let entry_type = readdir_buf[pos + 1];
                            pos += 2;
                            if pos + name_len > nb {
                                break;
                            }
                            let name = &readdir_buf[pos..pos + name_len];
                            pos += name_len;
                            emitted += 1;
                            // Skip subdirectories.
                            if entry_type == 1 {
                                continue;
                            }
                            // Extension filter (case-insensitive).
                            if filter_len > 0 {
                                let mut ok = false;
                                let mut fi = 0usize;
                                while fi < filter_len {
                                    let start = fi;
                                    while fi < filter_len && filter[fi] != b',' {
                                        fi += 1;
                                    }
                                    let elen = fi - start;
                                    if elen > 0 && elen <= name.len() {
                                        let tail = &name[name.len() - elen..];
                                        let mut m = true;
                                        let mut k = 0usize;
                                        while k < elen {
                                            let a = tail[k];
                                            let b = filter[start + k];
                                            let al = a.to_ascii_lowercase();
                                            let bl = b.to_ascii_lowercase();
                                            if al != bl {
                                                m = false;
                                                break;
                                            }
                                            k += 1;
                                        }
                                        if m {
                                            ok = true;
                                            break;
                                        }
                                    }
                                    if fi < filter_len && filter[fi] == b',' {
                                        fi += 1;
                                    }
                                }
                                if !ok {
                                    continue;
                                }
                            }
                            // Comma separator between items.
                            if !first && bp < body.len() {
                                body[bp] = b',';
                                bp += 1;
                            }
                            first = false;
                            // Opening quote.
                            if bp < body.len() {
                                body[bp] = b'"';
                                bp += 1;
                            }
                            // Name bytes (escape `"` and `\`; everything else
                            // pass-through — filenames are ASCII-ish in practice).
                            let mut k = 0usize;
                            while k < name.len() && bp + 2 < body.len() {
                                let c = name[k];
                                if c == b'"' || c == b'\\' {
                                    body[bp] = b'\\';
                                    bp += 1;
                                }
                                body[bp] = c;
                                bp += 1;
                                k += 1;
                            }
                            // Closing quote.
                            if bp < body.len() {
                                body[bp] = b'"';
                                bp += 1;
                            }
                        }
                    }
                    (sys.provider_call)(
                        dir_fd,
                        0x0903, /* FS_CLOSE */
                        core::ptr::null_mut(),
                        0,
                    );
                    // Closing `]}`.
                    let suffix: &[u8] = b"]}";
                    let mut si = 0usize;
                    while si < suffix.len() && bp < body.len() {
                        body[bp] = suffix[si];
                        bp += 1;
                        si += 1;
                    }
                    let body_len = bp as u32;

                    // Write status line + Content-Length headers, then
                    // the body bytes, all into send_buf.
                    build_header_with_len(s, b"200 OK", b"application/json", body_len);
                    // After build_header_with_len, send_len is the
                    // header length. Append the body bytes.
                    let header_end = cur_send_len(s) as usize;
                    let dst = cur_send_buf_mut_ptr(s);
                    let body_ptr = body.as_ptr();
                    let max_total = SEND_BUF_SIZE.min(header_end + bp);
                    let mut k = 0usize;
                    while header_end + k < max_total {
                        *dst.add(header_end + k) = *body_ptr.add(k);
                        k += 1;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.send_len = (header_end + k) as u16;
                        cur.send_offset = 0;
                        cur.phase = Phase::SendHeaders;
                    }
                }
                HANDLER_PROXY => {
                    // Build-time static proxy backend (`proxy_ip/port`).
                    // The dynamic-route path is handled before dispatch
                    // (no static route matched → `try_begin_dyn_proxy`).
                    let (ip, port) = {
                        let r = &*s.server.routes.as_ptr().add(ri as usize);
                        (r.proxy_ip, r.proxy_port)
                    };
                    if ip == 0 || port == 0 {
                        s.server.proxy_5xx = s.server.proxy_5xx.wrapping_add(1);
                        build_error(s, b"502 Bad Gateway", b"No proxy backend\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                    } else {
                        begin_proxy(s, ip, port, -1);
                    }
                }
                HANDLER_WEBSOCKET | HANDLER_WEBSOCKET_FANOUT | HANDLER_WEBSOCKET_SESSION => {
                    if begin_ws_upgrade(s) {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::WsHandshake;
                        }
                        let fan = if handler == HANDLER_WEBSOCKET_FANOUT
                            || handler == HANDLER_WEBSOCKET_SESSION
                        {
                            1
                        } else {
                            0
                        };
                        let session = handler == HANDLER_WEBSOCKET_SESSION;
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.ws_fan_out = fan;
                            if session {
                                // Session-mode: skip retention replay for this
                                // slot entirely — mark the replay already done
                                // so the WsActive path falls straight through
                                // to the live stream.
                                cur.retained_replay_started = 1;
                                cur.retained_replay_done = 1;
                            }
                        }
                    }
                    // begin_ws_upgrade has already populated send_buf
                    // and switched phase on the failure path.
                }
                _ => {
                    build_error(s, b"500 Internal Server Error", b"Unknown handler\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                }
            }
        }

        Phase::AwaitFsStat => {
            // Poll FS_STAT until the four-state code resolves:
            //   OK     → known length; commit Content-Length.
            //   ENOSYS → no Content-Length; commit streaming 200 OK.
            //            `fs_total = u32::MAX` is the streaming
            //            sentinel that `step_send_fs_file` reads to
            //            avoid gating on `fs_sent >= fs_total`.
            //   ENODEV → fetch failed; commit 502.
            //   EAGAIN → headers pending; keep polling up to
            //            `FS_STAT_PROBE_TIMEOUT_TICKS`, then 504.
            const E_NODEV: i32 = -19;
            const E_NOSYS: i32 = -38;
            const E_AGAIN: i32 = -11;
            const FS_STAT_PROBE_TIMEOUT_TICKS: u16 = 1500; // ~30 s on pi5 4 kHz
            let sys = &*s.syscalls;
            let mut stat = [0u8; 8];
            let st = (sys.provider_call)(
                cur_fs_fd(s),
                0x0904, // FS_STAT
                stat.as_mut_ptr(),
                stat.len(),
            );

            let ct_owner: Option<&Route> = if cur_matched_route(s) >= 0 {
                Some(&*s.server.routes.as_ptr().add(cur_matched_route(s) as usize))
            } else {
                None
            };
            let ct_len = ct_owner.map(|r| r.content_type_len as usize).unwrap_or(0);
            let mut ct_buf = [0u8; MAX_CONTENT_TYPE];
            if let Some(r) = ct_owner {
                if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                    ct_buf[..ct_len].copy_from_slice(&r.content_type[..ct_len]);
                }
            }
            // Content-Type resolution order:
            //   1. Route's explicit `content_type:` (e.g. HANDLER_FS_FILE
            //      with `content_type: "text/html"`).
            //   2. Sniffed from the request path's extension. Covers
            //      the HANDLER_FS_LIST file-serve path where the route
            //      has no fixed content_type — the request URL is the
            //      only source of mime info we have without a content
            //      sniff.
            //   3. Fallback `application/octet-stream`.
            let sniffed = if ct_len == 0 {
                let (req_p, req_l) = match cur_slot(s) {
                    Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
                    None => (core::ptr::null(), 0usize),
                };
                content_type_from_path(req_p, req_l)
            } else {
                &[][..]
            };
            let ct_slice: &[u8] = if ct_len > 0 {
                &ct_buf[..ct_len]
            } else if !sniffed.is_empty() {
                sniffed
            } else {
                b"application/octet-stream"
            };

            if st == E_NODEV {
                (sys.provider_call)(
                    cur_fs_fd(s),
                    0x0903, // FS_CLOSE
                    core::ptr::null_mut(),
                    0,
                );
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_fd = -1;
                }
                build_error(s, b"502 Bad Gateway", b"Upstream fetch failed\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return 2;
            }
            if st >= 0 {
                let size = u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]);
                // In keep-alive mode recv_buf may also hold pipelined
                // bytes from the next request; cap the Range scan at
                // the current request's head so a follow-up `Range:`
                // can't bleed into this request's framing decision.
                let (recv_ptr, scan_len) = match cur_slot(s) {
                    Some(c) => (
                        c.recv_buf as *const u8,
                        if c.header_end_off > 0 {
                            (c.header_end_off as usize).min(c.recv_len as usize)
                        } else {
                            c.recv_len as usize
                        },
                    ),
                    None => (core::ptr::null::<u8>(), 0usize),
                };
                let range = if recv_ptr.is_null() || scan_len == 0 {
                    wire::h1::RangeParse::None
                } else {
                    match wire::ws::find_header_value(recv_ptr, scan_len, b"Range") {
                        Some((off, n)) => wire::h1::parse_range_header(
                            core::slice::from_raw_parts(recv_ptr.add(off), n),
                            size,
                        ),
                        None => wire::h1::RangeParse::None,
                    }
                };

                match range {
                    wire::h1::RangeParse::Satisfiable { start, end } => {
                        // Pre-seek so the streamer's first FS_READ hits
                        // the right offset; if the provider can't seek
                        // (wasm browser-fetch returns ENOSYS), degrade
                        // to 200 OK on the full body rather than 5xx —
                        // the client falls back to a non-range fetch.
                        let mut seek_arg = (start as i32).to_le_bytes();
                        let seek_rc = (sys.provider_call)(
                            cur_fs_fd(s),
                            0x0902, // FS_SEEK
                            seek_arg.as_mut_ptr(),
                            seek_arg.len(),
                        );
                        if seek_rc < 0 {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.fs_total = size;
                            }
                            build_header_fs_full(s, b"200 OK", ct_slice, size);
                        } else {
                            // Re-target the streamer at the range:
                            // `fs_total` becomes the range length, the
                            // FD's position is at `start`, and the
                            // existing `fs_sent < fs_total` window stops
                            // at the right byte.
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.fs_total = end - start + 1;
                            }
                            build_header_fs_partial(s, ct_slice, start, end, size);
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                        return 2;
                    }
                    wire::h1::RangeParse::Unsatisfiable => {
                        (sys.provider_call)(
                            cur_fs_fd(s),
                            0x0903, // FS_CLOSE
                            core::ptr::null_mut(),
                            0,
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_fd = -1;
                            cur.phase = Phase::DrainSend;
                        }
                        build_error_416(s, size);
                        return 2;
                    }
                    wire::h1::RangeParse::None => {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_total = size;
                            cur.phase = Phase::SendHeaders;
                        }
                        build_header_fs_full(s, b"200 OK", ct_slice, size);
                        return 2;
                    }
                }
            }
            if st == E_NOSYS {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_total = u32::MAX;
                }
                build_header(s, b"200 OK", ct_slice);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::SendHeaders;
                }
                return 2;
            }
            if st == E_AGAIN {
                // The active slot is guaranteed by the AwaitFsStat
                // entry path (`HANDLER_FS_FILE` sets cur_slot before
                // transitioning here); the `if let` is just a
                // panic-free borrow that PIC builds tolerate (no
                // `core::option::expect_failed` symbol).
                let timed_out = if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_stat_ticks = cur.fs_stat_ticks.saturating_add(1);
                    cur.fs_stat_ticks >= FS_STAT_PROBE_TIMEOUT_TICKS
                } else {
                    false
                };
                if timed_out {
                    (sys.provider_call)(
                        cur_fs_fd(s),
                        0x0903, // FS_CLOSE
                        core::ptr::null_mut(),
                        0,
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_fd = -1;
                    }
                    build_error(
                        s,
                        b"504 Gateway Timeout",
                        b"Upstream fetch did not respond\n",
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                    return 2;
                }
                return 0;
            }
            // Unknown FS_STAT error — treat as a fetch failure.
            (sys.provider_call)(
                cur_fs_fd(s),
                0x0903, // FS_CLOSE
                core::ptr::null_mut(),
                0,
            );
            if let Some(cur) = cur_slot_mut(s) {
                cur.fs_fd = -1;
            }
            build_error(s, b"502 Bad Gateway", b"Upstream fetch failed\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return 2;
        }

        Phase::SendHeaders => {
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                let handler = if cur_matched_route(s) >= 0 {
                    (*s.server.routes.as_ptr().add(cur_matched_route(s) as usize)).handler
                } else {
                    HANDLER_FILE
                };

                // HEAD: the headers just drained are the whole response (RFC
                // 9110 §9.3.2 — identical headers to the equivalent GET,
                // `Content-Length` included, body suppressed). Skipping
                // straight to DrainSend is not merely an optimisation: writing
                // the body after a `Content-Length` the client will not read
                // leaves those bytes in the stream, where a keep-alive
                // connection reads them as the head of the NEXT response.
                //
                // Any body-side resource opened during dispatch has to be
                // released here rather than by the renderer that will now never
                // run — the fd explicitly, `file_chan` and the cache retain by
                // DrainSend itself.
                let head_only = cur_slot(s)
                    .map(|c| !wire::method::method_sends_response_body(c.req_method))
                    .unwrap_or(false);
                if head_only {
                    if cur_fs_fd(s) >= 0 {
                        ((*s.syscalls).provider_call)(
                            cur_fs_fd(s),
                            0x0903, // FS_CLOSE
                            core::ptr::null_mut(),
                            0,
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_fd = -1;
                        }
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                    return 2;
                }

                match handler {
                    HANDLER_STATIC | HANDLER_TEMPLATE | HANDLER_FILE | HANDLER_STREAM
                    | HANDLER_FS_FILE => {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendBody;
                        }
                    }
                    HANDLER_FS_LIST => {
                        // FS_LIST is dual-mode:
                        //   - exact-match listing: the JSON body is
                        //     already in `send_buf` and has drained;
                        //     close.
                        //   - file-serve (prefix `<route>/<file>`):
                        //     AwaitFsStat opened a real fd and only
                        //     emitted the status line + headers into
                        //     `send_buf`; the body still needs to be
                        //     streamed via FS_READ → SendBody. The fd
                        //     state (`fs_fd >= 0` after AwaitFsStat
                        //     committed) is the discriminator.
                        let has_open_fd = cur_fs_fd(s) >= 0;
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = if has_open_fd {
                                Phase::SendBody
                            } else {
                                Phase::DrainSend
                            };
                        }
                    }
                    _ => {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::CloseConn;
                        }
                    }
                }
                return 2;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::SendBody => {
            let handler = if cur_matched_route(s) >= 0 {
                (*s.server.routes.as_ptr().add(cur_matched_route(s) as usize)).handler
            } else {
                HANDLER_FILE
            };

            match handler {
                HANDLER_STATIC => {
                    return step_send_static(s);
                }
                HANDLER_TEMPLATE => {
                    return step_send_template(s);
                }
                HANDLER_FILE => {
                    let fi = cur_slot(s).map(|c| c.file_index).unwrap_or(-1);
                    if fi < 0 {
                        return step_send_index(s);
                    } else {
                        return step_send_file(s);
                    }
                }
                HANDLER_STREAM => {
                    return step_send_file(s);
                }
                HANDLER_FS_FILE => {
                    return step_send_fs_file(s);
                }
                HANDLER_FS_LIST => {
                    // Dual-mode FS_LIST in file-serve mode reuses the
                    // FS_FILE streamer wholesale — same fs_fd / fs_sent
                    // / fs_total state machine, same FS_READ chunked
                    // drain. SendHeaders only forwards us here when
                    // `cur_fs_fd >= 0` (i.e. AwaitFsStat opened a real
                    // file handle), so the FS_LIST listing path
                    // (single-shot send_buf) never reaches SendBody.
                    return step_send_fs_file(s);
                }
                _ => {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::CloseConn;
                    }
                }
            }
        }

        Phase::DrainSend => {
            // The body / fetch is done with file_chan; release
            // ownership so any sibling slot blocked in DispatchRoute
            // can claim it. `release_file_chan` is idempotent (only
            // frees if we're still the owner), so calling it on
            // every DrainSend tick during the chunked drain is
            // safe.
            release_file_chan(s);
            // Release the body-cache retain count if this slot was
            // rendering from a cache entry. `cache_retained` is the
            // gate that keeps this exactly-once across the chunked
            // drain.
            let (was_cached, route_idx) = match cur_slot(s) {
                Some(c) => (c.cache_retained != 0, c.matched_route),
                None => (false, -1),
            };
            if was_cached && route_idx >= 0 {
                cache_release_for_route(s, route_idx as u8);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.cache_retained = 0;
                }
            }
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                // A streamed application response is not finished when this
                // chunk drains — more envelopes are coming for the same
                // request. Returning to AwaitApp rather than finishing is what
                // lets a body exceed `send_buf`, which is the difference
                // between serving an API and serving artefacts.
                if cfg!(feature = "app")
                    && cur_slot(s).map(|c| c.app_streaming != 0).unwrap_or(false)
                {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.send_len = 0;
                        cur.send_offset = 0;
                        cur.phase = Phase::AwaitApp;
                    }
                    return 2;
                }
                finish_response(s);
                return 0;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::FetchContent => {
            if s.server.file_chan < 0 {
                build_error(s, b"500 Internal Server Error", b"No content source\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return 0;
            }
            let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            if poll > 0 && ((poll as u32 & POLL_IN) != 0 || (poll as u32 & POLL_HUP) != 0) {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CacheStream;
                }
                return 2;
            }
        }

        Phase::CacheStream => {
            if s.server.cache_count == 0 || s.server.file_chan < 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
            let ce_idx = 0usize;
            let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ce_idx);
            let arena_off = ce.arena_offset as usize;
            let cur_len = ce.length as usize;
            let pool_cap = s.server.body_pool_cap as usize;

            let space = pool_cap - (arena_off + cur_len);
            if space > 0 && !s.server.body_pool.is_null() {
                let dst = s.server.body_pool.add(arena_off + cur_len);
                let to_read = space.min(SEND_BUF_SIZE);
                let n = ((*s.syscalls).channel_read)(s.server.file_chan, dst, to_read);
                if n > 0 {
                    ce.length += n as u32;
                }
            }

            let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            let eof = poll > 0 && (poll as u32 & POLL_HUP) != 0 && (poll as u32 & POLL_IN) == 0;
            let full = (arena_off + ce.length as usize) >= pool_cap;

            if eof || full {
                ce.flags |= CACHE_COMPLETE;
                // Retain the entry on behalf of the imminent reader
                // (this slot, transitioning to SendHeaders →
                // SendBody → DrainSend). DrainSend's release path
                // calls cache_release_for_route to balance.
                ce.retain = ce.retain.saturating_add(1);
                let ri = cur_matched_route(s) as usize;
                let r = &mut *s.server.routes.as_mut_ptr().add(ri);
                r.body_offset = ce.arena_offset;
                r.body_len = ce.length;
                let handler = r.handler;
                let body_len = r.body_len;
                let mut ct = [0u8; MAX_CONTENT_TYPE];
                let ct_len = r.content_type_len as usize;
                if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                    ct[..ct_len].copy_from_slice(&r.content_type[..ct_len]);
                }
                let ct_slice: &[u8] = if ct_len == 0 {
                    b"text/html"
                } else {
                    &ct[..ct_len]
                };
                // Static bodies: Content-Length is known, so emit it
                // and keep-alive is preserved. Templates render
                // chunk-by-chunk with unknown total → close-delimited.
                if handler == HANDLER_STATIC {
                    build_header_with_len(s, b"200 OK", ct_slice, body_len);
                } else {
                    build_header(s, b"200 OK", ct_slice);
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.tmpl_pos = 0;
                    cur.cache_retained = 1;
                    cur.phase = Phase::SendHeaders;
                }
                return 2;
            }

            return 2;
        }

        Phase::CloseConn => {
            reset_connection(s);
            if s.server.draining != 0 {
                return 1;
            }
        }

        Phase::ProxyConnect => {
            // Serialise the CONNECT→CONNECTED handshake so demux can
            // correlate the reply (it carries only conn + module tag).
            let me = match current_slot_index(s) {
                Some(i) => i as i16,
                None => return 0,
            };
            if s.server.proxy_connect_owner >= 0 && s.server.proxy_connect_owner != me {
                return 0; // another slot mid-connect — retry next tick
            }
            s.server.proxy_connect_owner = me;
            if !proxy_dial(s) {
                return 0; // net_out full — retry next tick, keep ownership
            }
            let now = dev_millis(&*s.syscalls) as u32;
            if let Some(cur) = cur_slot_mut(s) {
                cur.proxy_connect_start_ms = now;
                cur.phase = Phase::ProxyWaitConnect;
            }
            return 2;
        }

        Phase::ProxyWaitConnect => {
            let (connected, failed, start) = match cur_slot(s) {
                Some(c) => (
                    c.proxy_connected != 0,
                    c.proxy_connect_failed != 0,
                    c.proxy_connect_start_ms,
                ),
                None => return 0,
            };
            if failed {
                proxy_connect_failed(s);
                return 2;
            }
            if connected {
                if let Some(idx) = current_slot_index(s) {
                    if s.server.proxy_connect_owner == idx as i16 {
                        s.server.proxy_connect_owner = -1;
                    }
                }
                proxy_build_forward_head(s);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::ProxySendRequest;
                }
                return 2;
            }
            let now = dev_millis(&*s.syscalls) as u32;
            if now.wrapping_sub(start) >= PROXY_CONNECT_TIMEOUT_MS {
                proxy_connect_failed(s);
                return 2;
            }
            return 0;
        }

        Phase::ProxySendRequest => {
            let backend = match cur_slot(s) {
                Some(c) => c.backend_conn_id,
                None => return 0,
            };
            if backend < 0 {
                proxy_connect_failed(s);
                return 2;
            }
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                // Head fully forwarded — enter the byte relay and free
                // `send_buf` so demux can stage backend→client bytes.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                    cur.send_len = 0;
                    cur.phase = Phase::ProxyRelayBody;
                }
                return 2;
            }
            let sent = net_send_conn(
                s,
                backend as u16,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::ProxyRelayHeaders | Phase::ProxyRelayBody => {
            proxy_relay_step(s);
        }

        Phase::WsHandshake => {
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                log(s, b"[http] websocket upgraded");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_len = 0;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::WsActive;
                }
                // Last-connection-wins: stamp this slot as the
                // current fan-out subscriber. Every other slot whose
                // `ws_fan_out=1` will self-close (CLOSE 1001) on its
                // next `WsActive` tick — see the displacement check
                // at the top of the WsActive arm. Doing it that way
                // (rather than walking the table here and queuing
                // CLOSE on busy slots) avoids the race where the
                // displaced slot is mid-flush of a big payload and
                // skipped because its `send_buf` is non-empty:
                // the per-slot check re-fires every tick until the
                // flush drains, at which point the close cleanly
                // takes over.
                if cur_ws_fan_out(s) != 0 {
                    s.server.latest_fanout_slot = s.server.cur_slot;
                }
                return 2;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::WsActive => {
            // `demux_inbound` (called once per `step()` before the
            // slot loop) routes MSG_ACCEPTED / MSG_CLOSED / MSG_DATA
            // to the right slot, so the per-tick handler here only
            // has to drain ws_in / recv_buf.
            //
            // Peer-closed fast path: if `linux_net` has signalled
            // MSG_CLOSED for this conn, the slot's TCP socket is
            // gone — sending any more bytes is wasted work, and
            // leaving `ws_fan_out=1` on the slot makes
            // `find_sentinel_ws_fanout_slot` hand new producers a dead
            // delivery target. Transition straight to CloseConn so
            // `slot_release_buffers` clears the fanout flag and
            // frees the slot for a new live client. Without this
            // gate, a reloaded browser tab leaves its old slot
            // hogging the fanout target indefinitely (lower slot
            // index always wins find_first), and the reloaded tab's
            // new slot never gets a single envelope.
            if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.ws_fan_out = 0;
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }

            // Last-connection-wins self-check: if a newer fan-out
            // upgrade has stamped `latest_fanout_slot` to a different
            // slot, this slot has been displaced. Queue a graceful
            // CLOSE 1001 the moment `send_buf` is clear and no
            // fragmentation is in flight; otherwise let the in-flight
            // flush complete and re-check on the next tick. Skipping
            // retention replay + ws_in drain here is intentional —
            // we don't want a being-displaced slot to consume more
            // envelopes that the new slot should be receiving.
            let me_idx = s.server.cur_slot;
            let displaced = cur_ws_fan_out(s) != 0
                && s.server.latest_fanout_slot >= 0
                && s.server.latest_fanout_slot != me_idx;
            if displaced {
                let send_empty = cur_send_len(s) == 0;
                let no_frag = cur_slot(s).map(|c| c.ws_frag_buf.is_null()).unwrap_or(true);
                if send_empty && no_frag {
                    ws_begin_close(s, wire::ws::CLOSE_GOING_AWAY);
                    return 2;
                }
                // Mid-flush: drain remaining bytes then re-check.
                if cur_send_len(s) > 0 && cur_send_offset(s) < cur_send_len(s) {
                    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
                    let sent = net_send(
                        s,
                        cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                        remaining,
                    );
                    if sent > 0 {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset += sent as u16;
                        }
                        if cur_send_offset(s) >= cur_send_len(s) {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.send_offset = 0;
                                cur.send_len = 0;
                            }
                        }
                    }
                }
                return 0;
            }

            // Retention replay: a freshly upgraded fan-out slot drains
            // any envelopes still held in `retained_buf` (the producer's
            // most recent snapshot) before joining the live fan-out
            // path. Single envelope per loop iteration so the existing
            // flush + fragmentation machinery handles each one
            // identically to a live ws_in arrival. Once `retained_used`
            // is exhausted (or the buffer has been reset mid-replay by
            // a fresh producer burst), `retained_replay_done` flips and
            // subsequent ticks fall through to the normal flow.
            let needs_replay = cur_slot(s)
                .map(|c| {
                    c.ws_fan_out != 0 && c.retained_replay_done == 0 && c.ws_frag_buf.is_null()
                })
                .unwrap_or(false);
            if needs_replay && cur_send_len(s) == 0 && !s.server.retained_buf.is_null() {
                // First tick in this slot: stamp the replay target
                // to the current `retained_used`. The replay walks
                // only up to that boundary, so envelopes captured
                // *after* the slot enters WsActive (which are also
                // queued live) don't get re-delivered through replay.
                let started = cur_slot(s).map(|c| c.retained_replay_started).unwrap_or(0);
                if started == 0 {
                    let snapshot = s.server.retained_used;
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.retained_replay_target = snapshot;
                        cur.retained_replay_started = 1;
                    }
                }
                let (offset, target) = (
                    cur_slot(s).map(|c| c.retained_replay_offset).unwrap_or(0),
                    cur_slot(s).map(|c| c.retained_replay_target).unwrap_or(0),
                );
                // If the buffer was reset since replay started
                // (retained_used dropped below the snapshot target),
                // the bytes the slot was about to read are
                // partially overwritten — abort cleanly.
                let buf_reset = s.server.retained_used < target;
                if offset >= target || buf_reset {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.retained_replay_done = 1;
                    }
                } else if (offset as usize) + RETAINED_ENVELOPE_HDR <= target as usize {
                    let buf = s.server.retained_buf.add(offset as usize);
                    let r_op = *buf;
                    let r_fin = *buf.add(1) != 0;
                    let r_len = u16::from_le_bytes([*buf.add(2), *buf.add(3)]) as usize;
                    let envelope_total = RETAINED_ENVELOPE_HDR + r_len;
                    if (offset as usize) + envelope_total > target as usize {
                        // Truncated tail (retained_buf reset mid-walk
                        // by a fresh burst). Bail out of replay; live
                        // path resumes next iteration.
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.retained_replay_done = 1;
                        }
                    } else {
                        let payload_ptr = buf.add(RETAINED_ENVELOPE_HDR);
                        if ws_queue_envelope_on_active(s, r_op, r_fin, payload_ptr, r_len) {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.retained_replay_offset = cur
                                    .retained_replay_offset
                                    .saturating_add(envelope_total as u32);
                            }
                        } else {
                            // Heap-alloc failure on fragmentation —
                            // give up on replay, let live producer
                            // re-emit if/when it can.
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.retained_replay_done = 1;
                            }
                        }
                    }
                }
            }

            // Loop within this tick alternating between flushing send_buf
            // to net_out and draining the next outbound frame from
            // ws_in / recv_buf. This keeps the pipeline saturated under
            // heavy producer load (spectrum_video chunking ~50 WsFrames
            // per video frame would otherwise take ~50 ticks to emit).
            // Exits as soon as no work can be done on either side.
            let mut did_any = false;
            // Bounded batch per tick. The loop's termination argument is
            // "exit when neither side made progress", which is sound but is
            // bounded by WORK AVAILABLE rather than by anything this module
            // controls: a producer that keeps `ws_in` saturated while net_out
            // keeps accepting can hold the tick for as long as it cares to.
            // That is a step-time problem rather than a hang — every other
            // module in the domain waits — so the batch is capped and the
            // remainder rolls into the next tick, the same shape the inbound
            // demux uses. 32 keeps the pipeline saturated (the fan-out case
            // this loop exists for chunks ~50 frames per video frame, so a
            // tick still carries most of one) without letting one connection
            // own the domain.
            const WS_BATCH_PER_TICK: usize = 32;
            for _ in 0..WS_BATCH_PER_TICK {
                let mut progress = false;

                // Flush as much of send_buf as net_out will accept.
                if cur_send_len(s) > 0 && cur_send_offset(s) < cur_send_len(s) {
                    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
                    let sent = net_send(
                        s,
                        cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                        remaining,
                    );
                    if sent > 0 {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset += sent as u16;
                        }
                        progress = true;
                    }
                    if cur_send_offset(s) >= cur_send_len(s) {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset = 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_len = 0;
                        }
                    }
                }

                // Drain a WsFrame from ws_in if send_buf is now empty.
                // ws_drain_fanout_input writes one WsFrame's worth into
                // send_buf and returns true on success.
                if cur_send_len(s) == 0 && cur_ws_fan_out(s) != 0 && ws_drain_fanout_input(s) {
                    progress = true;
                }

                // Process any pre-buffered inbound frame. In echo mode
                // this writes to send_buf (skip if non-empty); in
                // fan-out mode it writes to ws_out and is always safe.
                // A peer CLOSE frame is parsed even with send_buf
                // occupied: we're transitioning to WsClose anyway, and
                // a saturated ws_in feed (e.g. 50 fps fan-out) would
                // otherwise keep send_buf permanently refilled and
                // the CLOSE would never get parsed.
                let peer_close_pending = cur_recv_len(s) > 0 && *cur_recv_buf_ptr(s) == 0x88;
                let can_process = cur_send_len(s) == 0 || peer_close_pending;
                if can_process && ws_process_inbound(s) {
                    progress = true;
                }

                if !progress {
                    break;
                }
                did_any = true;
                // ws_process_inbound may have transitioned to WsClose
                // (peer sent CLOSE, or we initiated CLOSE on protocol
                // error). Exit the loop so the next tick handles the
                // outgoing CLOSE frame from the WsClose arm rather than
                // continuing to drain ws_in / parse stale recv_buf.
                if !matches!(cur_phase(s), Phase::WsActive) {
                    break;
                }
            }

            // The slot table is the parallelism bound: idle WSes
            // don't starve other conns on hosts with multiple
            // slots; embedded targets with `MAX_CONCURRENT_CONNS = 1`
            // simply reject new conns at the demux until the WS
            // closes.
            if did_any {
                return 2;
            }

            // Nothing more to process this tick. Inbound bytes are
            // routed to this slot's `recv_buf` by `demux_inbound`,
            // and `peer_closed` is set there too — no per-slot
            // channel poll needed.
            if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
        }

        Phase::WsClose => {
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
                if cur_send_offset(s) >= cur_send_len(s) {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::CloseConn;
                    }
                    return 0;
                }
            } else {
                // CLOSE-echo is best-effort: the peer initiated the
                // close, so they aren't waiting on our reply. If
                // `net_send` rejects (TCP send buffer full, slot gone,
                // zero peer window) free the slot rather than spin.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
        }

        #[cfg(not(feature = "h2"))]
        Phase::H2Active => {
            // Unreachable without h2 (nothing constructs H2Active —
            // the preface detect is compiled out), but the enum
            // variant is kept so phase numbering and the phase-walk
            // arms stay identical across variants. Fail closed.
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return 0;
        }
        #[cfg(feature = "h2")]
        Phase::H2Active => {
            let r = super::h2::step(s);
            if r == 1 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
            return r;
        }

        Phase::Error => {
            return 1;
        }
    }

    0
}
