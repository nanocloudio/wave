//! Response bodies: rendering them, and getting them onto the wire.
//!
//! Two halves that only make sense together. The `render_*_into` family writes
//! body bytes into a caller-supplied buffer and knows nothing about phases; the
//! `step_send_*` family owns a phase, drains `send_buf` against network
//! backpressure, and calls a renderer when it needs more bytes.
//!
//! The renderers are deliberately buffer-agnostic — route and cursor arrive as
//! parameters rather than being read from the slot — which is what lets h1, h2
//! and h3 all render the same template: h1 and h2 pass a connection slot's
//! cursor, h3 passes a stream slot's. A renderer that reached for `cur_slot`
//! would silently serve one concurrent request correctly and the rest wrongly.
//!
//!
//! Each renderer writes the next chunk of body bytes for the matched route
//! into a caller-provided `[dst, dst+cap)` buffer and returns
//! `(bytes_written, more_pending)`. They keep their position state in
//! `ServerState` (`tmpl_pos` / `index_pos` / `file_chan`) so that successive
//! calls advance through the body. h1's `step_send_*` helpers and h2's
//! `Sub::SendingBody` substate share these renderers — h1 writes to
//! `send_buf` at offset 0; h2 writes at offset `FRAME_HEADER_LEN` so it can
//! backfill an h2 DATA frame header.

use super::super::connection::{NET_BUF_SIZE, NET_CMD_SEND};
use super::cache::{cache_lookup_any, cache_release_for_route, lookup_var, CACHE_COMPLETE};
use super::response::{build_error, build_header, build_header_with_len};
use super::routes::{
    HANDLER_FILE, HANDLER_FS_FILE, HANDLER_STATIC, HANDLER_STREAM, HANDLER_TEMPLATE,
};
use super::{
    cur_fs_fd, cur_fs_sent, cur_fs_total, cur_matched_route, cur_recv_buf_mut_ptr,
    cur_send_buf_mut_ptr, cur_send_buf_ptr, cur_send_len, cur_send_offset, cur_slot, cur_slot_mut,
    dev_channel_ioctl, dev_csprng_fill, dev_log, dev_micros, dev_millis, dev_self_index,
    dev_telemetry_enabled, dev_telemetry_span, fmt_u32_raw, log, net_send, net_write_frame,
    release_file_chan, reset_connection, set_cur_phase, try_acquire_file_chan, ConnSlot, HttpState,
    Phase, IOCTL_FLUSH, IOCTL_NOTIFY, IOCTL_POLL_NOTIFY, MAX_ROUTES, MAX_VAR_VALUE, POLL_HUP,
    POLL_IN, RECV_BUF_SIZE, SEND_BUF_SIZE,
};

// ── Renderers ─────────────────────────────────────────────────────────────

/// Walk inline static body bytes from `body_pool`. `tmpl_pos` is the
/// offset within the route body (0 = start).
pub(crate) unsafe fn render_static_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return (0, false),
    };
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + (*cur_ptr).tmpl_pos as usize;
    if pos >= body_end || cap == 0 {
        return (0, pos < body_end);
    }
    let n = (body_end - pos).min(cap);
    let src = (s.server.body_pool as *const u8).add(pos);
    core::ptr::copy_nonoverlapping(src, dst, n);
    (*cur_ptr).tmpl_pos += n as u32;
    let more = (pos + n) < body_end;
    (n, more)
}

/// Render a template body chunk with `{{var}}` substitution into `dst`.
pub(crate) unsafe fn render_template_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return (0, false),
    };
    let route_idx = cur_matched_route(s);
    let mut cursor = (*cur_ptr).tmpl_pos;
    let r = render_template_route_into(s, route_idx, &mut cursor, dst, cap);
    (*cur_ptr).tmpl_pos = cursor;
    r
}

/// Render a template body chunk for an EXPLICIT route and cursor.
///
/// The same renderer, with its two connection-scoped dependencies lifted into
/// parameters: which route, and how far through the body we are. `http`'s
/// per-connection slot supplies both for HTTP/1 and HTTP/2; HTTP/3 supplies its
/// per-STREAM slot, because it multiplexes and a connection-scoped cursor would
/// interleave two responses into each other.
///
/// Deliberately takes `&HttpState`: rendering reads the body pool and the
/// variable table and mutates nothing but the caller's cursor, which is what
/// makes it shareable across generations at all.
pub(crate) unsafe fn render_template_route_into(
    s: &HttpState,
    route_idx: i8,
    cursor: &mut u32,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    if route_idx < 0 {
        return (0, false);
    }
    let route = &*s.server.routes.as_ptr().add(route_idx as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pool = s.server.body_pool as *const u8;
    let mut out = 0usize;
    let mut pos = body_start + *cursor as usize;

    while pos < body_end && out < cap {
        if pos + 1 < body_end && *pool.add(pos) == b'{' && *pool.add(pos + 1) == b'{' {
            // Look the variable up first so the headroom check uses
            // its actual width rather than the worst-case bound — a
            // tight `cap` (e.g. send_window-capped) can still emit a
            // small value that wouldn't have cleared `MAX_VAR_VALUE`.
            let saved_pos = pos;
            pos += 2;
            let mut hash: u32 = 0x811c9dc5;
            while pos + 1 < body_end && !(*pool.add(pos) == b'}' && *pool.add(pos + 1) == b'}') {
                let c = *pool.add(pos);
                if c != b' ' {
                    hash ^= c as u32;
                    hash = hash.wrapping_mul(0x01000193);
                }
                pos += 1;
            }
            if pos + 1 < body_end {
                pos += 2;
            }

            let (val_ptr, val_len) = lookup_var(s, hash);
            let emit_len = if val_ptr.is_null() { 0 } else { val_len };
            if out + emit_len > cap {
                // Defer the whole substitution to the next call —
                // rewinding to `{{` keeps us atomic so the caller
                // never sees a half-expanded value.
                pos = saved_pos;
                break;
            }
            if !val_ptr.is_null() {
                let mut vi = 0;
                while vi < val_len {
                    *dst.add(out) = *val_ptr.add(vi);
                    out += 1;
                    vi += 1;
                }
            }
        } else {
            *dst.add(out) = *pool.add(pos);
            out += 1;
            pos += 1;
        }
    }

    *cursor = (pos - body_start) as u32;
    (out, pos < body_end)
}

/// Pull the next chunk of file bytes from `file_chan`. Returns
/// `(0, true)` when no data is available yet but the channel hasn't
/// hung up — callers should yield and retry. Returns `(0, false)` once
/// HUP is observed with no payload.
pub(crate) unsafe fn render_file_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    if s.server.file_chan < 0 {
        return (0, false);
    }
    let n = ((*s.syscalls).channel_read)(s.server.file_chan, dst, cap);
    if n > 0 {
        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(n as u32);
        return (n as usize, true);
    }
    let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
    let hup = poll > 0 && (poll as u32 & POLL_HUP) != 0;
    (0, !hup)
}

/// Render the directory-index listing (decimal indices, one per line)
/// from `index_pos` up to `file_count`.
pub(crate) unsafe fn render_index_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return (0, false),
    };
    let mut off = 0usize;
    let mut idx = (*cur_ptr).index_pos;
    let file_count = (*cur_ptr).file_count;
    while idx < file_count && off + 7 < cap {
        off += fmt_u32_raw(dst.add(off), idx as u32);
        *dst.add(off) = b'\n';
        off += 1;
        idx += 1;
    }
    (*cur_ptr).index_pos = idx;
    (off, idx < file_count)
}

/// h1 template wrapper — writes a chunk into `send_buf` and updates
/// `send_offset`/`send_len` so the existing `step_send_template` flow can
/// flush it.
pub(crate) unsafe fn render_template_chunk(s: &mut HttpState) -> bool {
    let buf = cur_send_buf_mut_ptr(s);
    let (n, more) = render_template_into(s, buf, SEND_BUF_SIZE);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
    }
    more
}

// ── Legacy file mode ──────────────────────────────────────────────────────

pub(crate) unsafe fn parse_file_index(s: &HttpState) -> i16 {
    let cur = match cur_slot(s) {
        Some(c) => c,
        None => return -1,
    };
    let buf = cur.req_path.as_ptr();
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let suffix_start = route.path_len as usize;
    let path_end = cur.req_path_len as usize;

    if suffix_start >= path_end {
        return -1;
    }
    let mut pos = suffix_start;
    if *buf.add(pos) == b'/' {
        pos += 1;
    }
    if pos >= path_end {
        return -1;
    }

    let mut idx: i32 = 0;
    while pos < path_end {
        let c = *buf.add(pos);
        if !c.is_ascii_digit() {
            return -2;
        }
        idx = idx * 10 + (c - b'0') as i32;
        if idx > 0x7FFF {
            return -2;
        }
        pos += 1;
    }
    idx as i16
}

/// Returns `true` if the dispatch handled the request (advanced the
/// phase to SendHeaders / DrainSend). Returns `false` if `file_chan`
/// is currently held by another slot — caller should stay in
/// DispatchRoute and retry on the next tick.
pub(crate) unsafe fn step_legacy_file_dispatch(s: &mut HttpState) -> bool {
    let (buf, plen) = match cur_slot(s) {
        Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
        None => return true,
    };

    if plen == 1 && *buf == b'/' {
        if s.server.file_chan >= 0 {
            // POLL_NOTIFY is read-only and doesn't trample pending
            // FLUSH/NOTIFY state, but we still gate behind the
            // cross-slot lock so a concurrent slot can't observe
            // a half-modified channel state.
            if !try_acquire_file_chan(s) {
                return false;
            }
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
            cur.file_index = -1;
            cur.matched_route = -1;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::SendHeaders;
        }
    } else if plen >= 2 && *buf == b'/' {
        let mut idx: i32 = 0;
        let mut i = 1usize;
        let mut valid = true;
        while i < plen {
            let c = *buf.add(i);
            if !c.is_ascii_digit() {
                valid = false;
                break;
            }
            idx = idx * 10 + (c - b'0') as i32;
            if idx > 0x7FFF {
                valid = false;
                break;
            }
            i += 1;
        }
        if !valid {
            build_error(s, b"400 Bad Request", b"Bad Request\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return true;
        }

        if let Some(cur) = cur_slot_mut(s) {
            cur.file_index = idx as i16;
            cur.matched_route = -1;
        }
        if s.server.file_chan >= 0 {
            // Cross-slot serialisation for the FLUSH/NOTIFY pair.
            // If another slot owns the channel, leave the slot in
            // DispatchRoute and retry next tick.
            if !try_acquire_file_chan(s) {
                return false;
            }
            dev_channel_ioctl(
                &*s.syscalls,
                s.server.file_chan,
                IOCTL_FLUSH,
                core::ptr::null_mut(),
                0,
            );
            let mut pos = idx as u32;
            let pos_ptr = &mut pos as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr, 4);
            if r < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return true;
            }
            build_header(s, b"200 OK", b"application/octet-stream");
        } else {
            build_error(s, b"404 Not Found", b"Not Found\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return true;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::SendHeaders;
        }
    } else {
        build_error(s, b"400 Bad Request", b"Bad Request\n");
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::DrainSend;
        }
    }
    true
}

// ── Send phases ───────────────────────────────────────────────────────────

/// Emit the `http.server.request` span for the just-completed response. Joins
/// the caller's distributed trace when the request carried a `traceparent`
/// (parsed into the slot at request start); otherwise mints a fresh root.
/// `name_id = 0` is the first `[observability].spans` entry. No-op when the
/// telemetry port is unwired or no span was started for this request.
pub(crate) unsafe fn emit_request_span(s: &mut HttpState) {
    if !dev_telemetry_enabled(&*s.syscalls) {
        return;
    }
    let (start, tp_trace, tp_parent, tp_flags) = match cur_slot(s) {
        Some(c) if c.span_start_us != 0 => (
            c.span_start_us,
            c.span_trace_id,
            c.span_parent_id,
            c.span_flags,
        ),
        _ => return,
    };
    // Head-sampling gate FIRST — before any clock read or RNG. A propagated
    // `traceparent` carries the caller's decision; a minted root is sampled. An
    // unsampled flow emits nothing; the client
    // controls this, so the early gate matters.
    let propagated = tp_trace != [0u8; 16];
    let eff_flags = if propagated {
        tp_flags
    } else {
        super::super::abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    };
    if eff_flags & super::super::abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.span_start_us = 0;
        }
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let end_raw = dev_micros(sys);
    let end = if end_raw < start { start } else { end_raw };
    let mut ctx = super::super::abi::contracts::telemetry::SpanContext {
        trace_id: [0u8; 16],
        span_id: [0u8; 8],
        parent_id: [0u8; 8],
        flags: eff_flags,
    };
    // A non-zero trace id means the caller propagated context — join its trace
    // and parent under it; otherwise this is a minted root.
    if propagated {
        ctx.trace_id = tp_trace;
        ctx.parent_id = tp_parent;
    } else {
        dev_csprng_fill(sys, ctx.trace_id.as_mut_ptr(), 16);
    }
    dev_csprng_fill(sys, ctx.span_id.as_mut_ptr(), 8);
    dev_telemetry_span(
        sys,
        -1,
        me as u16,
        0, // name_id 0 = http.server.request
        super::super::abi::contracts::telemetry::SPAN_SERVER,
        super::super::abi::contracts::telemetry::STATUS_OK,
        &ctx,
        start,
        end,
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.span_start_us = 0;
    }
}

/// Transition out of a fully-drained response. Honours the slot's
/// `keepalive` flag: reuse the slot for the next request (compacting
/// any pipelined bytes already in `recv_buf`) or close the
/// connection.
pub(crate) unsafe fn finish_response(s: &mut HttpState) {
    // Observability: a response is fully drained here (keepalive reuse or
    // close), so this is the single span-end chokepoint for the request.
    emit_request_span(s);
    let (keepalive, header_end_off, recv_len) = match cur_slot(s) {
        Some(c) => (
            c.keepalive != 0,
            c.header_end_off as usize,
            c.recv_len as usize,
        ),
        None => {
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return;
        }
    };
    if !keepalive {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
        return;
    }
    // Compact any pipelined-request bytes to recv_buf[0..] so the
    // next RecvRequest pass parses them without needing a fresh
    // channel read.
    let leftover = recv_len.saturating_sub(header_end_off);
    if leftover > 0 {
        let buf = cur_recv_buf_mut_ptr(s);
        core::ptr::copy(buf.add(header_end_off), buf, leftover);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
        cur.recv_parsed = 0;
        cur.req_path_len = 0;
        // Per-REQUEST, not per-connection: a keep-alive connection serves
        // many, and a stale HEAD would suppress the body of the GET after it.
        cur.req_method = super::super::wire::method::METHOD_NONE;
        cur.matched_route = -1;
    }
    // Release this request's decoded body, for the same reason: the next
    // request on this connection must not inherit the previous one's payload.
    super::reqbody::reset_body(s);
    if let Some(cur) = cur_slot_mut(s) {
        cur.header_end_off = 0;
        cur.tmpl_pos = 0;
        cur.send_offset = 0;
        cur.send_len = 0;
        // `keepalive` left untouched — re-derived from the next
        // request's headers (clients may switch mid-session).
        cur.phase = Phase::RecvRequest;
    }
}

pub(crate) unsafe fn step_send_static(s: &mut HttpState) -> i32 {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return 0,
    };
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + (*cur_ptr).tmpl_pos as usize;

    if pos >= body_end {
        finish_response(s);
        return 0;
    }

    let remaining = body_end - pos;
    let to_send = remaining.min(SEND_BUF_SIZE);
    let ptr = (s.server.body_pool as *const u8).add(pos);
    let sent = net_send(s, ptr, to_send);
    if sent > 0 {
        (*cur_ptr).tmpl_pos += sent as u32;
        return 2;
    }
    0
}

pub(crate) unsafe fn step_send_template(s: &mut HttpState) -> i32 {
    if cur_send_offset(s) < cur_send_len(s) {
        let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
        let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
        let sent = net_send(s, ptr, remaining);
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
            }
        }
        return 0;
    }

    let has_more = render_template_chunk(s);
    if cur_send_len(s) > 0 {
        let ptr = cur_send_buf_ptr(s);
        let sent = net_send(s, ptr, cur_send_len(s) as usize);
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = sent as u16;
            }
        }
        return if has_more { 2 } else { 0 };
    }

    if !has_more {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
    }
    0
}

pub(crate) unsafe fn step_send_index(s: &mut HttpState) -> i32 {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return 0,
    };
    if (*cur_ptr).index_pos >= (*cur_ptr).file_count {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
        return 0;
    }

    if cur_send_offset(s) >= cur_send_len(s) {
        let buf = cur_send_buf_mut_ptr(s);
        let mut off = 0usize;
        let mut idx = (*cur_ptr).index_pos;
        let file_count = (*cur_ptr).file_count;
        while idx < file_count && off + 6 < SEND_BUF_SIZE {
            off += fmt_u32_raw(buf.add(off), idx as u32);
            *buf.add(off) = b'\n';
            off += 1;
            idx += 1;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = off as u16;
        }
        (*cur_ptr).index_pos = idx;
    }

    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
    let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
    let sent = net_send(s, ptr, remaining);
    if sent > 0 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset += sent as u16;
        }
        return 2;
    }
    0
}

pub(crate) unsafe fn step_send_file(s: &mut HttpState) -> i32 {
    if cur_send_offset(s) >= cur_send_len(s) {
        let n = ((*s.syscalls).channel_read)(
            s.server.file_chan,
            cur_send_buf_mut_ptr(s),
            SEND_BUF_SIZE,
        );
        if n > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
        } else {
            let chan_poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            if chan_poll > 0 && (chan_poll as u32 & POLL_HUP) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
            }
            return 0;
        }
    }

    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
    let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
    let sent = net_send(s, ptr, remaining);
    if sent > 0 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset += sent as u16;
        }
        return 2;
    }
    0
}

/// HANDLER_FS_FILE body streamer. Drains `send_buf` to net_out;
/// when empty, calls `FS_READ` for the next chunk. Closes the FD and
/// transitions to `CloseConn` when `fs_sent == fs_total` (or FS_READ
/// returns ≤ 0).
///
/// Runs up to `FS_SEND_ROUNDS` fill+send cycles per step — a single
/// 4 KiB round per step caps serving around 2 MB/s under the
/// scheduler's burst budget, an order of magnitude short of media
/// streaming. Backpressure exits immediately (net_send returning 0
/// ends the loop), so slow consumers see one-round pacing.
pub(crate) unsafe fn step_send_fs_file(s: &mut HttpState) -> i32 {
    const FS_SEND_ROUNDS: usize = 16;
    let mut progressed = false;
    for _ in 0..FS_SEND_ROUNDS {
        if cur_fs_fd(s) < 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return 0;
        }
        if cur_send_offset(s) >= cur_send_len(s) {
            // `fs_total == u32::MAX` is the streaming sentinel — read
            // until FS_READ signals EOF below. Otherwise close out once
            // the declared content length is reached.
            let length_known = cur_fs_total(s) != u32::MAX;
            if length_known && cur_fs_sent(s) >= cur_fs_total(s) {
                let sys = &*s.syscalls;
                (sys.provider_call)(
                    cur_fs_fd(s),
                    0x0903, // FS_CLOSE
                    core::ptr::null_mut(),
                    0,
                );
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_fd = -1;
                }
                // Self-delimited (Content-Length already emitted) — honour
                // the client's keep-alive intent.
                finish_response(s);
                return 0;
            }
            // Refill: streaming reads a full SEND_BUF; length-known caps
            // at the remaining bytes so we never over-read.
            let sys = &*s.syscalls;
            let want = SEND_BUF_SIZE as u32;
            let cap = if length_known {
                let remaining = cur_fs_total(s).saturating_sub(cur_fs_sent(s));
                (if remaining < want { remaining } else { want }) as usize
            } else {
                want as usize
            };
            let n = (sys.provider_call)(
                cur_fs_fd(s),
                0x0901, // FS_READ
                cur_send_buf_mut_ptr(s),
                cap,
            );
            // EAGAIN: provider has no bytes ready but the stream isn't
            // done. Yield; the next step re-polls. Distinguishing this
            // from EOF matters — closing on a not-yet-ready read would
            // truncate every async-backed file.
            if n == -11 {
                return if progressed { 2 } else { 0 };
            }
            if n <= 0 {
                (sys.provider_call)(
                    cur_fs_fd(s),
                    0x0903, // FS_CLOSE
                    core::ptr::null_mut(),
                    0,
                );
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_fd = -1;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
        }

        let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
        let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
        let sent = net_send(s, ptr, remaining);
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.fs_sent = cur.fs_sent.wrapping_add(sent as u32);
            }
            progressed = true;
            if (sent as usize) < remaining {
                // Net ring filled mid-buffer — no point retrying now.
                return 2;
            }
            continue;
        }
        // Net backpressure with nothing accepted this round.
        return if progressed { 2 } else { 0 };
    }
    2
}
