//! HTTP application fan-out — handing a request to a graph node and taking the
//! response back.
//!
//! Every other handler answers from something this module already holds: an
//! inline body, a template, a file, an upstream to relay to. `HANDLER_APP`
//! answers from something it cannot know — a downstream module decides what the
//! request means. Wave keeps HTTP framing, connection state, keep-alive and
//! bounded body handling; the application keeps method dispatch, authorization
//! and what a path denotes. That split is not invented here: it is what
//! `docs/specification.md` already says Wave does not own.
//!
//! **Modelled on `ws.rs`, deliberately.** WebSocket fan-out is the same shape —
//! envelopes out on one port, envelopes back on another, routed to the
//! connection they belong to — so two of its rules are reused verbatim:
//!
//! * *Backpressure by writeback.* If the target slot cannot accept a response
//!   yet, the envelope goes back on the input channel and is retried next tick,
//!   rather than being dropped or blocking the pump.
//! * *One mailbox write per envelope*, capped at the channel buffer, so a
//!   partial write can never present as a truncated request.
//!
//! And one detail is deliberately NOT reused: WS fan-out retains the last
//! envelope so a late subscriber sees current state. Replaying a previous
//! response to a new request would answer request N with response N-1, which is
//! the bug `HANDLER_WEBSOCKET_SESSION` exists to avoid. There is no retention
//! here.
//!
//! **Correlation is `(conn_id, stream_id)`, never `conn_id` alone.** Under h1 a
//! connection carries one request at a time and `stream_id` is 0. Under h2 it
//! carries many at once, and an application that answers them out of order —
//! which it is entitled to do — would have its responses delivered to the wrong
//! requests. The pair is what makes the port pair usable from h2 at all.

use super::super::wire::method;
use super::{cur_slot, cur_slot_mut, dev_millis, find_slot_by_conn_id, HttpState, MAX_PATH};

/// Fixed prefix of an `HttpRequest` envelope:
/// `[conn_id u16][stream_id u16][method u8][flags u8][path_len u16]
///  [hdr_len u16][body_len u16]`.
pub(crate) const REQ_HDR: usize = 12;

/// Fixed prefix of an `HttpResponse` envelope:
/// `[conn_id u16][stream_id u16][status u16][flags u8][ct_len u8]
///  [hdr_len u16][body_len u16]`.
pub(crate) const RESP_HDR: usize = 12;

/// `flags` bit 0 — more body follows in a subsequent envelope for the same
/// `(conn_id, stream_id)`. Reserved by this phase and honoured by the streaming
/// path; a single-envelope request/response leaves it clear.
pub(crate) const FLAG_MORE_BODY: u8 = 0x01;

/// Longest request header block forwarded to the application, in bytes.
///
/// The block is forwarded RAW rather than parsed: an application module needs
/// `Authorization`, `Content-Type`, `Range` and whatever else its API defines,
/// and a gateway that decided in advance which headers matter would have to be
/// edited every time an application learned a new one. Bounded because it is
/// copied into a fixed envelope buffer.
pub(crate) const MAX_FWD_HEADERS: usize = 2048;

/// How long a request may wait for its application response before the server
/// answers 504 itself, in milliseconds.
///
/// Without this, an application module that never replies holds a connection
/// slot forever, and enough such requests exhaust the slot table — a hung
/// downstream becomes a dead server rather than a degraded one. 30 s is longer
/// than any interactive request and shorter than every client's own timeout, so
/// the client sees a status rather than a silence.
pub(crate) const APP_TIMEOUT_MS: u64 = 30_000;

/// Serialise one `HttpRequest` envelope and write it to `req_out`.
///
/// Both generations funnel through here, so an application module cannot tell
/// which one carried a request — and should not be able to. They differ only in
/// where the parts come from: h1's live on the `ConnSlot`, h2's on the
/// `StreamSlot`, because an h2 connection carries many requests at once.
///
/// The slices must not alias the envelope buffer; in practice they point into
/// slot fields or the receive buffer.
pub(crate) unsafe fn write_request_envelope(
    s: &HttpState,
    conn_id: u16,
    stream_id: u16,
    verb: u8,
    path: &[u8],
    hdrs: &[u8],
    body: &[u8],
) -> EmitResult {
    let total = REQ_HDR + path.len() + hdrs.len() + body.len();
    if total > super::super::abi::CHANNEL_BUFFER_SIZE {
        return EmitResult::TooLarge;
    }

    let mut buf = [0u8; super::super::abi::CHANNEL_BUFFER_SIZE];
    buf[0..2].copy_from_slice(&conn_id.to_le_bytes());
    buf[2..4].copy_from_slice(&stream_id.to_le_bytes());
    buf[4] = verb;
    buf[5] = 0; // flags: whole body in this envelope
    buf[6..8].copy_from_slice(&(path.len() as u16).to_le_bytes());
    buf[8..10].copy_from_slice(&(hdrs.len() as u16).to_le_bytes());
    buf[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());

    let mut off = REQ_HDR;
    for part in [path, hdrs, body] {
        if !part.is_empty() {
            core::ptr::copy_nonoverlapping(part.as_ptr(), buf.as_mut_ptr().add(off), part.len());
            off += part.len();
        }
    }

    let sys = &*s.syscalls;
    if (sys.channel_write)(s.server.app_out_chan, buf.as_ptr(), off) <= 0 {
        return EmitResult::Full;
    }
    EmitResult::Sent
}

/// Emit the current h1 slot's request on `req_out` and start its timeout.
///
/// `head` is the request head as it still sits in `recv_buf`; the header block
/// is taken from it verbatim.
pub(crate) unsafe fn emit_request(s: &mut HttpState, head: &[u8]) -> EmitResult {
    if s.server.app_out_chan < 0 {
        return EmitResult::Unwired;
    }
    let (conn_id, verb, path, body) = match cur_slot(s) {
        Some(c) => (
            c.conn_id as u16,
            c.req_method,
            core::slice::from_raw_parts(
                c.req_path.as_ptr(),
                (c.req_path_len as usize).min(MAX_PATH),
            ),
            if c.body_buf.is_null() {
                &[][..]
            } else {
                core::slice::from_raw_parts(c.body_buf, c.body_len as usize)
            },
        ),
        None => return EmitResult::Unwired,
    };

    let hdr = header_block(head);
    let hdrs = &hdr[..hdr.len().min(MAX_FWD_HEADERS)];

    // `stream_id` is 0 under h1: a connection carries one request at a time, so
    // `conn_id` alone identifies it.
    let res = write_request_envelope(s, conn_id, 0, verb, path, hdrs, body);
    if res == EmitResult::Sent {
        // Latch the deadline as the request goes out, not when it was received:
        // the timeout measures how long the APPLICATION has had it.
        let now = dev_millis(&*s.syscalls);
        if let Some(cur) = cur_slot_mut(s) {
            cur.app_deadline_ms = now.saturating_add(APP_TIMEOUT_MS);
        }
    }
    res
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum EmitResult {
    Sent,
    /// `req_out` is not wired — the graph declares a HANDLER_APP route with
    /// nothing behind it.
    Unwired,
    /// The envelope exceeds the channel buffer. A configuration error
    /// (`max_body_kib` larger than the `req_out` ring), not a transient one.
    TooLarge,
    /// The ring is full right now; retry next tick.
    Full,
}

/// The raw header block of a request head: everything after the request line's
/// CRLF, up to the blank line that terminates the head.
fn header_block(head: &[u8]) -> &[u8] {
    let mut i = 0usize;
    while i + 1 < head.len() {
        if head[i] == b'\r' && head[i + 1] == b'\n' {
            break;
        }
        i += 1;
    }
    if i + 1 >= head.len() {
        return &[];
    }
    let start = i + 2;
    // The head ends with CRLFCRLF; drop the final CRLF so the block is just
    // the field lines.
    let end = head.len().saturating_sub(2);
    if end <= start {
        return &[];
    }
    &head[start..end]
}

/// A parsed `HttpResponse` envelope, as borrowed spans into the read buffer.
pub struct RespView<'a> {
    pub conn_id: u16,
    pub stream_id: u16,
    pub status: u16,
    pub flags: u8,
    pub content_type: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

/// Parse one `HttpResponse` envelope. Returns `None` if the buffer is too
/// short to hold what its own header claims — a malformed envelope is dropped
/// rather than read past.
pub fn parse_response(buf: &[u8]) -> Option<RespView<'_>> {
    if buf.len() < RESP_HDR {
        return None;
    }
    let conn_id = u16::from_le_bytes([buf[0], buf[1]]);
    let stream_id = u16::from_le_bytes([buf[2], buf[3]]);
    let status = u16::from_le_bytes([buf[4], buf[5]]);
    let flags = buf[6];
    let ct_len = buf[7] as usize;
    let hdr_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let body_len = u16::from_le_bytes([buf[10], buf[11]]) as usize;

    let need = RESP_HDR
        .checked_add(ct_len)?
        .checked_add(hdr_len)?
        .checked_add(body_len)?;
    if buf.len() < need {
        return None;
    }
    let ct_at = RESP_HDR;
    let hdr_at = ct_at + ct_len;
    let body_at = hdr_at + hdr_len;
    Some(RespView {
        conn_id,
        stream_id,
        status,
        flags,
        content_type: &buf[ct_at..hdr_at],
        headers: &buf[hdr_at..body_at],
        body: &buf[body_at..need],
    })
}

/// Find the slot awaiting the response identified by `(conn_id, stream_id)`.
///
/// Returns `None` when no slot is waiting — a response for a connection that
/// has since closed, or a duplicate. Dropping it is correct: there is nothing
/// left to answer.
pub(crate) unsafe fn find_awaiting_slot(
    s: &mut HttpState,
    conn_id: u16,
    stream_id: u16,
) -> Option<usize> {
    let idx = find_slot_by_conn_id(s, conn_id as u8)?;
    let slot = &*s.server.slots.as_ptr().add(idx);
    if slot.app_stream_id == stream_id && slot.app_pending != 0 {
        Some(idx)
    } else {
        None
    }
}

/// Whether the slot's application request has outlived `APP_TIMEOUT_MS`.
pub(crate) unsafe fn app_deadline_passed(s: &HttpState, idx: usize) -> bool {
    let slot = &*s.server.slots.as_ptr().add(idx);
    if slot.app_pending == 0 || slot.app_deadline_ms == 0 {
        return false;
    }
    // `dev_millis` is a u64 millisecond count, so a plain comparison is safe:
    // there is no wrap to defend against inside any plausible uptime.
    dev_millis(&*s.syscalls) >= slot.app_deadline_ms
}

/// Read one `HttpResponse` from `resp_in` and compose it onto the connection
/// that asked for it. Returns true if an envelope was consumed.
///
/// Driven once per `module_step` from the server pump rather than per slot: one
/// channel feeds every waiting connection, so a per-slot read would let
/// whichever slot happened to step first consume an envelope addressed to a
/// different one.
pub(crate) unsafe fn drain_responses(s: &mut HttpState) -> bool {
    if s.server.app_in_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let chan = s.server.app_in_chan;
    let poll = (sys.channel_poll)(chan, super::POLL_IN);
    if poll <= 0 || (poll as u32 & super::POLL_IN) == 0 {
        return false;
    }

    let mut buf = [0u8; super::super::abi::CHANNEL_BUFFER_SIZE];
    let n = (sys.channel_read)(
        chan,
        buf.as_mut_ptr(),
        super::super::abi::CHANNEL_BUFFER_SIZE,
    );
    if n < RESP_HDR as i32 {
        return false;
    }
    let read_len = n as usize;
    let (conn_id, stream_id, total) = match parse_response(&buf[..read_len]) {
        Some(v) => (
            v.conn_id,
            v.stream_id,
            RESP_HDR + v.content_type.len() + v.headers.len() + v.body.len(),
        ),
        // Malformed: the envelope claims more than it carries. Dropping it is
        // the only safe option — the slot it named will time out into a 504,
        // which is the honest outcome for an application speaking a broken
        // protocol.
        None => return false,
    };

    // An h2 stream on the named connection takes precedence: under h2 the
    // ConnSlot is the connection, not the request, and many requests share it.
    #[cfg(feature = "h2")]
    {
        if let Some(conn_idx) = find_slot_by_conn_id(s, conn_id as u8) {
            let has_h2 = !(*s.server.slots.as_ptr().add(conn_idx)).h2.is_null();
            if has_h2 {
                let saved = s.server.cur_slot;
                s.server.cur_slot = conn_idx as i32;
                let stream_idx = super::h2::find_app_stream(s, stream_id);
                if stream_idx >= 0 {
                    // `send_buf` is per-connection on h2 as well, so the same
                    // writeback backpressure applies.
                    let busy = {
                        let slot = &*s.server.slots.as_ptr().add(conn_idx);
                        slot.send_len > slot.send_offset
                    };
                    if busy {
                        s.server.cur_slot = saved;
                        let _ = (sys.channel_write)(chan, buf.as_ptr(), total);
                        return false;
                    }
                    let view = match parse_response(&buf[..total]) {
                        Some(v) => v,
                        None => {
                            s.server.cur_slot = saved;
                            return false;
                        }
                    };
                    let (status, ct, body, more) = (
                        view.status,
                        view.content_type,
                        view.body,
                        (view.flags & FLAG_MORE_BODY) != 0,
                    );
                    super::h2::deliver_app_response(s, stream_idx, status, ct, body, more);
                    s.server.cur_slot = saved;
                    return true;
                }
                s.server.cur_slot = saved;
            }
        }
    }

    let target = match find_awaiting_slot(s, conn_id, stream_id) {
        Some(i) => i,
        // No slot is waiting: the connection closed between the application's
        // write and this read, or the request already timed out. Nothing left
        // to answer.
        None => return false,
    };

    // The target's `send_buf` must be free before it is composed into. On
    // contention the envelope goes BACK on the channel and is retried next
    // tick — the same writeback the WS fan-out uses, and for the same reason:
    // the envelope has already left the mailbox, so dropping it here would
    // lose a response the application believes it delivered.
    let busy = {
        let slot = &*s.server.slots.as_ptr().add(target);
        slot.send_len > slot.send_offset
    };
    if busy {
        let _ = (sys.channel_write)(chan, buf.as_ptr(), total);
        return false;
    }

    let saved = s.server.cur_slot;
    s.server.cur_slot = target as i32;
    compose_response(s, &buf[..total]);
    s.server.cur_slot = saved;
    true
}

/// Compose a parsed `HttpResponse` into the current slot's `send_buf` and set
/// it running.
unsafe fn compose_response(s: &mut HttpState, envelope: &[u8]) {
    let view = match parse_response(envelope) {
        Some(v) => v,
        None => return,
    };

    // A continuation envelope: the head already went out, and this carries the
    // next slice of body. Recognised by the slot rather than by the envelope,
    // because only the slot knows whether a head was sent.
    if cur_slot(s).map(|c| c.app_streaming != 0).unwrap_or(false) {
        compose_stream_chunk(s, &view);
        return;
    }

    let verb = cur_slot(s).map(|c| c.req_method).unwrap_or(0);
    let allows_body = status_allows_body(view.status, verb);
    let body: &[u8] = if allows_body { view.body } else { &[] };

    let ct: &[u8] = if view.content_type.is_empty() {
        b"application/octet-stream"
    } else {
        view.content_type
    };

    // Streaming: `MORE_BODY` says this envelope is the first slice of a body
    // that will arrive across several. The length cannot come from this
    // envelope, so it comes from the application's own `Content-Length` header
    // if it declared one — and if it did not, the response is close-delimited
    // and the connection ends with the body.
    //
    // That is the honest pair of options. A gateway cannot invent a total it
    // has not been told, and a keep-alive connection whose response has no
    // determinable end is how the NEXT response gets misread.
    let streaming = (view.flags & FLAG_MORE_BODY) != 0 && allows_body;
    let declared_total = if streaming {
        declared_length(view.headers)
    } else {
        Some(view.body.len() as u32)
    };

    match declared_total {
        Some(total) => {
            super::response::build_app_header(s, view.status, ct, total, view.headers);
        }
        None => {
            if let Some(cur) = cur_slot_mut(s) {
                cur.keepalive = 0;
            }
            super::response::build_app_header_open_ended(s, view.status, ct, view.headers);
        }
    }

    let cap = super::SEND_BUF_SIZE;
    let off = cur_slot(s).map(|c| c.send_len as usize).unwrap_or(0);
    let room = cap.saturating_sub(off);
    let n = body.len().min(room);
    if n > 0 {
        let dst = super::cur_send_buf_mut_ptr(s).add(off);
        core::ptr::copy_nonoverlapping(body.as_ptr(), dst, n);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = (off + n) as u16;
        cur.send_offset = 0;
        cur.app_streaming = if streaming { 1 } else { 0 };
        // While streaming, the request stays PENDING: more envelopes are
        // expected for it, and clearing the flag would make the next chunk
        // look like a response to a request nobody sent.
        cur.app_pending = if streaming { 1 } else { 0 };
        cur.app_deadline_ms = if streaming { cur.app_deadline_ms } else { 0 };
        // A single-envelope body that did not fit `send_buf` cannot be
        // finished by a length-delimited response, so the connection closes
        // after it and the truncation is visible to the client as a short read
        // rather than as a corrupt next response. (An application with a body
        // this large should be streaming it.)
        if !streaming && n < body.len() {
            cur.keepalive = 0;
        }
        cur.phase = super::Phase::DrainSend;
    }
}

/// Append a continuation chunk of a streamed body to `send_buf`.
///
/// Only the body is read: status, content type and headers were settled by the
/// first envelope, and honouring them again mid-body would put a second
/// response head inside the first response.
unsafe fn compose_stream_chunk(s: &mut HttpState, view: &RespView<'_>) {
    let cap = super::SEND_BUF_SIZE;
    let n = view.body.len().min(cap);
    if n > 0 {
        core::ptr::copy_nonoverlapping(view.body.as_ptr(), super::cur_send_buf_mut_ptr(s), n);
    }
    let last = (view.flags & FLAG_MORE_BODY) == 0;
    let now = dev_millis(&*s.syscalls);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
        cur.send_offset = 0;
        if last {
            cur.app_streaming = 0;
            cur.app_pending = 0;
            cur.app_deadline_ms = 0;
        } else {
            // The deadline measures time since the last PROGRESS, not since
            // the request. Without the refresh, any transfer longer than
            // `APP_TIMEOUT_MS` is cut off mid-body no matter how steadily the
            // application is feeding it — which is every large artefact.
            cur.app_deadline_ms = now.saturating_add(APP_TIMEOUT_MS);
        }
        cur.phase = super::Phase::DrainSend;
    }
}

/// The `Content-Length` an application declared in its own header block, if
/// any. Used only to frame a streamed response — for a single-envelope
/// response the real body length is known and is always preferred.
fn declared_length(headers: &[u8]) -> Option<u32> {
    let mut line_start = 0usize;
    let mut i = 0usize;
    while i < headers.len() {
        if i + 1 < headers.len() && headers[i] == b'\r' && headers[i + 1] == b'\n' {
            if let Some(v) = content_length_of(&headers[line_start..i]) {
                return Some(v);
            }
            i += 2;
            line_start = i;
            continue;
        }
        i += 1;
    }
    if line_start < headers.len() {
        return content_length_of(&headers[line_start..]);
    }
    None
}

fn content_length_of(line: &[u8]) -> Option<u32> {
    let colon = line.iter().position(|c| *c == b':')?;
    if !line[..colon].eq_ignore_ascii_case(b"content-length") {
        return None;
    }
    let mut v: u32 = 0;
    let mut digits = 0usize;
    for c in &line[colon + 1..] {
        if *c == b' ' || *c == b'\t' {
            if digits == 0 {
                continue;
            }
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((*c - b'0') as u32)?;
        digits += 1;
    }
    if digits == 0 {
        None
    } else {
        Some(v)
    }
}

/// Whether an h2 stream id fits the 16 bits the envelope carries.
///
/// h2 stream ids are u32 and strictly increasing, so a connection that serves
/// enough requests eventually passes 65535. Truncating there would alias a new
/// stream onto a live one's correlation key and deliver its response to the
/// wrong request — silently, since both are valid HTTP. Refusing the dispatch
/// instead costs one 503 on a connection that has already served 32k requests,
/// and the client simply reconnects.
pub fn stream_id_fits(stream_id: u32) -> bool {
    stream_id <= u16::MAX as u32
}

/// Whether a status code is allowed to carry a body at all (RFC 9110 §6.4.1).
/// 204 and 304 have no body by definition, and emitting one desynchronises the
/// connection exactly as a HEAD body would.
pub fn status_allows_body(status: u16, verb: u8) -> bool {
    if !method::method_sends_response_body(verb) {
        return false;
    }
    !matches!(status, 204 | 304) && !(100..200).contains(&status)
}
