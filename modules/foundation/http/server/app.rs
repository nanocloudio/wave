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
//! **Correlation is `(conn_id, stream_id)`, never `conn_id` alone.** Under h2 a
//! connection carries many requests at once, and an application that answers
//! them out of order — which it is entitled to do — would have its responses
//! delivered to the wrong requests.
//!
//! Under h1 a connection carries one request at a time, so `stream_id` is not
//! separating concurrent requests; it is a REQUEST GENERATION, and it is
//! load-bearing for a different reason. Connection ids are recycled by the
//! transport, so a connection released with a request still outstanding is
//! followed by a new peer holding the same id and also awaiting an answer.
//! Pinning `stream_id` to 0 made those two indistinguishable, and the late
//! answer was served to the new peer: a valid, well-framed, entirely wrong
//! reply. See `ServerState::app_gen_next`.
//!
//! Either way the rule for an application is the same and was always the same:
//! **echo `stream_id` back**. An application that hardcodes 0 was already
//! broken under h2.

use super::super::wire::method;
use super::{
    cur_slot, cur_slot_mut, dev_millis, find_slot_by_conn_id, heap_alloc, heap_free, HttpState,
    MAX_PATH,
};

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
/// Request flag: a PEER IDENTITY trailer follows the body.
///
/// `[svid_len:u16 LE][svid]`, appended after `body`, present only when the
/// connection completed an mTLS handshake that actually verified the peer.
///
/// A trailer behind a flag rather than a field in the fixed head, because the
/// three section lengths are the envelope's ABI: every consumer reads path,
/// headers and body by them. A consumer that does not know this bit reads
/// exactly what it did before and never looks past `body_len`.
///
/// And a trailer rather than a synthetic header such as
/// `X-Forwarded-Client-Cert`: a header is forgeable by the client unless the
/// server strips every copy of it first, and one missed strip promotes an
/// anonymous caller to whoever it claims to be. A typed trailer sits in a
/// structure the client cannot reach at all.
pub(crate) const FLAG_PEER_IDENTITY: u8 = 0x02;
/// Request flag: the BODY is a reference, `sha256:<hex>` — the body itself
/// was staged in the store at `body_ref_prefix` + `sha256/<hex>` because it
/// was larger than `body_inline_max` (an envelope is one channel record).
pub(crate) const FLAG_BODY_REF: u8 = 0x04;

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

/// Response flag: the application HOLDS this stream open on purpose — a watch,
/// an event stream — and ends it itself. Between events such a stream is idle
/// for as long as the application has nothing to say, so its progress deadline
/// is `HOLD_TIMEOUT_MS`, not `APP_TIMEOUT_MS`. Meaningful with
/// `FLAG_MORE_BODY`; ignored without it. Request and response flags are two
/// vocabularies over the same byte, so this shares a value with
/// [`FLAG_BODY_REF`]: an envelope is one or the other, never both.
pub(crate) const FLAG_HOLD: u8 = 0x04;

/// A held stream's progress deadline: longer than any server-side watch
/// timeout an application sets (Kubernetes caps one at 30 min, then doubles it
/// at random), and still finite — an application that holds a stream and never
/// ends it cannot keep its slot forever.
pub(crate) const HOLD_TIMEOUT_MS: u64 = 3_600_000;

/// The progress deadline a streamed response runs under, from its flags.
pub(crate) fn progress_timeout_ms(flags: u8) -> u64 {
    if flags & FLAG_HOLD != 0 {
        HOLD_TIMEOUT_MS
    } else {
        APP_TIMEOUT_MS
    }
}

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
    // The peer identity belongs to the CONNECTION, not the request, so it is
    // looked up here rather than threaded through callers: h1 and h2 reach this
    // function by different paths and both must carry it.
    let peer = super::peer_svid(s, conn_id);
    let peer_len = peer.map_or(0, |p| 2 + p.len());
    // A body past the inline bound goes by reference.
    let mut refbuf = [0u8; 7 + 64];
    let staged = s.server.body_ref_prefix_len > 0 && body.len() > s.server.body_inline_max as usize;
    let body: &[u8] = if staged {
        match stage_body(s, body, &mut refbuf) {
            Staged::Done => &refbuf[..],
            // Taken and not yet decided. The caller holds the request where it
            // is and emits again, which re-derives the same key from the same
            // body \u2014 the byte-identical repeat the contract asks for.
            Staged::Pending => return EmitResult::Full,
            Staged::Failed => return EmitResult::StageFailed,
        }
    } else {
        body
    };
    let total = REQ_HDR + path.len() + hdrs.len() + body.len() + peer_len;
    if total > super::super::abi::CHANNEL_BUFFER_SIZE {
        return EmitResult::TooLarge;
    }

    let mut buf = [0u8; super::super::abi::CHANNEL_BUFFER_SIZE];
    buf[0..2].copy_from_slice(&conn_id.to_le_bytes());
    buf[2..4].copy_from_slice(&stream_id.to_le_bytes());
    buf[4] = verb;
    buf[5] = if peer.is_some() {
        FLAG_PEER_IDENTITY
    } else {
        0
    } | if staged { FLAG_BODY_REF } else { 0 }; // whole body (or its reference) here
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
    // The trailer goes AFTER the body, past every length in the fixed head, so
    // it is invisible to a reader that does not know the flag.
    if let Some(svid) = peer {
        buf[off..off + 2].copy_from_slice(&(svid.len() as u16).to_le_bytes());
        off += 2;
        core::ptr::copy_nonoverlapping(svid.as_ptr(), buf.as_mut_ptr().add(off), svid.len());
        off += svid.len();
    }

    let sys = &*s.syscalls;
    if (sys.channel_write)(s.server.app_out_chan, buf.as_ptr(), off) <= 0 {
        return EmitResult::Full;
    }
    EmitResult::Sent
}

/// How long a staged body stays before it is collected (its expiry key).
const STAGED_TTL_MS: u64 = 300_000;

/// What staging a body came to.
enum Staged {
    /// In the store, and `out` names it.
    Done,
    /// The store took a write and has not decided it. Nothing is lost by
    /// asking again with the same arguments; nothing may be concluded yet.
    Pending,
    /// The store refused, or there is no store.
    Failed,
}

/// Stage `body` in the store as `<prefix>sha256/<hex>` (content-addressed:
/// the same body is the same key) with its expiry at `<prefix>at/<hex>`,
/// and write `sha256:<hex>` into `out`.
///
/// Both writes are idempotent in the key they choose, so a repeat after
/// `Pending` cannot stage a second copy or a different one.
unsafe fn stage_body(s: &HttpState, body: &[u8], out: &mut [u8; 71]) -> Staged {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = super::super::body_digest::sha256(body);
    let mut hex = [0u8; 64];
    for (i, b) in digest.iter().enumerate() {
        hex[2 * i] = HEX[(b >> 4) as usize];
        hex[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    let pfx = &s.server.body_ref_prefix[..s.server.body_ref_prefix_len as usize];
    let sys = &*s.syscalls;
    let mut key = [0u8; 48 + 8 + 64];
    let kl = cat3(&mut key, pfx, b"sha256/", &hex);
    match obj_put(sys, &key[..kl], body) {
        Staged::Done => {}
        other => return other,
    }
    // The expiry: a store `ttl` chain collects the body after it, whether or
    // not a request ever consumed it.
    let mut digits = [0u8; 20];
    let dl = dec_u64(dev_millis(sys).saturating_add(STAGED_TTL_MS), &mut digits);
    let mut val = [0u8; 40];
    let vl = cat3(&mut val, b"{\"deadline\":", &digits[..dl], b"}");
    let kl = cat3(&mut key, pfx, b"at/", &hex);
    match obj_put(sys, &key[..kl], &val[..vl]) {
        Staged::Done => {}
        other => return other,
    }
    out[..7].copy_from_slice(b"sha256:");
    out[7..].copy_from_slice(&hex);
    Staged::Done
}

/// `v` in decimal into `out`; its length.
fn dec_u64(mut v: u64, out: &mut [u8; 20]) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 || n == 20 {
            break;
        }
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

/// `a ++ b ++ c` into `dst`: its length (short of `dst`, it stops there).
fn cat3(dst: &mut [u8], a: &[u8], b: &[u8], c: &[u8]) -> usize {
    let mut n = 0usize;
    for part in [a, b, c] {
        for &x in part {
            if let Some(d) = dst.get_mut(n) {
                *d = x;
                n += 1;
            }
        }
    }
    n
}

/// storage.object PUT (unconditional), value by pointer.
///
/// A write may be TAKEN rather than decided, so the return code is classified
/// by the contract's own `write_answer` rather than compared with zero: an
/// `EINPROGRESS` read as a refusal would fail a request whose body is on its
/// way into the store.
unsafe fn obj_put(sys: &super::super::abi::SyscallTable, key: &[u8], value: &[u8]) -> Staged {
    use super::super::abi::contracts::storage::object;
    let mut arg = [0u8; 256];
    if key.len() + 32 > arg.len() {
        return Staged::Failed;
    }
    let mut fence = [0u8; 62];
    let mut p = 0usize;
    arg[p..p + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    arg[p] = 0; // content_type_len
    p += 1;
    arg[p..p + 8].copy_from_slice(&(value.as_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 8].copy_from_slice(&(value.len() as u64).to_le_bytes());
    p += 8;
    arg[p] = 0; // precondition: any
    arg[p + 1] = 0; // no etag
    p += 2;
    arg[p..p + 8].copy_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 2].copy_from_slice(&62u16.to_le_bytes());
    p += 2;
    match object::write_answer((sys.provider_call)(-1, object::PUT, arg.as_mut_ptr(), p)) {
        object::WriteAnswer::Decided(0) => Staged::Done,
        object::WriteAnswer::Decided(_) => Staged::Failed,
        object::WriteAnswer::Pending => Staged::Pending,
    }
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

    // Under h1 a connection carries one request at a time, so `stream_id` does
    // not have to distinguish concurrent requests — but it does have to
    // distinguish this request from one asked by a PREVIOUS holder of the same
    // connection id, whose answer may still be in flight. See
    // `ServerState::app_gen_next`.
    let gen = s.server.app_gen_next;
    s.server.app_gen_next = gen.wrapping_add(1);
    let res = write_request_envelope(s, conn_id, gen, verb, path, hdrs, body);
    if res == EmitResult::Sent {
        // Latch the deadline as the request goes out, not when it was received:
        // the timeout measures how long the APPLICATION has had it.
        let now = dev_millis(&*s.syscalls);
        if let Some(cur) = cur_slot_mut(s) {
            cur.app_deadline_ms = now.saturating_add(APP_TIMEOUT_MS);
            cur.app_stream_id = gen;
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
    /// A body past `body_inline_max` could not be staged in the store (no
    /// store, or the write refused): the request cannot be forwarded whole.
    StageFailed,
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
    let idx = find_slot_by_conn_id(s, conn_id)?;
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

/// The most one connection may have held for it while it is slow to read:
/// past this the peer is not reading at the rate it is being answered, and the
/// connection closes (counted with `conns_timeout_stall` — a peer that stopped
/// reading). Host builds that forward to an application hold two 1 MiB
/// objects' worth of watch events — what a client busy with its own large
/// write lets pile up; everywhere else, a couple of envelopes.
#[cfg(all(feature = "app", target_arch = "aarch64"))]
pub(crate) const STASH_MAX: u32 = 4 << 20;
#[cfg(not(all(feature = "app", target_arch = "aarch64")))]
pub(crate) const STASH_MAX: u32 = 2 * super::super::abi::CHANNEL_BUFFER_SIZE as u32 + 8;

/// Read one `HttpResponse` from `resp_in` and compose it onto the connection
/// that asked for it. Returns true if an envelope was consumed.
///
/// Driven once per `module_step` from the server pump rather than per slot: one
/// channel feeds every waiting connection, so a per-slot read would let
/// whichever slot happened to step first consume an envelope addressed to a
/// different one.
///
/// An envelope for a connection that cannot take it yet (its `send_buf` still
/// draining) is held FOR THAT CONNECTION, in order, and delivered as it frees
/// (`pump_stashes`, first thing here). Never written back onto `resp_in`: that
/// reordered a streamed body's chunks, and a peer that stopped reading kept its
/// envelopes circling the one channel every other connection is answered
/// through until a writeback was refused and somebody's response was lost.
pub(crate) unsafe fn drain_responses(s: &mut HttpState) -> bool {
    if s.server.app_in_chan < 0 {
        return false;
    }
    pump_stashes(s);
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
        // The envelope claims more than this read carries. Two causes, and
        // they are counted the same because the consequence is identical: an
        // application speaking a broken protocol, or — far more likely — an
        // envelope larger than one channel read, on a port whose declared
        // record size exceeds the reader's. Dropping is the only safe option
        // once the read has consumed it, but dropping SILENTLY is not: the
        // request would wait out the full application timeout and surface as
        // a 504, pointing the investigation at the application rather than at
        // the port sizing that actually caused it.
        None => {
            s.server.app_envelopes_oversize = s.server.app_envelopes_oversize.wrapping_add(1);
            return false;
        }
    };
    let envelope = &buf[..total];

    let target = match app_target(s, conn_id, stream_id) {
        Some(i) => i,
        // No slot is waiting: the connection closed between the application's
        // write and this read, or the request already timed out. Nothing left
        // to answer.
        None => return false,
    };
    // Behind what is already held, never ahead of it: the held envelopes are
    // earlier parts of the same answers.
    let held = (*s.server.slots.as_ptr().add(target)).app_stash_len != 0;
    if !held && deliver(s, target, envelope) != Delivery::Busy {
        return true;
    }
    if !stash_push(s, target, envelope) {
        too_slow(s, target);
    }
    true
}

/// The slot an envelope answers: an h2 connection by its id (the stream is
/// found at delivery), an h1 one only while its request is pending.
unsafe fn app_target(s: &mut HttpState, conn_id: u16, stream_id: u16) -> Option<usize> {
    #[cfg(feature = "h2")]
    {
        if let Some(i) = find_slot_by_conn_id(s, conn_id) {
            if !(*s.server.slots.as_ptr().add(i)).h2.is_null() {
                return Some(i);
            }
        }
    }
    find_awaiting_slot(s, conn_id, stream_id)
}

#[derive(Clone, Copy, PartialEq)]
enum Delivery {
    /// Composed onto the connection.
    Done,
    /// Its `send_buf` is still draining: hold the envelope.
    Busy,
    /// Nothing waits for it any more (the stream or request is gone).
    Gone,
}

/// Compose `envelope` onto slot `idx` if its `send_buf` is free.
unsafe fn deliver(s: &mut HttpState, idx: usize, envelope: &[u8]) -> Delivery {
    let busy = {
        let slot = &*s.server.slots.as_ptr().add(idx);
        slot.send_len > slot.send_offset
    };
    // An h2 stream on the named connection takes precedence: under h2 the
    // ConnSlot is the connection, not the request, and many requests share it.
    #[cfg(feature = "h2")]
    {
        if !(*s.server.slots.as_ptr().add(idx)).h2.is_null() {
            let view = match parse_response(envelope) {
                Some(v) => v,
                None => return Delivery::Gone,
            };
            let saved = s.server.cur_slot;
            s.server.cur_slot = idx as i32;
            let stream_idx = super::h2::find_app_stream(s, view.stream_id);
            let out = if stream_idx < 0 {
                Delivery::Gone
            } else if busy {
                // `send_buf` is per-connection on h2 as well.
                Delivery::Busy
            } else {
                let more = (view.flags & FLAG_MORE_BODY) != 0;
                let timeout = progress_timeout_ms(view.flags);
                super::h2::deliver_app_response(
                    s,
                    stream_idx,
                    view.status,
                    view.content_type,
                    view.body,
                    more,
                    timeout,
                );
                Delivery::Done
            };
            s.server.cur_slot = saved;
            return out;
        }
    }
    if busy {
        return Delivery::Busy;
    }
    let slot = &*s.server.slots.as_ptr().add(idx);
    if slot.app_pending == 0 {
        return Delivery::Gone;
    }
    let saved = s.server.cur_slot;
    s.server.cur_slot = idx as i32;
    compose_response(s, envelope);
    s.server.cur_slot = saved;
    Delivery::Done
}

/// Hold `envelope` behind whatever slot `idx` already holds. False when the
/// stash would pass `STASH_MAX` or the arena cannot grow it.
unsafe fn stash_push(s: &mut HttpState, idx: usize, envelope: &[u8]) -> bool {
    let sys = &*s.syscalls;
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    let need = 4 + envelope.len() as u32;
    // Reclaim what was delivered before growing.
    if slot.app_stash_at != 0 && slot.app_stash_at + slot.app_stash_len + need > slot.app_stash_cap
    {
        core::ptr::copy(
            slot.app_stash.add(slot.app_stash_at as usize),
            slot.app_stash,
            slot.app_stash_len as usize,
        );
        slot.app_stash_at = 0;
    }
    let want = slot.app_stash_at + slot.app_stash_len + need;
    if want > STASH_MAX {
        return false;
    }
    if want > slot.app_stash_cap {
        let mut cap = if slot.app_stash_cap == 0 {
            super::super::abi::CHANNEL_BUFFER_SIZE as u32 + 8
        } else {
            slot.app_stash_cap
        };
        while cap < want {
            cap = cap.saturating_mul(2);
        }
        let cap = cap.min(STASH_MAX);
        let fresh = heap_alloc(sys, cap);
        if fresh.is_null() {
            return false;
        }
        if !slot.app_stash.is_null() {
            core::ptr::copy_nonoverlapping(
                slot.app_stash.add(slot.app_stash_at as usize),
                fresh,
                slot.app_stash_len as usize,
            );
            heap_free(sys, slot.app_stash);
        }
        slot.app_stash = fresh;
        slot.app_stash_cap = cap;
        slot.app_stash_at = 0;
    }
    let at = slot
        .app_stash
        .add((slot.app_stash_at + slot.app_stash_len) as usize);
    core::ptr::copy_nonoverlapping((envelope.len() as u32).to_le_bytes().as_ptr(), at, 4);
    core::ptr::copy_nonoverlapping(envelope.as_ptr(), at.add(4), envelope.len());
    slot.app_stash_len += need;
    true
}

/// Deliver what each connection holds, in order, as far as its `send_buf`
/// allows. A drained stash is freed: a connection is slow for a moment far
/// more often than for its whole life.
unsafe fn pump_stashes(s: &mut HttpState) {
    for idx in 0..super::MAX_CONCURRENT_CONNS {
        loop {
            let (p, len) = {
                let slot = &*s.server.slots.as_ptr().add(idx);
                if slot.app_stash_len == 0 {
                    break;
                }
                (
                    slot.app_stash.add(slot.app_stash_at as usize),
                    slot.app_stash_len,
                )
            };
            let mut lb = [0u8; 4];
            core::ptr::copy_nonoverlapping(p, lb.as_mut_ptr(), 4);
            let el = u32::from_le_bytes(lb);
            if 4 + el > len {
                // Cannot happen (`stash_push` writes both); fail closed.
                too_slow(s, idx);
                break;
            }
            let envelope = core::slice::from_raw_parts(p.add(4), el as usize);
            if deliver(s, idx, envelope) == Delivery::Busy {
                break;
            }
            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
            slot.app_stash_at += 4 + el;
            slot.app_stash_len -= 4 + el;
            if slot.app_stash_len == 0 {
                heap_free(&*s.syscalls, slot.app_stash);
                slot.app_stash = core::ptr::null_mut();
                slot.app_stash_cap = 0;
                slot.app_stash_at = 0;
            }
        }
    }
}

/// Slot `idx`'s peer is not reading as fast as it is answered: what it holds
/// is dropped and the connection closes — a short read the client can see and
/// retry (a watch re-lists), never a gap in the middle of a body.
unsafe fn too_slow(s: &mut HttpState, idx: usize) {
    s.server.conns_timeout_stall = s.server.conns_timeout_stall.wrapping_add(1);
    let sys = &*s.syscalls;
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    if !slot.app_stash.is_null() {
        heap_free(sys, slot.app_stash);
        slot.app_stash = core::ptr::null_mut();
    }
    slot.app_stash_cap = 0;
    slot.app_stash_len = 0;
    slot.app_stash_at = 0;
    slot.app_pending = 0;
    slot.app_streaming = 0;
    slot.keepalive = 0;
    slot.phase = super::Phase::CloseConn;
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
    let now = dev_millis(&*s.syscalls);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = (off + n) as u16;
        cur.send_offset = 0;
        cur.app_streaming = if streaming { 1 } else { 0 };
        // While streaming, the request stays PENDING: more envelopes are
        // expected for it, and clearing the flag would make the next chunk
        // look like a response to a request nobody sent.
        cur.app_pending = if streaming { 1 } else { 0 };
        // Streaming is progress: the deadline restarts, and a HELD stream
        // (`FLAG_HOLD`) runs under the long one from its first envelope.
        cur.app_deadline_ms = if streaming {
            now.saturating_add(progress_timeout_ms(view.flags))
        } else {
            0
        };
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
    // A chunk larger than `send_buf` cannot be delivered whole, and the bytes
    // past `n` are gone. Silently keeping the connection alive after that is
    // the worst available outcome: the declared `Content-Length` can never be
    // satisfied, so the client either hangs waiting for a body that has
    // stopped coming or — on keep-alive — reads the NEXT response as the
    // remainder of this one. Closing makes the loss a short read, which is
    // detectable, and matches what the single-envelope path above already does
    // when a body overruns the buffer.
    let truncated = view.body.len() > n;
    if truncated {
        s.server.app_envelopes_oversize = s.server.app_envelopes_oversize.wrapping_add(1);
    }
    let last = (view.flags & FLAG_MORE_BODY) == 0 || truncated;
    let now = dev_millis(&*s.syscalls);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
        cur.send_offset = 0;
        if truncated {
            cur.keepalive = 0;
        }
        if last {
            cur.app_streaming = 0;
            cur.app_pending = 0;
            cur.app_deadline_ms = 0;
        } else {
            // The deadline measures time since the last PROGRESS, not since
            // the request. Without the refresh, any transfer longer than
            // `APP_TIMEOUT_MS` is cut off mid-body no matter how steadily the
            // application is feeding it — which is every large artefact.
            cur.app_deadline_ms = now.saturating_add(progress_timeout_ms(view.flags));
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
