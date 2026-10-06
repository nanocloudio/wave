//! HTTP application fan-out — handing a request to a graph node and serving
//! what it answers, both directions streamed.
//!
//! Every other handler answers from something this module already holds: an
//! inline body, a template, a file, an upstream to relay to. `HANDLER_APP`
//! answers from something it cannot know — a downstream module decides what the
//! request means. This module keeps HTTP framing, connection state, keep-alive
//! and bounded bodies; the application keeps method dispatch, authorisation and
//! what a path denotes.
//!
//! The records are the SDK's exchange contract (`abi::contracts::exchange`), in
//! which this server is the requester. One exchange is one request and its
//! response; every connection on every generation shares the one
//! `request_out` / `response_in` pair, and every record names its exchange. This file
//! owns what all three generations share: the per-exchange state and credit,
//! the queue that holds an application's records until its connection can take
//! them, the abort queue, and the one reader of `response_in`. It also drives the
//! HTTP/1.1 exchange, which lives on the `ConnSlot`; HTTP/2 and HTTP/3 drive
//! theirs from their own stream tables through the same pieces.
//!
//! **Credit, not channel backpressure.** One channel carries every exchange,
//! so holding one body back by leaving the channel unread would hold back all
//! of them. Each direction therefore runs on credit: this module forwards
//! request-body bytes only as the application grants them, and grants
//! response-body credit only as bytes leave for the peer. An exchange whose
//! peer or application is slow stops on its own credit and nothing else does.
//! When the application grants none, `recv_buf` fills, the demux stops reading
//! the connection, and the transport's window closes — the backpressure reaches
//! the client.
//!
//! **Correlation is the record's id, never the connection alone.** Under h2 a
//! connection carries many requests at once and an application may answer
//! them in any order. Under h1 the id's stream is a request generation:
//! connection ids are recycled by the transport, and a late answer to a
//! connection's previous holder must not reach the next one.
//!
//! **A body that is already here travels in the HEAD.** When the whole request
//! body has arrived and fits one record, it rides inline in the request HEAD
//! with no MORE, and the application needs grant nothing. Only a client that
//! asked for `100 Continue`, or a body longer than one record, waits on the
//! application's credit.

use super::super::exchange::{
    abort as abort_reason, flag, header, link, parse_response, seal_body, write_abort,
    write_credit, write_request_head, ExchangeId, Record, RequestHead, BODY_MAX, HDR, RECORD_MAX,
    REQ_HEAD_FIXED,
};
use super::super::wire::method;
use super::{
    cur_slot, cur_slot_mut, find_slot_by_conn_id, heap_alloc, heap_free, HttpState,
    MAX_CONCURRENT_CONNS, SEND_BUF_SIZE,
};

/// Longest request header block forwarded, in bytes. A request whose header
/// block is longer is refused with 431, never forwarded with fields missing:
/// an application cannot tell a header that was dropped from one that was
/// never sent, and an `Authorization` that vanished is a different request.
pub(crate) const MAX_FWD_HEADERS: usize = 4096;

/// Longest request target (path and query) forwarded, in bytes. A request
/// target past it is refused with 414. A presigned object URL carries its
/// signature in the query, which is what this is sized for.
pub(crate) const MAX_TARGET: usize = 2048;

/// How long an application may go without progress on an exchange — a
/// response record, or credit for more of the request — before the server
/// answers for it, in milliseconds.
///
/// Measured from the last progress rather than from the request, so a long
/// upload the application keeps crediting is never cut off. Without it, an
/// application that never replies holds a slot forever, and enough such
/// requests exhaust the table — a hung downstream becomes a dead server
/// rather than a degraded one.
pub(crate) const APP_TIMEOUT_MS: u64 = 30_000;

/// A held stream's progress deadline: longer than any server-side watch
/// timeout an application sets (Kubernetes caps one at 30 min, then doubles it
/// at random), and still finite — an application that holds a stream and never
/// ends it cannot keep its slot forever.
pub(crate) const HOLD_TIMEOUT_MS: u64 = 3_600_000;

/// Response-body credit an exchange starts with, and the most of an
/// application's answer this module holds for one exchange. Four records on
/// hosts, so an application can run ahead of the peer by a few round trips;
/// one record on embedded targets.
#[cfg(target_arch = "aarch64")]
pub(crate) const RESP_WINDOW: u32 = 4 * BODY_MAX as u32;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const RESP_WINDOW: u32 = BODY_MAX as u32;

/// Most bytes one exchange's record queue holds: its credit window, plus the
/// head record and one record of slack for the prefixes the window does not
/// count. An application inside its credit never reaches it.
pub(crate) const QUEUE_LIMIT: u32 = RESP_WINDOW + 2 * (RECORD_MAX as u32 + 4);

/// Response credit is granted back once this much has left for the peer, or
/// when the exchange's queue runs empty, whichever comes first — one CREDIT
/// record per record's worth of body rather than one per frame.
const GRANT_MIN: u32 = BODY_MAX as u32;

/// Request-body records one h1 connection forwards per step.
const FORWARDS_PER_STEP: usize = 4;

/// Records read from `response_in` per step: enough that one busy exchange does
/// not starve the rest, few enough that a step stays bounded.
const RECORDS_PER_STEP: usize = 16;

#[cfg(feature = "h2")]
const H2_EXCHANGES: usize = MAX_CONCURRENT_CONNS * super::h2::MAX_STREAMS;
#[cfg(not(feature = "h2"))]
const H2_EXCHANGES: usize = 0;
#[cfg(feature = "h3")]
const H3_EXCHANGES: usize = super::h3::MAX_H3_STREAMS;
#[cfg(not(feature = "h3"))]
const H3_EXCHANGES: usize = 0;

/// Most exchanges open at once: one per h1 connection, `MAX_STREAMS` per h2
/// connection, and the h3 stream table.
pub(crate) const MAX_EXCHANGES: usize = MAX_CONCURRENT_CONNS + H2_EXCHANGES + H3_EXCHANGES;

/// Aborts waiting for room on `request_out`. No HEAD is sent while one waits, so
/// every waiting abort belongs to an exchange that was open when it was
/// queued, and the queue can never hold more than `MAX_EXCHANGES`.
pub(crate) const ABORT_QUEUE: usize = MAX_EXCHANGES;

/// Which transport an exchange arrived on. Part of the id: a TCP connection
/// and a QUIC session may hold the same number.
pub(crate) mod app_origin {
    pub(crate) const TCP: u8 = 1;
    pub(crate) const QUIC: u8 = 2;
}

/// What this server packs into an exchange id: the transport, the connection
/// (or QUIC session) and the stream (an h1 request generation, an h2 stream
/// id, an h3 stream handle). The layout is this module's own — the contract
/// makes the id opaque to the application, which only echoes it — and fills
/// all 14 bytes: `[origin u8][0 u8][conn u32][stream u64]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AppId {
    pub(crate) origin: u8,
    pub(crate) conn: u32,
    pub(crate) stream: u64,
}

impl AppId {
    /// The 14 bytes this id travels as.
    pub(crate) fn exchange_id(&self) -> ExchangeId {
        let mut b = [0u8; 14];
        b[0] = self.origin;
        b[2..6].copy_from_slice(&self.conn.to_le_bytes());
        b[6..14].copy_from_slice(&self.stream.to_le_bytes());
        ExchangeId(b)
    }

    /// The id an application echoed, when it is one this server could have
    /// minted.
    pub(crate) fn from_exchange_id(id: &ExchangeId) -> Option<Self> {
        let b = &id.0;
        if b[1] != 0 {
            return None;
        }
        Some(Self {
            origin: b[0],
            conn: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
            stream: u64::from_le_bytes([b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13]]),
        })
    }
}

/// Exchange state bits.
pub(crate) mod ex {
    /// The HEAD went out: the application knows this exchange.
    pub(crate) const OPEN: u8 = 0x01;
    /// The request direction has ended.
    pub(crate) const REQ_DONE: u8 = 0x02;
    /// The application's response HEAD has arrived.
    pub(crate) const RESP_HEAD: u8 = 0x04;
    /// The application's response has ended.
    pub(crate) const RESP_DONE: u8 = 0x08;
    /// The application has granted request-body credit at least once.
    pub(crate) const CREDITED: u8 = 0x10;
    /// The client asked for `100 Continue` and has not been sent it.
    pub(crate) const CONTINUE: u8 = 0x20;
}

/// One exchange's state, held by whichever table owns its request: a
/// `ConnSlot` (h1), an h2 stream, an h3 stream.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Exchange {
    /// The id's stream half: an h1 request generation, an h2 stream id, an
    /// h3 stream handle.
    pub(crate) stream: u64,
    /// `dev_millis` past which the application has failed to make progress;
    /// 0 when the application does not hold the turn.
    pub(crate) deadline_ms: u64,
    /// Request-body bytes the application has granted and not yet received.
    pub(crate) req_credit: u32,
    /// Response-body bytes the application may still send.
    pub(crate) resp_credit: u32,
    /// Response-body bytes that have left for the peer and not yet been
    /// granted back.
    pub(crate) resp_owed: u32,
    pub(crate) state: u8,
    /// The response HEAD's flags (`HOLD`, `WEBSOCKET`, …).
    pub(crate) resp_flags: u8,
    pub(crate) _pad: [u8; 2],
}

impl Exchange {
    pub(crate) const fn idle() -> Self {
        Self {
            stream: 0,
            deadline_ms: 0,
            req_credit: 0,
            resp_credit: 0,
            resp_owed: 0,
            state: 0,
            resp_flags: 0,
            _pad: [0; 2],
        }
    }

    pub(crate) fn is(&self, bits: u8) -> bool {
        self.state & bits == bits
    }

    pub(crate) fn open(&self) -> bool {
        self.is(ex::OPEN)
    }

    /// Both directions have ended.
    pub(crate) fn finished(&self) -> bool {
        self.is(ex::REQ_DONE | ex::RESP_DONE)
    }
}

/// An application's records for one exchange, held until its connection can
/// take them, in order. A front record can be taken in parts: its head first,
/// then its body as room allows.
#[repr(C)]
pub(crate) struct RecordQueue {
    buf: *mut u8,
    cap: u32,
    /// Offset of the front record's length prefix.
    at: u32,
    /// Bytes held from `at`.
    len: u32,
    /// Body bytes of the front record already taken.
    front_taken: u32,
    /// The front record's head has been taken.
    front_head_done: u8,
    _pad: [u8; 3],
}

impl RecordQueue {
    pub(crate) const fn empty() -> Self {
        Self {
            buf: core::ptr::null_mut(),
            cap: 0,
            at: 0,
            len: 0,
            front_taken: 0,
            front_head_done: 0,
            _pad: [0; 3],
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append one record. False when it would pass `QUEUE_LIMIT` or the arena
    /// cannot hold it.
    pub(crate) unsafe fn push(
        &mut self,
        sys: &super::super::abi::SyscallTable,
        rec: &[u8],
    ) -> bool {
        let need = 4 + rec.len() as u32;
        if self.at != 0 && self.at + self.len + need > self.cap {
            core::ptr::copy(self.buf.add(self.at as usize), self.buf, self.len as usize);
            self.at = 0;
        }
        let want = self.len + need;
        if want > QUEUE_LIMIT {
            return false;
        }
        if want > self.cap {
            let mut cap = if self.cap == 0 {
                RECORD_MAX as u32 + 4
            } else {
                self.cap
            };
            while cap < want {
                cap = cap.saturating_mul(2);
            }
            let cap = cap.min(QUEUE_LIMIT);
            let fresh = heap_alloc(sys, cap);
            if fresh.is_null() {
                return false;
            }
            if !self.buf.is_null() {
                core::ptr::copy_nonoverlapping(
                    self.buf.add(self.at as usize),
                    fresh,
                    self.len as usize,
                );
                heap_free(sys, self.buf);
            }
            self.buf = fresh;
            self.cap = cap;
            self.at = 0;
        }
        let p = self.buf.add((self.at + self.len) as usize);
        core::ptr::copy_nonoverlapping((rec.len() as u32).to_le_bytes().as_ptr(), p, 4);
        core::ptr::copy_nonoverlapping(rec.as_ptr(), p.add(4), rec.len());
        self.len += need;
        true
    }

    /// The front record, whole.
    pub(crate) unsafe fn front<'a>(&self) -> Option<&'a [u8]> {
        if self.len < 4 {
            return None;
        }
        let p = self.buf.add(self.at as usize);
        let mut lb = [0u8; 4];
        core::ptr::copy_nonoverlapping(p, lb.as_mut_ptr(), 4);
        let n = u32::from_le_bytes(lb);
        if 4 + n > self.len {
            return None;
        }
        Some(core::slice::from_raw_parts(p.add(4), n as usize))
    }

    pub(crate) fn front_taken(&self) -> usize {
        self.front_taken as usize
    }

    pub(crate) fn front_head_done(&self) -> bool {
        self.front_head_done != 0
    }

    pub(crate) fn take_front_head(&mut self) {
        self.front_head_done = 1;
    }

    pub(crate) fn take_front_body(&mut self, n: usize) {
        self.front_taken += n as u32;
    }

    /// Drop the front record.
    pub(crate) unsafe fn pop(&mut self, sys: &super::super::abi::SyscallTable) {
        if let Some(rec) = self.front() {
            let n = 4 + rec.len() as u32;
            self.at += n;
            self.len -= n;
        }
        self.front_taken = 0;
        self.front_head_done = 0;
        if self.len == 0 {
            self.release(sys);
        }
    }

    /// Forget every record, keeping the buffer for the next exchange. For an
    /// owner that cannot reach the allocator where it ends an exchange.
    pub(crate) fn clear(&mut self) {
        self.at = 0;
        self.len = 0;
        self.front_taken = 0;
        self.front_head_done = 0;
    }

    /// Free what the queue holds.
    pub(crate) unsafe fn release(&mut self, sys: &super::super::abi::SyscallTable) {
        if !self.buf.is_null() {
            heap_free(sys, self.buf);
        }
        *self = Self::empty();
    }
}

/// The body bytes a response record carries, and whether it is a HEAD.
pub(crate) fn record_body(rec: &[u8]) -> (&[u8], bool) {
    match parse_response(rec) {
        Some(Record::Head(h)) => (h.body, true),
        Some(Record::Body { data, .. }) => (data, false),
        _ => (&[], false),
    }
}

/// Whether a record (HEAD or BODY) ends the response.
pub(crate) fn record_ends(rec: &[u8]) -> bool {
    rec.len() > 1 && rec[1] & flag::MORE == 0
}

/// The progress deadline a response runs under, from its HEAD's flags.
pub(crate) fn progress_timeout_ms(flags: u8) -> u64 {
    if flags & flag::HOLD != 0 {
        HOLD_TIMEOUT_MS
    } else {
        APP_TIMEOUT_MS
    }
}

/// What taking a response record into an exchange came to.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Admit {
    /// A HEAD or BODY is queued for the connection.
    Queued,
    /// Request-body credit arrived.
    Credit,
    /// The application abandoned the exchange.
    Abort,
    /// The application broke the exchange's rules: body past its credit, a
    /// second HEAD, a BODY before the HEAD or after the end. The exchange is
    /// aborted.
    Violation,
    /// The exchange is not expecting records; the record is dropped.
    Stale,
}

/// Take one response record into its exchange: credit accounting, ordering
/// and the progress deadline. A HEAD or BODY is pushed onto `q`.
pub(crate) unsafe fn admit(
    s: &mut HttpState,
    x: &mut Exchange,
    q: &mut RecordQueue,
    rec: &[u8],
) -> Admit {
    if !x.open() {
        return Admit::Stale;
    }
    let Some(parsed) = parse_response(rec) else {
        return Admit::Violation;
    };
    let now = s.server.now_ms;
    match parsed {
        Record::Credit { bytes, .. } => {
            if x.is(ex::REQ_DONE) {
                return Admit::Stale;
            }
            x.req_credit = x.req_credit.saturating_add(bytes);
            x.state |= ex::CREDITED;
            if !x.is(ex::RESP_HEAD) {
                x.deadline_ms = now.saturating_add(APP_TIMEOUT_MS);
            }
            Admit::Credit
        }
        Record::Abort { .. } => Admit::Abort,
        Record::Datagram { .. } | Record::Link { .. } => Admit::Stale,
        Record::Head(h) => {
            if x.is(ex::RESP_HEAD) || h.body.len() as u32 > x.resp_credit {
                return Admit::Violation;
            }
            if !q.push(&*s.syscalls, rec) {
                return Admit::Violation;
            }
            x.resp_credit -= h.body.len() as u32;
            x.resp_flags = h.flags;
            x.state |= ex::RESP_HEAD;
            if h.flags & flag::MORE == 0 {
                x.state |= ex::RESP_DONE;
                x.deadline_ms = 0;
            } else {
                x.deadline_ms = now.saturating_add(progress_timeout_ms(h.flags));
            }
            Admit::Queued
        }
        Record::Body { flags, data, .. } => {
            if !x.is(ex::RESP_HEAD) || x.is(ex::RESP_DONE) || data.len() as u32 > x.resp_credit {
                return Admit::Violation;
            }
            if !q.push(&*s.syscalls, rec) {
                return Admit::Violation;
            }
            x.resp_credit -= data.len() as u32;
            if flags & flag::MORE == 0 {
                x.state |= ex::RESP_DONE;
                x.deadline_ms = 0;
            } else {
                x.deadline_ms = now.saturating_add(progress_timeout_ms(x.resp_flags));
            }
            Admit::Queued
        }
    }
}

/// Note that `n` response-body bytes left for the peer, and grant credit back
/// once enough has, or once nothing more is held.
pub(crate) unsafe fn note_delivered(
    s: &mut HttpState,
    id: &AppId,
    x: &mut Exchange,
    n: usize,
    queue_empty: bool,
) {
    x.resp_owed = x.resp_owed.saturating_add(n as u32);
    grant(s, id, x, queue_empty);
}

/// Send owed response credit if it is time to.
pub(crate) unsafe fn grant(s: &mut HttpState, id: &AppId, x: &mut Exchange, queue_empty: bool) {
    if x.resp_owed == 0 || x.is(ex::RESP_DONE) || !x.open() {
        return;
    }
    if x.resp_owed < GRANT_MIN && !queue_empty {
        return;
    }
    let mut rec = [0u8; HDR + 4];
    let Some(n) = write_credit(&id.exchange_id(), x.resp_owed, &mut rec) else {
        return;
    };
    if write_out(s, &rec[..n]) {
        x.resp_credit = x.resp_credit.saturating_add(x.resp_owed);
        x.resp_owed = 0;
    }
}

/// Write one record to `request_out`.
pub(crate) unsafe fn write_out(s: &mut HttpState, rec: &[u8]) -> bool {
    if s.server.app_out_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    (sys.channel_write)(s.server.app_out_chan, rec.as_ptr(), rec.len()) > 0
}

/// What sending a request HEAD came to.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Emit {
    Sent,
    /// `request_out` is full, or aborts are waiting ahead of it; try again.
    Full,
    /// The request body is still arriving and may yet fit the HEAD whole; try
    /// again once more of it is here.
    Waiting,
    /// Nothing is wired to `request_out`: a route declares HANDLER_APP with no
    /// application behind it. 503.
    Unwired,
    /// The head does not fit one record. 431.
    TooLarge,
    /// The request body passed the route's ceiling before the HEAD went. 413.
    BodyTooLarge,
    /// The request body's framing is malformed. 400.
    BodyBad,
}

/// Request-body bytes a HEAD carrying these fields has room for inline.
pub(crate) fn inline_room(target: &[u8], headers: &[u8], peer: &[u8]) -> usize {
    RECORD_MAX.saturating_sub(HDR + REQ_HEAD_FIXED + target.len() + headers.len() + peer.len())
}

/// Whether a request's header block asks for `100 Continue` before its body.
pub(crate) fn wants_continue(headers: &[u8]) -> bool {
    header(headers, b"expect").is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"))
}

/// Compose a request HEAD into `rec`, its length or the refusal it earns.
pub(crate) fn compose_head(head: &RequestHead<'_>, rec: &mut [u8]) -> Result<usize, Emit> {
    if head.headers.len() > MAX_FWD_HEADERS || head.target.len() > MAX_TARGET {
        return Err(Emit::TooLarge);
    }
    write_request_head(head, rec).ok_or(Emit::TooLarge)
}

/// Send a composed request HEAD, opening an exchange the application then
/// answers.
pub(crate) unsafe fn send_head(s: &mut HttpState, rec: &[u8]) -> Emit {
    if s.server.app_out_chan < 0 {
        return Emit::Unwired;
    }
    // Aborts first: an exchange the application still believes open must be
    // closed before another is opened, and holding heads back is what bounds
    // the abort queue.
    if !flush_aborts(s) {
        return Emit::Full;
    }
    if write_out(s, rec) {
        s.server.app_exchanges = s.server.app_exchanges.wrapping_add(1);
        Emit::Sent
    } else {
        Emit::Full
    }
}

/// Compose and send a request HEAD whose inline body, if any, is in hand.
pub(crate) unsafe fn emit_head(s: &mut HttpState, head: &RequestHead<'_>) -> Emit {
    if s.server.app_out_chan < 0 {
        return Emit::Unwired;
    }
    let mut rec = [0u8; RECORD_MAX];
    match compose_head(head, &mut rec) {
        Ok(n) => send_head(s, &rec[..n]),
        Err(e) => e,
    }
}

/// How a generation that holds a request body in a buffer of its own sends
/// it: whole in the HEAD, or after it on credit. `held` is what has arrived,
/// `ended` whether that is all of it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum BodyPlan {
    /// No body at all.
    None,
    /// All of it, inline in the HEAD.
    Inline,
    /// After the HEAD, as BODY records the application grants credit for.
    Stream,
    /// Not decided yet: the body may still fit the HEAD once it has arrived.
    Wait,
}

/// Decide [`BodyPlan`] for a buffered body: `held` bytes of it here, `ended`
/// when that is all of it, `declared` its `content-length` if the request
/// names one. A tunnel (`CONNECT`) and a client waiting for `100 Continue`
/// stream at once: neither sends its body until answered. A body still
/// arriving is waited for only when its declared length fits the record, so
/// it is certain to come whole; one of no declared length cannot be known to
/// fit until it ends, and streams.
pub(crate) fn plan_buffered(
    held: usize,
    ended: bool,
    declared: Option<u64>,
    room: usize,
    stream_now: bool,
) -> BodyPlan {
    if ended && held == 0 {
        return BodyPlan::None;
    }
    if stream_now || held > room {
        return BodyPlan::Stream;
    }
    if ended {
        return BodyPlan::Inline;
    }
    match declared {
        Some(n) if n <= room as u64 => BodyPlan::Wait,
        _ => BodyPlan::Stream,
    }
}

/// The `content-length` a request's header block declares, when it parses.
pub(crate) fn declared_request_length(headers: &[u8]) -> Option<u64> {
    declared_length(headers)
}

/// A fresh exchange, as its HEAD goes out.
pub(crate) fn opened(stream: u64, now: u64, has_body: bool, continue_first: bool) -> Exchange {
    let mut x = Exchange::idle();
    x.stream = stream;
    x.state = ex::OPEN;
    if !has_body {
        x.state |= ex::REQ_DONE;
    } else if continue_first {
        x.state |= ex::CONTINUE;
    }
    x.resp_credit = RESP_WINDOW;
    x.deadline_ms = now.saturating_add(APP_TIMEOUT_MS);
    x
}

/// Send one request-body record sealed in `rec`. `data_len` bytes are in place
/// at `rec[HDR..]`; `last` ends the request.
pub(crate) unsafe fn emit_body(
    s: &mut HttpState,
    id: &AppId,
    rec: &mut [u8],
    data_len: usize,
    last: bool,
) -> bool {
    let flags = if last { 0 } else { flag::MORE };
    let Some(n) = seal_body(&id.exchange_id(), flags, data_len, rec) else {
        return false;
    };
    write_out(s, &rec[..n])
}

/// Tell the application an exchange is over from this side. Queued when
/// `request_out` is full; nothing is lost.
pub(crate) unsafe fn abort(s: &mut HttpState, id: AppId, reason: u8) {
    s.server.app_aborts = s.server.app_aborts.wrapping_add(1);
    if s.server.abort_len == 0 {
        let mut rec = [0u8; HDR + 1];
        if let Some(n) = write_abort(&id.exchange_id(), reason, &mut rec) {
            if write_out(s, &rec[..n]) {
                return;
            }
        }
    }
    let len = s.server.abort_len as usize;
    if len < ABORT_QUEUE {
        s.server.abort_queue[len] = (id, reason);
        s.server.abort_len += 1;
    }
}

/// Send waiting aborts, in order. True once none waits.
pub(crate) unsafe fn flush_aborts(s: &mut HttpState) -> bool {
    while s.server.abort_len > 0 {
        let (id, reason) = s.server.abort_queue[0];
        let mut rec = [0u8; HDR + 1];
        let Some(n) = write_abort(&id.exchange_id(), reason, &mut rec) else {
            return false;
        };
        if !write_out(s, &rec[..n]) {
            return false;
        }
        let len = s.server.abort_len as usize;
        s.server.abort_queue.copy_within(1..len, 0);
        s.server.abort_len -= 1;
    }
    true
}

/// Read the application's records and hand each to the exchange it names.
///
/// One reader for every connection and generation, driven once per step:
/// `response_in` feeds them all, so a per-connection read would let whichever
/// connection stepped first take a record addressed to another.
pub(crate) unsafe fn drain_responses(s: &mut HttpState) {
    flush_aborts(s);
    if s.server.app_in_chan < 0 {
        return;
    }
    let mut rec = [0u8; RECORD_MAX];
    for _ in 0..RECORDS_PER_STEP {
        let sys = &*s.syscalls;
        let chan = s.server.app_in_chan;
        let poll = (sys.channel_poll)(chan, super::POLL_IN);
        if poll <= 0 || (poll as u32 & super::POLL_IN) == 0 {
            return;
        }
        let n = (sys.channel_read)(chan, rec.as_mut_ptr(), RECORD_MAX);
        if n <= 0 {
            return;
        }
        let raw = &rec[..n as usize];
        // The application's own backend went away: every exchange it holds
        // without an answer is unknowable. A request already streamed to it
        // cannot be issued again from here, so each is answered for — 502
        // before its response began, a cut-off response after.
        if let Some(Record::Link { state }) = parse_response(raw) {
            if state == link::DOWN {
                fail_all(s);
            }
            continue;
        }
        let Some(id) = record_id(raw) else {
            // A record that does not parse is an application speaking a broken
            // protocol, or one larger than a channel read on a port whose
            // record size exceeds the reader's. Counted rather than dropped
            // silently: the exchange it belonged to would otherwise surface as
            // a 504, pointing at the application's speed rather than its bytes.
            s.server.app_records_malformed = s.server.app_records_malformed.wrapping_add(1);
            continue;
        };
        match id.origin {
            app_origin::TCP => {
                let Some(idx) = find_slot_by_conn_id(s, id.conn as u16) else {
                    s.server.app_records_stale = s.server.app_records_stale.wrapping_add(1);
                    continue;
                };
                #[cfg(feature = "h2")]
                if !(*s.server.slots.as_ptr().add(idx)).h2.is_null() {
                    super::h2::app_record(s, idx, &id, raw);
                    continue;
                }
                h1_record(s, idx, &id, raw);
            }
            #[cfg(feature = "h3")]
            app_origin::QUIC => super::h3::app_record(s, &id, raw),
            _ => {
                s.server.app_records_stale = s.server.app_records_stale.wrapping_add(1);
            }
        }
    }
}

/// The id of a record the application wrote, when it parses and names an
/// exchange this server could have opened.
fn record_id(raw: &[u8]) -> Option<AppId> {
    let id = match parse_response(raw)? {
        Record::Head(h) => h.id,
        Record::Body { id, .. }
        | Record::Abort { id, .. }
        | Record::Credit { id, .. }
        | Record::Datagram { id, .. } => id,
        Record::Link { .. } => return None,
    };
    AppId::from_exchange_id(&id)
}

/// Answer for every exchange the application holds open without a complete
/// response, on every connection and generation.
unsafe fn fail_all(s: &mut HttpState) {
    let saved = s.server.cur_slot;
    for idx in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(idx);
        #[cfg(feature = "h2")]
        if !slot.h2.is_null() {
            super::h2::fail_app_streams(s, idx);
            continue;
        }
        if slot.app.open() && !slot.app.is(ex::RESP_DONE) {
            s.server.cur_slot = idx as i32;
            h1_fail(s, None);
        }
    }
    s.server.cur_slot = saved;
    #[cfg(feature = "h3")]
    super::h3::fail_app_streams(s);
}

// ── HTTP/1.1 ──────────────────────────────────────────────────────────────

/// The id of the current h1 slot's exchange.
pub(crate) unsafe fn h1_id(s: &HttpState) -> AppId {
    let (conn, stream) = cur_slot(s)
        .map(|c| (c.conn_id.max(0) as u32, c.app.stream))
        .unwrap_or((0, 0));
    AppId {
        origin: app_origin::TCP,
        conn,
        stream,
    }
}

/// Open the current h1 slot's exchange. `target` and `headers` are read from
/// the request head still in `recv_buf`; a body, when `has_body`, has been
/// armed on the slot's reader.
///
/// A body already received whole that fits the record goes inline in the
/// HEAD, and the exchange opens with its request direction ended. One whose
/// declared length fits but which is still arriving is waited for
/// ([`Emit::Waiting`]). A client waiting for `100 Continue`, or a body longer
/// than the record, is sent after the HEAD on the application's credit.
pub(crate) unsafe fn h1_begin(
    s: &mut HttpState,
    target: &[u8],
    headers: &[u8],
    has_body: bool,
    continue_first: bool,
) -> Emit {
    // Room `recv_buf` has for the body behind the head, and the body's
    // declared length (`u64::MAX` when it declares none).
    let (conn_id, verb, recv_room, declared) = match cur_slot(s) {
        Some(c) => (
            c.conn_id.max(0) as u16,
            c.req_method,
            (c.recv_cap as u64).saturating_sub(c.header_end_off as u64),
            c.body_declared,
        ),
        None => return Emit::Unwired,
    };
    if s.server.app_out_chan < 0 {
        return Emit::Unwired;
    }
    // A request generation, not a connection-scoped counter: the id must
    // differ from any a previous holder of this connection id was given.
    let stream = s.server.app_gen_next;
    let peer: &[u8] = match super::peer_svid(s, conn_id) {
        Some(p) => core::slice::from_raw_parts(p.as_ptr(), p.len()),
        None => &[],
    };
    let id = AppId {
        origin: app_origin::TCP,
        conn: conn_id as u32,
        stream,
    };
    let head = RequestHead {
        id: id.exchange_id(),
        flags: 0,
        method: verb,
        target,
        headers,
        peer,
        resp_credit: RESP_WINDOW,
        body: &[],
    };
    let mut rec = [0u8; RECORD_MAX];
    let n = match compose_head(&head, &mut rec) {
        Ok(n) => n,
        Err(e) => return e,
    };
    // The body is decoded straight into the record behind the head, which is
    // where an inline body sits; nothing is committed unless it goes.
    //
    // A body is waited for only when its declared length fits both the record
    // and `recv_buf`, so it is certain to arrive whole where it can be read.
    // A chunked body goes inline only if it is already here whole: its length
    // is not known until it ends.
    let mut inline = None;
    if has_body {
        rec[1] = flag::MORE;
        let fits = declared <= (RECORD_MAX - n) as u64 && declared <= recv_room;
        if !continue_first {
            match super::reqbody::peek(s, &mut rec, n) {
                Ok(p) if p.done => {
                    rec[1] = 0;
                    inline = Some(p);
                }
                Ok(_) | Err(super::reqbody::BodyStep::Wait) if fits => return Emit::Waiting,
                Err(super::reqbody::BodyStep::TooLarge) => return Emit::BodyTooLarge,
                Err(super::reqbody::BodyStep::Bad) => return Emit::BodyBad,
                // Longer than the record or `recv_buf`, or of no declared
                // length: the HEAD goes alone and the body follows on credit.
                _ => {}
            }
        }
    }
    let len = n + inline.map_or(0, |p| p.produced);
    let r = send_head(s, &rec[..len]);
    if r == Emit::Sent {
        if let Some(p) = inline {
            super::reqbody::commit(s, p);
        }
        s.server.app_gen_next = stream.wrapping_add(1);
        let now = s.server.now_ms;
        if let Some(cur) = cur_slot_mut(s) {
            cur.app = opened(stream, now, has_body && inline.is_none(), continue_first);
            cur.resp_started = 0;
            cur.resp_length_known = 0;
            cur.resp_remaining = 0;
        }
    }
    r
}

/// Hand a record to the h1 exchange on slot `idx`, if it is the one the record
/// names.
unsafe fn h1_record(s: &mut HttpState, idx: usize, id: &AppId, raw: &[u8]) {
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    if !slot.app.open() || slot.app.stream != id.stream {
        s.server.app_records_stale = s.server.app_records_stale.wrapping_add(1);
        return;
    }
    let mut x = slot.app;
    let mut q = core::ptr::read(&slot.app_queue);
    let outcome = admit(s, &mut x, &mut q, raw);
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot.app = x;
    core::ptr::write(&mut slot.app_queue, q);
    match outcome {
        Admit::Queued | Admit::Credit | Admit::Stale => {}
        Admit::Abort | Admit::Violation => {
            if outcome == Admit::Violation {
                s.server.app_violations = s.server.app_violations.wrapping_add(1);
            }
            let saved = s.server.cur_slot;
            s.server.cur_slot = idx as i32;
            h1_fail(
                s,
                if outcome == Admit::Violation {
                    Some(abort_reason::CREDIT_OVERRUN)
                } else {
                    None
                },
            );
            s.server.cur_slot = saved;
        }
    }
}

/// End the current h1 exchange because the application failed it. `reason` is
/// what to tell the application, if it is still owed an abort. Before any of
/// the response reached the peer, the server answers 502 for it; after, the
/// connection closes, which the peer sees as the truncated response it is.
unsafe fn h1_fail(s: &mut HttpState, reason: Option<u8>) {
    let id = h1_id(s);
    if let Some(r) = reason {
        abort(s, id, r);
    }
    let started = cur_slot(s).map(|c| c.resp_started != 0).unwrap_or(true);
    h1_close_exchange(s);
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    if started {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = super::Phase::CloseConn;
        }
    } else {
        super::response::build_error(s, b"502 Bad Gateway", b"Bad Gateway\n");
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = super::Phase::DrainSend;
        }
    }
}

/// Forget the current slot's exchange and release what it holds.
pub(crate) unsafe fn h1_close_exchange(s: &mut HttpState) {
    let sys = s.syscalls;
    if let Some(cur) = cur_slot_mut(s) {
        cur.app_queue.release(&*sys);
        cur.app = Exchange::idle();
        cur.resp_started = 0;
        cur.resp_length_known = 0;
        cur.resp_remaining = 0;
    }
}

/// A connection is being released: its exchange, if the application still
/// believes it open, is aborted.
pub(crate) unsafe fn on_slot_release(s: &mut HttpState, idx: usize) {
    let slot = &*s.server.slots.as_ptr().add(idx);
    if !slot.app.open() || slot.app.finished() {
        return;
    }
    let reason = if slot.peer_closed != 0 {
        abort_reason::PEER_GONE
    } else if s.server.draining != 0 {
        abort_reason::DRAINING
    } else {
        abort_reason::UNDELIVERABLE
    };
    let id = AppId {
        origin: app_origin::TCP,
        conn: slot.conn_id.max(0) as u32,
        stream: slot.app.stream,
    };
    abort(s, id, reason);
}

/// `Phase::AppExchange`: move the request body to the application and its
/// answer to the peer, as each side's credit and buffer allow.
pub(crate) unsafe fn h1_step(s: &mut HttpState) -> i32 {
    // Bytes already composed go first.
    let (send_len, send_off) = cur_slot(s)
        .map(|c| (c.send_len, c.send_offset))
        .unwrap_or((0, 0));
    if send_off < send_len {
        let sent = super::net_send(
            s,
            super::cur_send_buf_ptr(s).add(send_off as usize),
            (send_len - send_off) as usize,
        );
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
            }
            super::mark_progress(s);
        }
    }
    let drained = cur_slot(s)
        .map(|c| c.send_offset >= c.send_len)
        .unwrap_or(false);
    if drained {
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = 0;
            cur.send_offset = 0;
        }
        h1_compose(s);
        if cur_slot(s)
            .map(|c| c.phase != super::Phase::AppExchange)
            .unwrap_or(true)
        {
            return 2;
        }
    }

    let x = cur_slot(s).map(|c| c.app).unwrap_or(Exchange::idle());

    // The client is waiting for `100 Continue` before sending its body, and
    // the application has now asked for it.
    if x.is(ex::CONTINUE | ex::CREDITED) && !x.is(ex::RESP_HEAD) {
        if cur_slot(s).map(|c| c.send_len == 0).unwrap_or(false) {
            super::h1::stage_interim_continue(s);
            if let Some(cur) = cur_slot_mut(s) {
                cur.app.state &= !ex::CONTINUE;
            }
        }
        return 2;
    }

    // The request body, as far as credit goes.
    if !x.is(ex::REQ_DONE) && !x.is(ex::CONTINUE) {
        if let Some(r) = h1_forward(s) {
            return r;
        }
    }

    let x = cur_slot(s).map(|c| c.app).unwrap_or(Exchange::idle());
    let queue_empty = cur_slot(s).map(|c| c.app_queue.is_empty()).unwrap_or(true);
    let send_idle = cur_slot(s).map(|c| c.send_len == 0).unwrap_or(true);

    // The response is over: on to the next request, or to the close if the
    // request body was left unread.
    if x.is(ex::RESP_DONE) && queue_empty && send_idle {
        let short = cur_slot(s)
            .map(|c| c.resp_length_known != 0 && c.resp_remaining != 0)
            .unwrap_or(false);
        if !x.is(ex::REQ_DONE) || short {
            if let Some(cur) = cur_slot_mut(s) {
                cur.keepalive = 0;
            }
        }
        h1_close_exchange(s);
        super::body::finish_response(s);
        return 2;
    }

    // The peer has gone: nothing left to deliver to.
    if cur_slot(s).map(|c| c.peer_closed != 0).unwrap_or(false) && send_idle {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = super::Phase::CloseConn;
        }
        return 2;
    }

    // The application holds the turn and has let it lapse.
    if x.deadline_ms != 0 && s.server.now_ms >= x.deadline_ms {
        s.server.app_timeouts = s.server.app_timeouts.wrapping_add(1);
        let id = h1_id(s);
        abort(s, id, abort_reason::STALLED);
        let started = cur_slot(s).map(|c| c.resp_started != 0).unwrap_or(true);
        h1_close_exchange(s);
        if let Some(cur) = cur_slot_mut(s) {
            cur.keepalive = 0;
        }
        if started {
            // Mid-response, a 504 would be read as body. Closing is the only
            // honest signal left: the truncated transfer it is.
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = super::Phase::CloseConn;
            }
        } else {
            super::response::build_error(s, b"504 Gateway Timeout", b"Gateway Timeout\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = super::Phase::DrainSend;
            }
        }
        return 2;
    }
    0
}

/// Forward request-body bytes the application has credit for. `Some` ends the
/// step with that return code.
unsafe fn h1_forward(s: &mut HttpState) -> Option<i32> {
    let id = h1_id(s);
    let mut rec = [0u8; RECORD_MAX];
    // A few records per step: enough that framing between chunks costs no
    // step of its own, bounded so one connection cannot hold the step.
    let mut step = super::reqbody::BodyStep::Wait;
    for _ in 0..FORWARDS_PER_STEP {
        let credit = cur_slot(s).map(|c| c.app.req_credit).unwrap_or(0);
        let cap = HDR + (credit as usize).min(BODY_MAX);
        step = match super::reqbody::peek(s, &mut rec[..cap], HDR) {
            Ok(p) if p.produced == 0 && !p.done => super::reqbody::commit(s, p),
            Ok(p) => {
                if emit_body(s, &id, &mut rec[..cap], p.produced, p.done) {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.app.req_credit -= p.produced as u32;
                    }
                    super::reqbody::commit(s, p)
                } else {
                    super::reqbody::BodyStep::Wait
                }
            }
            Err(step) => step,
        };
        if step != super::reqbody::BodyStep::Progress {
            break;
        }
        super::mark_progress(s);
    }
    match step {
        super::reqbody::BodyStep::Progress => None,
        super::reqbody::BodyStep::Done => {
            if let Some(cur) = cur_slot_mut(s) {
                cur.app.state |= ex::REQ_DONE;
            }
            super::mark_progress(s);
            None
        }
        super::reqbody::BodyStep::Wait => {
            // A peer gone mid-body leaves a request that can never complete.
            if cur_slot(s).map(|c| c.peer_closed != 0).unwrap_or(false) {
                abort(s, id, abort_reason::PEER_GONE);
                h1_close_exchange(s);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = super::Phase::CloseConn;
                }
                return Some(2);
            }
            None
        }
        super::reqbody::BodyStep::Bad | super::reqbody::BodyStep::TooLarge => {
            let too_large = step == super::reqbody::BodyStep::TooLarge;
            abort(
                s,
                id,
                if too_large {
                    abort_reason::TOO_LARGE
                } else {
                    abort_reason::MALFORMED
                },
            );
            if too_large {
                s.server.bodies_refused = s.server.bodies_refused.wrapping_add(1);
            }
            let started = cur_slot(s).map(|c| c.resp_started != 0).unwrap_or(true);
            h1_close_exchange(s);
            // The rest of the body is still arriving and nothing is reading
            // it, so there is no next request boundary to find: close.
            if let Some(cur) = cur_slot_mut(s) {
                cur.keepalive = 0;
            }
            if started {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = super::Phase::CloseConn;
                }
            } else {
                if too_large {
                    super::response::build_error(
                        s,
                        b"413 Content Too Large",
                        b"Content Too Large\n",
                    );
                } else {
                    super::response::build_error(s, b"400 Bad Request", b"Bad Request\n");
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = super::Phase::DrainSend;
                }
            }
            Some(2)
        }
    }
}

/// Compose what the exchange's queue holds into the empty `send_buf`: the
/// response head when it is next, then body bytes as far as they fit.
unsafe fn h1_compose(s: &mut HttpState) {
    let idx = s.server.cur_slot;
    if idx < 0 || idx as usize >= MAX_CONCURRENT_CONNS {
        return;
    }
    let slot: *mut super::ConnSlot = s.server.slots.as_mut_ptr().add(idx as usize);
    let id = h1_id(s);
    while let Some(rec) = (*slot).app_queue.front() {
        let (body, is_head) = record_body(rec);
        if is_head && !(*slot).app_queue.front_head_done() {
            if !h1_compose_head(s, rec) {
                // A head the connection buffer cannot hold. Nothing has gone
                // out, so the server answers for the application.
                s.server.app_violations = s.server.app_violations.wrapping_add(1);
                h1_fail(s, Some(abort_reason::UNDELIVERABLE));
                return;
            }
            (*slot).app_queue.take_front_head();
            (*slot).resp_started = 1;
        }
        let taken = (*slot).app_queue.front_taken();
        let rest = &body[taken.min(body.len())..];
        let carries = (*slot).resp_carries_body != 0;
        let room = SEND_BUF_SIZE.saturating_sub((*slot).send_len as usize);
        let n = if carries {
            rest.len().min(room)
        } else {
            rest.len()
        };
        if carries && n > 0 {
            // A declared length the application overruns is a response the
            // peer would misframe: the extra bytes would read as the next
            // response. Refused before a byte past it is sent.
            if (*slot).resp_length_known != 0 && n as u64 > (*slot).resp_remaining {
                s.server.app_violations = s.server.app_violations.wrapping_add(1);
                h1_fail(s, Some(abort_reason::CREDIT_OVERRUN));
                return;
            }
            let dst = (*slot).send_buf.add((*slot).send_len as usize);
            core::ptr::copy_nonoverlapping(rest.as_ptr(), dst, n);
            (*slot).send_len += n as u16;
            if (*slot).resp_length_known != 0 {
                (*slot).resp_remaining -= n as u64;
            }
        }
        (*slot).app_queue.take_front_body(n);
        let whole = taken + n >= body.len();
        if whole {
            (*slot).app_queue.pop(&*s.syscalls);
        }
        let empty = (*slot).app_queue.is_empty();
        let mut x = (*slot).app;
        note_delivered(s, &id, &mut x, n, empty);
        (*slot).app = x;
        if !whole || (*slot).send_len as usize >= SEND_BUF_SIZE {
            return;
        }
    }
}

/// Write a response HEAD's status line and headers into `send_buf`. False when
/// they do not fit.
unsafe fn h1_compose_head(s: &mut HttpState, rec: &[u8]) -> bool {
    let Some(Record::Head(h)) = parse_response(rec) else {
        return false;
    };
    let verb = cur_slot(s).map(|c| c.req_method).unwrap_or(0);
    let carries = status_allows_body(h.status, verb);
    let streaming = h.flags & flag::MORE != 0;
    let declared = declared_length(h.headers);
    // The framing the peer reads the body by:
    //  - no body (HEAD, 204, 304): the application's own `Content-Length`,
    //    which for HEAD is the length the GET would carry;
    //  - one record: its body's length;
    //  - streamed: the application's declared length, or, without one, the
    //    end of the connection.
    let length: Option<u64> = if !carries {
        if method::method_sends_response_body(verb) && !matches!(h.status, 304) {
            None
        } else {
            declared
        }
    } else if !streaming {
        Some(h.body.len() as u64)
    } else {
        declared
    };
    // A response with no declared end, or one composed while the request
    // body is still unread, ends the connection — and its head says so.
    let body_unread = cur_slot(s).map(|c| !c.app.is(ex::REQ_DONE)).unwrap_or(true);
    if (carries && streaming && length.is_none()) || body_unread {
        if let Some(cur) = cur_slot_mut(s) {
            cur.keepalive = 0;
        }
    }
    let ct: &[u8] = if h.content_type.is_empty() {
        b"application/octet-stream"
    } else {
        h.content_type
    };
    let ok = super::response::build_app_header(s, h.status, ct, length, h.headers);
    if let Some(cur) = cur_slot_mut(s) {
        cur.resp_carries_body = carries as u8;
        cur.resp_length_known = (carries && length.is_some()) as u8;
        cur.resp_remaining = length.unwrap_or(0);
    }
    ok
}

/// The `Content-Length` an application declared in its own header block.
pub(crate) fn declared_length(headers: &[u8]) -> Option<u64> {
    let v = super::super::exchange::header(headers, b"content-length")?;
    if v.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in v {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
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
