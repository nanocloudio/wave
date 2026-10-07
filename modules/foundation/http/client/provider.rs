//! The client as an exchange provider: requests from the graph, answers back.
//!
//! A requester writes exchange request records on `request_in`; this client
//! performs each as an HTTP request against its origin and answers on
//! `response_out` under the requester's exchange id. Nothing here speaks HTTP:
//! it collects a request, hands its method, target, headers and body to the
//! generation's phase machine, and frames what that machine produces into
//! response records.
//!
//! # A request
//!
//! - `method`: `METHOD_GET` … `METHOD_OPTIONS`. `METHOD_CONNECT`,
//!   `METHOD_PUBLISH` and an unknown method are answered 400.
//! - `target`: the request target, `/path[?query]`, sent verbatim; empty
//!   means `/`. Anything else, or a byte outside `0x21..=0x7e`, is 400.
//! - `headers`: `name: value\r\n` lines sent as given, `content-type`
//!   included. `host` chooses the authority (below) and is written by this
//!   client; a `content-length` must equal the body's length and is written
//!   by this client too. A field this client frames the request with
//!   (`connection`, `keep-alive`, `transfer-encoding`, `te`, `trailer`,
//!   `upgrade`, `proxy-connection`, `expect`) is 400, as is a block that is
//!   not well-formed field lines: those bytes land in the request head and
//!   decide where it ends.
//! - `body`: inline in the HEAD, or after it in BODY records under the
//!   credit this client grants — all of it at once, up to the body bound.
//!   The request is performed once it is whole.
//! - flags: `BROADCAST`, `WEBSOCKET` and `WEBTRANSPORT` are 400.
//!
//! # Where a request goes
//!
//! A client whose `authority` parameter is set is PINNED: every request goes
//! there and carries it as `Host` / `:authority`; a request whose `host`
//! names anything else is 400. A client with no `authority` is OPEN: each
//! request's `host` header names the `host[:port]` to dial and to send, and a
//! request without one is 400. An open client keeps one connection and parks
//! one more, so alternating between two origins does not redial each time.
//!
//! # The answer
//!
//! The response HEAD carries the origin's status verbatim, its
//! `content-type`, and its header block without the fields that framed the
//! response on the wire (`connection`, `keep-alive`, `transfer-encoding`,
//! `te`, `trailer`, `upgrade`, `proxy-connection`); `content-length` stays.
//! The body follows the head inline and in BODY records, never past the
//! credit the requester grants, so a response of any length streams. A
//! response that arrives whole within one record is answered in one HEAD.
//!
//! What this client raises itself: 400 for a request it will not perform,
//! 413 for one past its bounds (`MAX_PATH_LEN`, `REQUEST_HEADERS_MAX`,
//! `REQUEST_BODY_SIZE`, an authority past `AUTHORITY_MAX`), 502 when the
//! origin cannot be reached or answers with something that does not parse,
//! 503 while it holds as many requests as it takes or is draining, 504 when
//! the origin does not answer in time. Each is a HEAD marked `RAISED`, which
//! is how a requester tells it from the origin answering with the same
//! number. After the head has gone, a failure is an ABORT.
//!
//! # LINK
//!
//! A pinned client has one backend. When a connection to it cannot be opened,
//! or drops before a response completes, the client writes LINK DOWN instead
//! of answering: the exchange in flight and any it holds are unknowable, and
//! the requester issues them again after LINK UP, which the client writes once
//! a connection to its origin opens again — on the next request, or on a
//! probe it dials itself with a backoff. A request taken while the link is
//! down is tried; if its connection fails too it is as unknowable as the
//! rest, and is issued again after LINK UP like them. Over HTTP/3 the link is
//! the QUIC session the transport announces. An open client has no one
//! backend and answers a failed connection 502.
//!
//! # Concurrency
//!
//! One request is performed at a time and one more is collected behind it; a
//! third is answered 503. A requester wanting concurrency asks for more
//! instances, which is also how it gets more sockets.

use super::super::connection::net_proto::Target;
use super::super::exchange::{
    abort, flag, header_lines, link, parse_request, status, write_abort, write_credit, write_link,
    write_refusal, write_response_head, Collector, ExchangeId, Record, Refuse, ResponseHead, HDR,
    METHOD_DELETE, METHOD_GET, METHOD_HEAD, METHOD_OPTIONS, METHOD_PATCH, METHOD_POST, METHOD_PUT,
    RECORD_MAX, RESP_HEAD_FIXED,
};
use super::super::{dev_channel_port, dev_millis, ExchangeOutbox, HttpState};
use super::{
    log, Phase, AUTHORITY_MAX, CAUSE_CONNECT, CAUSE_LINK, CAUSE_PEER, CAUSE_TIMEOUT, MAX_PATH_LEN,
    REQUEST_BODY_SIZE, REQUEST_HEADERS_MAX,
};

/// Collects one request whole while another is performed.
pub(crate) type RequestCollector =
    Collector<1, MAX_PATH_LEN, REQUEST_HEADERS_MAX, REQUEST_BODY_SIZE>;

/// The longest content type a response HEAD carries: the field's own bound.
pub(crate) const RESP_CT_MAX: usize = 255;
/// The response header block a generation that decodes fields one at a time
/// (h2, h3) assembles. h1 forwards from the decoder's own block.
pub(crate) const RESP_HDRS_MAX: usize = 2048;
/// The largest control record: a refusal HEAD with no content type, headers
/// or body. CREDIT and LINK are smaller.
const CTL_MAX: usize = HDR + RESP_HEAD_FIXED;
/// Request records read per step.
const RECORDS_PER_STEP: usize = 8;
/// The first and the longest wait between probes of a lost link.
const PROBE_FIRST_MS: u32 = 1_000;
const PROBE_MAX_MS: u32 = 30_000;

/// Header fields this client frames a request with, which a requester's block
/// may not name.
fn framing_field(name: &[u8]) -> bool {
    [
        &b"connection"[..],
        b"keep-alive",
        b"transfer-encoding",
        b"te",
        b"trailer",
        b"upgrade",
        b"proxy-connection",
        b"expect",
    ]
    .iter()
    .any(|f| name.eq_ignore_ascii_case(f))
}

/// Header fields that framed a response on the wire and do not describe it
/// to a requester, which reads the body already decoded.
pub(crate) fn hop_field(name: &[u8]) -> bool {
    [
        &b"connection"[..],
        b"keep-alive",
        b"transfer-encoding",
        b"te",
        b"trailer",
        b"upgrade",
        b"proxy-connection",
    ]
    .iter()
    .any(|f| name.eq_ignore_ascii_case(f))
}

/// An RFC 9110 token character. Spelled as a match rather than a search of
/// a literal: the search lowers to `memchr`, which a module image does not
/// link.
fn tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The exchange this client is a provider of.
pub(crate) struct Provider {
    /// in[8]: `request_in`.
    request_chan: i32,
    /// out[9]: `response_out`.
    response_chan: i32,
    collector: RequestCollector,
    /// A request is held in the collector: `queued_id` names it.
    queued: u8,
    /// The held request is complete and waits to be performed.
    ready: u8,
    queued_id: ExchangeId,
    in_rec: [u8; RECORD_MAX],

    /// The response record being composed, `out_len` bytes so far; 0 when
    /// none is. `out_head` says whether it is the HEAD.
    out_rec: [u8; RECORD_MAX],
    out_len: u16,
    out_head: u8,
    out_box: ExchangeOutbox,
    /// Grants, refusals and LINK records, beside the response in hand.
    ctl_rec: [u8; CTL_MAX],
    ctl_box: ExchangeOutbox,

    /// An exchange is being performed, or its terminal record is leaving.
    live: u8,
    id: ExchangeId,
    resp_credit: u32,
    /// Its response HEAD has been composed.
    head_given: u8,
    /// Its terminal record has been composed.
    ended: u8,
    /// The requester aborted it: nothing more is written for it.
    abandoned: u8,
    /// An ABORT owed for it once the response record in hand has left.
    abort_owed: u8,

    /// The backend link is down (pinned clients and HTTP/3).
    link_down: u8,
    /// A LINK record to write, `link::DOWN` or `link::UP`; 0 when none.
    link_owed: u8,
    /// The connection in hand is a probe of the lost link, not a request.
    probing: u8,
    probe_at_ms: u64,
    probe_wait_ms: u32,

    /// The response's content type and header block, for the generations
    /// that decode fields one at a time.
    pub(crate) resp_ct: [u8; RESP_CT_MAX],
    pub(crate) resp_ct_len: u16,
    pub(crate) resp_hdrs: [u8; RESP_HDRS_MAX],
    pub(crate) resp_hdrs_len: u16,
    /// The response's fields passed what is held for them.
    pub(crate) resp_over: u8,
}

/// Wire the exchange ports. Both are optional: a graph using the client in its
/// one-shot param form wires neither, and `armed()` stays false.
pub(crate) unsafe fn init(s: &mut HttpState) {
    let sys = &*s.syscalls;
    s.client.ex.request_chan = dev_channel_port(sys, 0, 8);
    s.client.ex.response_chan = dev_channel_port(sys, 1, 9);
    // Constructed, not left as the zeroed state it arrives in: an empty
    // collector's owed refusal is `None`, and zero bytes do not spell that.
    s.client.ex.collector = RequestCollector::new();
}

/// Is this client driven by the graph rather than by params?
pub(crate) fn armed(s: &HttpState) -> bool {
    s.client.ex.request_chan >= 0 && s.client.ex.response_chan >= 0
}

/// Is an exchange in flight, its terminal record included?
pub(crate) fn busy(s: &HttpState) -> bool {
    s.client.ex.live != 0
}

/// Is the connection in hand a probe of the lost link?
pub(crate) fn probing(s: &HttpState) -> bool {
    s.client.ex.probing != 0
}

/// Nothing is owed on `response_out` and nothing is held.
pub(crate) fn quiet(s: &HttpState) -> bool {
    let x = &s.client.ex;
    x.live == 0 && x.queued == 0 && !x.out_box.holding() && !x.ctl_box.holding() && x.link_owed == 0
}

/// Whether the connection in hand is to the authority of a pinned client.
fn pinned(s: &HttpState) -> bool {
    s.client.authority_len != 0
}

// ── Control records ─────────────────────────────────────────────────────

/// Offer a control record; false when one is already held.
unsafe fn ctl_send(s: &mut HttpState, len: usize) -> bool {
    let sys = &*s.syscalls;
    let x = &mut s.client.ex;
    !x.ctl_box.holding() && {
        x.ctl_box.send(sys, x.response_chan, &x.ctl_rec, len);
        true
    }
}

/// Refuse `id` with `code`, raised here and nothing else, on the control record.
unsafe fn ctl_refuse(s: &mut HttpState, id: ExchangeId, code: u16) -> bool {
    let Some(n) = write_refusal(&id, code, &mut s.client.ex.ctl_rec) else {
        return false;
    };
    ctl_send(s, n)
}

// ── Taking requests ─────────────────────────────────────────────────────

/// Read request records, place what is owed, and finish an exchange whose
/// terminal record has left. Runs every step, before the generation.
pub(crate) unsafe fn service(s: &mut HttpState) {
    let sys = &*s.syscalls;
    {
        let x = &mut s.client.ex;
        x.ctl_box.flush(sys, x.response_chan, &x.ctl_rec);
        x.out_box.flush(sys, x.response_chan, &x.out_rec);
    }
    // An ABORT waits behind the record that was leaving when it was owed.
    if s.client.ex.abort_owed != 0 && !s.client.ex.out_box.holding() {
        let x = &mut s.client.ex;
        if let Some(n) = write_abort(&x.id, x.abort_owed, &mut x.out_rec) {
            x.out_box.send(sys, x.response_chan, &x.out_rec, n);
        }
        x.abort_owed = 0;
    }
    let x = &mut s.client.ex;
    if x.live != 0 && x.ended != 0 && x.abort_owed == 0 && !x.out_box.holding() {
        x.live = 0;
    }
    if x.link_owed != 0 && !x.ctl_box.holding() {
        let state = x.link_owed;
        if let Some(n) = write_link(state, &mut x.ctl_rec) {
            x.link_owed = 0;
            ctl_send(s, n);
        }
    }
    for _ in 0..RECORDS_PER_STEP {
        if s.client.ex.ctl_box.holding() || s.client.ex.link_owed != 0 {
            break;
        }
        let chan = s.client.ex.request_chan;
        let poll = (sys.channel_poll)(chan, super::super::POLL_IN);
        if poll <= 0 || (poll as u32) & super::super::POLL_IN == 0 {
            break;
        }
        let n = (sys.channel_read)(chan, s.client.ex.in_rec.as_mut_ptr(), RECORD_MAX);
        if n <= 0 {
            break;
        }
        take_record(s, n as usize);
    }
    // A requester abort ends the exchange where it stands: the connection is
    // closed under it and nothing more is written for it.
    if s.client.ex.abandoned != 0 && s.client.ex.live != 0 {
        let x = &mut s.client.ex;
        x.out_len = 0;
        x.out_box = ExchangeOutbox::new();
        x.abort_owed = 0;
        x.live = 0;
        x.abandoned = 0;
        s.client.phase = Phase::Error;
        #[cfg(feature = "h2")]
        super::h2::abandon(s);
        #[cfg(feature = "h3")]
        if s.h3_mode != 0 {
            super::h3::abandon(s);
        }
    }
}

/// Take one request record of `n` bytes from `in_rec`.
unsafe fn take_record(s: &mut HttpState, n: usize) {
    let x = &mut s.client.ex;
    let Some(record) = parse_request(&x.in_rec[..n]) else {
        // Without a parse there is no id, and so nobody to answer.
        return;
    };
    let (id, is_head) = match record {
        Record::Head(h) => (h.id, true),
        Record::Body { id, .. }
        | Record::Abort { id, .. }
        | Record::Credit { id, .. }
        | Record::Datagram { id, .. } => (id, false),
        Record::Link { .. } => return,
    };
    if x.live != 0 && x.ended == 0 && id == x.id {
        match record {
            Record::Abort { .. } => x.abandoned = 1,
            Record::Credit { bytes, .. } => x.resp_credit = x.resp_credit.saturating_add(bytes),
            // The request in flight was taken whole; a later record for it
            // is a requester's mistake with nothing to act on.
            _ => {}
        }
        return;
    }
    let accepted = x.collector.accept(&x.in_rec[..n]);
    match accepted {
        Ok(Some(_)) => {
            x.queued = 1;
            x.ready = 1;
            x.queued_id = id;
        }
        Ok(None) if is_head => {
            x.queued = 1;
            x.ready = 0;
            x.queued_id = id;
        }
        Ok(None) => {
            if matches!(record, Record::Abort { .. }) && x.queued != 0 && id == x.queued_id {
                x.queued = 0;
                x.ready = 0;
            }
        }
        Err(_) => {
            if x.queued != 0 && id == x.queued_id && x.collector.live() == 0 {
                x.queued = 0;
                x.ready = 0;
            }
        }
    }
    if let Some((gid, bytes)) = s.client.ex.collector.take_grant() {
        if let Some(len) = write_credit(&gid, bytes, &mut s.client.ex.ctl_rec) {
            ctl_send(s, len);
        }
    } else if let Some((rid, why)) = s.client.ex.collector.take_refusal() {
        ctl_refuse(s, rid, why.status());
    }
}

/// Start what is due, when the generation is free: a probe of a lost link,
/// or the next collected request. True when the phase machine now has work.
pub(crate) unsafe fn start(s: &mut HttpState) -> bool {
    if s.client.draining != 0 || busy(s) || s.client.ex.ctl_box.holding() {
        return false;
    }
    // A request goes first: it probes the link as well as a probe would.
    if s.client.ex.ready != 0 {
        return adopt(s);
    }
    if s.client.ex.link_down != 0 && pinned(s) && s.h3_mode == 0 {
        let now = dev_millis(&*s.syscalls);
        if now >= s.client.ex.probe_at_ms {
            s.client.ex.probing = 1;
            let n = s.client.authority_len as usize;
            s.client.conn_authority[..n].copy_from_slice(&s.client.authority[..n]);
            s.client.conn_authority_len = n as u16;
            rearm(s);
            return true;
        }
    }
    false
}

/// Ready the phase machine for a fresh request on a fresh decoder.
unsafe fn rearm(s: &mut HttpState) {
    s.client.recv_len = 0;
    s.client.pending_offset = 0;
    s.client.headers_done = 0;
    s.client.bytes_received = 0;
    s.client.last_status = 0;
    s.client.fail_cause = CAUSE_PEER;
    s.client.peer_closed = 0;
    s.client.phase = Phase::Init;
    s.client.h2_phase = 0;
    #[cfg(feature = "h3")]
    if s.h3_mode != 0 {
        super::h3::next_request(s);
    }
}

/// Validate the collected request and hand it to the phase machine, or answer
/// it with the refusal it earns. True when it was started.
unsafe fn adopt(s: &mut HttpState) -> bool {
    let Some(req) = s.client.ex.collector.request(0) else {
        s.client.ex.ready = 0;
        return false;
    };
    let id = req.id;
    let verdict = check(
        s,
        req.method,
        req.flags,
        req.target,
        req.headers,
        req.body.len(),
    );
    let code = match verdict {
        Ok(()) => 0,
        Err(code) => code,
    };
    if code != 0 {
        if !ctl_refuse(s, id, code) {
            return false;
        }
        let x = &mut s.client.ex;
        x.collector.release(0);
        x.queued = 0;
        x.ready = 0;
        return false;
    }
    // Re-read: `check` took the state, which ended the borrow.
    let Some(req) = s.client.ex.collector.request(0) else {
        return false;
    };
    let method = req.method;
    let resp_credit = req.resp_credit;
    let target_len = req.target.len();
    let body_len = req.body.len();
    let (t, b) = (req.target.as_ptr(), req.body.as_ptr());
    let (h, hl) = (req.headers.as_ptr(), req.headers.len());
    if target_len == 0 {
        s.client.path[0] = b'/';
        s.client.path_len = 1;
    } else {
        core::ptr::copy_nonoverlapping(t, s.client.path.as_mut_ptr(), target_len);
        s.client.path_len = target_len as u16;
    }
    core::ptr::copy_nonoverlapping(b, s.client.request_body.as_mut_ptr(), body_len);
    s.client.request_body_len = body_len as u16;
    s.client.request_body_sent = 0;
    // The requester's block, without what this client writes itself.
    let block = core::slice::from_raw_parts(h, hl);
    let mut out = 0usize;
    let mut host: (usize, usize) = (0, 0);
    let mut at = 0usize;
    for line in block.split(|&c| c == b'\n') {
        let start = at;
        at += line.len() + 1;
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"host") {
            let (vs, ve) = value_span(line, colon);
            host = (start + vs, start + ve);
            continue;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            continue;
        }
        let whole = line.len() + 1;
        s.client.request_headers[out..out + whole].copy_from_slice(&block[start..start + whole]);
        out += whole;
    }
    s.client.request_headers_len = out as u16;
    s.client.method = method;

    // The authority: a pinned client's own, or the request's `host`.
    if !pinned(s) {
        let a = &block[host.0..host.1];
        let n = a.len();
        if s.client.conn_present != 0
            && &s.client.conn_authority[..s.client.conn_authority_len as usize] != a
        {
            // Kept for its own authority rather than closed: the next request
            // may well be for the origin being left behind. `Init` parks it.
            s.client.conn_stale = 1;
        }
        let mut copy = [0u8; AUTHORITY_MAX];
        copy[..n].copy_from_slice(a);
        s.client.conn_authority[..n].copy_from_slice(&copy[..n]);
        s.client.conn_authority_len = n as u16;
    }

    let x = &mut s.client.ex;
    x.collector.release(0);
    x.queued = 0;
    x.ready = 0;
    x.live = 1;
    x.id = id;
    x.resp_credit = resp_credit;
    x.head_given = 0;
    x.ended = 0;
    x.abandoned = 0;
    x.abort_owed = 0;
    x.out_len = 0;
    x.resp_ct_len = 0;
    x.resp_hdrs_len = 0;
    x.resp_over = 0;
    rearm(s);
    true
}

/// The value of a `name: value` line whose colon is at `colon`, trimmed.
fn value_span(line: &[u8], colon: usize) -> (usize, usize) {
    let mut vs = colon + 1;
    let mut ve = line.len();
    if ve > vs && line[ve - 1] == b'\r' {
        ve -= 1;
    }
    while vs < ve && (line[vs] == b' ' || line[vs] == b'\t') {
        vs += 1;
    }
    while ve > vs && (line[ve - 1] == b' ' || line[ve - 1] == b'\t') {
        ve -= 1;
    }
    (vs, ve)
}

/// Whether this client performs a request with these fields, or the status it
/// is refused with.
fn check(
    s: &HttpState,
    method: u8,
    flags: u8,
    target: &[u8],
    headers: &[u8],
    body_len: usize,
) -> Result<(), u16> {
    if !matches!(
        method,
        METHOD_GET
            | METHOD_HEAD
            | METHOD_POST
            | METHOD_PUT
            | METHOD_PATCH
            | METHOD_DELETE
            | METHOD_OPTIONS
    ) || flags & (flag::BROADCAST | flag::WEBSOCKET | flag::WEBTRANSPORT) != 0
    {
        return Err(status::BAD_REQUEST);
    }
    if !target.is_empty()
        && (target[0] != b'/' || target.iter().any(|&c| !(0x21..=0x7e).contains(&c)))
    {
        return Err(status::BAD_REQUEST);
    }
    // Field lines, each `name: value` ending CRLF, and nothing else: a blank
    // line would end the head early and put what followed on the wire as a
    // second request; a bare CR or LF splits a line where the origin reads
    // one.
    if !headers.is_empty() && !headers.ends_with(b"\r\n") {
        return Err(status::BAD_REQUEST);
    }
    let mut host: Option<&[u8]> = None;
    for line in headers.split(|&c| c == b'\n') {
        if line.is_empty() {
            // The split's tail after the final LF.
            continue;
        }
        let Some(line) = line.strip_suffix(b"\r") else {
            return Err(status::BAD_REQUEST);
        };
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            return Err(status::BAD_REQUEST);
        };
        let name = &line[..colon];
        if name.is_empty()
            || !name.iter().all(|&c| tchar(c))
            || line[colon + 1..]
                .iter()
                .any(|&c| c == b'\r' || c == b'\n' || c == 0)
        {
            return Err(status::BAD_REQUEST);
        }
        if framing_field(name) {
            return Err(status::BAD_REQUEST);
        }
        let (vs, ve) = value_span(line, colon);
        let value = &line[vs..ve];
        if name.eq_ignore_ascii_case(b"content-length") {
            if parse_decimal(value) != Some(body_len as u64) {
                return Err(status::BAD_REQUEST);
            }
        } else if name.eq_ignore_ascii_case(b"host") {
            if host.is_some() {
                return Err(status::BAD_REQUEST);
            }
            host = Some(value);
        }
    }
    let own = &s.client.authority[..s.client.authority_len as usize];
    match host {
        Some(h) if !own.is_empty() => {
            if !h.eq_ignore_ascii_case(own) {
                return Err(status::BAD_REQUEST);
            }
        }
        Some(h) => {
            if h.len() > AUTHORITY_MAX {
                return Err(status::TOO_LARGE);
            }
            if Target::parse(h).is_none() {
                return Err(status::BAD_REQUEST);
            }
        }
        None if own.is_empty() => return Err(status::BAD_REQUEST),
        None => {}
    }
    Ok(())
}

fn parse_decimal(v: &[u8]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut n = 0u64;
    for &c in v {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(n)
}

// ── Answering ───────────────────────────────────────────────────────────

/// Whether the exchange in flight still wants its response.
pub(crate) fn answering(s: &HttpState) -> bool {
    let x = &s.client.ex;
    x.live != 0 && x.ended == 0 && x.abandoned == 0
}

/// Whether the response HEAD has been composed.
pub(crate) fn head_given(s: &HttpState) -> bool {
    s.client.ex.head_given != 0
}

/// Compose the response HEAD: the origin's `status`, `content_type`, and a
/// header block already rid of hop-by-hop fields. Its body follows through
/// [`body`]. False when it does not fit one record, in which case the
/// exchange has been answered 502.
pub(crate) unsafe fn head(
    s: &mut HttpState,
    code: u16,
    content_type: &[u8],
    headers: &[u8],
) -> bool {
    if !answering(s) || head_given(s) {
        return true;
    }
    let x = &mut s.client.ex;
    let composed = if content_type.len() > RESP_CT_MAX {
        None
    } else {
        write_response_head(
            &ResponseHead {
                id: x.id,
                flags: flag::MORE,
                status: code,
                content_type,
                headers,
                body: &[],
            },
            &mut x.out_rec,
        )
    };
    match composed {
        Some(n) => {
            x.out_len = n as u16;
            x.out_head = 1;
            x.head_given = 1;
            true
        }
        None => {
            log(s, b"[http] response head does not fit one record");
            refuse_live(s, status::BAD_GATEWAY);
            false
        }
    }
}

/// Compose the HEAD for an HTTP/1.1 response from the decoder's header block:
/// the content type lifted out, the hop-by-hop fields dropped.
pub(crate) unsafe fn head_from_block(s: &mut HttpState, code: u16) -> bool {
    let block_len = s.client.response.head_len as usize;
    let mut kept = [0u8; super::super::wire::response::RESPONSE_HEAD_MAX];
    let mut ct = [0u8; RESP_CT_MAX];
    let mut ct_len = 0usize;
    let mut n = 0usize;
    // Read in place: the decoder's block is not touched again before the
    // head is composed from the copy below.
    let block = core::slice::from_raw_parts(s.client.response.head_bytes.as_ptr(), block_len);
    for (name, value) in header_lines(block) {
        if name.eq_ignore_ascii_case(b"content-type") {
            if value.len() > RESP_CT_MAX {
                refuse_live(s, status::BAD_GATEWAY);
                return false;
            }
            ct[..value.len()].copy_from_slice(value);
            ct_len = value.len();
            continue;
        }
        if hop_field(name) {
            continue;
        }
        let need = name.len() + 2 + value.len() + 2;
        if n + need > kept.len() {
            refuse_live(s, status::BAD_GATEWAY);
            return false;
        }
        for part in [name, b": ", value, b"\r\n"] {
            kept[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
    }
    head(s, code, &ct[..ct_len], &kept[..n])
}

/// Record one field of a response decoded a field at a time (h2, h3).
pub(crate) fn note_field(s: &mut HttpState, name: &[u8], value: &[u8]) {
    let x = &mut s.client.ex;
    if name.starts_with(b":") || hop_field(name) {
        return;
    }
    if name.eq_ignore_ascii_case(b"content-type") {
        if value.len() > RESP_CT_MAX {
            x.resp_over = 1;
            return;
        }
        x.resp_ct[..value.len()].copy_from_slice(value);
        x.resp_ct_len = value.len() as u16;
        return;
    }
    let at = x.resp_hdrs_len as usize;
    let need = name.len() + 2 + value.len() + 2;
    if at + need > RESP_HDRS_MAX {
        x.resp_over = 1;
        return;
    }
    let mut p = at;
    for part in [name, b": ", value, b"\r\n"] {
        x.resp_hdrs[p..p + part.len()].copy_from_slice(part);
        p += part.len();
    }
    x.resp_hdrs_len = p as u16;
}

/// Compose the HEAD from the fields [`note_field`] recorded.
pub(crate) unsafe fn head_from_fields(s: &mut HttpState, code: u16) -> bool {
    if s.client.ex.resp_over != 0 {
        refuse_live(s, status::BAD_GATEWAY);
        return false;
    }
    let ct_len = s.client.ex.resp_ct_len as usize;
    let hl = s.client.ex.resp_hdrs_len as usize;
    let mut ct = [0u8; RESP_CT_MAX];
    ct[..ct_len].copy_from_slice(&s.client.ex.resp_ct[..ct_len]);
    let mut hdrs = [0u8; RESP_HDRS_MAX];
    hdrs[..hl].copy_from_slice(&s.client.ex.resp_hdrs[..hl]);
    head(s, code, &ct[..ct_len], &hdrs[..hl])
}

/// Offer the record in hand with MORE set or not. It leaves now or is held,
/// and either way a new one may be composed only once the outbox is clear.
unsafe fn send_out(s: &mut HttpState, more: bool) {
    let sys = &*s.syscalls;
    let x = &mut s.client.ex;
    let len = x.out_len as usize;
    if len == 0 {
        return;
    }
    let flags = if more { flag::MORE } else { 0 };
    if x.out_head != 0 {
        x.out_rec[1] = flags;
    } else if super::super::exchange::seal_body(&x.id, flags, len - HDR, &mut x.out_rec).is_none() {
        x.out_len = 0;
        return;
    }
    x.out_len = 0;
    x.out_box.send(sys, x.response_chan, &x.out_rec, len);
}

/// Take response body bytes, as many as the requester's credit and the record
/// in hand allow. Returns how many were taken; the caller keeps the rest and
/// offers them again. Bytes for an exchange nobody is waiting on are taken
/// and dropped.
///
/// # Safety
/// `src` must be valid for reads of `len` bytes and must not alias the
/// provider's records.
pub(crate) unsafe fn body(s: &mut HttpState, src: *const u8, len: usize) -> usize {
    if !answering(s) || !head_given(s) {
        return len;
    }
    let sys = &*s.syscalls;
    let mut taken = 0usize;
    while taken < len {
        let x = &mut s.client.ex;
        if x.out_box.holding() && !x.out_box.flush(sys, x.response_chan, &x.out_rec) {
            break;
        }
        let at = if x.out_len == 0 {
            HDR
        } else {
            x.out_len as usize
        };
        let n = (len - taken)
            .min(RECORD_MAX - at)
            .min(x.resp_credit as usize);
        if n == 0 {
            // The record is full, or the credit is spent: what is in hand
            // goes, so the requester has it while the rest waits.
            let spent = x.resp_credit == 0;
            send_out(s, true);
            if spent {
                break;
            }
            continue;
        }
        if x.out_len == 0 {
            x.out_head = 0;
        }
        core::ptr::copy_nonoverlapping(src.add(taken), x.out_rec.as_mut_ptr().add(at), n);
        x.out_len = (at + n) as u16;
        x.resp_credit -= n as u32;
        taken += n;
    }
    taken
}

/// Place a composed record that is not yet full: the step is ending and the
/// requester should not wait for more bytes to fill it.
pub(crate) unsafe fn flush_partial(s: &mut HttpState) {
    if answering(s) && s.client.ex.out_len != 0 && !s.client.ex.out_box.holding() {
        let x = &s.client.ex;
        // A bare BODY prefix is nothing to send.
        if x.out_head == 0 && x.out_len as usize == HDR {
            return;
        }
        send_out(s, true);
    }
}

/// End the response: the record in hand goes without MORE. False when the
/// outbox is still placing an earlier record; offer it again next step.
pub(crate) unsafe fn end(s: &mut HttpState) -> bool {
    if !answering(s) {
        return true;
    }
    if !head_given(s) {
        // A response that ended with no head is not one this client read.
        refuse_live(s, status::BAD_GATEWAY);
        return true;
    }
    let sys = &*s.syscalls;
    let x = &mut s.client.ex;
    if x.out_box.holding() && !x.out_box.flush(sys, x.response_chan, &x.out_rec) {
        return false;
    }
    if x.out_len == 0 {
        x.out_len = HDR as u16;
        x.out_head = 0;
    }
    x.ended = 1;
    send_out(s, false);
    let x = &mut s.client.ex;
    if !x.out_box.holding() {
        x.live = 0;
    }
    true
}

/// Refuse the exchange in flight with `code`, raised here, before any of its
/// response has gone.
unsafe fn refuse_live(s: &mut HttpState, code: u16) {
    let sys = &*s.syscalls;
    let x = &mut s.client.ex;
    x.out_len = 0;
    x.ended = 1;
    if let Some(n) = write_refusal(&x.id, code, &mut x.out_rec) {
        x.out_box.send(sys, x.response_chan, &x.out_rec, n);
    }
    if !x.out_box.holding() {
        x.live = 0;
    }
}

/// The exchange in flight failed for `why` (a `CAUSE_*`). Before its head
/// went the requester is answered with a status; after, with an ABORT. On a
/// pinned client a lost connection is a lost link: LINK DOWN instead.
pub(crate) unsafe fn fail(s: &mut HttpState, why: u8) {
    if s.client.ex.probing != 0 {
        s.client.ex.probing = 0;
        if matches!(why, CAUSE_CONNECT | CAUSE_LINK) {
            schedule_probe(s);
        }
        return;
    }
    if !answering(s) {
        if s.client.ex.abandoned != 0 {
            s.client.ex.live = 0;
            s.client.ex.abandoned = 0;
        }
        return;
    }
    // A pinned client has one backend, and an HTTP/3 client's link is the
    // session the transport holds; losing either is losing the link.
    if (pinned(s) || s.h3_mode != 0) && matches!(why, CAUSE_CONNECT | CAUSE_LINK) {
        link_lost(s);
        return;
    }
    if !head_given(s) {
        refuse_live(
            s,
            if why == CAUSE_TIMEOUT {
                status::TIMEOUT
            } else {
                status::BAD_GATEWAY
            },
        );
        return;
    }
    let reason = match why {
        CAUSE_TIMEOUT => abort::STALLED,
        CAUSE_LINK | CAUSE_CONNECT => abort::PEER_GONE,
        _ => abort::MALFORMED,
    };
    let x = &mut s.client.ex;
    x.out_len = 0;
    x.ended = 1;
    x.abort_owed = reason;
    service_abort(s);
}

/// Place an owed ABORT now if the outbox allows.
unsafe fn service_abort(s: &mut HttpState) {
    let sys = &*s.syscalls;
    let x = &mut s.client.ex;
    if x.abort_owed == 0 || x.out_box.holding() {
        return;
    }
    if let Some(n) = write_abort(&x.id, x.abort_owed, &mut x.out_rec) {
        x.out_box.send(sys, x.response_chan, &x.out_rec, n);
    }
    x.abort_owed = 0;
    if !x.out_box.holding() {
        x.live = 0;
    }
}

/// The backend link went down: everything held without a terminal response
/// is unknowable, and the requester is told so once.
pub(crate) unsafe fn link_lost(s: &mut HttpState) {
    let x = &mut s.client.ex;
    if x.live != 0 && x.ended == 0 {
        x.out_len = 0;
        x.ended = 1;
        if !x.out_box.holding() {
            x.live = 0;
        }
    }
    x.collector = RequestCollector::new();
    x.queued = 0;
    x.ready = 0;
    if x.link_down == 0 {
        x.link_down = 1;
        x.link_owed = link::DOWN;
        x.probe_wait_ms = PROBE_FIRST_MS;
    }
    log(s, b"[http] link down");
    schedule_probe(s);
}

/// Dial the lost link again after the current wait, doubling it.
unsafe fn schedule_probe(s: &mut HttpState) {
    let now = dev_millis(&*s.syscalls);
    let x = &mut s.client.ex;
    let wait = if x.probe_wait_ms == 0 {
        PROBE_FIRST_MS
    } else {
        x.probe_wait_ms
    };
    x.probe_at_ms = now.saturating_add(u64::from(wait));
    x.probe_wait_ms = wait.saturating_mul(2).min(PROBE_MAX_MS);
}

/// A connection to the origin opened. Reports the link back up if it was
/// down. True when the connection was only a probe, which the caller closes.
pub(crate) unsafe fn connected(s: &mut HttpState) -> bool {
    link_restored(s);
    if s.client.ex.probing != 0 {
        s.client.ex.probing = 0;
        return true;
    }
    false
}

/// The backend link is (re)connected.
pub(crate) fn link_restored(s: &mut HttpState) {
    let x = &mut s.client.ex;
    if x.link_down != 0 {
        x.link_down = 0;
        x.probe_wait_ms = 0;
        x.link_owed = link::UP;
    }
}

/// Draining: the exchange in flight and the one held are answered rather than
/// performed — 503 while nothing of a response has gone, an ABORT after.
pub(crate) unsafe fn drain(s: &mut HttpState) {
    if answering(s) {
        if head_given(s) {
            let x = &mut s.client.ex;
            x.out_len = 0;
            x.ended = 1;
            x.abort_owed = abort::DRAINING;
            service_abort(s);
        } else {
            refuse_live(s, status::BUSY);
        }
    }
    if s.client.ex.queued != 0 && !s.client.ex.ctl_box.holding() {
        let id = s.client.ex.queued_id;
        if ctl_refuse(s, id, Refuse::Busy.status()) {
            let x = &mut s.client.ex;
            x.collector = RequestCollector::new();
            x.queued = 0;
            x.ready = 0;
        }
    }
}
