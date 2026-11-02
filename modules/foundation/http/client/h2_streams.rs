//! HTTP/2 for the exchange provider: one connection, many exchanges, one
//! stream each.
//!
//! A graph-driven client speaking HTTP/2 keeps one connection to its origin
//! and opens a stream per exchange, so a requester holding several watches
//! open and making calls beside them needs one connection rather than one
//! module instance per request. Each exchange is collected by the provider
//! (`provider.rs`) exactly as for HTTP/1.1, handed here once it is whole, and
//! answered from its stream.
//!
//! # Streams
//!
//! - Stream ids are allocated per exchange, odd and increasing (RFC 9113
//!   §5.1.1). A connection whose ids run out, that the origin sends GOAWAY
//!   on, or that an open client needs for another authority, opens no more
//!   streams; it closes once the ones it carries have ended, and the next
//!   request dials anew.
//! - Up to [`STREAMS`] at once, fewer when the origin's
//!   `SETTINGS_MAX_CONCURRENT_STREAMS` says so. One more request is
//!   collected behind them; past that a request is answered 503, as on
//!   HTTP/1.1. While no stream is open, requests wait in the channel instead,
//!   so the burst a requester opens with reaches the connection whole.
//! - A stream's end is its own: RST_STREAM from the origin answers that
//!   exchange alone — 503 for `REFUSED_STREAM` (it was not processed), 502
//!   otherwise, an ABORT once its head has gone — and GOAWAY answers the
//!   streams past its last id 503 while those before it run to their end.
//! - A requester ABORT resets its stream (`CANCEL`); nothing else moves.
//!
//! # Flow control
//!
//! The receive window of a stream IS its requester's response credit. This
//! client advertises `SETTINGS_INITIAL_WINDOW_SIZE = 0` and opens each
//! stream's window by WINDOW_UPDATE as far as the requester has granted, so
//! the origin never sends a stream more than its requester will take, and a
//! requester that stops reading holds back its own stream and no other.
//! Every DATA byte can therefore be forwarded as it arrives: none is held
//! here, and a DATA frame of any length streams through `recv_buf`. The
//! connection's window is opened to [`CONN_WINDOW`] and refilled as it is
//! spent. Request bodies go out under the origin's stream and connection
//! windows and its `SETTINGS_MAX_FRAME_SIZE`.
//!
//! # Deadlines
//!
//! `client_header_ms` bounds the wait for a stream's head, `client_total_ms`
//! its whole exchange, `client_stall_ms` a response whose window is open and
//! whose origin sends nothing. A HELD exchange (`flag::HOLD` on the request
//! HEAD: a watch, an event stream) is answered `HOLD | MORE` and is bounded
//! only until its head: it ends when its origin ends it. Its connection is
//! kept honest instead — while any stream is open and nothing has arrived
//! for `client_stall_ms`, a PING goes out, and a connection that does not
//! answer it within `client_stall_ms` is lost.
//!
//! # A lost connection
//!
//! A pinned client's connection is its link: losing it is LINK DOWN for
//! every stream on it and every request held, exactly as on HTTP/1.1. An
//! open client answers each stream 502, or ABORT once its head has gone.
//!
//! # Scope
//!
//! HPACK as `wire::hpack` has it: static table and literals, no dynamic
//! table (`SETTINGS_HEADER_TABLE_SIZE = 0` is advertised). No CONTINUATION:
//! a response header block is one HEADERS frame, read whole, so it is
//! bounded by `RECV_BUF_SIZE`. No push (`SETTINGS_ENABLE_PUSH = 0`).
//! Trailers end the answer; their fields are not carried.

use super::super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_SEND, NET_MSG_CLOSED, NET_MSG_CONNECTED, NET_MSG_DATA,
    NET_MSG_ERROR,
};
use super::super::exchange::{abort, flag, status, ExchangeId, BODY_MAX};
use super::super::wire::h2 as h2w;
use super::super::wire::hpack;
use super::super::HttpState;
use super::super::{
    dev_millis, dev_requester_tag, net_read_frame, net_read_frame_sized, NET_FRAME_HDR, POLL_IN,
};
use super::{
    log, provider, send_close_frame, AUTHORITY_MAX, CAUSE_CONNECT, CAUSE_LINK, CAUSE_TIMEOUT,
    CONNECT_TIMEOUT_MS, GEN_H1, GEN_H2, RECV_BUF_SIZE, REQUEST_BUF_SIZE,
};

/// Exchanges one connection carries at once.
pub(crate) const STREAMS: usize = 16;
/// The connection's receive window, opened in the preface and refilled as
/// it is spent. What bounds a stream is its own window; this only has to
/// keep the streams from waiting on each other.
const CONN_WINDOW: u32 = 1 << 20;
/// The largest window HTTP/2 can express (§6.9.1).
const WINDOW_MAX: u32 = 0x7fff_ffff;
/// The largest stream id (§5.1.1).
const SID_MAX: u32 = 0x7fff_ffff;
/// The longest field name a requester's header block may carry here: names
/// are lowercased into a buffer of this size on their way into HPACK.
const FIELD_NAME_MAX: usize = 128;
/// The default and least `SETTINGS_MAX_FRAME_SIZE` (§6.5.2).
const FRAME_SIZE_MIN: u32 = 16_384;
const FRAME_SIZE_MAX: u32 = 16_777_215;
/// The default initial window (§6.9.2).
const WINDOW_DEFAULT: i32 = 65_535;
/// Frames read and processed per step.
const FRAMES_PER_STEP: usize = 16;

// Connection phases.
const IDLE: u8 = 0;
const DIALING: u8 = 1;
const CONNECTING: u8 = 2;
/// The preface is sent; the origin's SETTINGS are awaited.
const HANDSHAKE: u8 = 3;
const READY: u8 = 4;
/// No more streams are opened; the connection closes once the open ones end.
const CLOSING: u8 = 5;

// Stream states.
const FREE: u8 = 0;
/// On the connection, answering.
const OPEN: u8 = 1;
/// Off the connection: answered, or owing only the record and RST below.
const DONE: u8 = 2;

// The terminal record a stream owes its requester.
const OWE_NONE: u8 = 0;
/// A raised status, `owed_val`.
const OWE_STATUS: u8 = 1;
/// An ABORT, reason `owed_val`.
const OWE_ABORT: u8 = 2;
/// An empty BODY without MORE: the answer is complete.
const OWE_END: u8 = 3;

#[derive(Clone, Copy)]
pub(crate) struct Stream {
    state: u8,
    held: u8,
    head_given: u8,
    /// The request has been sent whole (END_STREAM).
    local_end: u8,
    owed: u8,
    /// A RST_STREAM for `rst_sid` with `rst_code` is owed the origin.
    rst_owed: u8,
    owed_val: u16,
    /// The stream id while OPEN; 0 once off the connection.
    sid: u32,
    rst_sid: u32,
    rst_code: u32,
    id: ExchangeId,
    /// Response credit the requester has granted and this client has not yet
    /// opened as window.
    credit: u32,
    /// Window open to the origin and not yet spent.
    win_open: u32,
    /// The origin's window for this stream's request body.
    send_window: i32,
    start_ms: u64,
    /// The request went whole: the head is awaited from here.
    sent_ms: u64,
    /// The last response byte, or the moment the stream last waited on its
    /// requester rather than its origin.
    progress_ms: u64,
}

impl Stream {
    const EMPTY: Self = Stream {
        state: FREE,
        held: 0,
        head_given: 0,
        local_end: 0,
        owed: OWE_NONE,
        rst_owed: 0,
        owed_val: 0,
        sid: 0,
        rst_sid: 0,
        rst_code: 0,
        id: ExchangeId::NONE,
        credit: 0,
        win_open: 0,
        send_window: 0,
        start_ms: 0,
        sent_ms: 0,
        progress_ms: 0,
    };
}

/// The connection and its streams. Valid zeroed: an idle client with none.
pub(crate) struct Streams {
    phase: u8,
    /// The origin's GOAWAY arrived.
    goaway: u8,
    settings_ack_owed: u8,
    ping_ack_owed: u8,
    /// A keepalive PING is due to go out.
    ping_due: u8,
    /// A keepalive PING is out, unanswered.
    ping_out: u8,
    /// The connection let go of still owes the transport its CLOSE.
    close_owed: u8,
    /// Inside a DATA frame: `rx_left` body bytes then `rx_pad` padding to come.
    rx_in_data: u8,
    rx_end: u8,
    /// The stream whose request is in the client's fields, plus one: its
    /// body is still going out. 0 when the fields are free.
    opening: u8,
    authority_len: u16,
    authority: [u8; AUTHORITY_MAX],
    next_sid: u32,
    peer_max_streams: u32,
    peer_initial_window: i32,
    peer_max_frame: u32,
    conn_send_window: i32,
    conn_recv_left: u32,
    rx_sid: u32,
    rx_left: u32,
    rx_pad: u32,
    ping_opaque: [u8; 8],
    connect_ms: u64,
    rx_ms: u64,
    ping_ms: u64,
    streams: [Stream; STREAMS],
}

// ── What the provider and the step ask ──────────────────────────────────

/// Whether HTTP/2 streams carry this client's exchanges now: a connection
/// is held or being opened, a stream still owes something, or the next
/// connection is expected to speak HTTP/2 and HTTP/1.1 holds nothing.
pub(crate) fn holds_requests(s: &HttpState) -> bool {
    if s.h3_mode != 0 || !provider::armed(s) || provider::probing(s) {
        return false;
    }
    let st = &s.client.streams;
    st.phase != IDLE
        || st.close_owed != 0
        || live(s)
        || (super::preferred_generation(s) == GEN_H2 && s.client.conn_present == 0)
}

/// Whether any stream is in use.
pub(crate) fn live(s: &HttpState) -> bool {
    s.client.streams.streams.iter().any(|t| t.state != FREE)
}

/// Nothing is owed and no connection is held.
pub(crate) fn quiet(s: &HttpState) -> bool {
    s.client.streams.phase == IDLE && s.client.streams.close_owed == 0 && !live(s)
}

/// Let the connection in hand go. A CLOSE the transport refuses is retried
/// before anything else is dialled.
unsafe fn let_go(s: &mut HttpState) {
    s.client.recv_len = 0;
    s.client.request_len = 0;
    s.client.request_sent = 0;
    s.client.conn_stale = 0;
    s.client.streams.phase = IDLE;
    s.client.streams.close_owed = u8::from(!send_close_frame(s));
}

fn find_open(st: &Streams, id: &ExchangeId) -> Option<usize> {
    st.streams
        .iter()
        .position(|t| t.state == OPEN && t.id == *id)
}

fn find_sid(st: &Streams, sid: u32) -> Option<usize> {
    if sid == 0 {
        return None;
    }
    st.streams
        .iter()
        .position(|t| t.state == OPEN && t.sid == sid)
}

/// A requester's CREDIT or ABORT for an exchange a stream carries. True
/// when it was one.
pub(crate) fn requester_record(
    s: &mut HttpState,
    id: &ExchangeId,
    credit: u32,
    aborted: bool,
) -> bool {
    let st = &mut s.client.streams;
    let Some(i) = find_open(st, id) else {
        return false;
    };
    if aborted {
        // Nothing more is written for it; the origin is told to stop.
        let t = &mut st.streams[i];
        if t.sid != 0 {
            t.rst_owed = 1;
            t.rst_sid = t.sid;
            t.rst_code = h2w::ERR_CANCEL;
        }
        t.sid = 0;
        t.state = DONE;
        t.owed = OWE_NONE;
        if st.opening as usize == i + 1 {
            st.opening = 0;
        }
    } else {
        st.streams[i].credit = st.streams[i].credit.saturating_add(credit);
    }
    true
}

// ── The connection ───────────────────────────────────────────────────────

/// Fresh connection state, for the connection in hand.
unsafe fn begin(s: &mut HttpState, now: u64) {
    let n = s.client.conn_authority_len as usize;
    let st = &mut s.client.streams;
    st.authority[..n].copy_from_slice(&s.client.conn_authority[..n]);
    st.authority_len = n as u16;
    st.goaway = 0;
    st.settings_ack_owed = 0;
    st.ping_ack_owed = 0;
    st.ping_due = 0;
    st.ping_out = 0;
    st.rx_in_data = 0;
    st.rx_end = 0;
    st.opening = 0;
    st.next_sid = 1;
    st.peer_max_streams = u32::MAX;
    st.peer_initial_window = WINDOW_DEFAULT;
    st.peer_max_frame = FRAME_SIZE_MIN;
    st.conn_send_window = WINDOW_DEFAULT;
    st.conn_recv_left = CONN_WINDOW;
    st.connect_ms = now;
    st.rx_ms = now;
    st.phase = HANDSHAKE;
    s.client.recv_len = 0;
    s.client.request_len = 0;
    s.client.request_sent = 0;
    // The preface, this client's SETTINGS, and the connection window opened.
    let buf = s.client.request_buf.as_mut_ptr();
    core::ptr::copy_nonoverlapping(h2w::PREFACE.as_ptr(), buf, h2w::PREFACE.len());
    let mut o = h2w::PREFACE.len();
    o += h2w::write_settings(
        buf.add(o),
        &[
            (h2w::SETTINGS_HEADER_TABLE_SIZE, 0),
            (h2w::SETTINGS_ENABLE_PUSH, 0),
            (h2w::SETTINGS_MAX_CONCURRENT_STREAMS, 0),
            // A stream's window is its requester's credit, opened per stream.
            (h2w::SETTINGS_INITIAL_WINDOW_SIZE, 0),
            (
                h2w::SETTINGS_MAX_HEADER_LIST_SIZE,
                provider::RESP_HDRS_MAX as u32,
            ),
        ],
    );
    o += h2w::write_window_update(buf.add(o), 0, CONN_WINDOW - WINDOW_DEFAULT as u32);
    s.client.request_len = o as u16;
}

/// Take the connection in hand, which a session stage negotiated h2 for,
/// from the HTTP/1.1 phase machine that dialled it.
pub(crate) unsafe fn take_connection(s: &mut HttpState) {
    let now = dev_millis(&*s.syscalls);
    begin(s, now);
    log(s, b"[http] h2 negotiated");
}

/// The connection is gone, for `cause`. Every stream on it is answered
/// according to whose link it was.
unsafe fn lost(s: &mut HttpState, cause: u8) {
    let pinned = s.client.authority_len != 0;
    let mut dropped = false;
    {
        let st = &mut s.client.streams;
        for t in st.streams.iter_mut() {
            if t.state != OPEN {
                continue;
            }
            dropped = true;
            t.sid = 0;
            t.rst_owed = 0;
            t.state = DONE;
            if pinned {
                // Unknowable: LINK DOWN says so for all of them at once.
                t.owed = OWE_NONE;
            } else if t.head_given != 0 {
                t.owed = OWE_ABORT;
                t.owed_val = abort::PEER_GONE as u16;
            } else {
                t.owed = OWE_STATUS;
                t.owed_val = status::BAD_GATEWAY;
            }
        }
        for t in st.streams.iter_mut() {
            t.rst_owed = 0;
        }
        st.phase = IDLE;
        st.opening = 0;
        st.rx_in_data = 0;
    }
    let_go(s);
    let waiting = provider::unopened(s);
    if !dropped && !waiting {
        // An idle connection closed: nothing was lost, and the next request
        // dials anew.
        return;
    }
    log(s, b"[http] h2 connection lost");
    if pinned {
        provider::link_lost(s, dropped);
    } else if waiting {
        provider::fail(s, cause);
    }
}

/// A connection error of ours (`code`): GOAWAY, then the connection is lost.
unsafe fn fatal(s: &mut HttpState, code: u32) {
    if s.client.request_len == 0 {
        let n = h2w::write_goaway(s.client.request_buf.as_mut_ptr(), 0, code);
        s.client.request_len = n as u16;
        s.client.request_sent = 0;
        flush_tx(s);
    }
    lost(s, CAUSE_LINK);
}

/// One step of the HTTP/2 path.
pub(crate) unsafe fn step(s: &mut HttpState) {
    let now = dev_millis(&*s.syscalls);
    match s.client.streams.phase {
        IDLE => {
            if s.client.streams.close_owed != 0 {
                if !send_close_frame(s) {
                    return;
                }
                s.client.streams.close_owed = 0;
            }
            super::drain_unowned(s);
            pump_out(s);
            if !provider::unopened(s) && !provider::start(s) {
                return;
            }
            if provider::probing(s) || !provider::unopened(s) {
                return;
            }
            s.client.streams.phase = DIALING;
            dial(s, now);
        }
        DIALING => dial(s, now),
        CONNECTING => connecting(s, now),
        _ => run(s, now),
    }
}

unsafe fn dial(s: &mut HttpState, now: u64) {
    match super::dial(s) {
        Some(true) => {
            s.client.streams.phase = CONNECTING;
            s.client.streams.connect_ms = now;
            log(s, b"[http] connecting (h2)");
        }
        Some(false) => {}
        None => {
            log(s, b"[http] no authority to dial");
            s.client.streams.phase = IDLE;
            provider::fail(s, CAUSE_CONNECT);
        }
    }
}

/// Wait for the dial's answer: the connection, or the refusal tagged with
/// this client's dial — a failed connect, a failed handshake (`ECONNREFUSED`
/// from a session stage), or a stage not yet able to dial (`EAGAIN`). Each
/// failure is the link's: the provider reports it and probes with backoff.
unsafe fn connecting(s: &mut HttpState, now: u64) {
    if s.net_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    for _ in 0..8 {
        let poll = (sys.channel_poll)(chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let buf = s.net_buf.as_mut_ptr();
        let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
        if msg_type == 0 {
            break;
        }
        let payload = core::slice::from_raw_parts(buf.add(NET_FRAME_HDR), payload_len);
        let me = dev_requester_tag(sys);
        if msg_type == NET_MSG_CONNECTED && payload_len >= 2 {
            let (conn, tag) = net_proto::connected_parts(payload);
            if tag != 0 && tag != me {
                continue;
            }
            s.client.conn_id = conn;
            s.client.conn_present = 1;
            let generation = super::negotiate(s, payload);
            log(s, b"[http] connected");
            let _ = provider::connected(s);
            if generation == GEN_H1 {
                // The origin agreed HTTP/1.1 for this connection: the
                // request waiting for it goes there instead.
                s.client.streams.phase = IDLE;
                if provider::unopened(s) {
                    s.client.phase = super::Phase::Init;
                } else {
                    let_go(s);
                }
                return;
            }
            begin(s, now);
            return;
        }
        if msg_type == NET_MSG_ERROR && payload_len >= 3 {
            let (_, _, tag) = net_proto::error_parts(payload);
            if tag == 0 || tag == me {
                log(s, b"[http] connect error");
                s.client.streams.phase = IDLE;
                provider::fail(s, CAUSE_CONNECT);
                return;
            }
        }
    }
    if now.wrapping_sub(s.client.streams.connect_ms) >= CONNECT_TIMEOUT_MS {
        log(s, b"[http] connect timeout");
        s.client.streams.phase = IDLE;
        provider::fail(s, CAUSE_CONNECT);
    }
}

/// An established connection: frames in, deadlines, streams opened, frames
/// out, answers owed.
unsafe fn run(s: &mut HttpState, now: u64) {
    for _ in 0..FRAMES_PER_STEP {
        let pumped = match pump_inbound(s) {
            Inbound::Lost => {
                lost(s, CAUSE_LINK);
                return;
            }
            Inbound::Read => true,
            Inbound::None => false,
        };
        match process(s, now) {
            Err(code) => {
                fatal(s, code);
                return;
            }
            Ok(Flow::Blocked) => break,
            Ok(Flow::NeedMore) if !pumped => break,
            Ok(_) => {}
        }
    }
    if s.client.streams.phase == HANDSHAKE
        && now.wrapping_sub(s.client.streams.connect_ms) >= CONNECT_TIMEOUT_MS
    {
        log(s, b"[http] h2 settings timeout");
        lost(s, CAUSE_CONNECT);
        return;
    }
    deadlines(s, now);
    if keepalive_failed(s, now) {
        log(s, b"[http] h2 keepalive unanswered");
        lost(s, CAUSE_TIMEOUT);
        return;
    }
    queue_control(s);
    if !flush_tx(s) {
        pump_out(s);
        return;
    }
    // Open what is waiting, one stream after another while the connection
    // takes them and each request goes whole.
    for _ in 0..STREAMS {
        if !claim(s, now) {
            break;
        }
        send_body(s, now);
        if !flush_tx(s) {
            break;
        }
    }
    send_body(s, now);
    queue_control(s);
    flush_tx(s);
    pump_out(s);
    // A connection opening no more streams closes once its last has ended.
    let st = &s.client.streams;
    if st.phase == CLOSING
        && !st
            .streams
            .iter()
            .any(|t| t.state == OPEN || t.rst_owed != 0)
        && s.client.request_len == 0
    {
        let_go(s);
        log(s, b"[http] h2 connection closed");
    }
}

// ── Inbound ──────────────────────────────────────────────────────────────

enum Inbound {
    None,
    Read,
    Lost,
}

/// Move one `MSG_DATA` for this connection into `recv_buf`, while it has
/// room for the largest one. Another connection's frames are someone
/// else's, on a fanned lane, and are passed over.
unsafe fn pump_inbound(s: &mut HttpState) -> Inbound {
    if s.net_in_chan < 0 {
        return Inbound::None;
    }
    if s.client.recv_len as usize + super::super::connection::MAX_DATA_FRAGMENT > RECV_BUF_SIZE {
        return Inbound::None;
    }
    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    let poll = (sys.channel_poll)(chan, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return Inbound::None;
    }
    let buf = s.net_buf.as_mut_ptr();
    let (msg_type, payload_len, _) = net_read_frame_sized(sys, chan, buf, NET_BUF_SIZE);
    if !matches!(msg_type, NET_MSG_DATA | NET_MSG_CLOSED | NET_MSG_ERROR) || payload_len < 2 {
        return Inbound::None;
    }
    let payload = core::slice::from_raw_parts(buf.add(NET_FRAME_HDR), payload_len);
    if net_proto::conn_id(payload) != s.client.conn_id {
        return Inbound::None;
    }
    if msg_type != NET_MSG_DATA {
        return Inbound::Lost;
    }
    let data = &payload[2..];
    let at = s.client.recv_len as usize;
    let n = data.len().min(RECV_BUF_SIZE - at);
    s.client.recv_buf[at..at + n].copy_from_slice(&data[..n]);
    s.client.recv_len = (at + n) as u16;
    Inbound::Read
}

enum Flow {
    /// Nothing more can be read without more bytes.
    NeedMore,
    /// A record for a requester could not be placed: wait for the outbox.
    Blocked,
}

/// Shift `n` bytes off the front of `recv_buf`.
fn consume(s: &mut HttpState, n: usize) {
    let len = s.client.recv_len as usize;
    let n = n.min(len);
    s.client.recv_buf.copy_within(n..len, 0);
    s.client.recv_len = (len - n) as u16;
}

fn be32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

/// Read frames out of `recv_buf` until more bytes are needed or a record
/// cannot be placed. `Err` is a connection error and its code.
unsafe fn process(s: &mut HttpState, now: u64) -> Result<Flow, u32> {
    loop {
        if s.client.streams.rx_in_data != 0 {
            if !data_bytes(s, now) {
                return Ok(Flow::Blocked);
            }
            if s.client.streams.rx_in_data != 0 {
                return Ok(Flow::NeedMore);
            }
            continue;
        }
        let len = s.client.recv_len as usize;
        let Some(hdr) = h2w::parse_header(s.client.recv_buf.as_ptr(), len) else {
            return Ok(Flow::NeedMore);
        };
        s.client.streams.rx_ms = now;
        if hdr.ftype == h2w::FRAME_DATA {
            if !data_header(s, &hdr, now)? {
                return Ok(Flow::NeedMore);
            }
            continue;
        }
        let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
        if total > RECV_BUF_SIZE {
            // A frame this client cannot hold whole: a header block past what
            // a response here carries.
            return Err(h2w::ERR_FRAME_SIZE_ERROR);
        }
        if total > len {
            return Ok(Flow::NeedMore);
        }
        if s.client.streams.phase == HANDSHAKE && hdr.ftype != h2w::FRAME_SETTINGS {
            // §3.4: the server's preface is a SETTINGS frame.
            return Err(h2w::ERR_PROTOCOL_ERROR);
        }
        let p = core::slice::from_raw_parts(
            s.client.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN),
            hdr.length as usize,
        );
        match hdr.ftype {
            h2w::FRAME_HEADERS => {
                if !headers(s, &hdr, now)? {
                    return Ok(Flow::Blocked);
                }
            }
            h2w::FRAME_SETTINGS => {
                if hdr.stream_id != 0 {
                    return Err(h2w::ERR_PROTOCOL_ERROR);
                }
                if hdr.flags & h2w::FLAG_ACK == 0 {
                    if hdr.length % 6 != 0 {
                        return Err(h2w::ERR_FRAME_SIZE_ERROR);
                    }
                    settings(s, p)?;
                    let st = &mut s.client.streams;
                    st.settings_ack_owed = st.settings_ack_owed.saturating_add(1);
                    if st.phase == HANDSHAKE {
                        st.phase = READY;
                        log(s, b"[http] h2 ready");
                    }
                }
            }
            h2w::FRAME_PING => {
                if hdr.stream_id != 0 || hdr.length != 8 {
                    return Err(h2w::ERR_PROTOCOL_ERROR);
                }
                let st = &mut s.client.streams;
                if hdr.flags & h2w::FLAG_ACK != 0 {
                    st.ping_out = 0;
                } else {
                    st.ping_opaque.copy_from_slice(&p[..8]);
                    st.ping_ack_owed = 1;
                }
            }
            h2w::FRAME_GOAWAY => {
                if hdr.stream_id != 0 || hdr.length < 8 {
                    return Err(h2w::ERR_PROTOCOL_ERROR);
                }
                let last = be32(p) & SID_MAX;
                go_away(s, last);
            }
            h2w::FRAME_WINDOW_UPDATE => {
                if hdr.length != 4 {
                    return Err(h2w::ERR_FRAME_SIZE_ERROR);
                }
                let delta = be32(p) & WINDOW_MAX;
                window_update(s, hdr.stream_id, delta)?;
            }
            h2w::FRAME_RST_STREAM => {
                if hdr.length != 4 {
                    return Err(h2w::ERR_FRAME_SIZE_ERROR);
                }
                if hdr.stream_id == 0 {
                    return Err(h2w::ERR_PROTOCOL_ERROR);
                }
                let code = be32(p);
                reset_by_peer(s, hdr.stream_id, code);
            }
            // Push is disabled, and a header block never continues here.
            h2w::FRAME_PUSH_PROMISE | h2w::FRAME_CONTINUATION => {
                return Err(h2w::ERR_PROTOCOL_ERROR);
            }
            // PRIORITY and unknown types are ignored (§5.5).
            _ => {}
        }
        consume(s, total);
    }
}

/// The header of a DATA frame, and its pad length when padded: account its
/// whole length against the windows, then read its body as it arrives.
/// False when the pad length has not arrived yet.
unsafe fn data_header(s: &mut HttpState, hdr: &h2w::Header, now: u64) -> Result<bool, u32> {
    let len = s.client.recv_len as usize;
    let padded = hdr.flags & h2w::FLAG_PADDED != 0;
    let off = h2w::FRAME_HEADER_LEN + usize::from(padded);
    if len < off {
        return Ok(false);
    }
    if hdr.stream_id == 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    let pad = if padded {
        u32::from(s.client.recv_buf[h2w::FRAME_HEADER_LEN])
    } else {
        0
    };
    let pad_total = pad + u32::from(padded);
    if pad_total > hdr.length {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    let st = &mut s.client.streams;
    if hdr.length > st.conn_recv_left {
        return Err(h2w::ERR_FLOW_CONTROL_ERROR);
    }
    st.conn_recv_left -= hdr.length;
    let body = hdr.length - pad_total;
    if let Some(i) = find_sid(st, hdr.stream_id) {
        let t = &mut st.streams[i];
        if t.head_given == 0 {
            // §8.1: DATA before the response's HEADERS.
            detach(
                st,
                i,
                OWE_STATUS,
                status::BAD_GATEWAY,
                h2w::ERR_PROTOCOL_ERROR,
            );
        } else if hdr.length > t.win_open {
            // Past the window, which is past what the requester granted.
            detach(
                st,
                i,
                OWE_ABORT,
                abort::CREDIT_OVERRUN as u16,
                h2w::ERR_FLOW_CONTROL_ERROR,
            );
        } else {
            t.win_open -= hdr.length;
            // Padding spends window but is no body: it goes back to the
            // credit it was opened from.
            t.credit = t.credit.saturating_add(pad_total);
            t.progress_ms = now;
        }
    }
    st.rx_in_data = 1;
    st.rx_sid = hdr.stream_id;
    st.rx_left = body;
    st.rx_pad = pad;
    st.rx_end = u8::from(hdr.flags & h2w::FLAG_END_STREAM != 0);
    consume(s, off);
    Ok(true)
}

/// Forward the body bytes of the DATA frame being read, as far as they have
/// arrived. False when a record could not be placed.
unsafe fn data_bytes(s: &mut HttpState, now: u64) -> bool {
    loop {
        let avail = s.client.recv_len as usize;
        let st = &mut s.client.streams;
        if st.rx_left > 0 {
            if avail == 0 {
                return true;
            }
            let n = avail.min(st.rx_left as usize).min(BODY_MAX);
            let ends = n == st.rx_left as usize && st.rx_pad == 0 && st.rx_end != 0;
            if let Some(i) = find_sid(st, st.rx_sid) {
                let id = st.streams[i].id;
                let src = s.client.recv_buf.as_ptr();
                if !provider::stream_body(s, &id, src, n, !ends) {
                    return false;
                }
                let st = &mut s.client.streams;
                st.streams[i].progress_ms = now;
                if ends {
                    finish(st, i);
                }
            }
            consume(s, n);
            s.client.streams.rx_left -= n as u32;
            continue;
        }
        if st.rx_pad > 0 {
            if avail == 0 {
                return true;
            }
            let n = avail.min(st.rx_pad as usize);
            st.rx_pad -= n as u32;
            consume(s, n);
            continue;
        }
        // The frame is read. An END_STREAM its body did not carry — an
        // empty or padded last frame — ends the answer here.
        if st.rx_end != 0 {
            if let Some(i) = find_sid(st, st.rx_sid) {
                let id = st.streams[i].id;
                if !provider::stream_body(s, &id, core::ptr::null(), 0, false) {
                    return false;
                }
                finish(&mut s.client.streams, i);
            }
        }
        s.client.streams.rx_in_data = 0;
        return true;
    }
}

/// A HEADERS frame, whole in `recv_buf`: a response head, or trailers that
/// end it. False when a record could not be placed; the frame stays.
unsafe fn headers(s: &mut HttpState, hdr: &h2w::Header, now: u64) -> Result<bool, u32> {
    if hdr.flags & h2w::FLAG_END_HEADERS == 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if hdr.stream_id == 0 || hdr.stream_id & 1 == 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    let payload = s.client.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN);
    let (off, block_len) = h2w::headers_block_extent(payload, hdr.length, hdr.flags)
        .map_err(|_| h2w::ERR_PROTOCOL_ERROR)?;
    let block = payload.add(off);
    let end = hdr.flags & h2w::FLAG_END_STREAM != 0;
    let Some(i) = find_sid(&s.client.streams, hdr.stream_id) else {
        // A stream this client has already let go of. Its block is still
        // checked, and otherwise dropped.
        hpack::decode_block(block, block_len, |_, _| {}).map_err(|_| h2w::ERR_COMPRESSION_ERROR)?;
        return Ok(true);
    };
    let t = s.client.streams.streams[i];
    if t.head_given != 0 {
        // Trailers: they end the answer, and carry nothing a requester reads.
        hpack::decode_block(block, block_len, |_, _| {}).map_err(|_| h2w::ERR_COMPRESSION_ERROR)?;
        let st = &mut s.client.streams;
        if !end {
            detach(
                st,
                i,
                OWE_ABORT,
                abort::MALFORMED as u16,
                h2w::ERR_PROTOCOL_ERROR,
            );
            return Ok(true);
        }
        if !provider::stream_body(s, &t.id, core::ptr::null(), 0, false) {
            return Ok(false);
        }
        finish(&mut s.client.streams, i);
        return Ok(true);
    }
    provider::clear_fields(s);
    let mut code: u16 = 0;
    let code_ptr = &mut code as *mut u16;
    let sp = s as *mut HttpState;
    hpack::decode_block(block, block_len, |name, value| {
        if name == b":status" {
            let mut v: u16 = 0;
            if value.len() == 3 && value.iter().all(|c| c.is_ascii_digit()) {
                for &c in value {
                    v = v * 10 + u16::from(c - b'0');
                }
            }
            *code_ptr = v;
        } else {
            provider::note_field(&mut *sp, name, value);
        }
    })
    .map_err(|_| h2w::ERR_COMPRESSION_ERROR)?;
    if code < 200 {
        // An interim response (1xx) is not the answer and cannot end the
        // stream; a head with no readable status is not one.
        if code < 100 || code == 101 || end {
            detach(
                &mut s.client.streams,
                i,
                OWE_STATUS,
                status::BAD_GATEWAY,
                h2w::ERR_PROTOCOL_ERROR,
            );
        }
        return Ok(true);
    }
    let flags = if end {
        0
    } else {
        flag::MORE | if t.held != 0 { flag::HOLD } else { 0 }
    };
    match provider::stream_head(s, &t.id, code, flags) {
        None => Ok(false),
        Some(false) => {
            log(s, b"[http] response head does not fit one record");
            detach(
                &mut s.client.streams,
                i,
                OWE_STATUS,
                status::BAD_GATEWAY,
                h2w::ERR_CANCEL,
            );
            Ok(true)
        }
        Some(true) => {
            let st = &mut s.client.streams;
            st.streams[i].head_given = 1;
            st.streams[i].progress_ms = now;
            if end {
                finish(st, i);
            }
            Ok(true)
        }
    }
}

/// The origin's SETTINGS, whole.
unsafe fn settings(s: &mut HttpState, p: &[u8]) -> Result<(), u32> {
    let st = &mut s.client.streams;
    for e in p.chunks_exact(6) {
        let id = u16::from_be_bytes([e[0], e[1]]);
        let v = be32(&e[2..]);
        if id == h2w::SETTINGS_MAX_CONCURRENT_STREAMS {
            st.peer_max_streams = v;
        } else if id == h2w::SETTINGS_INITIAL_WINDOW_SIZE {
            if v > WINDOW_MAX {
                return Err(h2w::ERR_FLOW_CONTROL_ERROR);
            }
            // §6.9.2: the change applies to every open stream's window.
            let delta = v as i32 - st.peer_initial_window;
            st.peer_initial_window = v as i32;
            for t in st.streams.iter_mut() {
                if t.state == OPEN && t.sid != 0 {
                    t.send_window = t.send_window.saturating_add(delta);
                }
            }
        } else if id == h2w::SETTINGS_MAX_FRAME_SIZE {
            if !(FRAME_SIZE_MIN..=FRAME_SIZE_MAX).contains(&v) {
                return Err(h2w::ERR_PROTOCOL_ERROR);
            }
            st.peer_max_frame = v;
        }
    }
    Ok(())
}

unsafe fn window_update(s: &mut HttpState, sid: u32, delta: u32) -> Result<(), u32> {
    let st = &mut s.client.streams;
    if sid == 0 {
        let w = i64::from(st.conn_send_window) + i64::from(delta);
        if w > i64::from(WINDOW_MAX) {
            return Err(h2w::ERR_FLOW_CONTROL_ERROR);
        }
        st.conn_send_window = w as i32;
        return Ok(());
    }
    if let Some(i) = find_sid(st, sid) {
        let w = i64::from(st.streams[i].send_window) + i64::from(delta);
        if w > i64::from(WINDOW_MAX) {
            let (owe, val) = refusal_for(&st.streams[i], status::BAD_GATEWAY);
            detach(st, i, owe, val, h2w::ERR_FLOW_CONTROL_ERROR);
        } else {
            st.streams[i].send_window = w as i32;
        }
    }
    Ok(())
}

/// The origin reset a stream: that exchange alone is answered.
unsafe fn reset_by_peer(s: &mut HttpState, sid: u32, code: u32) {
    let st = &mut s.client.streams;
    let Some(i) = find_sid(st, sid) else {
        return;
    };
    // Refused before it was processed: repeating it is safe.
    let raised = if code == h2w::ERR_REFUSED_STREAM {
        status::BUSY
    } else {
        status::BAD_GATEWAY
    };
    let (owe, val) = refusal_for(&st.streams[i], raised);
    detach(st, i, owe, val, 0);
}

/// GOAWAY: the streams past `last` were never processed and are answered
/// 503; those up to it run to their end on a connection opening no more.
unsafe fn go_away(s: &mut HttpState, last: u32) {
    let st = &mut s.client.streams;
    st.goaway = 1;
    st.phase = CLOSING;
    for i in 0..STREAMS {
        let t = &st.streams[i];
        if t.state == OPEN && t.sid > last {
            detach(st, i, OWE_STATUS, status::BUSY, 0);
        }
    }
    log(s, b"[http] h2 goaway");
}

/// The answer a stream that failed is owed: `raised` before its head went,
/// an ABORT after.
fn refusal_for(t: &Stream, raised: u16) -> (u8, u16) {
    if t.head_given != 0 {
        (OWE_ABORT, abort::PEER_GONE as u16)
    } else {
        (OWE_STATUS, raised)
    }
}

/// Take stream `i` off the connection, owing its requester `owe` (`val`) and
/// the origin a RST_STREAM with `rst` (none when 0).
fn detach(st: &mut Streams, i: usize, owe: u8, val: u16, rst: u32) {
    let t = &mut st.streams[i];
    if rst != 0 && t.sid != 0 {
        t.rst_owed = 1;
        t.rst_sid = t.sid;
        t.rst_code = rst;
    }
    t.sid = 0;
    t.state = DONE;
    t.owed = owe;
    t.owed_val = val;
    if st.opening as usize == i + 1 {
        st.opening = 0;
    }
}

/// Stream `i`'s answer is complete. A request still sending is stopped.
fn finish(st: &mut Streams, i: usize) {
    let rst = if st.streams[i].local_end == 0 {
        h2w::ERR_CANCEL
    } else {
        0
    };
    detach(st, i, OWE_NONE, 0, rst);
}

// ── Deadlines ────────────────────────────────────────────────────────────

unsafe fn deadlines(s: &mut HttpState, now: u64) {
    let header_ms = u64::from(s.client.client_header_ms);
    let total_ms = u64::from(s.client.client_total_ms);
    let stall_ms = u64::from(s.client.client_stall_ms);
    let st = &mut s.client.streams;
    for i in 0..STREAMS {
        let t = &mut st.streams[i];
        if t.state != OPEN {
            continue;
        }
        if t.win_open == 0 {
            // Waiting on its requester's credit, not on the origin.
            t.progress_ms = now;
        }
        let late = |since: u64, budget: u64| budget != 0 && now.wrapping_sub(since) >= budget;
        let expired = (t.head_given == 0 && t.local_end != 0 && late(t.sent_ms, header_ms))
            || (t.held == 0 && late(t.start_ms, total_ms))
            || (t.held == 0 && t.head_given != 0 && late(t.progress_ms, stall_ms));
        if expired {
            let (owe, val) = if t.head_given != 0 {
                (OWE_ABORT, abort::STALLED as u16)
            } else {
                (OWE_STATUS, status::TIMEOUT)
            };
            detach(st, i, owe, val, h2w::ERR_CANCEL);
        }
    }
}

/// Keep a connection carrying streams honest: PING it after
/// `client_stall_ms` of silence, and report it lost when that goes
/// unanswered as long again.
unsafe fn keepalive_failed(s: &mut HttpState, now: u64) -> bool {
    let stall_ms = u64::from(s.client.client_stall_ms);
    let st = &mut s.client.streams;
    if stall_ms == 0 || st.phase == HANDSHAKE || !st.streams.iter().any(|t| t.state == OPEN) {
        st.ping_out = 0;
        return false;
    }
    if st.ping_out != 0 {
        return now.wrapping_sub(st.ping_ms) >= stall_ms;
    }
    if now.wrapping_sub(st.rx_ms) >= stall_ms {
        st.ping_due = 1;
        st.ping_ms = now;
        st.ping_opaque = now.to_be_bytes();
    }
    false
}

// ── Outbound ─────────────────────────────────────────────────────────────

/// Room for `need` more bytes at the end of `request_buf`, compacting what
/// is still leaving to its front. The place to write them, or `None`.
fn tx_room(s: &mut HttpState, need: usize) -> Option<usize> {
    let sent = s.client.request_sent as usize;
    let len = s.client.request_len as usize;
    if sent > 0 {
        s.client.request_buf.copy_within(sent..len, 0);
        s.client.request_len = (len - sent) as u16;
        s.client.request_sent = 0;
    }
    let at = s.client.request_len as usize;
    (at + need <= REQUEST_BUF_SIZE).then_some(at)
}

fn tx_commit(s: &mut HttpState, n: usize) {
    s.client.request_len += n as u16;
}

/// Send what `request_buf` holds. True when all of it has gone.
unsafe fn flush_tx(s: &mut HttpState) -> bool {
    if s.net_out_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    while s.client.request_sent < s.client.request_len {
        let remaining = (s.client.request_len - s.client.request_sent) as usize;
        let n = remaining.min(NET_BUF_SIZE - NET_FRAME_HDR - 2);
        let scratch = s.net_buf.as_mut_ptr();
        let payload_len = 2 + n;
        let mut cb = [0u8; 2];
        net_proto::put_conn_id(&mut cb, s.client.conn_id);
        *scratch = NET_CMD_SEND;
        *scratch.add(1) = (payload_len & 0xFF) as u8;
        *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
        *scratch.add(3) = cb[0];
        *scratch.add(4) = cb[1];
        core::ptr::copy_nonoverlapping(
            s.client
                .request_buf
                .as_ptr()
                .add(s.client.request_sent as usize),
            scratch.add(5),
            n,
        );
        let total = NET_FRAME_HDR + payload_len;
        if (sys.channel_write)(s.net_out_chan, scratch, total) < total as i32 {
            return false;
        }
        s.client.request_sent += n as u16;
    }
    s.client.request_len = 0;
    s.client.request_sent = 0;
    true
}

/// The control frames owed the origin: SETTINGS and PING acknowledgements,
/// resets, the connection's window refilled, each stream's window opened as
/// far as its requester's credit, and a keepalive PING.
unsafe fn queue_control(s: &mut HttpState) {
    if s.client.streams.phase == HANDSHAKE && s.client.streams.settings_ack_owed == 0 {
        return;
    }
    while s.client.streams.settings_ack_owed > 0 {
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN) else {
            return;
        };
        let n = h2w::write_settings_ack(s.client.request_buf.as_mut_ptr().add(at));
        tx_commit(s, n);
        s.client.streams.settings_ack_owed -= 1;
    }
    if s.client.streams.ping_ack_owed != 0 {
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN + 8) else {
            return;
        };
        let opaque = s.client.streams.ping_opaque;
        let n = h2w::write_ping_ack(s.client.request_buf.as_mut_ptr().add(at), opaque.as_ptr());
        tx_commit(s, n);
        s.client.streams.ping_ack_owed = 0;
    }
    if s.client.streams.ping_due != 0 {
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN + 8) else {
            return;
        };
        let opaque = s.client.streams.ping_opaque;
        let p = s.client.request_buf.as_mut_ptr().add(at);
        h2w::write_header(p, 8, h2w::FRAME_PING, 0, 0);
        core::ptr::copy_nonoverlapping(opaque.as_ptr(), p.add(h2w::FRAME_HEADER_LEN), 8);
        tx_commit(s, h2w::FRAME_HEADER_LEN + 8);
        let st = &mut s.client.streams;
        st.ping_due = 0;
        st.ping_out = 1;
    }
    for i in 0..STREAMS {
        if s.client.streams.streams[i].rst_owed == 0 {
            continue;
        }
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN + 4) else {
            return;
        };
        let t = s.client.streams.streams[i];
        let n = h2w::write_rst_stream(
            s.client.request_buf.as_mut_ptr().add(at),
            t.rst_sid,
            t.rst_code,
        );
        tx_commit(s, n);
        s.client.streams.streams[i].rst_owed = 0;
    }
    if s.client.streams.conn_recv_left <= CONN_WINDOW / 2 {
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN + 4) else {
            return;
        };
        let delta = CONN_WINDOW - s.client.streams.conn_recv_left;
        let n = h2w::write_window_update(s.client.request_buf.as_mut_ptr().add(at), 0, delta);
        tx_commit(s, n);
        s.client.streams.conn_recv_left = CONN_WINDOW;
    }
    for i in 0..STREAMS {
        let t = s.client.streams.streams[i];
        if t.state != OPEN || t.sid == 0 {
            continue;
        }
        let want = t.credit.min(WINDOW_MAX - t.win_open);
        if want == 0 {
            continue;
        }
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN + 4) else {
            return;
        };
        let n = h2w::write_window_update(s.client.request_buf.as_mut_ptr().add(at), t.sid, want);
        tx_commit(s, n);
        let t = &mut s.client.streams.streams[i];
        t.credit -= want;
        t.win_open += want;
    }
}

/// Open a stream for the exchange in hand, adopting the next collected one
/// first when the client's fields are free. True when a stream opened.
unsafe fn claim(s: &mut HttpState, now: u64) -> bool {
    let st = &s.client.streams;
    if st.phase != READY || st.opening != 0 {
        return false;
    }
    let open = st.streams.iter().filter(|t| t.state == OPEN).count() as u32;
    let Some(slot) = st.streams.iter().position(|t| t.state == FREE) else {
        return false;
    };
    if open >= st.peer_max_streams {
        return false;
    }
    if !provider::unopened(s)
        && (!provider::ready(s) || !provider::start(s) || !provider::unopened(s))
    {
        return false;
    }
    // An open client's request for another origin waits for this
    // connection to end.
    let st = &s.client.streams;
    let n = s.client.conn_authority_len as usize;
    if s.client.conn_authority[..n] != st.authority[..st.authority_len as usize] {
        s.client.streams.phase = CLOSING;
        return false;
    }
    if st.next_sid > SID_MAX {
        s.client.streams.phase = CLOSING;
        return false;
    }
    // A HEADERS frame goes into an empty buffer: it then fits or never will.
    if s.client.request_len != 0 {
        return false;
    }
    let sid = st.next_sid;
    let has_body = s.client.request_body_len > 0;
    let Some(len) = encode_request(s, sid, !has_body) else {
        log(s, b"[http] request head does not fit a HEADERS frame");
        let _ = provider::refuse_unopened(s, status::TOO_LARGE);
        return false;
    };
    let Some((id, credit, held)) = provider::hand_off(s) else {
        return false;
    };
    s.client.request_len = len as u16;
    s.client.request_sent = 0;
    s.client.request_body_sent = 0;
    let st = &mut s.client.streams;
    st.next_sid = sid + 2;
    st.streams[slot] = Stream {
        state: OPEN,
        held: u8::from(held),
        local_end: u8::from(!has_body),
        sid,
        id,
        credit,
        send_window: st.peer_initial_window,
        start_ms: now,
        sent_ms: now,
        progress_ms: now,
        ..Stream::EMPTY
    };
    if has_body {
        st.opening = slot as u8 + 1;
    }
    true
}

/// HPACK-encode the request in the client's fields as one HEADERS frame on
/// stream `sid` at the front of `request_buf`. Its length, or `None` when
/// it does not fit.
unsafe fn encode_request(s: &mut HttpState, sid: u32, end_stream: bool) -> Option<usize> {
    let buf = s.client.request_buf.as_mut_ptr();
    let cap = REQUEST_BUF_SIZE;
    let mut o = h2w::FRAME_HEADER_LEN;
    let field = |o: &mut usize, name: &[u8], value: &[u8]| -> bool {
        let n = hpack::encode_header(buf.add(*o), cap - *o, name, value);
        *o += n;
        n != 0
    };
    let method = super::super::wire::method::method_name(s.client.method);
    let scheme: &[u8] = if s.client.session_tls != 0 {
        b"https"
    } else {
        b"http"
    };
    let path = core::slice::from_raw_parts(s.client.path.as_ptr(), s.client.path_len as usize);
    let authority = core::slice::from_raw_parts(
        s.client.conn_authority.as_ptr(),
        s.client.conn_authority_len as usize,
    );
    if method.is_empty()
        || !field(&mut o, b":method", method)
        || !field(&mut o, b":scheme", scheme)
        || !field(&mut o, b":path", path)
        || !field(&mut o, b":authority", authority)
    {
        return None;
    }
    // The requester's fields, names lowercased as RFC 9113 §8.2.1 requires.
    let block = core::slice::from_raw_parts(
        s.client.request_headers.as_ptr(),
        s.client.request_headers_len as usize,
    );
    for (name, value) in super::super::exchange::header_lines(block) {
        if name.len() > FIELD_NAME_MAX {
            return None;
        }
        let mut lower = [0u8; FIELD_NAME_MAX];
        for (d, c) in lower.iter_mut().zip(name) {
            *d = c.to_ascii_lowercase();
        }
        if !field(&mut o, &lower[..name.len()], value) {
            return None;
        }
    }
    if !end_stream {
        let mut clen = [0u8; 11];
        let n = super::super::fmt_u32_raw(clen.as_mut_ptr(), s.client.request_body_len as u32);
        if !field(&mut o, b"content-length", &clen[..n]) {
            return None;
        }
    }
    h2w::write_headers_frame_header(buf, o - h2w::FRAME_HEADER_LEN, sid, end_stream, true);
    Some(o)
}

/// Send the body of the request in the client's fields, as far as the
/// origin's windows and frame size let it.
unsafe fn send_body(s: &mut HttpState, now: u64) {
    let opening = s.client.streams.opening as usize;
    if opening == 0 {
        return;
    }
    let i = opening - 1;
    loop {
        let t = s.client.streams.streams[i];
        if t.state != OPEN || t.sid == 0 {
            s.client.streams.opening = 0;
            return;
        }
        let sent = s.client.request_body_sent as usize;
        let total = s.client.request_body_len as usize;
        let st = &s.client.streams;
        let window = t.send_window.min(st.conn_send_window).max(0) as usize;
        let n = (total - sent)
            .min(window)
            .min(st.peer_max_frame as usize)
            .min(REQUEST_BUF_SIZE - h2w::FRAME_HEADER_LEN);
        if n == 0 {
            return;
        }
        let Some(at) = tx_room(s, h2w::FRAME_HEADER_LEN + 1) else {
            return;
        };
        let n = n.min(REQUEST_BUF_SIZE - at - h2w::FRAME_HEADER_LEN);
        let end = sent + n == total;
        let p = s.client.request_buf.as_mut_ptr().add(at);
        h2w::write_data_frame_header(p, n, t.sid, end);
        core::ptr::copy_nonoverlapping(
            s.client.request_body.as_ptr().add(sent),
            p.add(h2w::FRAME_HEADER_LEN),
            n,
        );
        tx_commit(s, h2w::FRAME_HEADER_LEN + n);
        s.client.request_body_sent += n as u16;
        let st = &mut s.client.streams;
        st.conn_send_window -= n as i32;
        st.streams[i].send_window -= n as i32;
        if end {
            st.streams[i].local_end = 1;
            st.streams[i].sent_ms = now;
            st.opening = 0;
            return;
        }
    }
}

/// Place the terminal records streams owe their requesters, and free the
/// streams that owe nothing more.
unsafe fn pump_out(s: &mut HttpState) {
    for i in 0..STREAMS {
        let t = s.client.streams.streams[i];
        if t.state != DONE {
            continue;
        }
        let placed = match t.owed {
            OWE_STATUS => provider::stream_refuse(s, &t.id, t.owed_val),
            OWE_ABORT => provider::stream_abort(s, &t.id, t.owed_val as u8),
            OWE_END => provider::stream_body(s, &t.id, core::ptr::null(), 0, false),
            _ => true,
        };
        if !placed {
            return;
        }
        let t = &mut s.client.streams.streams[i];
        t.owed = OWE_NONE;
        // A reset still owed the origin keeps the slot: it names the stream.
        if t.rst_owed == 0 || s.client.streams.phase == IDLE {
            s.client.streams.streams[i] = Stream::EMPTY;
        }
    }
}

// ── Draining ─────────────────────────────────────────────────────────────

/// Draining: every stream is answered rather than finished — 503 before its
/// head, an ABORT after — and the connection is let go.
pub(crate) unsafe fn drain(s: &mut HttpState) {
    {
        let st = &mut s.client.streams;
        for i in 0..STREAMS {
            if st.streams[i].state == OPEN {
                let (owe, val) = if st.streams[i].head_given != 0 {
                    (OWE_ABORT, abort::DRAINING as u16)
                } else {
                    (OWE_STATUS, status::BUSY)
                };
                detach(st, i, owe, val, 0);
            }
            st.streams[i].rst_owed = 0;
        }
        st.opening = 0;
        st.rx_in_data = 0;
    }
    if s.client.streams.phase != IDLE {
        let_go(s);
    }
    pump_out(s);
}
