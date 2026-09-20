//! HTTP client — connects to a peer, issues a request, streams the
//! response body to the module's data output channel.
//!
//! This file is the core: `ClientState`, the phase enum, param decode, and the
//! small helpers every generation shares. Each generation's state machine is its
//! own file. Pure-byte parse and build helpers come from `super::wire`; framing
//! constants come from `super::connection`.

// Per-generation front ends onto this core, one file each — the same shape as
// `super::server`. `h3` rides Fluxor's `mux` contract rather than net_proto, so
// it shares this core's shape but not its `ClientState`.
#[cfg(feature = "exchange")]
pub(crate) mod exchange;
#[cfg(not(feature = "host-test"))]
pub(crate) mod h1;
// Exposed under host-test so the harness can unit-test the status-line
// parser feeding `surface_status`; the firmware symbol surface is unchanged.
#[cfg(feature = "host-test")]
pub mod h1;
#[cfg(feature = "h2")]
pub(crate) mod h2;
#[cfg(all(feature = "h3", not(feature = "host-test")))]
pub(crate) mod h3;
#[cfg(all(feature = "h3", feature = "host-test"))]
pub mod h3;

use super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_CLOSE, NET_CMD_SEND, NET_MSG_CLOSED, NET_MSG_CONNECTED,
    NET_MSG_DATA, NET_MSG_ERROR,
};
use super::wire;
use super::HttpState;
use super::{
    dev_channel_port, dev_log, dev_millis, dev_requester_tag, net_read_frame,
    net_read_frame_aligned, net_write_frame, E_AGAIN, NET_FRAME_HDR, POLL_IN, POLL_OUT,
    SOCK_TYPE_STREAM,
};

// ── Sizes / capacities ─────────────────────────────────────────────────────

pub(crate) const RECV_BUF_SIZE: usize = 2048;

/// A path plus its query string.
///
/// The one-shot client's path is a build-time parameter, so it is short by
/// construction. A graph-driven one carries whatever the producer put in the
/// record — a query string is the ordinary way to parameterise a GET — so the
/// exchange build takes the larger bound and pays for it in `REQUEST_BUF_SIZE`
/// below.
#[cfg(not(feature = "exchange"))]
pub(crate) const MAX_PATH_LEN: usize = 128;
#[cfg(feature = "exchange")]
pub(crate) const MAX_PATH_LEN: usize = 1024;

/// Smallest default body-output ring declared in the module manifest.
pub(crate) const OUTPUT_CHUNK: usize = 256;

/// One framed chunk of an extended body. Larger than `OUTPUT_CHUNK`, which
/// bounds the raw stream of the one-shot client, because a framed chunk
/// carries its own length and the port it goes to was sized for it.
pub(crate) const EXT_CHUNK: usize = 1024;
pub(crate) const AUTHORITY_MAX: usize = 128;

/// Headers a graph-driven request may carry. Bounded like everything else on
/// this path: a caller that needs more than this is composing a different
/// request, not a longer one. The block a RESPONSE is answered with is a
/// separate bound, `wire::response::RESPONSE_HEAD_MAX`.
#[cfg(feature = "exchange")]
pub(crate) const REQUEST_HEADERS_MAX: usize = 1024;
#[cfg(not(feature = "exchange"))]
pub(crate) const REQUEST_HEADERS_MAX: usize = 0;

/// Scratch for the composed request HEAD. Derived from the bounds it has to
/// hold — the path, the authority, the content type and a caller's own header
/// block — never chosen independently: `write_request_head` fails closed when
/// the head does not fit, so a buffer too small for the longest admissible
/// request would refuse one this client had already accepted.
pub(crate) const REQUEST_BUF_SIZE: usize =
    MAX_PATH_LEN + AUTHORITY_MAX + CONTENT_TYPE_MAX + REQUEST_HEADERS_MAX + 192;

/// One-shot param client: a small body configured at build time.
#[cfg(not(feature = "exchange"))]
pub(crate) const REQUEST_BODY_SIZE: usize = 256;

/// Longest `Content-Type` a composed request will carry. Ample for the
/// registered media types plus parameters; a longer value is truncated at this
/// bound like every other string param here.
pub(crate) const CONTENT_TYPE_MAX: usize = 64;
/// Graph-driven client: a body the graph supplies, at the contract's ceiling.
#[cfg(feature = "exchange")]
pub(crate) const REQUEST_BODY_SIZE: usize = super::exchange::PAYLOAD_MAX;

/// Exchange sizes come from the contract, not from numbers chosen here: the
/// surface names one payload ceiling so a producer can stay under it, and a
/// response above it is answered with a typed OVERSIZE refusal rather than
/// truncated.
#[cfg(feature = "exchange")]
pub(crate) use super::exchange::{
    KEY_MAX as EXCHANGE_KEY_MAX, PAYLOAD_MAX as EXCHANGE_REPLY_MAX, PUBLISH_FRAME_MAX,
    REPLY_FRAME_MAX,
};

/// Staging for one frame in either direction, envelope included.
///
/// One buffer serves both: a publish is decoded out of it before a reply is
/// composed into it, so the two are never live together. Sized to whichever
/// frame is larger — they are equal today, and taking the max keeps that a
/// fact the code checks rather than one a reader has to.
#[cfg(feature = "exchange")]
pub(crate) const EXCHANGE_STAGE_SIZE: usize = 3 + if PUBLISH_FRAME_MAX > REPLY_FRAME_MAX {
    PUBLISH_FRAME_MAX
} else {
    REPLY_FRAME_MAX
};

pub(crate) const CONNECT_TIMEOUT_MS: u64 = 10_000;

// ── Error codes returned from step ─────────────────────────────────────────

pub(crate) const E_NET_FAILED: i32 = -30;
pub(crate) const E_CONNECT_FAILED: i32 = -31;
pub(crate) const E_SEND_FAILED: i32 = -32;
pub(crate) const E_WRITE_FAILED: i32 = -34;
/// Construction refused: the `authority` parameter is unusable — not
/// `host[:port]`, or longer than [`AUTHORITY_MAX`].
pub(crate) const E_BAD_AUTHORITY: i32 = -22;

// ── Phase machine ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Phase {
    Init = 0,
    Connecting = 1,
    WaitConnect = 2,
    SendRequest = 3,
    WaitSend = 4,
    RecvHeaders = 5,
    RecvBody = 6,
    Writing = 7,
    Done = 8,
    Error = 255,
}

// ── Client state ──────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct ClientState {
    pub(crate) conn_id: u16,
    /// 1 once `MSG_CONNECTED` established a connection, 0 otherwise. Tracks
    /// connection PRESENCE separately from `conn_id`'s value because IP can
    /// legitimately assign `conn_id == 0`; keying "connected" off `conn_id != 0`
    /// would leak the first connection (its `CMD_CLOSE` suppressed).
    pub(crate) conn_present: u8,
    /// Set by `module_drain`. The client finishes the exchange it already
    /// admitted, then closes and reports quiescence — it does not abandon a
    /// request whose response a caller is waiting for, and it does not sit
    /// open once there is nothing left to finish.
    pub(crate) draining: u8,
    /// 1 when the connection in hand must be closed before the next dial: an
    /// open client was asked for a different authority than the one it is
    /// holding open and the one it holds cannot be kept.
    pub(crate) conn_stale: u8,
    /// One connection kept open for an authority this client is not using
    /// right now, so alternating between two origins does not redial each
    /// time.
    ///
    /// Deliberately ONE, not a table. A pool of reusable connections is
    /// where a client crosses a response onto the wrong request, and the
    /// failure is silent and security-relevant. One slot gets the whole
    /// benefit of the common case — a program talking to two origins — with
    /// an invariant small enough to state: a parked connection is resumed
    /// only for the exact authority it was opened for, and only if nothing
    /// at all arrived on it while it was parked. Anything else closes it and
    /// dials afresh.
    pub(crate) parked_id: u16,
    /// 1 when `parked_id` names a connection still worth resuming.
    pub(crate) parked_present: u8,
    pub(crate) parked_authority: [u8; AUTHORITY_MAX],
    pub(crate) parked_authority_len: u16,
    /// 1 when the `authority` parameter was longer than [`AUTHORITY_MAX`].
    /// Recorded rather than truncated: a prefix of an authority is a
    /// different host, and construction refuses it — with a diagnostic that
    /// says it was the LENGTH, which a parse of the truncation could not.
    pub(crate) authority_oversize: u8,
    pub(crate) out_chan: i32,
    /// `in[1]` — when wired (≥ 0), the WS client reads outgoing
    /// payloads from this channel and emits them as WS TEXT frames.
    /// Channel HUP triggers a clean WS CLOSE. Unwired (−1) keeps the
    /// one-shot `request_body` behavior.
    pub(crate) data_in_chan: i32,

    /// The `authority` parameter, `host[:port]`: where this client connects,
    /// what the transport in front verifies, and what every request carries
    /// verbatim as `Host:` / `:authority`. Empty means the client is OPEN:
    /// each exchange record names the authority it is for.
    pub(crate) authority: [u8; AUTHORITY_MAX],
    pub(crate) authority_len: u16,
    /// The authority of the connection in hand — dialled, being dialled, or
    /// about to be. Equal to `authority` on a pinned client; on an open one
    /// it is the record's, and a record naming another marks the connection
    /// stale so the next dial goes where that record asked.
    pub(crate) conn_authority: [u8; AUTHORITY_MAX],
    pub(crate) conn_authority_len: u16,
    pub(crate) request_invalid: u8,
    pub(crate) keep_alive: u8,
    pub(crate) idle_since_ms: u64,
    pub(crate) path_len: u16,
    /// Status code of the response in flight, parsed when its headers
    /// complete. Zero before that, and for a status line this parser will not
    /// read — a refusal is never minted from a guess. Cleared per exchange.
    pub(crate) last_status: u16,
    /// `surface_status` (param 103): when non-zero, an exchange whose response
    /// carries a status of 400 or above answers as `REFUSE_UPSTREAM` with the
    /// code as its payload, rather than as a successful exchange carrying the
    /// error body.
    ///
    /// Opt-in, because for most consumers an error body IS the answer. It is
    /// worth arming where the producer must act on the class of failure —
    /// retrying a 503 or a 429, discarding a permanent 4xx — which it cannot
    /// decide from a payload whose shape it does not know.
    pub(crate) surface_status: u8,
    /// `Content-Type` for the composed request (param 102), or empty to omit
    /// the header entirely.
    ///
    /// A server that accepts a typed body is entitled to refuse one that
    /// arrives unlabelled, so a graph POSTing a concrete format — protobuf,
    /// say — sets this and a graph POSTing nothing does not.
    pub(crate) content_type: [u8; CONTENT_TYPE_MAX],
    pub(crate) content_type_len: u16,

    pub(crate) phase: Phase,
    pub(crate) headers_done: u8,
    /// Wire protocol — 0 = HTTP/1.1, 1 = HTTP/2 cleartext (h2c).
    /// Read by `mod.rs::module_step` to pick the right state machine.
    pub(crate) protocol: u8,
    /// The request verb, a `wire::method` code. `post_params` defaults it to
    /// `METHOD_GET`; a graph-driven request overwrites it per exchange. Zero
    /// (`METHOD_NONE`) is not a verb and composes no request head.
    pub(crate) method: u8,
    /// HTTP/2 client sub-state. Interpreted as `client_h2::H2Phase` when
    /// `protocol == 1`; ignored otherwise.
    pub(crate) h2_phase: u8,
    /// 1 = bootstrap a WebSocket session (RFC 8441 extended CONNECT)
    /// after the h2 handshake instead of issuing a GET/POST. Only
    /// honored when `protocol == 1`.
    pub(crate) websocket: u8,
    /// WS phase: 0 = haven't sent CLOSE, 1 = CLOSE queued, 2 = peer
    /// CLOSE echo observed → exit on next tick.
    pub(crate) ws_done: u8,
    /// 1 = issue a gRPC unary POST instead of a plain POST: the request
    /// carries `content-type: application/grpc` and `te: trailers`
    /// (RFC-required for gRPC-over-HTTP/2). Only honored when
    /// `protocol == 1` and a `request_body` (the length-prefixed message)
    /// is set. The body itself is passed through unframed — the caller
    /// supplies the gRPC `[compressed-flag:1][len:4 BE][message]` LPM.
    pub(crate) grpc: u8,
    /// 1 = a connection-level WINDOW_UPDATE should be queued in
    /// `request_buf` once it's free, refilling our recv flow-control
    /// window. Tracked per client (h2 only).
    pub(crate) window_update_pending: u8,

    pub(crate) connect_start_ms: u64,
    pub(crate) request_start_ms: u64,
    pub(crate) response_start_ms: u64,
    pub(crate) progress_ms: u64,
    pub(crate) client_header_ms: u32,
    pub(crate) client_stall_ms: u32,
    pub(crate) client_total_ms: u32,

    pub(crate) pending_offset: u16,
    pub(crate) recv_len: u16,
    pub(crate) response: wire::response::ResponseDecoder,
    pub(crate) h1_input_len: u16,
    pub(crate) h1_input_offset: u16,

    pub(crate) content_length: u32,
    pub(crate) bytes_received: u32,

    pub(crate) request_len: u16,
    pub(crate) request_sent: u16,

    /// Optional request body (POST). Empty length means GET.
    pub(crate) request_body_len: u16,
    /// Bytes of the body already framed onto the wire. Used by the h2
    /// client to fragment large bodies across multiple DATA frames.
    pub(crate) request_body_sent: u16,
    /// Connection-level recv flow-control window for h2 (RFC 7540
    /// §6.9.1). Decremented as response DATA frames arrive; refilled
    /// via WINDOW_UPDATE when it crosses the threshold.
    pub(crate) recv_window: i32,

    pub(crate) path: [u8; MAX_PATH_LEN],
    pub(crate) recv_buf: [u8; RECV_BUF_SIZE],
    pub(crate) request_buf: [u8; REQUEST_BUF_SIZE],
    pub(crate) request_body: [u8; REQUEST_BODY_SIZE],
    /// Headers a graph-driven request asked for, as the block they go on the
    /// wire as. Empty for a request composed from params.
    pub(crate) request_headers: [u8; REQUEST_HEADERS_MAX],
    pub(crate) request_headers_len: u16,
    /// Whether the request in flight asked to be answered with the whole
    /// response -- its status and headers -- rather than with its body alone.
    pub(crate) exchange_extended: u8,
    /// Whether the head of that response has already been answered.
    ///
    /// An extended exchange answers as soon as the head is known, not when
    /// the body ends: a consumer building a response needs the status before
    /// it can decide what to do with the bytes, and one that waits for the
    /// body before learning the status cannot stream at all -- it must hold
    /// the whole of it first, which is the bound this exists to remove.
    pub(crate) exchange_head_sent: u8,
    /// Whether the zero-length chunk that ends the body has been written.
    pub(crate) exchange_terminated: u8,
    /// One framed chunk of an extended body, and how much of it has left.
    ///
    /// A channel may take part of a write, and the raw stream handles that by
    /// advancing. A framed chunk cannot: rewriting it from the start after a
    /// short write puts its prefix on the wire twice, and a reader counting
    /// lengths then reads everything after it wrong. So the frame is composed
    /// once and sent from where it got to.
    pub(crate) ext_frame: [u8; EXT_CHUNK],
    pub(crate) ext_len: u16,
    pub(crate) ext_sent: u16,

    // ── Exchange mode (`stream.ordered_ack` with `reply = "yes"`) ──
    //
    // An exchange serves many requests over time, each arriving on a channel
    // and each answered by correlation id. These fields hold the request in
    // flight; the phase machine that performs it is the same one a param
    // client uses, re-armed per request rather than duplicated.
    /// in[8]: `publish_in`, where requests arrive.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_in_chan: i32,
    /// out[9]: `reply_out`, where answers leave.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_out_chan: i32,
    /// Correlation id of the request in flight; 0 when idle.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_corr: u64,
    #[cfg(feature = "exchange")]
    pub(crate) exchange_pending: u16,
    /// The request's `msg_key`, echoed unchanged on the reply so a downstream
    /// stage can rejoin without holding state.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_key: [u8; EXCHANGE_KEY_MAX],
    #[cfg(feature = "exchange")]
    pub(crate) exchange_key_len: u16,
    /// Response body accumulated across `RecvBody` chunks. A reply is ONE
    /// frame, so it cannot stream the way `file_ctrl` does.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_reply: [u8; EXCHANGE_REPLY_MAX],
    #[cfg(feature = "exchange")]
    pub(crate) exchange_reply_len: u16,
    /// Set when the response outgrew `EXCHANGE_REPLY_MAX`; the reply becomes
    /// a typed refusal instead of a truncated body.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_oversize: u8,
    /// Staging for one frame in either direction. Its own buffer because a
    /// frame at the ceiling does not fit in `recv_buf`, which is holding the
    /// response while the reply is being composed.
    #[cfg(feature = "exchange")]
    pub(crate) exchange_stage: [u8; EXCHANGE_STAGE_SIZE],
}

// ClientState lives inside HttpState, which the kernel allocates as a
// zeroed buffer of `module_state_size()` bytes. `init()` below sets
// only those fields whose default is not zero.

// ── Param parsers ─────────────────────────────────────────────────────────

pub(crate) unsafe fn parse_request_body(s: &mut HttpState, d: *const u8, len: usize) {
    if len > REQUEST_BODY_SIZE {
        s.client.request_invalid = 1;
    }
    let n = len.min(REQUEST_BODY_SIZE);
    let mut i = 0;
    while i < n {
        s.client.request_body[i] = *d.add(i);
        i += 1;
    }
    s.client.request_body_len = n as u16;
}

// ── Init / post-params ────────────────────────────────────────────────────

pub(crate) unsafe fn init(s: &mut HttpState) {
    s.client.out_chan = -1;
    s.client.data_in_chan = -1;
    s.client.authority_len = 0;
    s.client.conn_authority_len = 0;
    s.client.conn_stale = 0;
    s.client.parked_present = 0;
    s.client.parked_authority_len = 0;
    s.client.authority_oversize = 0;
    s.client.request_invalid = 0;
    s.client.content_type = [0; CONTENT_TYPE_MAX];
    s.client.content_type_len = 0;
    s.client.last_status = 0;
    s.client.surface_status = 0;
    s.client.phase = Phase::Init;
    s.client.client_header_ms = 15000;
    s.client.client_stall_ms = 15000;
    s.client.client_total_ms = 60000;
    // h2 connection-level recv window starts at the spec default.
    s.client.recv_window = 65535;
}

/// Finish construction from the decoded params. Non-zero refuses the module:
/// a client whose one address is not an address cannot be given a
/// connection it would dial wrongly.
pub(crate) unsafe fn post_params(s: &mut HttpState) -> i32 {
    let sys = &*s.syscalls;
    s.client.out_chan = dev_channel_port(sys, 1, 1); // out[1]: body data
    s.client.data_in_chan = dev_channel_port(sys, 0, 1); // in[1]: outbound WS payload data

    // The authority is parsed once here so that a graph naming one that no
    // dial can carry fails to load rather than failing its first request.
    // Every connection a pinned client opens goes to it, so it is also the
    // authority of the connection in hand from the start.
    // Length first: a truncated authority can parse perfectly well as a
    // shorter host, so checking the shape of what survived would accept a
    // pin to somewhere the graph never named.
    if s.client.authority_oversize != 0 {
        log(
            s,
            b"[http] authority is longer than the 128 bytes held for it",
        );
        return E_BAD_AUTHORITY;
    }
    let n = s.client.authority_len as usize;
    if n > 0 {
        if net_proto::Target::parse(&s.client.authority[..n]).is_none() {
            log(s, b"[http] authority is not host[:port]");
            return E_BAD_AUTHORITY;
        }
        set_conn_authority(s, n);
    }

    if s.client.path_len == 0 {
        s.client.path[0] = b'/';
        s.client.path_len = 1;
    }
    // Zeroed state means `METHOD_NONE`, which composes no head at all.
    // Nothing in the param set names a verb, so a param-configured request
    // is a GET.
    if s.client.method == wire::method::METHOD_NONE {
        s.client.method = wire::method::METHOD_GET;
    }

    #[cfg(feature = "exchange")]
    exchange::init(s);

    log(s, b"[http] client configured");
    0
}

/// Make the module's own authority the authority of the connection in hand.
unsafe fn set_conn_authority(s: &mut HttpState, n: usize) {
    core::ptr::copy_nonoverlapping(
        s.client.authority.as_ptr(),
        s.client.conn_authority.as_mut_ptr(),
        n,
    );
    s.client.conn_authority_len = n as u16;
}

/// Dial the authority of the connection in hand. `None` when there is none
/// to dial — an open client with no record, or a bad one — which the caller
/// answers as a failed connect; `Some(false)` when the transport refused the
/// frame and it is to be offered again.
pub(crate) unsafe fn dial(s: &mut HttpState) -> Option<bool> {
    if s.net_out_chan < 0 || s.client.conn_authority_len == 0 {
        return None;
    }
    let sys = &*s.syscalls;
    let tag = dev_requester_tag(sys);
    let chan = s.net_out_chan;
    let n = s.client.conn_authority_len as usize;
    super::connection::dial(
        sys,
        chan,
        s.net_buf.as_mut_ptr(),
        &s.client.conn_authority[..n],
        tag,
    )
}

#[inline(always)]
pub(crate) unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

/// Compose the request head into `request_buf`.
///
/// Returns false when the head does not fit or names a verb the writer does
/// not know — a request that cannot be composed is not one to send in part.
#[must_use]
pub(crate) unsafe fn build_request(s: &mut HttpState) -> bool {
    let mut len = wire::h1::write_request_head(
        s.client.request_buf.as_mut_ptr(),
        REQUEST_BUF_SIZE,
        s.client.method,
        s.client.path.as_ptr(),
        s.client.path_len as usize,
        &wire::h1::RequestOptions {
            authority: &s.client.conn_authority[..s.client.conn_authority_len as usize],
            body_len: s.client.request_body_len as usize,
            content_type: &s.client.content_type[..s.client.content_type_len as usize],
            http11: true,
            keep_alive: s.client.keep_alive != 0,
        },
    );
    // A caller's own headers go in ahead of the blank line that ends the
    // head, which is the only place they can go and still be headers. Their
    // bytes therefore decide where the head ends and what the origin reads as
    // framing, so a block is admitted only after the record parser
    // (the `http_exchange` contract) has read it as field lines naming
    // nothing this module writes itself. The param client sets no block, so
    // its length here is structurally 0.
    let extra = s.client.request_headers_len as usize;
    if len > 0 && extra > 0 {
        if len + extra > REQUEST_BUF_SIZE {
            return false;
        }
        let at = len - 2;
        core::ptr::copy_nonoverlapping(
            s.client.request_headers.as_ptr(),
            s.client.request_buf.as_mut_ptr().add(at),
            extra,
        );
        s.client.request_buf[at + extra] = b'\r';
        s.client.request_buf[at + extra + 1] = b'\n';
        len = at + extra + 2;
    }
    s.client.request_len = len as u16;
    s.client.request_sent = 0;
    s.client.request_body_sent = 0;
    len > 0
}

/// Close the client's connection. Returns whether the transport took the
/// CLOSE — `true` also when there was nothing to close.
///
/// Ownership is released only on a confirmed write. Clearing it after a refused
/// one abandons a connection the peer still holds open, and nothing afterwards
/// knows the CLOSE is owed.
#[must_use]
pub(crate) unsafe fn send_close_frame(s: &mut HttpState) -> bool {
    if s.client.conn_present == 0 || s.net_out_chan < 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 2];
    net_proto::put_conn_id(&mut payload, s.client.conn_id);
    if net_write_frame(
        sys,
        chan,
        NET_CMD_CLOSE,
        payload.as_ptr(),
        2,
        buf,
        NET_BUF_SIZE,
    ) == 0
    {
        return false;
    }
    s.client.conn_id = 0;
    s.client.conn_present = 0;
    true
}

/// Park the connection in hand for the authority it belongs to, instead of
/// closing it, so a later request for that authority can resume it.
///
/// Refuses to park anything that is not cleanly reusable — a connection the
/// response decoder marked unreusable, one mid-exchange, or one whose peer
/// asked to close. A parked connection that is not certainly idle is worse
/// than no parked connection at all.
pub(crate) unsafe fn park_connection(s: &mut HttpState) -> bool {
    if s.client.conn_present == 0
        || s.client.keep_alive == 0
        || !s.client.response.reusable
        || s.client.draining != 0
    {
        return false;
    }
    // Only one may be parked; an existing one is closed rather than leaked.
    if s.client.parked_present != 0 {
        let _ = close_parked(s);
    }
    let n = s.client.conn_authority_len as usize;
    if n == 0 || n > AUTHORITY_MAX {
        return false;
    }
    s.client.parked_authority[..n].copy_from_slice(&s.client.conn_authority[..n]);
    s.client.parked_authority_len = n as u16;
    s.client.parked_id = s.client.conn_id;
    s.client.parked_present = 1;
    // The connection is no longer THIS client's active one; it stays open on
    // the provider and is adopted again by id.
    s.client.conn_present = 0;
    s.client.conn_id = 0;
    true
}

/// Resume the parked connection when it is for `authority`. The caller has
/// already established that no connection is in hand.
pub(crate) unsafe fn resume_parked(s: &mut HttpState, authority: &[u8]) -> bool {
    if s.client.parked_present == 0 {
        return false;
    }
    let n = s.client.parked_authority_len as usize;
    if n != authority.len() || &s.client.parked_authority[..n] != authority {
        return false;
    }
    s.client.conn_id = s.client.parked_id;
    s.client.conn_present = 1;
    s.client.parked_present = 0;
    s.client.parked_authority_len = 0;
    s.client.response.reusable = true;
    true
}

/// Close whatever is parked, if anything. Used when it cannot be trusted any
/// more — data arrived on it, or another authority needs the slot.
pub(crate) unsafe fn close_parked(s: &mut HttpState) -> bool {
    if s.client.parked_present == 0 {
        return true;
    }
    let id = s.client.parked_id;
    s.client.parked_present = 0;
    s.client.parked_authority_len = 0;
    let sys = &*s.syscalls;
    let mut payload = [0u8; 2];
    net_proto::put_conn_id(&mut payload, id);
    let mut buf = [0u8; NET_BUF_SIZE];
    net_write_frame(
        sys,
        s.net_out_chan,
        NET_CMD_CLOSE,
        payload.as_ptr(),
        2,
        buf.as_mut_ptr(),
        NET_BUF_SIZE,
    ) != 0
}

/// Drop what arrives for other consumers while this client holds no
/// connection of its own.
///
/// `net_in` is fanned from a lane stream consumers share, so a client that has
/// not dialled still receives every frame they do. Left unread those copies
/// fill the edge, and a full edge back-pressures the provider until it can no
/// longer deliver to the consumer the bytes were for — one idle leg stalling
/// the leg doing the work, and only once a response outgrew the edge.
///
/// Draining is unconditional here precisely BECAUSE there is no connection: a
/// client without one owns nothing that can arrive, so nothing it reads can be
/// a frame it needed. With a connection the protocol decides what an
/// unsolicited frame means — for h1 [`h1::idle`], which knows that data
/// between exchanges makes a connection unreusable; for h2 the server's
/// SETTINGS and PING are ordinary, so this must not touch it.
pub(crate) unsafe fn drain_unowned(s: &mut HttpState) {
    if s.client.conn_present != 0 || s.net_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    for _ in 0..8 {
        let (kind, _n) = net_read_frame(sys, s.net_in_chan, s.net_buf.as_mut_ptr(), NET_BUF_SIZE);
        if kind == 0 {
            break;
        }
    }
}

/// True when a just-read established-stream frame (`MSG_DATA` / `MSG_CLOSED` /
/// `MSG_ERROR`, all of which lead with `conn_id`) belongs to a DIFFERENT
/// connection than this client's. `ip.net_out` can be fanned to other stream
/// consumers, so a client must not consume another connection's bytes as its
/// own response. The frame has already been read (FIFO stays aligned); the
/// caller simply ignores it.
#[inline(always)]
pub(crate) unsafe fn is_foreign_frame(
    s: &HttpState,
    msg_type: u8,
    payload_len: usize,
    nbuf: *const u8,
) -> bool {
    matches!(msg_type, NET_MSG_DATA | NET_MSG_CLOSED | NET_MSG_ERROR)
        && payload_len >= 2
        && net_proto::conn_id(core::slice::from_raw_parts(
            nbuf.add(NET_FRAME_HDR),
            payload_len,
        )) != s.client.conn_id
}
