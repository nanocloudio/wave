//! HTTP server — accepts connections, routes requests, serves static content,
//! templates, files and proxy responses.
//!
//! This file is the CORE, and it holds exactly what every generation and every
//! subsystem shares: `ConnSlot` and `ServerState`, the `Phase` enum, the
//! `cur_*` slot accessors, `init`/`post_params`, and the tick entry (`step`,
//! `demux_inbound`). Nothing here knows how to serve a request.
//!
//! # Layout
//!
//! Two kinds of child, and the difference matters when deciding where a change
//! belongs.
//!
//! **Per-generation front ends** — `h1`, `h2`, `h3` — each drive a connection
//! through its generation's state machine. They are alternatives: a connection
//! is served by exactly one. `h1` also carries the bind and accept phases,
//! because that lifecycle is HTTP/1.1's and the other two reach their own front
//! ends through it.
//!
//! **Subsystems** — `routes`, `listeners`, `params`, `cache`, `response`,
//! `body`, `ws`, `proxy` — each own one concern and are driven BY the front
//! ends, so all three generations share them. A template renders identically on
//! h1, h2 and h3 because `body` is the only thing that knows how.
//!
//! The dependency runs one way: a front end calls into a subsystem, a subsystem
//! calls back only into the slot helpers here. The short `use` block below is
//! the whole of what the core needs from its children — if it grows, something
//! has been put in the wrong file.
//!
//! Pure-byte parse and build helpers come from `super::wire`, which is
//! role-neutral: `wire::h1` serves this server's request parser and the client's
//! response parser. Framing constants come from `super::connection`.

/// Declare a child module of the server core.
///
/// Every child is `pub` only under `host-test`: the firmware links one crate,
/// so `pub(crate)` there keeps the symbol surface exactly as it was, while the
/// suites — which are separate crates, because `modules/**` bans inline tests —
/// need real `pub` to reach in. Written once rather than four lines per module.
macro_rules! server_mod {
    ($( $(#[$gate:meta])* $name:ident ),* $(,)?) => { $(
        $(#[$gate])* #[cfg(not(feature = "host-test"))] pub(crate) mod $name;
        $(#[$gate])* #[cfg(feature = "host-test")] pub mod $name;
    )* };
}

// Subsystems of the core: each owns one concern and is driven by the
// per-generation front ends below.
server_mod!(
    // Application fan-out is feature-gated: the `web` variant exists for
    // rp2350 flash, and a handler that forwards to a module the device does
    // not run is pure cost there. Every other variant carries it.
    #[cfg(feature = "app")]
    app,
    body,
    cache,
    listeners,
    params,
    proxy,
    reqbody,
    response,
    routes,
    ws,
);

// What the core itself needs back from them. Short by design: everything else
// flows the other way, from a subsystem reaching into the slot helpers below.
use cache::{cache_release_for_route, drain_variables, CacheEntry, VarEntry};
use h1::step_active_slot;
use listeners::{is_listen_port, pump_listeners, DynListeners, NET_MSG_BIND_REFUSED};
use proxy::{find_slot_by_backend_conn, is_proxy_relay_phase};
use routes::{
    match_route, match_route_path, DynRoutes, Route, HANDLER_STATIC, HANDLER_TEMPLATE,
    HANDLER_WEBSOCKET,
};
use ws::RETAINED_BUF_CAP;

// Per-generation front ends onto this core, one file each.
server_mod!(
    h1,
    #[cfg(feature = "h2")]
    h2,
    #[cfg(feature = "h3")]
    h3,
);

use super::abi::SyscallTable;
use super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_BIND, NET_CMD_CLOSE, NET_CMD_CONNECT, NET_CMD_SEND,
    NET_MSG_ACCEPTED, NET_MSG_BOUND, NET_MSG_CLOSED, NET_MSG_CONNECTED, NET_MSG_DATA,
    NET_MSG_ERROR, NET_MSG_TRACE_CTX,
};
use super::wire;
use super::HttpState;
use super::{
    dev_channel_ioctl, dev_channel_port, dev_csprng_fill, dev_log, dev_micros, dev_millis,
    dev_owner_tag, dev_requester_tag, dev_self_index, dev_telemetry_enabled, dev_telemetry_span,
    fmt_u32_raw, heap_alloc, heap_free, heap_realloc, msg_read, net_read_frame, net_write_frame,
    p_u16, p_u32, p_u8, IOCTL_FLUSH, IOCTL_NOTIFY, IOCTL_POLL_NOTIFY, MSG_HDR_SIZE, NET_FRAME_HDR,
    POLL_HUP, POLL_IN, POLL_OUT, SOCK_TYPE_STREAM,
};

// ── Sizes / capacities ─────────────────────────────────────────────────────
//
// All cross-cutting capacity tunables live in `abi::config::http`,
// `abi::config::kernel`, etc. Per-board profiles. See
// `../fluxor/modules/sdk/abi/config.rs` for the full envelope.

pub(crate) use super::abi::config::http::{
    ARENA_WORKING_SET_CONNS, DEFAULT_BODY_POOL_SIZE, MAX_CACHE, MAX_CONCURRENT_CONNS,
    MAX_CONTENT_TYPE, MAX_DYN_ROUTES, MAX_FS_PATH, MAX_PATH, MAX_ROUTES, MAX_ROUTE_BACKENDS,
    MAX_VARS, MAX_VAR_VALUE, RECV_BUF_SIZE, SEND_BUF_SIZE,
};

// ── Table consumers ───────────────────────────────────────────────────────
//
// Two runtime tables are programmed from the store rather than from params:
// the dynamic route arena (`routes`) and the dynamic listener set
// (`listeners`). Both ride the
// reusable `cores/table_consumer` core, `include!`d here — it is an
// implementation, not a wire contract, so it is included rather than linked
// (see the file header). `SyscallTable` is brought into scope for the include
// per the core's includer contract.
mod table_consumer {
    use super::super::abi::SyscallTable;
    include!("../../../../target/fluxor/fluxor-abi/sdk/cores/table_consumer.rs");
}
pub(crate) use table_consumer::{TableConsumer, TableSink};

/// Key buffer for a table row — the `/dataplane/…` path that names it, and so
/// its stable identity across upsert and remove. One bound for both consumers:
/// they subscribe to sibling prefixes of the same store.
pub(crate) const MAX_DYN_KEY: usize = 64;

/// Find the `;`-separated `tag=` field's value in a compact record.
///
/// Both tables encode their value as `tag=v;tag=v;…`, so the field split and
/// the integer parse below are shared. Anything a single table understands
/// — `be=` backend sets, `tls=` flags — is decoded by that table's own sink.
pub(crate) fn dyn_field<'a>(value: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let mut start = 0;
    while start <= value.len() {
        let end = value[start..]
            .iter()
            .position(|&b| b == b';')
            .map(|i| start + i)
            .unwrap_or(value.len());
        let seg = &value[start..end];
        if seg.len() >= tag.len() && &seg[..tag.len()] == tag {
            return Some(&seg[tag.len()..]);
        }
        if end >= value.len() {
            break;
        }
        start = end + 1;
    }
    None
}

/// Parse a leading run of ASCII digits as u32.
pub(crate) fn dyn_u32(b: &[u8]) -> u32 {
    let mut n: u32 = 0;
    for &c in b {
        if c.is_ascii_digit() {
            n = n.wrapping_mul(10).wrapping_add((c - b'0') as u32);
        } else {
            break;
        }
    }
    n
}

/// Decode one hex digit (`0-9a-fA-F`) for percent-unescaping request
/// paths. Returns `None` for non-hex bytes.
pub(crate) fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ── Phase machine ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Phase {
    Init = 0,
    Binding = 1,
    WaitBound = 2,
    WaitAccept = 4,
    RecvRequest = 5,
    DispatchRoute = 6,
    /// Reading a request body, between the head and dispatch. Entered only
    /// when the framing headers say there is one; drains a staged
    /// `100 Continue` first, then decodes until the body is whole.
    RecvBody = 23,
    /// `HANDLER_APP`: the request is out on `req_out` and this slot is
    /// waiting for the matching `HttpResponse`. Leaves for `SendHeaders`
    /// when one arrives, or for a 504 when `app::APP_TIMEOUT_MS` elapses.
    AwaitApp = 24,
    SendHeaders = 7,
    SendBody = 8,
    DrainSend = 9,
    CloseConn = 10,
    FetchContent = 11,
    CacheStream = 12,
    ProxyConnect = 13,
    ProxyWaitConnect = 14,
    ProxySendRequest = 15,
    ProxyRelayHeaders = 16,
    ProxyRelayBody = 17,

    /// The upgrade has been reported on `ws_admit_out` and this slot is
    /// waiting for the matching decision on `ws_admit_in`. Leaves for
    /// `WsHandshake` on an accept, and for a refusal response otherwise.
    WsAwaitAdmit = 25,
    /// 101 Switching Protocols composed; flush it then enter `WsActive`.
    WsHandshake = 18,
    /// WebSocket frame loop. Reads masked client frames from net_in,
    /// echoes data frames, replies to ping with pong, processes close.
    WsActive = 19,
    /// A close frame is queued in `send_buf`; flush it then close the
    /// connection.
    WsClose = 20,

    /// HTTP/2 connection mode (h2c). Reached when the first 24 bytes
    /// of a connection match the h2 preface; all further state lives
    /// in `ServerState.h2`.
    H2Active = 21,

    /// HANDLER_FS_FILE: file is open but the FS provider hasn't yet
    /// resolved length / final status (wasm browser-fetch with
    /// response headers in flight). Polls `FS_STAT` each step until
    /// it returns OK (length known → `SendHeaders` with
    /// Content-Length), ENOSYS (no Content-Length → streaming
    /// `SendHeaders`), ENODEV (`DrainSend` 502), or stays EAGAIN
    /// past the poll-timeout (`DrainSend` 504). No response bytes
    /// hit the wire until the outcome is known.
    AwaitFsStat = 22,

    Error = 255,
}

// ── Verified peers ────────────────────────────────────────────────────────

/// Longest peer fingerprint retained, taken from the contract that defines the
/// record rather than chosen here — a second opinion about a field's width is
/// how the two drift apart.
///
/// A fingerprint longer than this is refused rather than truncated: half a
/// fingerprint is not a weaker identity, it is a different one, and it can
/// collide with somebody else's.
pub(crate) const MAX_PEER_SVID: usize = crate::abi::contracts::net::peer_identity::MAX_FINGERPRINT;

/// One verified peer, keyed by CONNECTION rather than by slot.
///
/// The identity does not arrive in step with the slot. `tls` emits it the
/// moment a handshake completes, which can be before this module has processed
/// the `MSG_ACCEPTED` for that connection, so an identity keyed by slot would
/// find none and be dropped — and a dropped identity is not a visible error,
/// it is a caller the application sees as anonymous.
#[derive(Clone, Copy)]
pub(crate) struct PeerEntry {
    /// `-1` when free.
    pub(crate) conn_id: i32,
    pub(crate) svid: [u8; MAX_PEER_SVID],
    pub(crate) len: u8,
}

/// A free entry. `conn_id = -1` and not zero, because zero is a valid
/// connection id: a table left zeroed reads as "connection 0 is this peer".
pub(crate) const PEER_EMPTY: PeerEntry = PeerEntry {
    conn_id: -1,
    svid: [0; MAX_PEER_SVID],
    len: 0,
};

// ── Server state ──────────────────────────────────────────────────────────

/// Per-connection state. `ServerState` holds an array of these and
/// the step machine ticks each active slot every step so multiple
/// HTTP transactions progress in parallel.
///
/// A slot is **free** when `phase == Phase::Init` AND `conn_id < 0`.
/// The accept path allocates the first free slot it finds; the close
/// path resets the slot back to that state.
#[repr(C)]
pub(crate) struct ConnSlot {
    /// Conn id from `MSG_ACCEPTED`. `-1` when the slot is free.
    pub(crate) conn_id: i32,
    /// Per-slot phase machine state.
    pub(crate) phase: Phase,
    pub(crate) matched_route: i8,
    pub(crate) recv_parsed: u8,
    pub(crate) req_path_len: u16,
    /// Method of the request currently being served, as a
    /// `wire::method::METHOD_*` value. Set in `Phase::RecvRequest`,
    /// consumed by dispatch (HEAD suppresses the response body) and by
    /// the body reader. Reset to `METHOD_NONE` per request, not per
    /// connection: a keep-alive connection serves many, and a stale
    /// method would suppress the body of the GET that followed a HEAD.
    pub(crate) req_method: u8,
    pub(crate) peer_closed: u8,
    /// Keep-alive for the current request. Derived in
    /// `Phase::RecvRequest` from the version + `Connection:` header,
    /// consumed by `finish_response`. Cleared in `free_slot`.
    pub(crate) keepalive: u8,
    /// Set to 1 when the matched route uses
    /// `HANDLER_WEBSOCKET_FANOUT` and the upgrade succeeded.
    pub(crate) ws_fan_out: u8,
    /// 1 while this slot's upgrade is waiting on an admission decision.
    pub(crate) ws_admit_pending: u8,
    /// 1 once the admission request has been handed to `ws_admit_out`.
    ///
    /// The request is offered until the channel takes it: a request dropped
    /// because the channel was briefly full would leave the peer waiting on a
    /// decision nobody was ever asked for.
    pub(crate) ws_admit_sent: u8,
    /// 1 once an `opened` event has been reported for this connection, so a
    /// `closed` is reported for exactly the connections that opened.
    pub(crate) ws_opened_sent: u8,
    /// The RFC 6455 accept value computed at admission time.
    ///
    /// Kept because the request buffer is reused while the decision is
    /// outstanding, and the key it was derived from would be gone.
    pub(crate) ws_accept: [u8; 28],
    /// Ticks spent awaiting a decision, against `WS_ADMIT_TIMEOUT_TICKS`.
    pub(crate) ws_admit_ticks: u16,
    /// The RFC 6455 close code observed for this connection, or 0 when it
    /// ended without one.
    pub(crate) ws_close_code: u16,
    /// Set to 1 if a WsFrame envelope read from `ws_in` had fin=1
    /// and was split into multiple wire fragments. The final wire
    /// fragment will carry `fin=1`; intermediate ones carry `fin=0`.
    pub(crate) ws_frag_orig_fin: u8,
    /// 1 while this slot is rendering bytes from a body-cache
    /// entry (incremented on `cache_try_or_fetch::Hit` or
    /// `cache_fetch_step::Ready`; decremented on transition out
    /// of body emission via `cache_release_for_route`). Pair-flag
    /// so over- or under-release can't happen if the slot enters
    /// DrainSend more than once.
    pub(crate) cache_retained: u8,

    pub(crate) recv_len: u16,
    /// Offset in `recv_buf` of the first byte after `\r\n\r\n` (or
    /// the start of the next pipelined request). 0 before parse.
    pub(crate) header_end_off: u16,
    pub(crate) send_offset: u16,
    pub(crate) send_len: u16,
    pub(crate) file_index: i16,
    pub(crate) file_count: u16,
    pub(crate) index_pos: u16,
    pub(crate) fs_stat_ticks: u16,
    /// Render position into the route's `body_offset..body_offset+body_len`
    /// region of the body_pool arena. Widened to u32 to match the
    /// route's `body_offset` / `body_len` widths — large inline /
    /// template / cached bodies (e.g. >64 KiB single-page apps,
    /// jpeg/png assets) would wrap a u16 cursor and cause the
    /// renderer to resend or corrupt mid-body.
    pub(crate) tmpl_pos: u32,

    pub(crate) fs_fd: i32,
    pub(crate) fs_total: u32,
    pub(crate) fs_sent: u32,

    // ── Request body ingestion ─────────────────────────────────────
    //
    // Set from the framing headers when the head completes; driven by
    // `Phase::RecvBody` until the body is whole. See `server::reqbody`.
    /// `reqbody::BODY_MODE_*` — how this request's body is delimited.
    pub(crate) body_mode: u8,
    /// `reqbody::CHUNK_*` — sub-state within a chunked body.
    pub(crate) chunk_state: u8,
    /// 1 while a `100 Continue` is staged in `send_buf` and has not yet
    /// drained. The body must not be read until it has: the client is
    /// waiting for it before sending anything.
    pub(crate) body_continue: u8,
    /// Bytes still expected in the current framing unit — the whole body
    /// under `Content-Length`, or the current chunk under `chunked`.
    pub(crate) body_remaining: u64,
    /// Decoded body bytes accumulated so far. Checked against the cap on
    /// every append, not just against the declared length, because a
    /// chunked sender declares nothing up front.
    pub(crate) body_len: u32,
    /// Heap-allocated decoded body. Null until the first body byte is
    /// accepted, so a connection serving only GETs never pays for it.
    /// Freed by `free_slot` and at the end of each request.
    pub(crate) body_buf: *mut u8,
    pub(crate) body_cap: u32,

    // ── HANDLER_APP correlation ────────────────────────────────────
    /// 1 while this slot has a request out on `req_out` and is waiting for
    /// the matching `HttpResponse`. Cleared when one arrives, on timeout,
    /// and by `free_slot`.
    pub(crate) app_pending: u8,
    /// The stream this slot's pending request belongs to. Always 0 under
    /// h1 — a connection carries one request at a time — and a real
    /// stream id under h2, where it is the half of the correlation key
    /// that `conn_id` cannot supply.
    pub(crate) app_stream_id: u16,
    /// `dev_millis` value past which the pending request is answered 504.
    /// 0 when nothing is pending. See `app::APP_TIMEOUT_MS`.
    pub(crate) app_deadline_ms: u64,
    /// 1 while a multi-envelope application response is mid-flight: the head
    /// has been sent and more body envelopes are expected.
    ///
    /// This is what lets a route serve a body larger than `send_buf`, which is
    /// the difference between serving an API and serving artefacts — a
    /// container layer does not fit in a connection buffer, and never will.
    /// While it is set, `Phase::DrainSend` returns to `AwaitApp` for the next
    /// chunk instead of finishing the response.
    pub(crate) app_streaming: u8,

    pub(crate) req_path: [u8; MAX_PATH],
    /// Heap-allocated request buffer. Allocated by
    /// `alloc_free_slot` on accept, freed by `free_slot` on close.
    /// `null` while the slot is free — keeping idle slots small so
    /// the slot table can scale to thousands of connections without
    /// reserving 8 KB × N permanent memory.
    pub(crate) recv_buf: *mut u8,
    pub(crate) recv_cap: u16,

    /// Heap-allocated response buffer; lifecycle parallels `recv_buf`.
    pub(crate) send_buf: *mut u8,
    pub(crate) send_cap: u16,

    /// HTTP/2 connection state. Heap-allocated lazily on the h2c
    /// preface (or h2-via-ALPN entry); null while the slot is in
    /// h1 mode or idle. Sized at ~3 KB on aarch64 (4 streams + WS
    /// reassembly buffer), so making it lazy saves ~3 MB on a
    /// 1024-slot table for h1-only workloads.
    #[cfg(feature = "h2")]
    pub(crate) h2: *mut h2::H2State,

    // ── WebSocket fan-out fragmentation state ──────────────────────
    //
    // When a WsFrame envelope read from `ws_in` carries a payload
    // larger than `SEND_BUF_SIZE - WS_FRAG_HDR_RESERVE`, it can't
    // fit as a single wire frame. The first fragment is queued
    // immediately with the original opcode and `fin=0`; subsequent
    // chunks ride out as `CONTINUATION` frames over later step()
    // iterations. `ws_frag_buf` holds the source payload until the
    // final fragment is queued, then is freed.
    /// Heap-allocated copy of the source payload during fragmentation.
    /// `null` outside fragmentation. Size = `ws_frag_total` bytes.
    pub(crate) ws_frag_buf: *mut u8,
    /// Total source payload length (bytes still belonging to the
    /// in-flight logical message). 0 when no fragmentation in flight.
    pub(crate) ws_frag_total: u16,
    /// Bytes already queued in earlier fragments. Next fragment
    /// starts at `ws_frag_buf + ws_frag_offset`.
    pub(crate) ws_frag_offset: u16,
    /// Original opcode (BINARY/TEXT) the source frame carried, used
    /// only on the first fragment; subsequent fragments carry
    /// `OP_CONT (0x0)`.
    pub(crate) ws_frag_opcode: u8,
    _slot_pad1: [u8; 3],

    // ── Retention replay state ─────────────────────────────────────
    //
    // When a slot enters `WsActive` (fresh client connect on a
    // fan-out route), it first drains any envelopes captured in the
    // server-wide `retained_buf` so that reloads see the producer's
    // most recent snapshot without the producer having to re-emit.
    // `retained_replay_offset` walks the retain buffer one envelope
    // at a time, bounded by `retained_replay_target` (snapshot of
    // `retained_used` taken on the slot's first WsActive tick). New
    // live envelopes captured during replay grow `retained_used` past
    // the target — replay must NOT cross that boundary or the new
    // subscriber would receive them twice (once via live queue, once
    // via replay walk). `retained_replay_done` flips to 1 when offset
    // hits the target (caught up; normal live flow resumes).
    pub(crate) retained_replay_offset: u32,
    pub(crate) retained_replay_target: u32,
    pub(crate) retained_replay_done: u8,
    /// 1 once the replay-start snapshot has been captured for this
    /// slot. Zero on slot reset → first WsActive tick stamps
    /// `retained_replay_target = retained_used` and flips this bit.
    pub(crate) retained_replay_started: u8,
    _slot_pad2: [u8; 2],

    /// Observability: monotonic-micros start of this request's
    /// `http.server.request` span, latched when the request head is parsed and
    /// the telemetry port is wired (`0` = no span). Keepalive reuses the slot,
    /// so it's re-latched per request. See `../standards/observability.md`.
    pub(crate) span_start_us: u64,
    /// W3C trace context the span actually adopts (per request): the client's
    /// `traceparent` header when present, else the connection context below.
    /// All-zero trace id → root span.
    pub(crate) span_trace_id: [u8; 16],
    pub(crate) span_parent_id: [u8; 8],
    /// W3C trace-flags the span adopts (per request): the `traceparent` flags
    /// when present, else `conn_flags`. Low bit = `sampled`.
    pub(crate) span_flags: u8,
    /// Connection-scoped trace context from IP→TLS `MSG_TRACE_CTX` (TLS's span
    /// id as parent). Set once at accept, applied to every request on the
    /// connection that doesn't carry its own `traceparent`. All-zero = none.
    pub(crate) conn_trace_id: [u8; 16],
    pub(crate) conn_parent_id: [u8; 8],
    /// W3C trace-flags from the connection's `MSG_TRACE_CTX`. Low bit = `sampled`.
    pub(crate) conn_flags: u8,

    // ── Proxy relay state ──────────────────────────────────────────
    //
    // A HANDLER_PROXY route (static `proxy_ip/port`) or a dynamic-route
    // match dials an upstream backend and relays bytes both ways
    // within this slot's existing `recv_buf` (client→backend) and
    // `send_buf` (backend→client) windows — no extra arenas.
    /// Upstream backend conn id latched from `MSG_CONNECTED`; `-1`
    /// when no backend conn is dialed / open.
    pub(crate) backend_conn_id: i32,
    /// Dyn-route index driving this relay (`-1` = static proxy route
    /// or none). Used to advance `rr_cursor` + reselect on failover.
    pub(crate) proxy_dyn_idx: i16,
    /// Selected backend address for the (re)dial.
    pub(crate) proxy_be_ip: u32,
    pub(crate) proxy_be_port: u16,
    /// Client's source address for `X-Forwarded-For`. 0 (`0.0.0.0`)
    /// when unknown — the net layer's `MSG_ACCEPTED` carries only
    /// `[conn_id][local_port]`, not the peer address (P1 correction),
    /// so this stays 0 in production until a peer-address surface
    /// lands. The XFF injection path itself is real and exercised.
    pub(crate) client_ip: u32,
    /// Wall-clock ms the current dial started (connect timeout).
    pub(crate) proxy_connect_start_ms: u32,
    /// Connect attempts made so far (0 = first). Retry budget is 1.
    pub(crate) proxy_attempt: u8,
    /// 1 once demux latched `MSG_CONNECTED` for our pending dial.
    pub(crate) proxy_connected: u8,
    /// 1 once demux saw a connect `MSG_ERROR` for our pending dial.
    pub(crate) proxy_connect_failed: u8,
    /// 1 once the backend peer closed (`MSG_CLOSED` on `backend_conn_id`).
    pub(crate) backend_closed: u8,
    /// Read cursor into `recv_buf` for the client→backend body relay.
    pub(crate) proxy_creq_off: u16,
    _proxy_pad: [u8; 2],
}

impl ConnSlot {
    /// True when the slot is available for `alloc_free_slot`. Free
    /// slots have null buffers — their heap allocations have been
    /// returned to the arena.
    pub(crate) fn is_free(&self) -> bool {
        self.conn_id < 0 && matches!(self.phase, Phase::Init | Phase::WaitAccept)
    }
}

/// Slot lifecycle helpers. Operate on the slot table indirectly so
/// they can call `heap_alloc` / `heap_free` via the syscall table.
///
/// `slot_init_zero` is called once per slot at module init (the
/// kernel zero-fills `module_state` so we just need to set the
/// `-1` sentinels — no heap activity yet).
unsafe fn slot_init_zero(slot: &mut ConnSlot) {
    slot.conn_id = -1;
    slot.matched_route = -1;
    slot.file_index = -1;
    slot.fs_fd = -1;
    // Proxy relay sentinels — a zero-fill leaves these at 0, which is
    // a *valid* conn id / route index, so they must be re-set to -1.
    slot.backend_conn_id = -1;
    slot.proxy_dyn_idx = -1;
}

/// Drain every pending `peer_identity` record onto its connection.
///
/// Bounded per step so a burst cannot starve the protocol work: identities are
/// small and one per handshake, and whatever is left is read on the next tick.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn drain_peer_identities(s: &mut HttpState) {
    use crate::abi::contracts::net::peer_identity as pid;
    const PER_STEP: usize = 8;
    let chan = s.server.peer_chan;
    if chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    for _ in 0..PER_STEP {
        let poll = (sys.channel_poll)(chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            return;
        }
        // Sized from the contract, so the buffer holds the largest record the
        // layout admits. One too small is not a short read: the length check
        // fails, no identity binds, and the undelivered bytes desync whatever
        // follows.
        let mut buf = [0u8; pid::MAX_TOTAL];
        let n = (sys.channel_read)(chan, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            return;
        }
        // The contract's accessor rather than literal offsets: this module does
        // not own the layout, and a reader counting somebody else's bytes is
        // invisible to review and to the compiler when a field moves.
        let Some((msg_type, plen)) =
            pid::frame_parts(&buf[..n as usize]).map(|(t, p)| (t, p.len()))
        else {
            continue;
        };
        if msg_type != pid::MSG_PEER_IDENTITY {
            continue;
        }
        // A record that arrives and binds NOTHING presents exactly as
        // plaintext: the application sees an anonymous caller either way.
        // Counted rather than logged — one line per handshake is noise, and a
        // counter is the same evidence without it.
        if note_peer_identity(s, &buf[pid::FRAME_HDR..pid::FRAME_HDR + plen]) {
            s.server.peers_bound = s.server.peers_bound.wrapping_add(1);
        } else {
            s.server.peers_unbound = s.server.peers_unbound.wrapping_add(1);
        }
    }
}

/// The verified peer fingerprint bound to `conn_id`, if any.
///
/// Looked up by connection rather than passed down, because both HTTP
/// generations reach the envelope writer by different paths and the identity is
/// a property of the connection either way.
pub(crate) unsafe fn peer_svid(s: &HttpState, conn_id: u16) -> Option<&[u8]> {
    for i in 0..MAX_CONCURRENT_CONNS {
        let e = &*s.server.peers.as_ptr().add(i);
        if e.conn_id == i32::from(conn_id) && e.len > 0 {
            return Some(&e.svid[..e.len as usize]);
        }
    }
    None
}

/// Forget the peer bound to `conn_id`. Called when the connection ends:
/// connection ids are RECYCLED, and an identity left behind would authenticate
/// the next holder of the id as the previous one.
pub(crate) unsafe fn forget_peer(s: &mut HttpState, conn_id: i32) {
    for i in 0..MAX_CONCURRENT_CONNS {
        let e = &mut *s.server.peers.as_mut_ptr().add(i);
        if e.conn_id == conn_id {
            *e = PEER_EMPTY;
        }
    }
}

/// Record a verified peer identity against its connection.
///
/// Whether a record binds at all is the contract's decision, not this
/// module's: `fingerprint` yields bytes only for a handshake that succeeded,
/// whose chain validated, and whose peer proved possession of the key. A
/// certificate that was merely presented is a different fact from a peer that
/// was authenticated, and treating the first as the second is the
/// confused-deputy shape mutual TLS exists to close.
pub(crate) unsafe fn note_peer_identity(s: &mut HttpState, payload: &[u8]) -> bool {
    use crate::abi::contracts::net::peer_identity as pid;
    if payload.len() < pid::PAYLOAD_FIXED {
        return false;
    }
    let conn_id = i32::from(pid::conn_id(payload));
    let fingerprint = pid::fingerprint(payload);

    // Always CLEAR first: a record that does not bind an identity, for a
    // connection that previously had one, must REMOVE it — a renegotiation
    // that downgrades the peer must not leave the old identity standing.
    forget_peer(s, conn_id);
    let Some(fp) = fingerprint else {
        return false;
    };
    if fp.len() > MAX_PEER_SVID {
        return false;
    }
    for i in 0..MAX_CONCURRENT_CONNS {
        let e = &mut *s.server.peers.as_mut_ptr().add(i);
        if e.conn_id >= 0 {
            continue;
        }
        e.conn_id = conn_id;
        e.svid[..fp.len()].copy_from_slice(fp);
        e.len = fp.len() as u8;
        return true;
    }
    false
}

/// Free a slot's heap allocations (recv_buf, send_buf, h2),
/// zero its metadata, and clear its bit in the ready bitmap.
/// Called from `free_slot` (close path) and as the cleanup half
/// of `alloc_free_slot` when a buffer's allocation fails.
unsafe fn slot_release_buffers(s: &mut HttpState, idx: usize) {
    // Connection ids are RECYCLED, so the peer bound to this one must go with
    // it — otherwise the next holder of the id inherits somebody's identity.
    {
        let cid = (*s.server.slots.as_ptr().add(idx)).conn_id;
        if cid >= 0 {
            forget_peer(s, cid);
        }
    }
    // A connection that opened owes a committed closure. Reported here, where
    // every path that ends a connection converges, so it is reported once and
    // for exactly the connections that opened — not where a close was
    // REQUESTED, which is a different fact.
    {
        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);

        if slot.ws_opened_sent != 0 {
            let conn = if slot.conn_id >= 0 {
                slot.conn_id as u32
            } else {
                0
            };
            let origin = if slot.peer_closed != 0 {
                ws::WS_ORIGIN_PEER
            } else {
                ws::WS_ORIGIN_LOCAL
            };
            let code = slot.ws_close_code;
            slot.ws_opened_sent = 0;
            ws::ws_report_event(s, conn, ws::WS_EV_CLOSED, origin, code, b"");
        }
    }
    // If this slot owned `file_chan`, release the lock so a sibling
    // slot blocked in DispatchRoute can proceed. Done before the
    // slot's `cur_slot` index is touched so `release_file_chan`
    // matches the right owner check.
    if s.server.file_chan_owner == idx as i16 {
        s.server.file_chan_owner = -1;
    }
    // Same for a serialised proxy connect owned by this slot — a slot
    // freed mid-dial must not wedge the connect serialisation.
    if s.server.proxy_connect_owner == idx as i16 {
        s.server.proxy_connect_owner = -1;
    }
    // If this slot was the current fan-out winner, clear the
    // pointer so the next subscriber doesn't immediately self-close
    // against a stale index.
    if s.server.latest_fanout_slot == idx as i32 {
        s.server.latest_fanout_slot = -1;
    }
    // If this slot was retaining a body-cache entry (mid-emission
    // close), release the retain so the entry can be evicted.
    {
        let slot = &*s.server.slots.as_ptr().add(idx);
        if slot.cache_retained != 0 && slot.matched_route >= 0 {
            let route_idx = slot.matched_route;
            cache_release_for_route(s, route_idx as u8);
            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
            slot.cache_retained = 0;
        }
    }
    let sys = s.syscalls;
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    if !slot.recv_buf.is_null() {
        heap_free(&*sys, slot.recv_buf);
        slot.recv_buf = core::ptr::null_mut();
        slot.recv_cap = 0;
    }
    if !slot.send_buf.is_null() {
        heap_free(&*sys, slot.send_buf);
        slot.send_buf = core::ptr::null_mut();
        slot.send_cap = 0;
    }
    #[cfg(feature = "h2")]
    if !slot.h2.is_null() {
        heap_free(&*sys, slot.h2 as *mut u8);
        slot.h2 = core::ptr::null_mut();
    }
    // WS fan-out fragmentation may have a heap-allocated source
    // payload buffer in flight when the conn closes mid-message.
    // Free it explicitly — the slot zero-fill below clears the
    // pointer, which would otherwise leak the allocation.
    if !slot.ws_frag_buf.is_null() {
        heap_free(&*sys, slot.ws_frag_buf);
        slot.ws_frag_buf = core::ptr::null_mut();
        slot.ws_frag_total = 0;
        slot.ws_frag_offset = 0;
    }
    // Same hazard for a request body in flight when the peer hangs up
    // mid-upload: the zero-fill below would clear the pointer and leak it.
    if !slot.body_buf.is_null() {
        heap_free(&*sys, slot.body_buf);
        slot.body_buf = core::ptr::null_mut();
        slot.body_cap = 0;
        slot.body_len = 0;
    }
    // Zero the rest of the slot then re-set sentinels.
    let p = slot as *mut ConnSlot as *mut u8;
    core::ptr::write_bytes(p, 0, core::mem::size_of::<ConnSlot>());
    slot_init_zero(slot);
    ready_clear(s, idx);
}

/// Allocate the per-slot heap buffers. Returns `false` on
/// allocation failure — caller is expected to release any partial
/// allocation via `slot_release_buffers` and close the conn.
unsafe fn slot_acquire_buffers(s: &mut HttpState, idx: usize) -> bool {
    let sys = s.syscalls;
    let recv = heap_alloc(&*sys, RECV_BUF_SIZE as u32);
    if recv.is_null() {
        return false;
    }
    let send = heap_alloc(&*sys, SEND_BUF_SIZE as u32);
    if send.is_null() {
        heap_free(&*sys, recv);
        return false;
    }
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot.recv_buf = recv;
    slot.recv_cap = RECV_BUF_SIZE as u16;
    slot.send_buf = send;
    slot.send_cap = SEND_BUF_SIZE as u16;
    true
}

/// Server-wide state shared across all connections. Holds channel
/// handles, route configuration, the body cache + arena, telemetry
/// variables, the per-connection slot table, and the step
/// iterator's bookkeeping. Per-connection state lives in
/// [`ConnSlot`] inside `slots`.
#[repr(C)]
pub(crate) struct ServerState {
    /// `var_chan` carries `FmpMessage` updates that drive
    /// `{{var:name}}` substitutions in template responses.
    pub(crate) var_chan: i32,
    /// File-backed content channel used by `HANDLER_FILE`,
    /// `HANDLER_STREAM`, and `HANDLER_TEMPLATE`'s cache-fill path.
    /// One channel shared across all slots; serialised via
    /// `file_chan_owner` so concurrent fetches don't race on
    /// `IOCTL_FLUSH`/`IOCTL_NOTIFY`. `HANDLER_FS_FILE` (handler 7)
    /// bypasses this entirely via per-slot `fs_fd` through the
    /// FS_CONTRACT and is the recommended path for new deployments.
    pub(crate) file_chan: i32,
    /// Slot index that currently owns `file_chan` (-1 = free). A
    /// handler that needs the channel calls `try_acquire_file_chan`
    /// to claim it; if another slot is mid-fetch, the caller stalls
    /// in `DispatchRoute` and retries on the next tick. Released on
    /// transition to `DrainSend` (fetch / body-send complete) and
    /// in `slot_release_buffers` (any close path).
    pub(crate) file_chan_owner: i16,
    _file_chan_pad: [u8; 2],
    pub(crate) out_chan: i32,
    /// Output channel for `ws_out` (manifest port out[2]). Carries
    /// `WsFrame` records when a route uses `HANDLER_WEBSOCKET_FANOUT`.
    /// `-1` if the port is unwired.
    pub(crate) ws_out_chan: i32,
    /// Where admission requests are offered.
    pub(crate) ws_admit_out_chan: i32,
    /// Where admission decisions arrive.
    pub(crate) ws_admit_in_chan: i32,
    /// Where verified peer identities arrive, or `-1` when the graph left the
    /// port unwired. Unwired is the plaintext deployment and is silent, not an
    /// error: every request is simply anonymous.
    pub(crate) peer_chan: i32,
    /// Where committed lifecycle facts are reported.
    pub(crate) ws_event_out_chan: i32,
    /// Input channel for `ws_in` (manifest port in[3]). Carries
    /// `WsFrame` records to be queued back as outbound WS frames.
    /// `-1` if the port is unwired.
    pub(crate) ws_in_chan: i32,
    /// Output channel for `req_out` (manifest port out[6]). Carries
    /// `HttpRequest` envelopes when a route uses `HANDLER_APP`.
    /// `-1` if the port is unwired.
    pub(crate) app_out_chan: i32,
    /// Input channel for `resp_in` (manifest port in[6]). Carries the
    /// `HttpResponse` envelopes that answer them. `-1` if unwired.
    pub(crate) app_in_chan: i32,

    pub(crate) port: u16,
    /// Bytes currently consumed in `body_pool`. u32 so the pool
    /// can grow past 64 KiB for hosts that configure many or
    /// large templates.
    pub(crate) body_pool_used: u32,
    /// Largest request body this server will accept, in bytes. Configured by
    /// the `max_body_kib` param; zero means the built-in default.
    ///
    /// A cap rather than a limit-free read is what "bounded body handling"
    /// means: the buffer is heap-allocated per connection, so an uncapped
    /// server lets any client decide how much of the device's memory to take.
    /// Over the cap is 413, which is a refusal the client can act on — unlike
    /// a truncation, which it cannot detect.
    pub(crate) max_body: u32,

    pub(crate) route_count: u8,
    /// Configured at boot in `post_params` based on the wired routes.
    /// Server-wide (not per-conn) — every connection's dispatch path
    /// keys off the same configured mode.
    pub(crate) legacy_mode: u8,
    pub(crate) cache_count: u8,
    pub(crate) cache_tick: u8,
    /// Telemetry-variable count. Updates arrive on `var_chan` and
    /// apply to every connection's template render — vars are
    /// shared so two concurrent renders see the same snapshot.
    pub(crate) var_count: u8,

    pub(crate) routes: [Route; MAX_ROUTES],
    /// Variable table keyed by `name_hash`; updated by
    /// `drain_variables` from `var_chan`, read by `lookup_var`
    /// during template render. Shared across all connections.
    pub(crate) vars: [VarEntry; MAX_VARS],
    cache_entries: [CacheEntry; MAX_CACHE],
    pub(crate) body_pool: *mut u8,
    pub(crate) body_pool_cap: u32,
    pub(crate) draining: u8,
    /// Set to `1` after the IP module's `MSG_BOUND` arrives. Gates
    /// `demux_inbound` so it stays dormant during the bind sequence
    /// (Init → Binding → WaitBound) but stays active once binding
    /// has succeeded — even if slot 0 cycles Init → assigned →
    /// Init → assigned through subsequent connections.
    pub(crate) bound: u8,

    /// Per-connection slot table. Each slot can independently be in
    /// any phase, including `Init` (free). The accept path allocates
    /// the first free slot, the close path resets the slot back to
    /// free.
    pub(crate) slots: [ConnSlot; MAX_CONCURRENT_CONNS],
    /// Verified peers, by connection. One per concurrent connection — a
    /// connection can only have one peer.
    pub(crate) peers: [PeerEntry; MAX_CONCURRENT_CONNS],
    /// Peer records that bound an identity, and those that did not.
    ///
    /// The second is the load-bearing one: non-zero on a listener configured
    /// for mutual TLS means callers are reaching the application anonymous.
    /// Nothing at request level shows that — the request succeeds, and the
    /// application simply never learns who made it.
    pub(crate) peers_bound: u32,
    pub(crate) peers_unbound: u32,
    /// id 18 `requests_total` — every HTTP/1 request whose response fully
    /// drained, including those whose span was not sampled, so the rate it
    /// yields does not shrink when sampling tightens.
    pub(crate) requests_total: u64,
    /// id 19 `request_latency_us` — 16-bucket duration histogram against
    /// [`body::LAT_BOUNDS_US`], bucket 15 being the implicit `+Inf`.
    /// Cumulative counts, emitted on the telemetry cadence.
    ///
    /// Maintained only while a telemetry consumer is subscribed, because a
    /// duration costs a clock read. It therefore reconciles with
    /// `requests_total` across a window in which one stayed subscribed, and
    /// not across a server's whole lifetime.
    pub(crate) lat_hist: [u64; 16],
    /// Index of the currently-active slot. `-1` when no connection
    /// is being ticked.
    pub(crate) cur_slot: i32,
    /// Round-robin cursor for the step iterator. Tracks which slot
    /// got the most recent phase tick so the next tick picks a
    /// different one — fairness across concurrent transactions.
    pub(crate) step_cursor: u32,
    /// Bitmap of slots that need ticking. Bit `i` set ⇔ the
    /// iterator should call `step_active_slot` for slot `i` this
    /// tick. Allocating a slot via `alloc_free_slot` sets the bit;
    /// freeing it via `slot_release_buffers` clears it. Slot 0
    /// stays set during the boot bind sequence
    /// (Init → Binding → WaitBound) and the WaitBound→WaitAccept
    /// transition clears it. This makes per-tick cost O(active)
    /// instead of O(MAX_CONCURRENT_CONNS).
    pub(crate) ready_bits: [u64; READY_BITS_WORDS],

    // ── Retention buffer ──────────────────────────────────────────
    //
    // Server-wide capture of the most recent burst of WsFrame
    // envelopes seen on `ws_in`. Each envelope is encoded as
    // `[opcode:u8][fin:u8][payload_len:u16 LE][payload:N]` and
    // appended to `retained_buf`. When a NEW connection enters
    // `WsActive` with `ws_fan_out=1`, its first `retained_used`
    // bytes' worth of replay drains this buffer envelope-by-envelope
    // into `send_buf` before live envelopes resume.
    //
    // Single subscriber by design: the producer emits once per state
    // change; the server retains the latest "complete" snapshot
    // (defined by an idle gap > `RETAIN_RESET_TICKS`). New connects
    // see the snapshot immediately; live envelopes mid-capture also
    // see the live stream via the normal `ws_drain_fanout_input`
    // path.
    pub(crate) retained_buf: *mut u8,
    pub(crate) retained_cap: u32,
    pub(crate) retained_used: u32,
    pub(crate) retained_envelope_count: u16,
    /// Ticks since the last `ws_in` envelope was captured. Reset to
    /// 0 on capture; saturating-incremented every step. When it
    /// exceeds `RETAIN_RESET_TICKS` the next captured envelope
    /// triggers a wipe of `retained_used` so the buffer holds the
    /// fresh post-idle snapshot instead of growing without bound.
    pub(crate) retained_idle_ticks: u16,
    _retained_pad: [u8; 2],

    /// Last-connection-wins: index of the slot that most recently
    /// completed a fan-out WS upgrade, or `-1` when no fan-out
    /// subscriber is active. Every other slot whose `ws_fan_out=1`
    /// self-closes (CLOSE 1001) on its next `WsActive` tick. The
    /// fan-out routes are inherently single-subscriber — image
    /// viewers, raster bridges, telemetry feeds — so a second tab
    /// connecting must displace the first cleanly, and a displaced
    /// tab must NOT auto-reconnect (the WS source built-in and the
    /// canonical runtime shell both have no reconnect logic).
    pub(crate) latest_fanout_slot: i32,

    // ── Dynamic routes ─────────────────────────────────────────────
    //
    // Default-off: `routes_prefix_len == 0` means the whole subsystem
    // is dormant and the server behaves byte-for-byte as before.
    /// Store prefix the table_consumer subscribes to (e.g.
    /// `/dataplane/edge/`). Empty (`routes_prefix_len == 0`) = feature
    /// off.
    pub(crate) routes_prefix: [u8; MAX_DYN_PREFIX],
    pub(crate) routes_prefix_len: u16,
    /// Change-sink channel (store SUBSCRIBE pushes here; self-edge
    /// alloc, in[DYN_ROUTES_PORT_INDEX]). `-1` until resolved.
    pub(crate) routes_sink: i32,
    /// Subscription bookkeeping.
    pub(crate) tc: TableConsumer,
    /// The dynamic-route arena + rebuild shadow.
    pub(crate) dyn_routes: DynRoutes,
    /// Scratch for the `CHANGES` relist response.
    pub(crate) routes_scratch: [u8; DYN_SCRATCH],

    // ── Proxy relay bookkeeping ────────────────────────────────────
    /// Slot index owning the in-flight proxy `CONNECT` handshake, or
    /// `-1`. `MSG_CONNECTED`/`MSG_ERROR` carry only `[conn_id][tag]`
    /// and the tag is the module index (identical across slots), so
    /// the CONNECT→CONNECTED window is serialised — demux correlates
    /// the reply to this owner. Mirrors `file_chan_owner`; the relay
    /// itself (the long part) runs concurrently across slots.
    pub(crate) proxy_connect_owner: i16,
    _proxy_owner_pad: [u8; 2],
    /// Cumulative failover retries (`http.proxy.retries`, §3). A reader
    /// surfaces this via telemetry, never a store key (dynamic_routes §6).
    pub(crate) proxy_retries: u32,
    /// Cumulative relay 5xx responses (`http.proxy.5xx`, §3).
    pub(crate) proxy_5xx: u32,

    /// Next request generation stamped into an HTTP/1.1 application request's
    /// `stream_id`.
    ///
    /// Under h1 a connection carries one request at a time, so `stream_id` was
    /// pinned to 0 and `(conn_id, stream_id)` reduced to the connection. That is
    /// sound only while a connection id means one thing forever, and it does
    /// not: the transport recycles ids, so a slot released with an application
    /// request still outstanding is followed by a NEW peer holding the same id
    /// and also awaiting an answer with `stream_id` 0. The late answer then
    /// matched the new peer's request exactly, and one connection was served
    /// another's response — a valid, well-framed, entirely wrong reply.
    ///
    /// A generation makes the pair mean what it claims. It lives on the server
    /// rather than the slot because `slot_release_buffers` zeroes the slot, so
    /// anything held there is reset precisely when a connection id is about to
    /// be reused — which is the moment the discriminator has to survive.
    ///
    /// Applications echo `stream_id` back, which the fan-out contract already
    /// requires of them, so this is transparent to any application that was
    /// correct under h2. It wraps at 65_536 outstanding-request generations;
    /// a stale answer surviving that long is not distinguishable by any scheme
    /// this envelope can carry, and the request it would collide with has long
    /// since timed out.
    pub(crate) app_gen_next: u16,

    // ── Load-shedding counters ─────────────────────────────────────
    //
    // Every path below sheds work under pressure, and each one used to
    // present to an operator as the same symptom — a slow or reset
    // client. They are separate counters because they have separate
    // fixes: the first two decide whether to raise the slot table or
    // the arena, and confusing them sends a capacity investigation to
    // the wrong constant. A resource denial that cannot say who asked
    // for what is the failure mode the resource model exists to end.
    /// Connections refused because no `ConnSlot` was free
    /// (`http.conns.refused.slots`). Raise `MAX_CONCURRENT_CONNS`.
    pub(crate) conns_refused_slots: u32,
    /// Connections refused because the module arena could not supply the
    /// slot's buffers (`http.conns.refused.arena`). Raise
    /// `ARENA_WORKING_SET_CONNS` — the slot table was NOT the limit.
    pub(crate) conns_refused_arena: u32,
    /// Ticks the inbound demux stopped early because the target slot's
    /// `recv_buf` was full (`http.demux.stalls`). Rising here means one
    /// slow peer is holding up delivery for every other connection,
    /// which is head-of-line blocking rather than a throughput limit.
    pub(crate) demux_stalls: u32,
    /// Application requests answered 504 by the module because the
    /// application never replied (`http.app.timeouts`).
    pub(crate) app_timeouts: u32,
    /// Application responses lost because the backpressure writeback to
    /// `resp_in` was itself refused (`http.app.envelopes.lost`). The
    /// application believes it answered; the client will not be answered.
    /// Non-zero means the response path dropped data, not merely delayed
    /// it, and is never expected in a healthy graph.
    pub(crate) app_envelopes_lost: u32,
    /// Envelopes discarded because they exceeded what one channel read
    /// can carry (`http.app.envelopes.oversize`). A configuration error:
    /// the port's declared record size is larger than the reader's.
    pub(crate) app_envelopes_oversize: u32,
    /// WebSocket fan-out envelopes dropped — unknown conn, no fan-out
    /// slot active, or oversize (`http.ws.envelopes.dropped`).
    pub(crate) ws_envelopes_dropped: u32,
    /// WebSocket lifecycle events dropped because the retry ring was already
    /// full (`http.ws.events.dropped`). Non-zero means an application is far
    /// enough behind on `ws_event_out` that its view of which connections
    /// exist has diverged from this module's.
    pub(crate) ws_events_dropped: u32,
    /// Lifecycle events awaiting a `ws_event_out` that refused them.
    pub(crate) ws_event_ring: [ws::PendingWsEvent; ws::WS_EVENT_RING],
    pub(crate) ws_event_len: u8,
    /// HTTP/2 streams refused because the connection's stream table was
    /// full (`http.h2.streams.refused`). Expected under a client that
    /// outruns `MAX_STREAMS`; a floor, not a fault.
    pub(crate) h2_streams_refused: u32,
    /// HTTP/3 requests answered 501 because the matched route's handler is not
    /// served over h3 (`http.h3.handler_unavailable`). A CONFIGURATION signal,
    /// not a load one: it means a route that works over HTTP/1.1 and HTTP/2 is
    /// reachable over HTTP/3 and cannot be served there. Without the counter
    /// this is visible only to the client that asked.
    pub(crate) h3_handler_unavailable: u32,
    /// HTTP/3 responses refused because their field section exceeds the peer's
    /// advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`
    /// (`http.h3.field_limit_refused`). Non-zero means a peer's limit is
    /// tighter than our smallest response, so nothing can be served to it —
    /// which otherwise presents as a client that connects and then gets
    /// nothing, with no error on either side naming the cause.
    pub(crate) h3_field_limit_refused: u32,

    // ── Dynamic listeners ──────────────────────────────────────────
    //
    // Default-off: `listeners_prefix_len == 0` leaves the whole
    // mid-life-bind subsystem dormant and the server byte-identical.
    /// Store prefix the listener table_consumer subscribes to (e.g.
    /// `/dataplane/edge-listeners/`). Empty = feature off.
    pub(crate) listeners_prefix: [u8; MAX_DYN_PREFIX],
    pub(crate) listeners_prefix_len: u16,
    /// Change-sink channel (self-edge alloc, in[DYN_LISTENERS_PORT_INDEX]).
    /// `-1` until resolved.
    pub(crate) listeners_sink: i32,
    /// Listener-subscription bookkeeping (second table consumer).
    pub(crate) ltc: TableConsumer,
    /// Desired-listener table + reconciler bind records.
    pub(crate) listeners: DynListeners,
}

/// Store-prefix buffer for `routes_prefix`.
pub(crate) const MAX_DYN_PREFIX: usize = 64;
/// `CHANGES` relist scratch. Holds the full snapshot for a cold-start /
/// LOST rebuild; a snapshot larger than this fails closed (keeps the
/// prior table) — sized to comfortably cover the arena's worst case.
pub(crate) const DYN_SCRATCH: usize = 8192;
/// Input port index carrying the self-edged change sink (in[4]).
pub(crate) const DYN_ROUTES_PORT_INDEX: u8 = 4;

/// Number of `u64` words needed to cover `MAX_CONCURRENT_CONNS`
/// bits (rounded up). At the host profile's 256 that is 4 words = 32 bytes;
/// on `profile_embedded`'s single slot, one word.
pub(crate) const READY_BITS_WORDS: usize = MAX_CONCURRENT_CONNS.div_ceil(64);

#[inline(always)]
pub(crate) unsafe fn ready_set(s: &mut HttpState, idx: usize) {
    if idx < MAX_CONCURRENT_CONNS {
        s.server.ready_bits[idx / 64] |= 1u64 << (idx % 64);
    }
}

#[inline(always)]
pub(crate) unsafe fn ready_clear(s: &mut HttpState, idx: usize) {
    if idx < MAX_CONCURRENT_CONNS {
        s.server.ready_bits[idx / 64] &= !(1u64 << (idx % 64));
    }
}

// ServerState lives inside HttpState, which the kernel allocates as a
// zeroed buffer of `module_state_size()` bytes. `init()` below sets
// only those fields whose default is not zero.

// ── Multi-conn slot helpers ───────────────────────────────────────────────
//
// These helpers locate / allocate / free slots in the
// `ServerState::slots` array. They underpin the iterator-based step
// machine — `cur_slot` is the slot index the per-tick handler is
// currently running against; convenience accessors below
// (`cur_recv_len`, `cur_send_buf_mut_ptr`, …) read or mutate that
// slot's per-conn state.

/// Find the slot whose `conn_id` matches `conn_id`. Returns `None`
/// when no slot owns that conn id (e.g. an MSG_DATA arrived for a
/// peer that already closed and got pruned).
pub(crate) unsafe fn find_slot_by_conn_id(s: &HttpState, conn_id: u16) -> Option<usize> {
    let needle = conn_id as i32;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.conn_id == needle {
            return Some(i);
        }
    }
    None
}

/// Resolve the "unclaimed" (`u32::MAX`) sentinel `ws_stream` stamps on an
/// envelope before it has observed an inbound frame and learned a real conn id.
///
/// Returns the fan-out slot the envelope belongs to, or `None` when that cannot
/// be known.
///
/// `ws_stream` is a framing adapter with a single-connection model by design —
/// it latches one conn id and a second connection replaces it — so a sentinel
/// envelope means "the one connection". The server enforces the same policy
/// from its side with last-connection-wins: a newer fan-out upgrade displaces
/// the older slot, which is sent a graceful close.
///
/// The subtlety is the displacement WINDOW. Between the new upgrade and the old
/// slot's close draining, two fan-out slots are live, and the previous
/// behaviour — take the lowest-indexed one — resolved the sentinel to whichever
/// happened to sit earlier in the table. That is frequently the slot being
/// closed, so a producer pushing on connect had its bytes delivered to the
/// departing client instead of the arriving one.
///
/// So the newest fan-out slot wins, because that is the connection the producer
/// means. Only when no slot is identifiable does this refuse, and the caller
/// counts the drop — an unaddressable envelope becomes a visible loss rather
/// than an invisible delivery to the wrong peer.
pub(crate) unsafe fn find_sentinel_ws_fanout_slot(s: &HttpState) -> Option<usize> {
    let is_live_fanout = |i: usize| -> bool {
        let slot = &*s.server.slots.as_ptr().add(i);
        slot.conn_id >= 0 && slot.ws_fan_out != 0
    };
    // The most recent fan-out upgrade, when it is still live: the connection a
    // producer-first bundle is for.
    let latest = s.server.latest_fanout_slot;
    if latest >= 0 && (latest as usize) < MAX_CONCURRENT_CONNS && is_live_fanout(latest as usize) {
        return Some(latest as usize);
    }
    // No current winner (none has upgraded yet this run, or it has closed):
    // fall back to the sole live fan-out slot if there is exactly one.
    let mut found: Option<usize> = None;
    for i in 0..MAX_CONCURRENT_CONNS {
        if is_live_fanout(i) {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    found
}

/// Allocate the first free slot and acquire its heap buffers.
/// Returns `None` when the slot table is full or the heap is
/// exhausted — caller closes the incoming connection in either
/// case (the IP module would otherwise leave the slot in
/// `Established` until the per-conn timeout, exhausting
/// `MAX_TCP_CONNS` under any non-trivial load).
///
/// Free slots are guaranteed clean (zeroed metadata, null buffer
/// pointers) by `slot_release_buffers` on the close path — this
/// function therefore only needs to acquire fresh buffers and set
/// the conn id.
pub(crate) unsafe fn alloc_free_slot(s: &mut HttpState, conn_id: u16) -> Option<usize> {
    let mut chosen: Option<usize> = None;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.is_free() {
            chosen = Some(i);
            break;
        }
    }
    // The two ways this returns None are different capacity limits with
    // different fixes, so they are counted apart. Reported as one number they
    // are unactionable: "connections are being refused" does not say whether
    // to raise the slot table or the arena, and raising the wrong one changes
    // nothing while looking like a fix.
    let idx = match chosen {
        Some(i) => i,
        None => {
            s.server.conns_refused_slots = s.server.conns_refused_slots.wrapping_add(1);
            return None;
        }
    };
    if !slot_acquire_buffers(s, idx) {
        // Arena exhausted — leave the slot free and tell the caller. The slot
        // table still had room, so `MAX_CONCURRENT_CONNS` is NOT the limit here.
        s.server.conns_refused_arena = s.server.conns_refused_arena.wrapping_add(1);
        return None;
    }
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot.conn_id = conn_id as i32;
    // Clear any trace context inherited from a prior connection on this slot;
    // the new connection's `MSG_TRACE_CTX` (if any) repopulates it.
    slot.conn_trace_id = [0u8; 16];
    slot.conn_parent_id = [0u8; 8];
    slot.conn_flags = 0;
    slot.span_trace_id = [0u8; 16];
    slot.span_parent_id = [0u8; 8];
    slot.span_flags = 0;
    ready_set(s, idx);
    Some(idx)
}

/// Free the slot at `idx`: returns its heap buffers to the arena
/// and zeroes its metadata so the next `alloc_free_slot` call can
/// pick it up cleanly.
pub(crate) unsafe fn free_slot(s: &mut HttpState, idx: usize) {
    if idx >= MAX_CONCURRENT_CONNS {
        return;
    }
    slot_release_buffers(s, idx);
}

/// Borrow the currently-active slot — the one whose state the
/// per-tick handler is reading/writing. Returns `None` when
/// `cur_slot < 0`, i.e. the server is idle / between connections.
pub(crate) unsafe fn cur_slot(s: &HttpState) -> Option<&ConnSlot> {
    let idx = s.server.cur_slot;
    if idx < 0 || (idx as usize) >= MAX_CONCURRENT_CONNS {
        return None;
    }
    Some(&*s.server.slots.as_ptr().add(idx as usize))
}

/// Mutable variant of [`cur_slot`].
pub(crate) unsafe fn cur_slot_mut(s: &mut HttpState) -> Option<&mut ConnSlot> {
    let idx = s.server.cur_slot;
    if idx < 0 || (idx as usize) >= MAX_CONCURRENT_CONNS {
        return None;
    }
    Some(&mut *s.server.slots.as_mut_ptr().add(idx as usize))
}

/// Convenience read of the active slot's `matched_route`. Returns
/// `-1` (the "no match" sentinel) when no slot is active.
#[inline(always)]
pub(crate) unsafe fn cur_matched_route(s: &HttpState) -> i8 {
    cur_slot(s).map(|c| c.matched_route).unwrap_or(-1)
}

/// Convenience read of the active slot's `ws_fan_out`. Returns 0
/// when no slot is active.
#[inline(always)]
pub(crate) unsafe fn cur_ws_fan_out(s: &HttpState) -> u8 {
    cur_slot(s).map(|c| c.ws_fan_out).unwrap_or(0)
}

/// Convenience read of the active slot's `recv_len`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_recv_len(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.recv_len).unwrap_or(0)
}

/// Convenience read of the active slot's `send_offset`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_offset(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.send_offset).unwrap_or(0)
}

/// Convenience read of the active slot's `send_len`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_len(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.send_len).unwrap_or(0)
}

/// Convenience read of the active slot's `fs_fd`. -1 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_fs_fd(s: &HttpState) -> i32 {
    cur_slot(s).map(|c| c.fs_fd).unwrap_or(-1)
}

/// Convenience read of the active slot's `fs_total`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_fs_total(s: &HttpState) -> u32 {
    cur_slot(s).map(|c| c.fs_total).unwrap_or(0)
}

/// Convenience read of the active slot's `fs_sent`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_fs_sent(s: &HttpState) -> u32 {
    cur_slot(s).map(|c| c.fs_sent).unwrap_or(0)
}

/// Convenience read of the active slot's `phase`. `Phase::Init` when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_phase(s: &HttpState) -> Phase {
    cur_slot(s).map(|c| c.phase).unwrap_or(Phase::Init)
}

/// Set the active slot's `phase`. No-op if no slot.
#[inline(always)]
pub(crate) unsafe fn set_cur_phase(s: &mut HttpState, p: Phase) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = p;
    }
}

/// Active slot's `H2State` shared ref. Caller must already know
/// the slot is in h2 mode (i.e. h2 has been allocated via
/// `ensure_h2_state`).
///
/// # Safety
/// `cur_slot` must point at a non-free slot whose `h2` pointer is
/// non-null. The h2 phase machine maintains both invariants — it
/// only reads h2 state after `enter()` (which calls
/// `ensure_h2_state`) and before the slot transitions to
/// `CloseConn` (which clears the pointer).
#[cfg(feature = "h2")]
#[inline(always)]
pub(crate) unsafe fn cur_h2(s: &HttpState) -> &h2::H2State {
    &*cur_slot(s).unwrap_unchecked().h2
}

/// Active slot's `H2State` mut ref. Same precondition as
/// [`cur_h2`].
#[cfg(feature = "h2")]
#[inline(always)]
pub(crate) unsafe fn cur_h2_mut(s: &mut HttpState) -> &mut h2::H2State {
    &mut *cur_slot_mut(s).unwrap_unchecked().h2
}

/// Allocate the active slot's `H2State` if not already allocated.
/// Called from `h2::enter()` before the slot runs its first h2
/// tick. Returns `false` on heap exhaustion — the caller must
/// transition to `CloseConn` rather than enter `H2Active`.
#[cfg(feature = "h2")]
pub(crate) unsafe fn ensure_h2_state(s: &mut HttpState) -> bool {
    let idx = match current_slot_index(s) {
        Some(i) => i,
        None => return false,
    };
    let slot = &*s.server.slots.as_ptr().add(idx);
    if !slot.h2.is_null() {
        return true;
    }
    let sys = s.syscalls;
    let raw = heap_alloc(&*sys, core::mem::size_of::<h2::H2State>() as u32);
    if raw.is_null() {
        return false;
    }
    // Initialise via H2State::zeroed() — `write_bytes(0)` would
    // leave `emit_cursor`, `file_owner`, `recv_window`,
    // `send_window`, and `peer_initial_window_size` at zero, which
    // makes every new stream's send_window 0 (RFC 7540 §6.9.2:
    // streams inherit peer_initial_window_size). h2 DATA emission
    // would then stall waiting for a WINDOW_UPDATE the peer has no
    // reason to send.
    core::ptr::write(raw as *mut h2::H2State, h2::H2State::zeroed());
    let slot_mut = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot_mut.h2 = raw as *mut h2::H2State;
    true
}

/// Active slot's `recv_buf` const pointer; null when no slot or
/// the slot's heap allocation is missing (between close and the
/// next `alloc_free_slot`).
#[inline(always)]
pub(crate) unsafe fn cur_recv_buf_ptr(s: &HttpState) -> *const u8 {
    cur_slot(s)
        .map(|c| c.recv_buf as *const u8)
        .unwrap_or(core::ptr::null())
}

/// Active slot's `recv_buf` mut pointer; null when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_recv_buf_mut_ptr(s: &mut HttpState) -> *mut u8 {
    cur_slot(s)
        .map(|c| c.recv_buf)
        .unwrap_or(core::ptr::null_mut())
}

/// Active slot's `send_buf` const pointer; null when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_buf_ptr(s: &HttpState) -> *const u8 {
    cur_slot(s)
        .map(|c| c.send_buf as *const u8)
        .unwrap_or(core::ptr::null())
}

/// Active slot's `send_buf` mut pointer; null when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_buf_mut_ptr(s: &mut HttpState) -> *mut u8 {
    cur_slot(s)
        .map(|c| c.send_buf)
        .unwrap_or(core::ptr::null_mut())
}

/// Active slot's `conn_id` on the wire type. The slot stores conn_id as i32
/// with `-1` meaning free; callers reaching this are only in-flight
/// phases where the slot is live (conn_id ≥ 0). The cast to u8
/// matches the wire format in MSG_ACCEPTED / CMD_SEND etc.
#[inline(always)]
pub(crate) unsafe fn cur_conn_id(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.conn_id as u16).unwrap_or(0)
}

/// Number of slots currently in use (any phase other than `Init`
/// with a non-negative `conn_id`). Used by the step iterator to
/// know when to round-robin and by tests to assert occupancy.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub(crate) unsafe fn active_slot_count(s: &HttpState) -> usize {
    let mut count = 0;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if !slot.is_free() {
            count += 1;
        }
    }
    count
}

// ── Init / post-params ────────────────────────────────────────────────────

pub(crate) unsafe fn init(s: &mut HttpState) {
    let sys = s.syscalls;
    s.server.var_chan = -1;
    s.server.file_chan = -1;
    s.server.file_chan_owner = -1;
    s.server.out_chan = -1;
    s.server.ws_out_chan = -1;
    s.server.ws_admit_out_chan = -1;
    s.server.peer_chan = -1;
    // `conn_id = -1` is FREE. The arena arrives zeroed, and zero is a valid
    // connection id — an uninitialised table would read as "connection 0 has
    // this identity" and hand it to whoever connected first.
    for i in 0..MAX_CONCURRENT_CONNS {
        *s.server.peers.as_mut_ptr().add(i) = PEER_EMPTY;
    }
    s.server.peers_bound = 0;
    s.server.peers_unbound = 0;
    s.server.requests_total = 0;
    s.server.lat_hist = [0; 16];
    s.server.ws_admit_in_chan = -1;
    s.server.ws_event_out_chan = -1;
    s.server.ws_in_chan = -1;
    s.server.app_out_chan = -1;
    s.server.app_in_chan = -1;
    s.server.latest_fanout_slot = -1;
    // Dynamic-route subscription: sink resolved lazily on first pump.
    // The arena, shadow, and TableConsumer are zero-init (kernel
    // zero-fills state) — equivalent to `DynRoutes::new()` /
    // `TableConsumer::new()`.
    s.server.routes_sink = -1;
    // Dynamic-listener subscription: sink resolved lazily on first pump;
    // the table, shadow, bind records, and TableConsumer are zero-init.
    s.server.listeners_sink = -1;
    s.server.proxy_connect_owner = -1;
    s.server.port = 80;
    if let Some(cur) = cur_slot_mut(s) {
        cur.fs_fd = -1;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.fs_total = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.fs_sent = 0;
    }
    // `matched_route`, `file_index`, `peer_closed`, `ws_fan_out`, and
    // `ws_pending_stuck_ticks` live in `ConnSlot`; the slot reset
    // below (`ConnSlot::reset`) zero-initializes them for every slot.

    // Multi-conn slots all start free (`conn_id = -1`,
    // `phase = Phase::Init`). The kernel zero-fills `module_state`
    // so we just need to set the `-1` sentinels — no heap activity
    // happens here; buffers are allocated on `alloc_free_slot` when
    // an MSG_ACCEPTED arrives.
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &mut *s.server.slots.as_mut_ptr().add(i);
        slot_init_zero(slot);
    }
    // Slot 0 owns the bind sequence (Init → Binding → WaitBound →
    // WaitAccept). Mark it ready so the iterator drives it; the
    // WaitBound→WaitAccept transition clears the bit, making the
    // slot truly idle until the demux re-allocates it.
    s.server.cur_slot = 0;
    s.server.step_cursor = 0;
    s.server.ready_bits = [0u64; READY_BITS_WORDS];
    ready_set(s, 0);
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = Phase::Init;
    }

    let pool = heap_alloc(&*sys, DEFAULT_BODY_POOL_SIZE as u32);
    if !pool.is_null() {
        s.server.body_pool = pool;
        s.server.body_pool_cap = DEFAULT_BODY_POOL_SIZE as u32;
    }

    // Retention buffer: server-wide snapshot of the most recent
    // burst on `ws_in`. Best-effort — if STATE_ARENA can't satisfy
    // a 2 MiB request we leave `retained_buf` null and the capture /
    // replay paths short-circuit (retention silently degrades to off,
    // producers must re-emit on every connect just like before).
    let retained = heap_alloc(&*sys, RETAINED_BUF_CAP as u32);
    if !retained.is_null() {
        s.server.retained_buf = retained;
        s.server.retained_cap = RETAINED_BUF_CAP as u32;
    } else {
        log(s, b"[http] retention disabled (no heap)");
    }
}

pub(crate) unsafe fn post_params(s: &mut HttpState) {
    let sys = &*s.syscalls;

    // Discover additional ports:
    //   in[1]  = variable updates  (FmpMessage)
    //   in[2]  = file data         (OctetStream)
    //   in[3]  = ws_in             (WsFrame, fan-out only)
    //   out[1] = file ctrl         (OctetStream)
    //   out[2] = ws_out            (WsFrame, fan-out only)
    s.server.var_chan = dev_channel_port(sys, 0, 1);
    s.server.file_chan = dev_channel_port(sys, 0, 2);
    s.server.ws_in_chan = dev_channel_port(sys, 0, 3);
    s.server.out_chan = dev_channel_port(sys, 1, 1);
    s.server.ws_out_chan = dev_channel_port(sys, 1, 2);
    //   in[7]  = ws_admit_in       (OctetStream, admission decisions)
    //   out[7] = ws_admit_out      (OctetStream, admission requests)
    //   out[8] = ws_event_out      (OctetStream, committed lifecycle facts)
    //   in[9]  = peer_identity     (OctetStream, mTLS only; -1 when unwired)
    s.server.peer_chan = dev_channel_port(sys, 0, 9);
    s.server.ws_admit_in_chan = dev_channel_port(sys, 0, 7);
    s.server.ws_admit_out_chan = dev_channel_port(sys, 1, 7);
    s.server.ws_event_out_chan = dev_channel_port(sys, 1, 8);
    //   in[6]  = resp_in           (HttpResponse, HANDLER_APP only)
    //   out[6] = req_out           (HttpRequest, HANDLER_APP only)
    #[cfg(feature = "app")]
    {
        s.server.app_in_chan = dev_channel_port(sys, 0, 6);
        s.server.app_out_chan = dev_channel_port(sys, 1, 6);
    }

    if s.server.route_count == 0 {
        let r0 = &mut *s.server.routes.as_mut_ptr().add(0);
        if r0.body_len > 0 {
            *r0.path.as_mut_ptr() = b'/';
            r0.path_len = 1;
            r0.handler = HANDLER_STATIC;
            s.server.route_count = 1;
            s.server.legacy_mode = 1;
        } else if s.server.file_chan >= 0 {
            s.server.legacy_mode = 2;
        }
    }

    if s.server.file_chan >= 0 {
        let mut count: u32 = 0;
        let count_ptr = &mut count as *mut u32 as *mut u8;
        let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_POLL_NOTIFY, count_ptr, 4);
        if r >= 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.file_count = count as u16;
            }
        }
    }

    // Diagnostic: dump each route's final body_len + offset so we
    // can pinpoint where body packing truncates without needing
    // browser dev tools.
    let mut i = 0u8;
    while i < s.server.route_count {
        let r = &*s.server.routes.as_ptr().add(i as usize);
        let mut buf = [0u8; 96];
        let p = buf.as_mut_ptr();
        let pfx = b"[http] route ";
        let mut q = 0usize;
        let mut t = 0;
        while t < pfx.len() {
            *p.add(q) = pfx[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), i as u32);
        let bl = b" body_len=";
        let mut t = 0;
        while t < bl.len() {
            *p.add(q) = bl[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), r.body_len);
        let bo = b" body_off=";
        let mut t = 0;
        while t < bo.len() {
            *p.add(q) = bo[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), r.body_offset);
        dev_log(&*s.syscalls, 2, p, q);
        i += 1;
    }
    {
        let mut buf = [0u8; 64];
        let p = buf.as_mut_ptr();
        let pfx = b"[http] body_pool used=";
        let mut q = 0usize;
        let mut t = 0;
        while t < pfx.len() {
            *p.add(q) = pfx[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), s.server.body_pool_used);
        let cp = b" cap=";
        let mut t = 0;
        while t < cp.len() {
            *p.add(q) = cp[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), s.server.body_pool_cap);
        dev_log(&*s.syscalls, 2, p, q);
    }
    log(s, b"[http] server ready");
}

// ── Internal helpers ──────────────────────────────────────────────────────

#[inline(always)]
pub(crate) unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

/// Try to claim exclusive use of `file_chan` for the active slot.
/// Returns `true` if the channel is now ours (either freshly claimed
/// or already held by us). Returns `false` if another slot owns it —
/// caller must stall in its current phase and retry on the next
/// tick.
///
/// Multi-conn safety: HANDLER_FILE / HANDLER_STREAM / HANDLER_TEMPLATE's
/// cache-fill path issue `IOCTL_FLUSH` + `IOCTL_NOTIFY` and then read
/// the response body across multiple step()s. Without serialisation
/// a second slot's FLUSH wipes the first's pending notify mid-fetch,
/// shredding the body. This guard linearises the channel.
#[inline]
pub(crate) unsafe fn try_acquire_file_chan(s: &mut HttpState) -> bool {
    let me = s.server.cur_slot;
    if me < 0 {
        return false;
    }
    let me = me as i16;
    let owner = s.server.file_chan_owner;
    if owner == me {
        return true;
    }
    if owner < 0 {
        s.server.file_chan_owner = me;
        return true;
    }
    false
}

/// Release `file_chan` ownership held by the active slot. No-op if
/// the channel was held by another slot (defensive — a misordered
/// release shouldn't free another slot's lock).
#[inline]
pub(crate) unsafe fn release_file_chan(s: &mut HttpState) {
    let me = s.server.cur_slot;
    if me < 0 {
        return;
    }
    if s.server.file_chan_owner == me as i16 {
        s.server.file_chan_owner = -1;
    }
}

/// Public wrapper for `try_acquire_file_chan` so h2 paths
/// (`begin_file_response`) can claim cross-slot ownership without
/// duplicating the helper.
#[cfg(feature = "h2")]
#[inline]
pub(crate) unsafe fn try_acquire_file_chan_external(s: &mut HttpState) -> bool {
    try_acquire_file_chan(s)
}

/// Public wrapper for `release_file_chan` so h2 error paths can
/// release on aborted fetch.
#[cfg(feature = "h2")]
#[inline]
pub(crate) unsafe fn release_file_chan_external(s: &mut HttpState) {
    release_file_chan(s);
}

pub(crate) unsafe fn reset_connection(s: &mut HttpState) {
    // Skip CMD_CLOSE if the peer already closed (`peer_closed` flag).
    // Otherwise the IP module would either no-op (empty slot) OR —
    // worse, under fast slot reuse — close the next browser connection
    // that just landed on the same slot index.
    let peer_closed = cur_slot(s).map(|c| c.peer_closed).unwrap_or(0);
    if peer_closed == 0 && cur_phase(s) as u8 > Phase::WaitAccept as u8 && s.net_out_chan >= 0 {
        close_net_conn(s, cur_conn_id(s));
    }
    // Close any FS_CONTRACT FD left open by a previous response. The
    // FS dispatch handles CLOSE on a mid-stream slot, so this is safe
    // even if the connection dropped before we reached EOF.
    if cur_fs_fd(s) >= 0 {
        ((*s.syscalls).provider_call)(
            cur_fs_fd(s),
            0x0903, // FS_CLOSE
            core::ptr::null_mut(),
            0,
        );
    }
    // Proxy relay teardown: close the upstream backend conn (if any,
    // and not already closed by the peer) and drop any serialised
    // connect ownership this slot held.
    let (backend, backend_closed) = match cur_slot(s) {
        Some(c) => (c.backend_conn_id, c.backend_closed),
        None => (-1, 0),
    };
    if backend >= 0 && backend_closed == 0 && s.net_out_chan >= 0 {
        close_net_conn(s, backend as u16);
    }
    if let Some(idx) = current_slot_index(s) {
        if s.server.proxy_connect_owner == idx as i16 {
            s.server.proxy_connect_owner = -1;
        }
    }
    // Release the slot's heap buffers (recv_buf, send_buf) and zero
    // every per-conn field so the next `alloc_free_slot` call can
    // reuse the slot cleanly. The `is_free()` predicate now reads
    // `phase=Init && conn_id<0` — both set by `slot_init_zero`
    // inside `slot_release_buffers`. Idle slots cost only their
    // ~250 B inline metadata; the heap buffers are returned to the
    // arena for the next accept (or any other allocator caller).
    if let Some(idx) = current_slot_index(s) {
        slot_release_buffers(s, idx);
    }
}

/// Returns `Some(idx)` when `cur_slot >= 0`, otherwise `None`.
/// Useful when you need the slot index (not just the slot itself)
/// to call slot-lifecycle helpers.
#[inline(always)]
pub(crate) unsafe fn current_slot_index(s: &HttpState) -> Option<usize> {
    let idx = s.server.cur_slot;
    if idx < 0 || (idx as usize) >= MAX_CONCURRENT_CONNS {
        None
    } else {
        Some(idx as usize)
    }
}

pub(crate) unsafe fn close_net_conn(s: &mut HttpState, conn_id: u16) {
    if s.net_out_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 2];
    net_proto::put_conn_id(&mut payload, conn_id);
    net_write_frame(
        sys,
        chan,
        NET_CMD_CLOSE,
        payload.as_ptr(),
        2,
        buf,
        NET_BUF_SIZE,
    );
}

// ── Outbound data send (CMD_SEND envelope) ────────────────────────────────

/// Send up to `len` bytes of HTTP payload to the IP module wrapped in a
/// CMD_SEND frame. Returns the number of payload bytes actually
/// accepted (0 if the channel is full).
pub(crate) unsafe fn net_send(s: &mut HttpState, data: *const u8, len: usize) -> i32 {
    let conn_id = cur_conn_id(s);
    net_send_conn(s, conn_id, data, len)
}

/// Like [`net_send`] but targets an explicit `conn_id` rather than the
/// active slot's client conn. The proxy relay uses it to write to the
/// backend conn (`backend_conn_id`) while the same slot's client conn
/// stays the `cur_conn_id` target. Byte-identical framing / sizing to
/// `net_send`; the only difference is which conn the bytes address.
pub(crate) unsafe fn net_send_conn(
    s: &mut HttpState,
    conn_id: u16,
    data: *const u8,
    len: usize,
) -> i32 {
    if s.net_out_chan < 0 {
        return 0;
    }
    // Per-call payload sizing depends on the downstream:
    //
    //  * `linux_net` (Linux host) → `libc::send()` into the kernel TCP
    //    stack. The kernel handles segmentation (TSO, etc.), so a
    //    large CMD_SEND amortises channel-write + syscall cost across
    //    many MSSes.
    //
    //  * fluxor's `ip` module (bcm2712 bare metal, …) → emits one TCP
    //    segment per CMD_SEND and drops anything in the chunk that
    //    overflows the effective send window. Capping at one MSS
    //    keeps the module from losing data when the IP send queue
    //    is tight.
    //
    // Both paths build for aarch64-unknown-none in PIC, so the cap is
    // a module-local runtime field set from the `host_tcp` param.
    let frame_cap = NET_BUF_SIZE - NET_FRAME_HDR - 2;
    let per_call_cap = if s.host_tcp != 0 {
        frame_cap
    } else {
        1460usize // single MSS — safe with fluxor IP segmenter
    };
    let to_send = len.min(per_call_cap).min(frame_cap);
    if to_send == 0 {
        return 0;
    }

    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 2 + to_send;
    let mut cb = [0u8; 2];
    net_proto::put_conn_id(&mut cb, conn_id);
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    *scratch.add(3) = cb[0];
    *scratch.add(4) = cb[1];
    core::ptr::copy_nonoverlapping(data, scratch.add(5), to_send);
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written == total as i32 {
        s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(to_send as u32);
        to_send as i32
    } else {
        // Atomic FIFO write rejected — treat as backpressure.
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        0
    }
}

// ── Per-tick step machine ──────────────────────────────────────────────────

/// Drain `net_in_chan` once per step and route each frame to the
/// owning slot. Replaces the per-phase channel polls in `WaitAccept`
/// / `RecvRequest` / `drain_background_messages` so that an idle
/// peer on one slot can never starve another slot's data, and so
/// that messages for any slot get routed regardless of which slot
/// happens to be `cur_slot` this tick.
///
/// Gated on slot 0 being past the bind sequence — the binding
/// state machine itself still consumes `MSG_BOUND` directly via
/// the `WaitBound` handler.
unsafe fn demux_inbound(s: &mut HttpState) {
    if s.net_in_chan < 0 {
        return;
    }
    // Don't demux until the listener is bound. Slot 0's binding
    // flow (Init → Binding → WaitBound → WaitAccept) consumes
    // CMD_BIND / MSG_BOUND directly. Once `bound=1` the demux runs
    // every step, regardless of slot 0's current phase (slot 0
    // cycles Init → assigned → Init → ... as later connections
    // recycle it).
    if s.server.bound == 0 {
        return;
    }

    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    // Bound the loop so a stuck channel can't monopolise a tick;
    // anything left over rolls into the next demux call.
    for _ in 0..16 {
        let poll = (sys.channel_poll)(chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            return;
        }

        // Peek the frame header (and the conn_id byte for MSG_DATA)
        // before consuming. If the target slot's recv_buf can't
        // hold the payload, leave the frame on `net_in_chan` and
        // return: the channel fills, the IP module's next
        // `channel_write` for that conn fails (atomic-FIFO
        // whole-frame reject), IP closes that conn's `rcv_wnd`,
        // and the peer retransmits once we drain. Consuming
        // unconditionally would let IP advance ACK and the peer
        // would never retransmit the bytes we couldn't hold.
        let mut hdr = [0u8; NET_FRAME_HDR + 2];
        let peeked = (sys.channel_peek)(chan, hdr.as_mut_ptr(), hdr.len());
        if peeked < NET_FRAME_HDR as i32 {
            return;
        }
        let peeked_msg = hdr[0];
        let peeked_payload_len = u16::from_le_bytes([hdr[1], hdr[2]]) as usize;
        if peeked_msg == NET_MSG_DATA && peeked_payload_len > 2 {
            // Need at least the conn_id bytes to find the target.
            if peeked < NET_FRAME_HDR as i32 + 2 {
                return;
            }
            let conn = net_proto::conn_id(&hdr[NET_FRAME_HDR..]);
            let data_len = peeked_payload_len - 2;
            if let Some(idx) = find_slot_by_conn_id(s, conn) {
                let slot = &*s.server.slots.as_ptr().add(idx);
                if !slot.recv_buf.is_null() {
                    let space = slot.recv_cap as usize - slot.recv_len as usize;
                    if data_len > space {
                        // Target full. Leave the frame on the
                        // channel and stop the demux loop — we
                        // can't safely skip past one frame to
                        // process later ones without peeking the
                        // next header, so a slow consumer briefly
                        // stalls siblings until it drains. IP's
                        // TCP backpressure handles the producer
                        // side correctly.
                        //
                        // Counted because "briefly" is an assumption, not a
                        // guarantee: a peer that stops reading holds its
                        // recv_buf full for as long as it stays silent, and
                        // for that whole window this server is effectively
                        // single-connection. A rising stall count is the
                        // signature of head-of-line blocking and is not
                        // visible in throughput until it is severe.
                        s.server.demux_stalls = s.server.demux_stalls.wrapping_add(1);
                        return;
                    }
                }
                // recv_buf null (slot freed mid-stream): the data
                // has nowhere to go, but we still have to consume
                // to make room on the channel. Falls through to
                // the consume-and-discard path below.
            } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                // Backend→client bytes for a proxy relay. Stage them
                // into the slot's `send_buf`, but only once the request
                // has been forwarded (relay phase). Before that, or
                // when `send_buf` is full, leave the frame on the
                // channel so TCP backpressure applies to the backend.
                let slot = &*s.server.slots.as_ptr().add(idx);
                if !is_proxy_relay_phase(slot.phase) {
                    s.server.demux_stalls = s.server.demux_stalls.wrapping_add(1);
                    return;
                }
                if !slot.send_buf.is_null() {
                    let space = slot.send_cap as usize - slot.send_len as usize;
                    if data_len > space {
                        s.server.demux_stalls = s.server.demux_stalls.wrapping_add(1);
                        return;
                    }
                }
            }
            // Unknown conn (no matching slot): same consume-and-
            // discard fallthrough — the IP module shouldn't send
            // data for an unmapped conn, and we won't let it
            // wedge the demux loop if it does.
        }

        let buf = s.net_buf.as_mut_ptr();
        let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
        match msg_type {
            NET_MSG_ACCEPTED if payload_len >= 2 => {
                let conn = net_proto::conn_id(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                ));
                // Multi-anchor demux: when the accept carries a listener
                // port (payload_len >= 4), claim it only if it matches our
                // bound port — a fanned net_out delivers every consumer's
                // accepts to all of them. A port-less frame (single-anchor
                // producer) is always ours. A non-matching accept is
                // ignored (the owning anchor closes/claims it).
                let ours = payload_len < 4 || {
                    let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                    let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 3);
                    is_listen_port(s, (lo as u16) | ((hi as u16) << 8))
                };
                if ours {
                    if s.server.draining != 0 {
                        // Admission stops at the drain, and it stops HERE
                        // rather than at the top of `step`: inbound bytes for
                        // connections admitted BEFORE the drain must keep
                        // flowing or the work the drain exists to finish
                        // never completes. Closing the new conn rather than
                        // dropping it is what stops a continuous arrival
                        // stream from holding quiescence open indefinitely.
                        close_net_conn(s, conn);
                    } else if let Some(idx) = alloc_free_slot(s, conn) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        slot.phase = Phase::RecvRequest;
                    } else {
                        // Slot table full — actively close the new conn
                        // (never drop silently: the IP module would
                        // otherwise leave the slot in `Established`
                        // until per-conn timeout, exhausting MAX_TCP_CONNS).
                        close_net_conn(s, conn);
                    }
                }
            }
            // A dynamic listener's mid-life bind completed (§4.2). Post-
            // `bound`, a MSG_BOUND is only ever a pooled-listener bind (the
            // static bind is consumed pre-`bound` by slot 0's WaitBound).
            // Payload `[conn_id:1][port:2 LE]`.
            NET_MSG_BOUND if payload_len >= 4 => {
                let conn = net_proto::conn_id(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                )) as i32;
                let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 3);
                let port = (lo as u16) | ((hi as u16) << 8);
                s.server.listeners.mark_bound(port, conn);
            }
            // A mid-life bind was refused — the port is outside the edge
            // owner's lease pool. linux_net
            // frames it `[port:2 LE][errno:1]`. Acted on ONLY with the
            // feature configured, so the metal `ip` module's 0x07
            // (RETRANSMIT) is never misread on the byte-identical path.
            NET_MSG_BIND_REFUSED if s.server.listeners_prefix_len != 0 && payload_len >= 2 => {
                let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                let port = (lo as u16) | ((hi as u16) << 8);
                s.server.listeners.mark_refused(port);
            }
            NET_MSG_DATA if payload_len > 2 => {
                let conn = net_proto::conn_id(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                ));
                let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                let data_len = payload_len - 2;
                if let Some(idx) = find_slot_by_conn_id(s, conn) {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    if slot.recv_buf.is_null() {
                        // Slot freed mid-stream; drop the data.
                        continue;
                    }
                    let space = slot.recv_cap as usize - slot.recv_len as usize;
                    // Peek above guarantees `data_len <= space` for
                    // a valid slot — this is just a defence-in-depth
                    // bound, not a truncation point.
                    let to_copy = data_len.min(space);
                    if to_copy > 0 {
                        let dst = slot.recv_buf.add(slot.recv_len as usize);
                        core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                        slot.recv_len += to_copy as u16;
                        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(to_copy as u32);
                    }
                } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                    // Proxy backend→client: stage into `send_buf` for
                    // the relay step to flush. Gated on the relay phase
                    // (the peek above already backpressured otherwise).
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    if !slot.send_buf.is_null() && is_proxy_relay_phase(slot.phase) {
                        let space = slot.send_cap as usize - slot.send_len as usize;
                        let to_copy = data_len.min(space);
                        if to_copy > 0 {
                            let dst = slot.send_buf.add(slot.send_len as usize);
                            core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                            slot.send_len += to_copy as u16;
                            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(to_copy as u32);
                        }
                    }
                }
                // Else: orphan — slot already closed; drop the data.
            }
            NET_MSG_CONNECTED if payload_len >= 2 => {
                // Reply to a serialised proxy dial. `MSG_CONNECTED` carries
                // `[conn_id u16][requester_tag u8]`. The tag is our module
                // index + 1 and is identical across slots, so it cannot say
                // WHICH slot dialled — the pending `proxy_connect_owner` is
                // that correlator — but it does say whether the connection is
                // OURS at all. On a fanned `net_in` (TLS, an OTLP exporter, a
                // co-wired client) another consumer's connect would otherwise
                // be latched as this server's backend, binding one request's
                // client to another module's socket.
                let conn = net_proto::conn_id(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                ));
                let me = dev_requester_tag(sys);
                let (_, tag) = net_proto::connected_parts(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                ));
                if tag == 0 || tag == me {
                    let owner = s.server.proxy_connect_owner;
                    if owner >= 0 && (owner as usize) < MAX_CONCURRENT_CONNS {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(owner as usize);
                        slot.backend_conn_id = conn as i32;
                        slot.proxy_connected = 1;
                    }
                }
            }
            NET_MSG_ERROR if payload_len >= 2 => {
                // An ERROR is one of two different events and they are told
                // apart by which field identifies the owner.
                //
                // A CONNECT-PHASE failure is identified by `requester_tag`
                // ALONE. The contract is explicit that a connect failure's
                // `conn_id` is meaningless — it is 0 when the dial failed
                // before a slot was allocated, which is indistinguishable
                // from a valid id 0 — so the tag is the only usable
                // discriminator, and it is what says the failure is ours
                // rather than a co-wired consumer's on a fanned `net_in`.
                //
                // An ESTABLISHED-CONNECTION error carries the owning
                // connection's conn_id, so it is routed by slot lookup like
                // MSG_CLOSED. Previously this arm read NEITHER field and
                // failed whichever slot happened to hold `proxy_connect_owner`
                // — so any peer reset anywhere aborted an unrelated backend
                // dial and charged a spurious failover against a healthy
                // upstream.
                let conn = net_proto::conn_id(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                ));
                let tag = if payload_len >= 3 {
                    net_proto::error_parts(core::slice::from_raw_parts(
                        s.net_buf.as_ptr().add(NET_FRAME_HDR),
                        payload_len,
                    ))
                    .2
                } else {
                    net_proto::REQUESTER_TAG_NONE
                };
                if tag != 0 {
                    // TAGGED: a connect-phase failure, attributed to the
                    // requester that dialled. Ours only if the tag is ours —
                    // on a fanned `net_in` this is what stops a co-wired
                    // consumer's failed dial from aborting our backend
                    // connect. The conn_id is deliberately NOT consulted.
                    if tag == dev_requester_tag(sys) {
                        let owner = s.server.proxy_connect_owner;
                        if owner >= 0 && (owner as usize) < MAX_CONCURRENT_CONNS {
                            let slot = &mut *s.server.slots.as_mut_ptr().add(owner as usize);
                            slot.proxy_connect_failed = 1;
                        }
                    }
                } else if let Some(idx) = find_slot_by_conn_id(s, conn) {
                    // UNTAGGED: the transport passes tag 0 for errors that are
                    // not tied to an outbound connect, so this is an error on
                    // an established connection and routes by conn_id exactly
                    // as MSG_CLOSED does. Error on a client conn = peer gone.
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.peer_closed = 1;
                } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                    // Error on an established upstream: the relay flushes what
                    // is staged, then tears down.
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.backend_closed = 1;
                } else if dev_requester_tag(sys) == 0 {
                    // Untagged, and owned by no slot of ours. This is only OUR
                    // connect failure if we dialled untagged too — `proxy_dial`
                    // stamps `dev_requester_tag`, so an untagged dial means the
                    // module has no index to tag with. A tagged module reaching
                    // here is looking at another consumer's error for a
                    // connection it does not own, and must ignore it: claiming
                    // it would abort a healthy dial on every peer reset
                    // anywhere in the graph.
                    let owner = s.server.proxy_connect_owner;
                    if owner >= 0 && (owner as usize) < MAX_CONCURRENT_CONNS {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(owner as usize);
                        slot.proxy_connect_failed = 1;
                    }
                }
            }
            NET_MSG_CLOSED if payload_len >= 2 => {
                let conn = net_proto::conn_id(core::slice::from_raw_parts(
                    s.net_buf.as_ptr().add(NET_FRAME_HDR),
                    payload_len,
                ));
                if let Some(idx) = find_slot_by_conn_id(s, conn) {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.peer_closed = 1;
                } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                    // Upstream backend closed — the relay flushes any
                    // staged bytes to the client, then tears down.
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.backend_closed = 1;
                }
                // Else: nothing to clean up.
            }
            _ => {}
        }
    }
}

/// Outer step loop. Drains inbound messages once via the demux,
/// then walks the ready-slot bitmap so per-tick cost is O(active)
/// rather than O(MAX_CONCURRENT_CONNS).
///
/// The bitmap holds one bit per slot. `alloc_free_slot` sets it on
/// accept; `slot_release_buffers` clears it on close. Slot 0
/// during the bind sequence is the one exception: bit 0 is set by
/// `init()` and cleared when the WaitBound→WaitAccept transition
/// completes (slot 0 then behaves like any other slot).
///
/// Iteration starts at `step_cursor` and walks the bitmap forward
/// (wrapping at the end). Each tick advances the cursor by one
/// slot so no single conn can starve others on consecutive ticks.
/// Pump the dynamic-route table consumer one step: resolve the sink on
/// first use, then run the subscribe / apply / shadow-relist state
/// machine against `routes_prefix`. No-op when the feature is off
/// (`routes_prefix_len == 0`), keeping the server byte-identical.
pub(crate) unsafe fn pump_dyn_routes(s: &mut HttpState) {
    let prefix_len = s.server.routes_prefix_len as usize;
    if prefix_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.server.routes_sink < 0 {
        s.server.routes_sink = dev_channel_port(sys, 0, DYN_ROUTES_PORT_INDEX);
        if s.server.routes_sink < 0 {
            return; // port unwired — nothing to subscribe against
        }
    }
    let sink = s.server.routes_sink;
    // Disjoint field borrows of `s.server`.
    let prefix = &s.server.routes_prefix[..prefix_len];
    let scratch = &mut s.server.routes_scratch;
    let tc = &mut s.server.tc;
    let dyn_routes = &mut s.server.dyn_routes;
    tc.step(sys, sink, prefix, scratch, dyn_routes);
}

pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    demux_inbound(s);
    pump_dyn_routes(s);
    pump_listeners(s);
    // Re-offer lifecycle events a full `ws_event_out` refused earlier. Before
    // the drain check below, so a closure reported on the last connection is
    // handed over rather than stranded by the instance reporting itself done.
    ws::ws_flush_events(s);

    // Graceful-drain check, run before any per-slot work. Drain is
    // complete once `module_drain` has set the flag, the listener
    // has bound, and no in-flight conns remain. This is
    // slot-agnostic on purpose — slot 0 is reused for connections
    // after bind, so it's not always the listener slot when drain
    // is requested.
    //
    // Also once every lifecycle event has been delivered: an application whose
    // last `closed` never arrived would track the connection indefinitely.
    if s.server.draining != 0
        && s.server.bound != 0
        && active_slot_count(s) == 0
        && s.server.ws_event_len == 0
    {
        return 1;
    }

    let mut aggregated = 0i32;
    // Snapshot the bitmap. The body of step_active_slot may set
    // or clear other slots' bits (e.g. demux runs implicitly via
    // any phase that re-enters the channel poll), but we only
    // walk the slots that were ready at the start of the tick.
    let ready_snapshot = s.server.ready_bits;
    // MAX_CONCURRENT_CONNS is a PROFILE constant: 1 on profile_embedded, 256 on
    // host and bcm2712 (../fluxor/modules/sdk/abi/config.rs). clippy::modulo_one fires only on the
    // embedded build, where `% 1` really is a no-op — but removing the modulo
    // would silently break round-robin fairness on every other profile. The wrap
    // is correct; it is the constant that collapses.
    #[allow(
        clippy::modulo_one,
        reason = "MAX_CONCURRENT_CONNS == 1 on profile_embedded only; the wrap is required on profiles where it is 256"
    )]
    let cursor_start = (s.server.step_cursor as usize) % MAX_CONCURRENT_CONNS;
    // First half: cursor_start..MAX. Second half: 0..cursor_start.
    // Walking in two halves keeps round-robin fairness across ticks.
    for half in 0..2 {
        let (lo, hi) = if half == 0 {
            (cursor_start, MAX_CONCURRENT_CONNS)
        } else {
            (0, cursor_start)
        };
        let mut word_idx = lo / 64;
        let word_end = hi.div_ceil(64);
        while word_idx < word_end {
            let mut word = ready_snapshot[word_idx];
            // Mask off bits before `lo` and at-or-after `hi` to
            // respect the half boundaries.
            let bit_base = word_idx * 64;
            if bit_base < lo {
                word &= !((1u64 << (lo - bit_base)) - 1);
            }
            if bit_base + 64 > hi {
                let drop = bit_base + 64 - hi;
                word &= u64::MAX >> drop;
            }
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let idx = bit_base + bit;
                word &= word - 1;
                s.server.cur_slot = idx as i32;
                let r = step_active_slot(s);
                if r > aggregated {
                    aggregated = r;
                }
            }
            word_idx += 1;
        }
    }
    s.server.cur_slot = 0;
    #[allow(
        clippy::modulo_one,
        reason = "same profile-dependent MAX_CONCURRENT_CONNS as the cursor_start wrap above"
    )]
    let next_cursor = (cursor_start + 1) % MAX_CONCURRENT_CONNS;
    s.server.step_cursor = next_cursor as u32;
    aggregated
}

/// Snapshot of the load-shedding counters, in `[observability].metrics` id
/// order (ids 5..13): backpressure steps, connections refused for want of a
/// slot, connections refused for want of arena, demux stalls, application
/// timeouts, application envelopes lost, application envelopes oversize,
/// WebSocket envelopes dropped, HTTP/2 streams refused.
///
/// Exposed so a test can assert the counter its scenario should have moved.
/// A counter with no test that moves it is a counter that will silently stop
/// working, and these exist precisely to be trusted during an incident.
///
/// # Safety
/// See [`routes::test_inject_dyn_route`].
#[cfg(feature = "host-test")]
pub unsafe fn test_shed_metrics(state: *mut u8) -> ShedMetrics {
    let s = &*(state as *mut HttpState);
    ShedMetrics {
        bp_steps: s.tlm.bp_steps,
        idle_steps: s.tlm.idle_steps,
        conns_refused_slots: s.server.conns_refused_slots,
        conns_refused_arena: s.server.conns_refused_arena,
        demux_stalls: s.server.demux_stalls,
        app_timeouts: s.server.app_timeouts,
        app_envelopes_lost: s.server.app_envelopes_lost,
        app_envelopes_oversize: s.server.app_envelopes_oversize,
        ws_envelopes_dropped: s.server.ws_envelopes_dropped,
        h2_streams_refused: s.server.h2_streams_refused,
    }
}

/// See [`test_shed_metrics`].
#[cfg(feature = "host-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ShedMetrics {
    pub bp_steps: u32,
    /// Steps in which nothing moved — no bytes either way and no backpressure.
    /// The signal the scheduler's adaptive tick reads to slow a quiet module
    /// down, so it is what "minimising hardware use under light load" means in
    /// practice.
    pub idle_steps: u32,
    pub conns_refused_slots: u32,
    pub conns_refused_arena: u32,
    pub demux_stalls: u32,
    pub app_timeouts: u32,
    pub app_envelopes_lost: u32,
    pub app_envelopes_oversize: u32,
    pub ws_envelopes_dropped: u32,
    pub h2_streams_refused: u32,
}
