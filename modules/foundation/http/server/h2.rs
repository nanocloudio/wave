//! HTTP/2 connection state machine — server side, h2c (cleartext) and
//! h2-over-TLS (ALPN).
//!
//! Drives one TCP/TLS connection through the h2 lifecycle: SETTINGS
//! exchange, HEADERS / DATA / control-frame processing, response
//! emission. The matching route is looked up against the existing
//! `ServerState.routes` table so the same YAML config that drives h1
//! routes drives h2.
//!
//! # Scope
//!
//! - up to `MAX_STREAMS` (4) concurrent client streams. Streams beyond
//!   the limit are refused with REFUSED_STREAM.
//! - `HANDLER_STATIC`, `HANDLER_TEMPLATE` (inline + file-cached), and
//!   `HANDLER_FILE` are streamed via `Sub::SendingBody`. Each tick
//!   advances one slot's emission round-robin via `emit_cursor` so
//!   multiple streams' HEADERS and DATA frames interleave on the wire.
//!   `file_chan` and the body cache are guarded by a single
//!   `file_owner` mutex; only one HANDLER_FILE / cache-fetch slot runs
//!   at a time, while inline streams continue to interleave alongside.
//! - `HANDLER_WEBSOCKET`: extended CONNECT (RFC 8441) is accepted —
//!   the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`,
//!   replies `:status = 200`, and from then on tunnels RFC 6455 frames
//!   inside DATA frames in both directions. WS frames may span multiple
//!   DATA frames; payloads accumulate in `H2State.ws_buf` and a drain
//!   loop pops complete frames as they appear. Frames larger than
//!   `WS_BUF_SIZE` close with 1009 (Message Too Big). At most one WS
//!   stream per connection (the buffer is shared).
//! - GET / POST / PUT / PATCH / DELETE / HEAD; request bodies are
//!   discarded (the static / template / file handlers don't read them).
//! - flow control: connection- and stream-level recv windows refilled
//!   via WINDOW_UPDATE when they cross `RECV_WINDOW_THRESHOLD`; DATA
//!   emission caps each chunk by `min(conn_send_window, stream_send_window)`
//!   and honours peer-sent SETTINGS_INITIAL_WINDOW_SIZE adjustments.
//! - no Huffman string compression on either side.
//! - no PUSH (`SETTINGS_ENABLE_PUSH = 0`).
//! - no CONTINUATION; HEADERS frames must carry END_HEADERS.
//! - frames whose declared length exceeds `RECV_BUF_SIZE` are refused
//!   with `GOAWAY(FRAME_SIZE_ERROR)`.

use super::super::connection::{NET_BUF_SIZE, NET_CMD_SEND};
#[cfg(feature = "app")]
use super::routes::HANDLER_APP;
use super::routes::{
    HANDLER_FILE, HANDLER_GRPC, HANDLER_STATIC, HANDLER_TEMPLATE, HANDLER_WEBSOCKET,
};
use super::{
    cur_conn_id, cur_h2, cur_h2_mut, cur_recv_buf_mut_ptr, cur_recv_buf_ptr, cur_recv_len,
    cur_send_buf_mut_ptr, cur_send_buf_ptr, cur_send_len, cur_send_offset, cur_slot_mut, MAX_PATH,
    RECV_BUF_SIZE, SEND_BUF_SIZE,
};

/// Per-stream WebSocket reassembly buffer. Cross-DATA-frame WS frames
/// land here until a complete RFC 6455 frame can be parsed and echoed.
/// Bound matches the largest WS frame the server is willing to handle;
/// frames that don't fit close with 1009 (Message Too Big).
const WS_BUF_SIZE: usize = 512;

/// Maximum concurrent client-initiated streams. Advertised in our
/// SETTINGS frame. Sized for the embedded memory budget; bump the
/// constant if `H2State` can absorb additional slots.
pub(crate) const MAX_STREAMS: usize = 4;

/// Initial connection-level recv window — RFC 7540 §6.9.2 default.
const RECV_WINDOW_INITIAL: i32 = 65535;
/// Below this, we proactively send WINDOW_UPDATE to refill so peer
/// keeps streaming. Picked at half the initial window to leave a
/// generous in-flight buffer.
const RECV_WINDOW_THRESHOLD: i32 = 32768;
/// Initial conn-level + per-stream send window — RFC 7540 §6.9.2
/// default. Adjusted by peer SETTINGS_INITIAL_WINDOW_SIZE (per-stream)
/// or peer WINDOW_UPDATE deltas.
const SEND_WINDOW_INITIAL: i32 = 65535;
use super::super::wire::h2 as h2w;
use super::super::wire::method;
use super::super::wire::ws;
use super::super::HttpState;
use super::super::{
    dev_channel_ioctl, dev_log, net_write_frame, IOCTL_FLUSH, IOCTL_NOTIFY, IOCTL_POLL_NOTIFY,
    NET_FRAME_HDR,
};

// ── Sub-state within `Phase::H2Active` ────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Sub {
    /// Send our initial SETTINGS frame.
    SendSettings = 0,
    /// Frame loop: read frames from `recv_buf`, dispatch, queue
    /// responses into `send_buf`.
    Active = 1,
    /// At least one slot is mid-response. Each tick drives one cache
    /// fetch step (if any slot is `Fetching`) and emits one DATA / HEADERS
    /// frame for the next round-robin Sending slot.
    SendingBody = 2,
    /// Drain a queued GOAWAY then close.
    Closing = 3,
}

/// Per-stream slot state. Each `StreamSlot` tracks one concurrent
/// client-initiated stream; the connection serializes body emission
/// (only one slot at a time can fill `send_buf`).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SlotState {
    /// Slot is unused (`id == 0`).
    Idle = 0,
    /// HEADERS arrived; awaiting END_STREAM via DATA frames.
    Open = 1,
    /// Request fully received; waiting for an emitter slot to free up.
    Pending = 2,
    /// Currently the active sender. `Sub::SendingBody` operates on
    /// this slot; only one slot in this state at any time.
    Sending = 3,
    /// Cache fetch in progress for this slot; only one slot in this
    /// state at any time.
    Fetching = 4,
    /// Upgraded to WebSocket-over-h2; DATA frames carry WS frames.
    WsActive = 5,
}

#[repr(C)]
pub(crate) struct StreamSlot {
    pub(crate) id: u32,
    pub(crate) state: SlotState,
    /// The request's method as a `wire::method::METHOD_*` value — the same
    /// vocabulary h1 uses, so a request means the same thing on either
    /// generation.
    pub(crate) method_kind: u8,
    pub(crate) end_stream_in: u8,
    pub(crate) req_path_len: u8,
    /// 1 = a per-stream WINDOW_UPDATE owes peer, queued by the active
    /// loop the next time `send_buf` is free.
    pub(crate) window_update_pending: u8,
    /// Per-slot rendering state. Set by `dispatch_request`; consumed
    /// lazily by the round-robin emitter in `step_sending_body`.
    pub(crate) headers_sent: u8,
    pub(crate) body_handler: u8,
    pub(crate) matched_route: i8,
    pub(crate) file_index: i16,
    /// Render position into the route's body region. u32 to match
    /// the route's u32 `body_offset` / `body_len` — large bodies
    /// (>64 KiB single-page apps, jpeg/png assets) would wrap a
    /// u16 cursor and corrupt the response mid-stream.
    pub(crate) tmpl_pos: u32,
    /// Stream-level recv flow-control window (RFC 7540 §6.9.1). Starts
    /// at 65535; decremented as peer sends DATA on this stream;
    /// refilled with a per-stream WINDOW_UPDATE when low.
    pub(crate) recv_window: i32,
    /// Stream-level send flow-control window. Starts at peer's
    /// SETTINGS_INITIAL_WINDOW_SIZE (default 65535); decremented as
    /// we emit DATA on this stream; bumped by peer's per-stream
    /// WINDOW_UPDATE.
    pub(crate) send_window: i32,

    // ── Request body + application fan-out ─────────────────────────
    //
    // Per-STREAM, not per-connection: h2 multiplexes many requests over
    // one connection, so a body or a pending application request held on
    // the ConnSlot would be overwritten by whichever stream arrived next.
    /// Decoded request body, accumulated from DATA frames. Null until the
    /// first body byte, freed by `free_slot`.
    pub(crate) body_buf: *mut u8,
    pub(crate) body_len: u32,
    pub(crate) body_cap: u32,
    /// The request's non-pseudo header fields, re-serialised as
    /// `name: value\r\n` lines during HPACK decode. HANDLER_APP forwards
    /// them; nothing else reads them, so the buffer is only allocated for
    /// a stream that reaches an application route.
    pub(crate) hdr_buf: *mut u8,
    pub(crate) hdr_len: u32,
    /// 1 while this stream has a request out on `req_out`.
    pub(crate) app_pending: u8,
    /// `dev_millis` past which the pending request is answered 504.
    pub(crate) app_deadline_ms: u64,

    pub(crate) req_path: [u8; MAX_PATH],
}

impl StreamSlot {
    pub(crate) const fn zeroed() -> Self {
        Self {
            id: 0,
            state: SlotState::Idle,
            method_kind: 0,
            end_stream_in: 0,
            req_path_len: 0,
            window_update_pending: 0,
            headers_sent: 0,
            body_handler: 0,
            matched_route: -1,
            file_index: -1,
            tmpl_pos: 0,
            recv_window: RECV_WINDOW_INITIAL,
            send_window: SEND_WINDOW_INITIAL,
            body_buf: core::ptr::null_mut(),
            body_len: 0,
            body_cap: 0,
            hdr_buf: core::ptr::null_mut(),
            hdr_len: 0,
            app_pending: 0,
            app_deadline_ms: 0,
            req_path: [0; MAX_PATH],
        }
    }
}

#[repr(C)]
pub(crate) struct H2State {
    pub(crate) sub: Sub,
    pub(crate) settings_acked: u8,
    /// Round-robin cursor: index of the slot that emitted the most
    /// recent frame. `step_sending_body` advances this each tick to
    /// pick the next Sending slot.
    pub(crate) emit_cursor: i8,
    /// Index of the slot currently using `file_chan` /
    /// `body_pool` cache fetch. Only one such slot can be Sending at
    /// a time; other file/cache slots stay Pending.
    pub(crate) file_owner: i8,
    pub(crate) last_stream_id: u32,
    pub(crate) ws_active: u8, // 1 when any slot is WsActive (capped at one)
    /// 1 if a WINDOW_UPDATE frame should be queued as soon as
    /// `send_buf` is free again. See `recv_window` below.
    pub(crate) window_update_pending: u8,
    pub(crate) ws_buf_len: u16,
    pub(crate) ws_stream_id: u32,
    /// Connection-level recv flow-control window (RFC 7540 §6.9.1).
    /// Decremented as peer's DATA frames arrive; refilled with
    /// WINDOW_UPDATE when it crosses the threshold.
    pub(crate) recv_window: i32,
    /// Connection-level send flow-control window (RFC 7540 §6.9.1).
    /// Decremented as we emit DATA across all streams; bumped by
    /// peer's connection-level WINDOW_UPDATE (stream_id == 0).
    pub(crate) send_window: i32,
    /// Most-recent value of peer's SETTINGS_INITIAL_WINDOW_SIZE;
    /// changes here adjust every open stream's `send_window` by the
    /// delta (RFC 7540 §6.9.2).
    pub(crate) peer_initial_window_size: i32,
    pub(crate) streams: [StreamSlot; MAX_STREAMS],
    /// WebSocket reassembly buffer. Shared across the (at most one)
    /// WS-active stream. RFC 6455 frames may span multiple h2 DATA
    /// frames; raw payloads accumulate here until parsed and echoed.
    pub(crate) ws_buf: [u8; WS_BUF_SIZE],
}

impl H2State {
    pub(crate) const fn zeroed() -> Self {
        const SLOT: StreamSlot = StreamSlot::zeroed();
        Self {
            sub: Sub::SendSettings,
            settings_acked: 0,
            emit_cursor: -1,
            file_owner: -1,
            last_stream_id: 0,
            ws_active: 0,
            window_update_pending: 0,
            ws_buf_len: 0,
            ws_stream_id: 0,
            recv_window: RECV_WINDOW_INITIAL,
            send_window: SEND_WINDOW_INITIAL,
            peer_initial_window_size: SEND_WINDOW_INITIAL,
            streams: [SLOT; MAX_STREAMS],
            ws_buf: [0; WS_BUF_SIZE],
        }
    }
}

// ── Stream-slot lookup helpers ────────────────────────────────────────────

/// Return the index into `streams` whose `id` matches, or `-1`.
unsafe fn slot_for_id(s: &HttpState, id: u32) -> i8 {
    if id == 0 {
        return -1;
    }
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
        if slot.id == id && slot.state != SlotState::Idle {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Allocate an Idle slot for a new stream id. Returns `-1` if the table
/// is full (caller should respond REFUSED_STREAM).
unsafe fn alloc_slot(s: &mut HttpState, id: u32) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(i as usize);
        if slot.state == SlotState::Idle {
            slot.id = id;
            slot.state = SlotState::Open;
            slot.method_kind = 0;
            slot.end_stream_in = 0;
            slot.req_path_len = 0;
            slot.window_update_pending = 0;
            slot.recv_window = RECV_WINDOW_INITIAL;
            // Each new stream inherits peer's most-recent advertised
            // initial window size (default 65535).
            slot.send_window = cur_h2(s).peer_initial_window_size;
            return i as i8;
        }
        i += 1;
    }
    -1
}

unsafe fn free_slot(s: &mut HttpState, idx: i8) {
    if idx < 0 {
        return;
    }
    // If this stream owned the conn-level file context, drop both
    // the h2 internal owner field AND the server-level
    // `file_chan_owner` lock so other connections aren't blocked.
    // Defensive: callers throughout h2 also clear `file_owner`
    // explicitly in some paths (e.g. RST_STREAM, END_STREAM); this
    // catches paths that don't.
    if cur_h2(s).file_owner == idx {
        cur_h2_mut(s).file_owner = -1;
        super::release_file_chan_external(s);
    }
    // Release any cache-entry retain count this stream held while
    // emitting from a cached body. cache_try_or_fetch's Hit path
    // and cache_fetch_step's Ready path each bump the entry's
    // refcount; the matching decrement happens here so a stream
    // that closed mid-emission (END_STREAM, RST_STREAM, error)
    // doesn't pin the entry forever.
    let slot = &*cur_h2_mut(s).streams.as_ptr().add(idx as usize);
    let mr = slot.matched_route;
    if mr >= 0 && (slot.body_handler == HANDLER_STATIC || slot.body_handler == HANDLER_TEMPLATE) {
        super::cache::cache_release_for_route(s, mr as u8);
    }
    // Release the per-stream request body and header copy. The slot is
    // reused for the next stream on this connection, so anything left
    // attached here leaks for the life of the connection and, worse, would
    // be served as the next request's body.
    let sys = s.syscalls;
    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(idx as usize);
    if !slot.body_buf.is_null() {
        super::heap_free(&*sys, slot.body_buf);
        slot.body_buf = core::ptr::null_mut();
    }
    slot.body_len = 0;
    slot.body_cap = 0;
    if !slot.hdr_buf.is_null() {
        super::heap_free(&*sys, slot.hdr_buf);
        slot.hdr_buf = core::ptr::null_mut();
    }
    slot.hdr_len = 0;
    slot.app_pending = 0;
    slot.app_deadline_ms = 0;
    slot.id = 0;
    slot.state = SlotState::Idle;
}

/// Largest per-stream header copy forwarded to an application, in bytes.
/// Bounded for the same reason h1's is: it is copied into a fixed envelope.
const H2_HDR_CAP: usize = super::app::MAX_FWD_HEADERS;

/// Append DATA-frame payload to a stream's request body, bounded by the
/// server's `max_body`. Returns false when the cap is reached — the caller
/// answers 413 and resets the stream.
unsafe fn append_stream_body(s: &mut HttpState, idx: usize, src: *const u8, n: usize) -> bool {
    if n == 0 {
        return true;
    }
    let cap = if s.server.max_body == 0 {
        super::reqbody::DEFAULT_MAX_BODY
    } else {
        s.server.max_body
    };
    let sys = s.syscalls;
    let (have_len, have_cap, buf) = {
        let slot = &*cur_h2(s).streams.as_ptr().add(idx);
        (slot.body_len, slot.body_cap, slot.body_buf)
    };
    let want = match have_len.checked_add(n as u32) {
        Some(w) => w,
        None => return false,
    };
    if want > cap {
        return false;
    }
    if have_cap < want || buf.is_null() {
        let mut next = if have_cap == 0 { 1024 } else { have_cap };
        while next < want {
            next = next.saturating_mul(2);
        }
        if next > cap {
            next = cap;
        }
        let fresh = super::heap_alloc(&*sys, next);
        if fresh.is_null() {
            return false;
        }
        if !buf.is_null() {
            if have_len > 0 {
                core::ptr::copy_nonoverlapping(buf, fresh, have_len as usize);
            }
            super::heap_free(&*sys, buf);
        }
        let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(idx);
        slot.body_buf = fresh;
        slot.body_cap = next;
    }
    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(idx);
    core::ptr::copy_nonoverlapping(src, slot.body_buf.add(slot.body_len as usize), n);
    slot.body_len = want;
    true
}

/// Find any Pending slot — caller has just finished emitting a body
/// and wants to start the next one. Returns `-1` if none.
unsafe fn find_pending_slot(s: &HttpState) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
        if slot.state == SlotState::Pending {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// True when at least one slot is currently in the Sending state.
unsafe fn any_sending_slot(s: &HttpState) -> bool {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
        if slot.state == SlotState::Sending {
            return true;
        }
        i += 1;
    }
    false
}

/// Returns the slot index currently doing a cache fetch, or `-1`. At
/// most one slot can be in this state — the `file_owner` mutex
/// enforces serialisation across HANDLER_FILE / cache-fetch handlers.
unsafe fn fetching_slot(s: &HttpState) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
        if slot.state == SlotState::Fetching {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Drive one tick of the cache fetch loop for the slot currently
/// holding `file_owner`. Bridges into `arm_slot_for_emission` once the
/// fetch completes so the same emission round-robin picks the slot up.
/// Returns true if `send_buf` got new bytes (caller should yield to
/// flush them).
unsafe fn drive_cache_fetch(s: &mut HttpState) -> bool {
    use super::cache::{cache_fetch_step, cache_try_or_fetch, CacheLookup, CacheStepResult};
    let slot_idx = fetching_slot(s);
    if slot_idx < 0 {
        return false;
    }
    let me = s.server.cur_slot;
    // Cross-slot serialisation: drive_cache_fetch is the retry
    // loop for `Busy` — if we don't yet hold `file_chan_owner`,
    // we never issued the FLUSH/NOTIFY for this stream and
    // `cache_fetch_step` would just return Pending forever
    // (POLL_IN never fires on a channel we haven't notified).
    // Re-attempt cache_try_or_fetch; on success it acquires the
    // lock + issues IOCTLs and transitions us to the normal
    // Pending → Ready flow.
    if me >= 0 && s.server.file_chan_owner != me as i16 {
        let matched = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).matched_route;
        let handler = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).body_handler;
        match cache_try_or_fetch(s, matched) {
            CacheLookup::Hit | CacheLookup::NoSource => {
                arm_slot_for_emission(s, slot_idx, handler, -1, matched);
                cur_h2_mut(s).file_owner = -1;
                // Cache hit/no-source: we never acquired the
                // server-level lock here (cache_try_or_fetch only
                // acquires on the cache-miss → Pending path), but
                // a previous Pending might have left ownership
                // dangling if we're recovering. Defensive release.
                super::release_file_chan_external(s);
                return false;
            }
            CacheLookup::Pending => {
                // Acquired + IOCTLs issued; fall through to
                // cache_fetch_step.
            }
            CacheLookup::Busy => {
                // Lock still held by another slot; try next tick.
                return false;
            }
        }
    }
    match cache_fetch_step(s) {
        CacheStepResult::Pending => false,
        CacheStepResult::Ready => {
            let handler = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).body_handler;
            let matched = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).matched_route;
            arm_slot_for_emission(s, slot_idx, handler, -1, matched);
            // Cache is filled; subsequent emission reads from the
            // in-memory body_pool (not file_chan). Release the
            // server-level lock so a sibling slot can fetch its
            // own route.
            cur_h2_mut(s).file_owner = -1;
            super::release_file_chan_external(s);
            false
        }
        CacheStepResult::Error => {
            let stream_id = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).id;
            emit_response(s, stream_id, b"500", b"text/plain", b"cache fetch failed\n");
            free_slot(s, slot_idx);
            cur_h2_mut(s).file_owner = -1;
            super::release_file_chan_external(s);
            true
        }
    }
}

// ── Public entry from server.rs ───────────────────────────────────────────

pub(crate) unsafe fn enter(s: &mut HttpState) -> bool {
    if !super::ensure_h2_state(s) {
        // Heap exhausted — caller should drop the connection rather
        // than enter `H2Active` against a null h2 pointer.
        log(s, b"[http] h2c upgrade dropped: heap exhausted");
        return false;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = 0;
    }
    log(s, b"[http] h2c connection upgraded");
    true
}

/// Drive one tick of the h2 state machine. Mirrors the server.rs step
/// contract: returns 0 normally, 1 to indicate "done — close
/// connection", -1 on hard error.
pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    // Always try to flush pending outbound bytes first.
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
        }
        if cur_send_offset(s) < cur_send_len(s) {
            return 0;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = 0;
        }
        if cur_h2_mut(s).sub == Sub::Closing {
            return 1;
        }
    }

    // A stream waiting on an application that never answers must not hold its
    // slot forever — enough of them exhaust `MAX_STREAMS` and the connection
    // stops accepting new requests while looking healthy. Swept here, with
    // `send_buf` known drained by the flush above, because the 504 it emits
    // needs it.
    #[cfg(feature = "app")]
    if cur_send_len(s) == 0 {
        sweep_app_timeouts(s);
        if cur_send_len(s) > 0 {
            return 0;
        }
    }

    match cur_h2(s).sub {
        Sub::SendSettings => {
            let n = h2w::write_settings(
                cur_send_buf_mut_ptr(s),
                &[
                    (h2w::SETTINGS_ENABLE_PUSH, 0),
                    (h2w::SETTINGS_MAX_CONCURRENT_STREAMS, MAX_STREAMS as u32),
                    (h2w::SETTINGS_HEADER_TABLE_SIZE, 0),
                    (h2w::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
                ],
            );
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
            cur_h2_mut(s).sub = Sub::Active;
            0
        }
        Sub::Active => active(s),
        Sub::SendingBody => step_sending_body(s),
        Sub::Closing => {
            // Pending GOAWAY already drained by the flush above.
            1
        }
    }
}

// ── Body streaming substate ───────────────────────────────────────────────

unsafe fn step_sending_body(s: &mut HttpState) -> i32 {
    // Drive any in-progress cache fetch first. Reads from `file_chan`
    // never touch `send_buf`, so a fetch tick happens regardless of
    // whether we have outbound bytes still draining. If the fetch
    // completes mid-call the slot transitions to Sending and is
    // picked up by the round-robin below in the same tick.
    if drive_cache_fetch(s) && cur_send_len(s) > 0 {
        return 2;
    }

    if cur_send_len(s) > 0 {
        return 0;
    }

    // Pick the next Sending slot via round-robin starting just after
    // `emit_cursor`. Each call emits at most one frame, so multiple
    // Sending slots interleave their HEADERS / DATA on the wire.
    let n = MAX_STREAMS;
    let cursor_start = ((cur_h2(s).emit_cursor as i32 + 1).max(0) as usize) % n;
    let mut emit_idx: i8 = -1;
    for offset in 0..n {
        let i = (cursor_start + offset) % n;
        let slot = &*cur_h2(s).streams.as_ptr().add(i);
        if slot.state == SlotState::Sending {
            emit_idx = i as i8;
            break;
        }
    }

    if emit_idx < 0 {
        // No more Sending slots. If a Fetching slot is still in flight
        // we stay in `Sub::SendingBody` so its `cache_fetch_step`
        // keeps ticking; otherwise fall back to Active to pick up
        // Pending slots / inbound frames.
        if fetching_slot(s) >= 0 {
            return 0;
        }
        cur_h2_mut(s).sub = Sub::Active;
        cur_h2_mut(s).emit_cursor = -1;
        try_dispatch_pending(s);
        if cur_send_len(s) > 0 {
            return 2;
        }
        return 0;
    }

    cur_h2_mut(s).emit_cursor = emit_idx;
    let slot_ptr = cur_h2(s).streams.as_ptr().add(emit_idx as usize);
    let slot_id = (*slot_ptr).id;
    let body_handler = (*slot_ptr).body_handler;
    let headers_sent = (*slot_ptr).headers_sent;
    let stream_send_window = (*slot_ptr).send_window;
    let slot_matched = (*slot_ptr).matched_route;
    let slot_tmpl_pos = (*slot_ptr).tmpl_pos;
    let slot_file_index = (*slot_ptr).file_index;

    if headers_sent == 0 {
        emit_slot_headers(s, emit_idx, body_handler, slot_file_index, slot_id);
        let slot_mut = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(emit_idx as usize);
        slot_mut.headers_sent = 1;
        return 2;
    }

    // Render a DATA chunk for this slot. Cap by send_window.
    let mut avail = cur_h2(s).send_window.min(stream_send_window);
    if avail <= 0 {
        // Window-stall: drain whatever inbound frames demux has
        // already routed into our recv_buf. A queued WINDOW_UPDATE
        // bumps `send_window` / `streams[i].send_window` and we
        // resume on the next tick. If recv_buf is short, the loop
        // breaks on NeedMore and the next tick's demux brings
        // more bytes — h2 relies on demux_inbound's per-conn
        // routing rather than reading the shared net_in_chan
        // itself.
        loop {
            match peek_frame_complete(s) {
                FrameStatus::Complete => {}
                FrameStatus::NeedMore => break,
                FrameStatus::TooBig => {
                    queue_goaway(s, h2w::ERR_FRAME_SIZE_ERROR);
                    return 2;
                }
            }
            if process_one_frame(s) < 0 {
                return 0;
            }
            if cur_send_len(s) > 0 {
                return 2;
            }
        }
        let refreshed_stream = (*cur_h2(s).streams.as_ptr().add(emit_idx as usize)).send_window;
        avail = cur_h2(s).send_window.min(refreshed_stream);
        if avail <= 0 {
            return 0;
        }
    }

    // Swap in slot's render state for the renderer to consume.
    // The renderers read/write `cur_slot`'s tmpl_pos/file_index now,
    // so the swap targets the active slot's fields.
    if let Some(cur) = super::cur_slot_mut(s) {
        cur.matched_route = slot_matched;
        cur.tmpl_pos = slot_tmpl_pos;
        cur.file_index = slot_file_index;
    }

    let buf = cur_send_buf_mut_ptr(s);
    let dst = buf.add(h2w::FRAME_HEADER_LEN);
    let raw_cap = SEND_BUF_SIZE - h2w::FRAME_HEADER_LEN;
    let dst_cap = raw_cap.min(avail as usize);

    let (n, more) = match body_handler {
        HANDLER_STATIC => super::body::render_static_into(s, dst, dst_cap),
        HANDLER_TEMPLATE => super::body::render_template_into(s, dst, dst_cap),
        HANDLER_FILE => {
            if slot_file_index < 0 {
                super::body::render_index_into(s, dst, dst_cap)
            } else {
                super::body::render_file_into(s, dst, dst_cap)
            }
        }
        _ => (0, false),
    };

    // Save updated render state back into the slot.
    {
        let updated_tmpl_pos = super::cur_slot(s).map(|c| c.tmpl_pos).unwrap_or(0);
        let slot_mut = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(emit_idx as usize);
        slot_mut.tmpl_pos = updated_tmpl_pos;
    }

    if n == 0 && more {
        return 0;
    }

    h2w::write_data_frame_header(buf, n, slot_id, !more);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = (h2w::FRAME_HEADER_LEN + n) as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    cur_h2_mut(s).send_window = cur_h2(s).send_window.saturating_sub(n as i32);
    if more {
        let slot_mut = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(emit_idx as usize);
        slot_mut.send_window = slot_mut.send_window.saturating_sub(n as i32);
    } else {
        // END_STREAM emitted — release the slot now so a peer can
        // open a fresh stream in this position before we tick
        // again. If this stream owned the file context, also
        // release the server-level lock so other connections can
        // claim file_chan for their own fetches.
        let was_owner = cur_h2_mut(s).file_owner == emit_idx;
        free_slot(s, emit_idx);
        if was_owner {
            cur_h2_mut(s).file_owner = -1;
            super::release_file_chan_external(s);
        }
    }
    2
}

/// Lazy HEADERS emission for a slot. Picks the appropriate
/// content-type from the handler kind / file_index. Status code is
/// always 200 — error responses go through `emit_response` (single
/// HEADERS+DATA frame) and never reach the streaming path.
unsafe fn emit_slot_headers(
    s: &mut HttpState,
    _slot_idx: i8,
    body_handler: u8,
    file_index: i16,
    stream_id: u32,
) {
    let content_type: &[u8] = match body_handler {
        HANDLER_STATIC | HANDLER_TEMPLATE => b"text/html",
        HANDLER_FILE => {
            if file_index < 0 {
                b"text/plain"
            } else {
                b"application/octet-stream"
            }
        }
        _ => b"text/plain",
    };

    let buf = cur_send_buf_mut_ptr(s);
    let cap = SEND_BUF_SIZE;
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;
    o += super::super::wire::hpack::encode_header(buf.add(o), cap - o, b":status", b"200");
    o += super::super::wire::hpack::encode_header(
        buf.add(o),
        cap - o,
        b"content-type",
        content_type,
    );
    let block_len = o - block_start;
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = o as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
}

// ── Active loop ───────────────────────────────────────────────────────────

unsafe fn active(s: &mut HttpState) -> i32 {
    // Refill recv flow-control windows first: if we owe peer a
    // connection-level OR per-stream WINDOW_UPDATE and `send_buf` is
    // free, emit one before anything else so the peer keeps streaming.
    // `queue_window_update` emits at most one frame per call; the
    // active loop comes back here on subsequent ticks to drain the
    // rest of the queue.
    if cur_send_len(s) == 0
        && (cur_h2(s).window_update_pending != 0 || any_stream_window_pending(s))
    {
        queue_window_update(s);
        if cur_send_len(s) > 0 {
            return 2;
        }
    }

    // If we left a partial WS frame queue from a previous tick, try to
    // drain another frame now that send_buf is free again.
    if cur_h2(s).ws_active != 0 && cur_send_len(s) == 0 && cur_h2(s).ws_buf_len > 0 {
        ws_drain_buf(s);
        if cur_send_len(s) > 0 {
            return 2;
        }
    }

    // If recv_buf doesn't yet hold a full frame, yield this tick.
    // demux_inbound (run at the top of every step()) will route
    // more bytes into recv_buf for the next pass.
    match peek_frame_complete(s) {
        FrameStatus::NeedMore => return 0,
        FrameStatus::TooBig => {
            queue_goaway(s, h2w::ERR_FRAME_SIZE_ERROR);
            return 2;
        }
        FrameStatus::Complete => {}
    }

    loop {
        match peek_frame_complete(s) {
            FrameStatus::Complete => {}
            FrameStatus::NeedMore => break,
            FrameStatus::TooBig => {
                queue_goaway(s, h2w::ERR_FRAME_SIZE_ERROR);
                return 2;
            }
        }
        if process_one_frame(s) < 0 {
            return 0;
        }
        if cur_send_len(s) > 0 {
            return 2;
        }
    }
    0
}

enum FrameStatus {
    Complete,
    NeedMore,
    /// Peer announced a frame larger than `recv_buf` can hold. Caller
    /// should respond with GOAWAY(FRAME_SIZE_ERROR) and close — RFC
    /// 7540 §4.2 lets a receiver bound the maximum frame size below
    /// the spec default by emitting a connection error.
    TooBig,
}

unsafe fn peek_frame_complete(s: &HttpState) -> FrameStatus {
    let len = cur_recv_len(s) as usize;
    let hdr = match h2w::parse_header(cur_recv_buf_ptr(s), len) {
        Some(h) => h,
        None => return FrameStatus::NeedMore,
    };
    let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
    if total > RECV_BUF_SIZE {
        return FrameStatus::TooBig;
    }
    if total > len {
        FrameStatus::NeedMore
    } else {
        FrameStatus::Complete
    }
}

/// Process exactly one complete frame from the head of `recv_buf` and
/// shift the remainder. Returns 0 normally, -1 if a connection-level
/// error has been queued (caller should drain and close).
unsafe fn process_one_frame(s: &mut HttpState) -> i32 {
    let len = cur_recv_len(s) as usize;
    let hdr = match h2w::parse_header(cur_recv_buf_ptr(s), len) {
        Some(h) => h,
        None => return 0, // peek_frame_complete already verified completeness
    };
    let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
    let payload_ptr = cur_recv_buf_ptr(s).add(h2w::FRAME_HEADER_LEN);
    let stream_id = hdr.stream_id;

    let result = match hdr.ftype {
        h2w::FRAME_SETTINGS => handle_settings(s, &hdr, payload_ptr),
        h2w::FRAME_PING => handle_ping(s, &hdr, payload_ptr),
        h2w::FRAME_HEADERS => handle_headers(s, &hdr, payload_ptr),
        h2w::FRAME_DATA => handle_data(s, &hdr, payload_ptr),
        h2w::FRAME_WINDOW_UPDATE => handle_window_update(s, &hdr, payload_ptr),
        h2w::FRAME_PRIORITY => Ok(()), // ignored — no priority enforcement
        h2w::FRAME_RST_STREAM => {
            let idx = slot_for_id(s, stream_id);
            if idx >= 0 {
                let slot_state = (*cur_h2(s).streams.as_ptr().add(idx as usize)).state;
                if cur_h2_mut(s).file_owner == idx {
                    cur_h2_mut(s).file_owner = -1;
                    // Stream got reset mid-fetch — release the
                    // server-level file_chan lock so siblings
                    // aren't permanently blocked.
                    super::release_file_chan_external(s);
                }
                if slot_state == SlotState::WsActive {
                    cur_h2_mut(s).ws_active = 0;
                    cur_h2_mut(s).ws_buf_len = 0;
                    cur_h2_mut(s).ws_stream_id = 0;
                }
                free_slot(s, idx);
                // If no Sending or Fetching slots remain, fall back
                // to Active so the loop picks up Pending or new
                // inbound work. A surviving Fetching slot keeps us in
                // `SendingBody` so `drive_cache_fetch` keeps ticking.
                if !any_sending_slot(s) && fetching_slot(s) < 0 {
                    cur_h2_mut(s).sub = Sub::Active;
                    cur_h2_mut(s).emit_cursor = -1;
                }
            }
            Ok(())
        }
        h2w::FRAME_GOAWAY => {
            // Peer is closing; drain remaining frames then close.
            cur_h2_mut(s).sub = Sub::Closing;
            Ok(())
        }
        h2w::FRAME_PUSH_PROMISE => Err(h2w::ERR_PROTOCOL_ERROR),
        h2w::FRAME_CONTINUATION => Err(h2w::ERR_PROTOCOL_ERROR), // we cap headers at one frame
        _ => Ok(()), // unknown frame types are ignored per §5.5
    };

    // Shift consumed bytes off the front of recv_buf.
    let leftover = len - total;
    if leftover > 0 {
        let p = cur_recv_buf_mut_ptr(s);
        let mut i = 0;
        while i < leftover {
            *p.add(i) = *p.add(total + i);
            i += 1;
        }
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
    }

    if let Err(code) = result {
        queue_goaway(s, code);
        return -1;
    }
    0
}

// ── Per-frame handlers ────────────────────────────────────────────────────

unsafe fn handle_settings(
    s: &mut HttpState,
    hdr: &h2w::Header,
    payload: *const u8,
) -> Result<(), u32> {
    if hdr.stream_id != 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & h2w::FLAG_ACK) != 0 {
        if hdr.length != 0 {
            return Err(h2w::ERR_FRAME_SIZE_ERROR);
        }
        cur_h2_mut(s).settings_acked = 1;
        return Ok(());
    }
    if !hdr.length.is_multiple_of(6) {
        return Err(h2w::ERR_FRAME_SIZE_ERROR);
    }
    // Walk SETTINGS payload (each entry: 2-byte id, 4-byte value).
    // We honor SETTINGS_INITIAL_WINDOW_SIZE so per-stream send_window
    // adjustments stay correct; other settings are tolerated as ack.
    let mut i = 0usize;
    let total = hdr.length as usize;
    while i + 6 <= total {
        let id = ((*payload.add(i) as u16) << 8) | (*payload.add(i + 1) as u16);
        let val = ((*payload.add(i + 2) as u32) << 24)
            | ((*payload.add(i + 3) as u32) << 16)
            | ((*payload.add(i + 4) as u32) << 8)
            | (*payload.add(i + 5) as u32);
        if id == h2w::SETTINGS_INITIAL_WINDOW_SIZE {
            // Per RFC 7540 §6.9.2: must fit in i32 (≤ 2^31-1).
            if val > 0x7FFF_FFFF {
                return Err(h2w::ERR_FLOW_CONTROL_ERROR);
            }
            apply_initial_window_size(s, val as i32);
        }
        i += 6;
    }
    let n = h2w::write_settings_ack(cur_send_buf_mut_ptr(s));
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    Ok(())
}

/// Apply a new SETTINGS_INITIAL_WINDOW_SIZE: bump every open stream's
/// `send_window` by the delta between old and new (RFC 7540 §6.9.2).
unsafe fn apply_initial_window_size(s: &mut HttpState, new_val: i32) {
    let old_val = cur_h2(s).peer_initial_window_size;
    let delta = (new_val as i64) - (old_val as i64);
    cur_h2_mut(s).peer_initial_window_size = new_val;
    if delta == 0 {
        return;
    }
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(i as usize);
        if slot.id != 0 && slot.state != SlotState::Idle {
            // Saturate to i32 range to avoid overflow if peer sends
            // back-to-back wild SETTINGS values.
            let new_w = (slot.send_window as i64).saturating_add(delta);
            slot.send_window = new_w.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        }
        i += 1;
    }
}

/// Apply a WINDOW_UPDATE: bumps connection-level `send_window` (when
/// `stream_id == 0`) or the matching stream's `send_window`.
unsafe fn handle_window_update(
    s: &mut HttpState,
    hdr: &h2w::Header,
    payload: *const u8,
) -> Result<(), u32> {
    if hdr.length != 4 {
        return Err(h2w::ERR_FRAME_SIZE_ERROR);
    }
    let delta = (((*payload as u32) << 24)
        | ((*payload.add(1) as u32) << 16)
        | ((*payload.add(2) as u32) << 8)
        | (*payload.add(3) as u32))
        & 0x7FFF_FFFF;
    if delta == 0 {
        // RFC 7540 §6.9: 0 is a PROTOCOL_ERROR (or stream-level error
        // — we conservatively treat both as connection error).
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if hdr.stream_id == 0 {
        cur_h2_mut(s).send_window = cur_h2(s).send_window.saturating_add(delta as i32);
    } else {
        let idx = slot_for_id(s, hdr.stream_id);
        if idx >= 0 {
            let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(idx as usize);
            slot.send_window = slot.send_window.saturating_add(delta as i32);
        }
        // Unknown stream — silently drop; peer might be referring to a
        // stream we already closed.
    }
    Ok(())
}

unsafe fn handle_ping(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) -> Result<(), u32> {
    if hdr.stream_id != 0 || hdr.length != 8 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & h2w::FLAG_ACK) != 0 {
        return Ok(()); // peer ack'd our (nonexistent) ping; ignore
    }
    let n = h2w::write_ping_ack(cur_send_buf_mut_ptr(s), payload);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    Ok(())
}

unsafe fn handle_headers(
    s: &mut HttpState,
    hdr: &h2w::Header,
    payload: *const u8,
) -> Result<(), u32> {
    if hdr.stream_id == 0 || (hdr.stream_id & 1) == 0 {
        // §5.1.1: client-initiated streams must use odd, nonzero ids.
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & h2w::FLAG_END_HEADERS) == 0 {
        // CONTINUATION frames not yet supported.
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    // §5.1.1: stream ids must monotonically increase.
    if hdr.stream_id <= cur_h2(s).last_stream_id {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }

    let slot_idx = alloc_slot(s, hdr.stream_id);
    if slot_idx < 0 {
        // Stream table full — refuse this stream, leave existing ones alone.
        let n = h2w::write_rst_stream(
            cur_send_buf_mut_ptr(s),
            hdr.stream_id,
            h2w::ERR_REFUSED_STREAM,
        );
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = n as u16;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        return Ok(());
    }

    let (block_off, block_len) =
        super::super::wire::h2::headers_block_extent(payload, hdr.length, hdr.flags)
            .map_err(|_| h2w::ERR_PROTOCOL_ERROR)?;
    let block_ptr = payload.add(block_off);

    cur_h2_mut(s).last_stream_id = hdr.stream_id;
    let end_stream = (hdr.flags & h2w::FLAG_END_STREAM) != 0;

    // Decode into stack-local scratch; raw-pointer scratch avoids the
    // closure-borrow miscompile under -O on PIC aarch64.
    let mut method_kind: u8 = 0;
    let mut protocol_ws: u8 = 0;
    let mut path_buf = [0u8; MAX_PATH];
    let mut path_len: u8 = 0;
    let mk_ptr = &mut method_kind as *mut u8;
    let pr_ptr = &mut protocol_ws as *mut u8;
    let pl_ptr = &mut path_len as *mut u8;
    let pb_ptr = path_buf.as_mut_ptr();

    // Non-pseudo header fields are re-serialised as they decode, into a heap
    // buffer owned by the stream. This is the ONLY chance to capture them:
    // HPACK compresses against the connection's whole header history, so the
    // original bytes cannot be recovered from the frame afterwards, and a
    // second decode pass would desynchronise the dynamic table.
    //
    // Allocated up front and written through raw pointers rather than by
    // borrowing `s` in the closure — the same reason the scratch above is raw
    // pointers, per the closure-borrow miscompile noted there.
    let hdr_scratch = super::heap_alloc(&*s.syscalls, H2_HDR_CAP as u32);
    let mut hdr_used: u32 = 0;
    let hb_ptr = hdr_scratch;
    let hu_ptr = &mut hdr_used as *mut u32;

    let dec = super::super::wire::hpack::decode_block(block_ptr, block_len, |name, value| {
        if bytes_eq(name, b":method") {
            // The shared vocabulary, not a local bucketing by body-bearing-ness:
            // an application module has to tell a create from a delete, and h1
            // resolves the same token against the same table.
            *mk_ptr = method::method_from_token(value);
        } else if bytes_eq(name, b":path") {
            let n = value.len().min(MAX_PATH);
            let mut i = 0;
            while i < n {
                *pb_ptr.add(i) = value[i];
                i += 1;
            }
            *pl_ptr = n as u8;
        } else if bytes_eq(name, b":protocol") && bytes_eq(value, b"websocket") {
            *pr_ptr = 1;
        } else if !name.is_empty() && name[0] != b':' && !hb_ptr.is_null() {
            // An ordinary field. Pseudo-headers are excluded: they are the
            // request line in h2's encoding, and an application reading them
            // as headers would see a `:method` field that h1 never sends.
            let need = name.len() + 2 + value.len() + 2;
            let used = *hu_ptr as usize;
            if used + need <= H2_HDR_CAP {
                let mut o = used;
                core::ptr::copy_nonoverlapping(name.as_ptr(), hb_ptr.add(o), name.len());
                o += name.len();
                *hb_ptr.add(o) = b':';
                *hb_ptr.add(o + 1) = b' ';
                o += 2;
                core::ptr::copy_nonoverlapping(value.as_ptr(), hb_ptr.add(o), value.len());
                o += value.len();
                *hb_ptr.add(o) = b'\r';
                *hb_ptr.add(o + 1) = b'\n';
                o += 2;
                *hu_ptr = o as u32;
            }
        }
    });
    if dec.is_err() {
        if !hdr_scratch.is_null() {
            super::heap_free(&*s.syscalls, hdr_scratch);
        }
        free_slot(s, slot_idx);
        return Err(h2w::ERR_COMPRESSION_ERROR);
    }

    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
    slot.hdr_buf = hdr_scratch;
    slot.hdr_len = hdr_used;
    slot.method_kind = method_kind;
    slot.req_path_len = path_len;
    slot.end_stream_in = if end_stream { 1 } else { 0 };
    let mut ci = 0usize;
    while ci < path_len as usize {
        slot.req_path[ci] = path_buf[ci];
        ci += 1;
    }

    if method_kind == 0 || path_len == 0 {
        let n = h2w::write_rst_stream(
            cur_send_buf_mut_ptr(s),
            hdr.stream_id,
            h2w::ERR_PROTOCOL_ERROR,
        );
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = n as u16;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        free_slot(s, slot_idx);
        return Ok(());
    }

    // Extended CONNECT (RFC 8441) — WS-over-h2 upgrade. Must not have
    // END_STREAM and we cap WS at one stream per connection.
    if method_kind == method::METHOD_CONNECT && protocol_ws == 1 {
        if end_stream || cur_h2(s).ws_active != 0 {
            let n = h2w::write_rst_stream(
                cur_send_buf_mut_ptr(s),
                hdr.stream_id,
                if end_stream {
                    h2w::ERR_PROTOCOL_ERROR
                } else {
                    h2w::ERR_REFUSED_STREAM
                },
            );
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = 0;
            }
            free_slot(s, slot_idx);
            return Ok(());
        }
        accept_ws_upgrade(s, slot_idx);
        return Ok(());
    }

    if !method::method_is_dispatchable(method_kind) {
        // CONNECT without `:protocol = websocket` not supported; anything
        // outside the recognised vocabulary is well-formed but unimplemented,
        // which is 501 on both generations now.
        emit_response(
            s,
            hdr.stream_id,
            b"501",
            b"text/plain",
            b"method unsupported on h2\n",
        );
        free_slot(s, slot_idx);
        return Ok(());
    }

    if end_stream {
        // Request fully received; mark Pending. The active loop will
        // pick this slot up once any in-flight emitter finishes.
        slot.state = SlotState::Pending;
        try_dispatch_pending(s);
    }
    // Else slot stays Open until DATA frame with END_STREAM arrives.
    Ok(())
}

unsafe fn handle_data(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) -> Result<(), u32> {
    if hdr.stream_id == 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }

    // Account for the bytes against connection-level + stream-level
    // recv windows. The window doesn't care whether we kept the
    // payload or discarded it.
    consume_recv_window(s, hdr.length);
    let idx = slot_for_id(s, hdr.stream_id);
    if idx >= 0 {
        consume_slot_recv_window(s, idx, hdr.length);
    }
    if idx < 0 {
        let n = h2w::write_rst_stream(
            cur_send_buf_mut_ptr(s),
            hdr.stream_id,
            h2w::ERR_STREAM_CLOSED,
        );
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = n as u16;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        return Ok(());
    }

    let slot_state = (*cur_h2(s).streams.as_ptr().add(idx as usize)).state;
    if slot_state == SlotState::WsActive {
        ws_handle_data(s, hdr, payload);
        return Ok(());
    }

    // Request body for non-WS streams is accumulated, bounded by the server's
    // `max_body`. Discarding it is survivable only while every route answers
    // from configuration: a route that hands the request to an application must
    // deliver the body too, because a PUT whose body evaporates is worse than a
    // PUT that is refused.
    //
    // Padding is excluded: `data_payload_extent` resolves the pad length, and
    // padding is transport filler that is not part of the body.
    let end_stream = (hdr.flags & h2w::FLAG_END_STREAM) != 0;
    if hdr.length > 0 {
        match h2w::data_payload_extent(payload, hdr.length, hdr.flags) {
            Ok((off, len)) if len > 0 => {
                if !append_stream_body(s, idx as usize, payload.add(off), len as usize) {
                    // Over the cap. RST_STREAM rather than a 413 response: the
                    // peer is mid-upload and there is no point reading the rest
                    // of a body that has already been refused, while the
                    // connection and its other streams stay healthy.
                    let n = h2w::write_rst_stream(
                        cur_send_buf_mut_ptr(s),
                        hdr.stream_id,
                        h2w::ERR_ENHANCE_YOUR_CALM,
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.send_len = n as u16;
                        cur.send_offset = 0;
                    }
                    free_slot(s, idx);
                    return Ok(());
                }
            }
            Ok(_) => {}
            Err(_) => return Err(h2w::ERR_PROTOCOL_ERROR),
        }
    }
    if end_stream {
        let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(idx as usize);
        slot.end_stream_in = 1;
        if slot.state == SlotState::Open {
            slot.state = SlotState::Pending;
        }
        try_dispatch_pending(s);
    }
    Ok(())
}

/// Decrement connection-level `recv_window` by `n` bytes. If it
/// crosses the refill threshold, mark `H2State.window_update_pending`
/// so the active loop emits a connection-level WINDOW_UPDATE the next
/// time `send_buf` is free.
unsafe fn consume_recv_window(s: &mut HttpState, n: u32) {
    cur_h2_mut(s).recv_window = cur_h2(s).recv_window.saturating_sub(n as i32);
    if cur_h2(s).recv_window <= RECV_WINDOW_THRESHOLD {
        cur_h2_mut(s).window_update_pending = 1;
    }
}

/// Decrement a stream's `recv_window` by `n` bytes. Sets the slot's
/// own `window_update_pending` flag when it crosses the threshold.
unsafe fn consume_slot_recv_window(s: &mut HttpState, slot_idx: i8, n: u32) {
    if slot_idx < 0 {
        return;
    }
    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
    slot.recv_window = slot.recv_window.saturating_sub(n as i32);
    if slot.recv_window <= RECV_WINDOW_THRESHOLD {
        slot.window_update_pending = 1;
    }
}

/// Returns true if any stream slot needs a per-stream WINDOW_UPDATE.
/// Used so the active loop knows whether to call `queue_window_update`
/// even when the connection-level window is full.
unsafe fn any_stream_window_pending(s: &HttpState) -> bool {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
        if slot.id != 0 && slot.window_update_pending != 0 && slot.state != SlotState::Idle {
            return true;
        }
        i += 1;
    }
    false
}

/// Queue a WINDOW_UPDATE frame in `send_buf` (caller must have
/// verified it's free). Connection-level pending takes priority; if
/// none, scan slots and emit a per-stream WINDOW_UPDATE for the first
/// pending one. Each call emits at most one frame; subsequent ticks
/// drain the rest until the queue is empty.
unsafe fn queue_window_update(s: &mut HttpState) {
    if cur_h2(s).window_update_pending != 0 {
        let delta = (RECV_WINDOW_INITIAL - cur_h2(s).recv_window) as u32;
        if delta != 0 {
            let n = h2w::write_window_update(cur_send_buf_mut_ptr(s), 0, delta);
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = 0;
            }
            cur_h2_mut(s).recv_window = RECV_WINDOW_INITIAL;
        }
        cur_h2_mut(s).window_update_pending = 0;
        return;
    }
    // Per-stream pending — find one and emit it.
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(i as usize);
        if slot.id != 0 && slot.window_update_pending != 0 && slot.state != SlotState::Idle {
            let delta = (RECV_WINDOW_INITIAL - slot.recv_window) as u32;
            if delta != 0 {
                let n = h2w::write_window_update(cur_send_buf_mut_ptr(s), slot.id, delta);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_len = n as u16;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                }
                slot.recv_window = RECV_WINDOW_INITIAL;
            }
            slot.window_update_pending = 0;
            return;
        }
        i += 1;
    }
}

// ── WebSocket-over-h2 (RFC 8441) ──────────────────────────────────────────

/// Validate that a CONNECT + `:protocol = websocket` request maps to a
/// HANDLER_WEBSOCKET route, then queue the 200 HEADERS frame and arm
/// `ws_active`. RFC 8441 §5: the response carries no
/// `Sec-WebSocket-Accept` (that header only applies to the h1
/// handshake); the 200 alone signals the upgrade.
unsafe fn accept_ws_upgrade(s: &mut HttpState, slot_idx: i8) {
    let stream_id = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).id;
    let stream_ptr = cur_h2(s).streams.as_ptr().add(slot_idx as usize);
    let plen = (*stream_ptr).req_path_len as usize;
    if let Some(cur) = super::cur_slot_mut(s) {
        cur.req_path_len = plen as u8;
        let mut i = 0usize;
        while i < plen {
            cur.req_path[i] = (*stream_ptr).req_path[i];
            i += 1;
        }
    }

    let matched = super::match_route(s);
    if matched < 0 {
        emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
        free_slot(s, slot_idx);
        return;
    }
    let route = &*s.server.routes.as_ptr().add(matched as usize);
    if route.handler != HANDLER_WEBSOCKET {
        emit_response(
            s,
            stream_id,
            b"404",
            b"text/plain",
            b"Not a WebSocket route\n",
        );
        free_slot(s, slot_idx);
        return;
    }
    if let Some(cur) = super::cur_slot_mut(s) {
        cur.matched_route = matched;
    }

    // 200 HEADERS, no END_STREAM (DATA frames will follow with WS
    // frames in both directions).
    let buf = cur_send_buf_mut_ptr(s);
    let cap = SEND_BUF_SIZE;
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;
    o += super::super::wire::hpack::encode_header(buf.add(o), cap - o, b":status", b"200");
    let block_len = o - block_start;
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = o as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }

    cur_h2_mut(s).ws_active = 1;
    cur_h2_mut(s).ws_stream_id = stream_id;
    (*cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize)).state = SlotState::WsActive;
    log(s, b"[http] websocket upgraded (h2)");
}

unsafe fn ws_handle_data(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) {
    let plen = hdr.length as usize;
    let cur = cur_h2(s).ws_buf_len as usize;
    if cur + plen > WS_BUF_SIZE {
        queue_ws_close(s, ws::CLOSE_MESSAGE_TOO_BIG);
        return;
    }
    if plen > 0 {
        core::ptr::copy_nonoverlapping(payload, cur_h2_mut(s).ws_buf.as_mut_ptr().add(cur), plen);
        cur_h2_mut(s).ws_buf_len = (cur + plen) as u16;
    }
    ws_drain_buf(s);
}

/// Pop and echo as many complete RFC 6455 frames as possible from
/// `ws_buf`. Stops when (a) the buffer holds only an incomplete frame
/// or (b) `send_buf` is busy with a queued echo (next tick will retry
/// after the wire drains).
pub(crate) unsafe fn ws_drain_buf(s: &mut HttpState) {
    while cur_h2(s).ws_active != 0 && cur_send_len(s) == 0 && cur_h2(s).ws_buf_len > 0 {
        let buflen = cur_h2(s).ws_buf_len as usize;
        let frame = match ws::parse_frame(cur_h2(s).ws_buf.as_ptr(), buflen) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(()) => {
                queue_ws_close(s, ws::CLOSE_PROTOCOL_ERROR);
                return;
            }
        };
        let total = frame.header_len as usize + frame.payload_len as usize;
        if total > buflen {
            return; // need more bytes
        }
        if !frame.masked {
            // RFC 6455 §5.3 / RFC 8441 §5.1 — client→server frames
            // must be masked.
            queue_ws_close(s, ws::CLOSE_PROTOCOL_ERROR);
            return;
        }

        let pl_ptr = cur_h2_mut(s)
            .ws_buf
            .as_mut_ptr()
            .add(frame.header_len as usize);
        ws::unmask(pl_ptr, frame.payload_len, &frame.mask_key);

        let mut consume_only = false;
        match frame.opcode {
            ws::OP_CLOSE => {
                queue_ws_frame(s, ws::OP_CLOSE, pl_ptr, frame.payload_len as usize, true);
                let ws_idx = slot_for_id(s, cur_h2(s).ws_stream_id);
                if ws_idx >= 0 {
                    free_slot(s, ws_idx);
                }
                cur_h2_mut(s).ws_active = 0;
                cur_h2_mut(s).ws_stream_id = 0;
                cur_h2_mut(s).ws_buf_len = 0;
                return;
            }
            ws::OP_PING => {
                queue_ws_frame(s, ws::OP_PONG, pl_ptr, frame.payload_len as usize, false);
            }
            ws::OP_PONG => consume_only = true, // drop silently
            ws::OP_TEXT | ws::OP_BINARY | ws::OP_CONTINUATION => {
                queue_ws_frame(s, frame.opcode, pl_ptr, frame.payload_len as usize, false);
            }
            _ => {
                queue_ws_close(s, ws::CLOSE_PROTOCOL_ERROR);
                return;
            }
        }

        // Shift the consumed frame off the front of ws_buf.
        let leftover = buflen - total;
        if leftover > 0 {
            let p = cur_h2_mut(s).ws_buf.as_mut_ptr();
            let mut i = 0;
            while i < leftover {
                *p.add(i) = *p.add(total + i);
                i += 1;
            }
        }
        cur_h2_mut(s).ws_buf_len = leftover as u16;
        if !consume_only {
            // We queued an echo; send_buf is busy. Bail and let the
            // next tick drain the wire and resume.
            return;
        }
    }
}

/// Wrap a single RFC 6455 frame in an h2 DATA frame on the WS stream.
/// `end_stream` set on a CLOSE echo terminates the WS stream.
unsafe fn queue_ws_frame(
    s: &mut HttpState,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    end_stream: bool,
) {
    let stream_id = cur_h2(s).ws_stream_id;
    let buf = cur_send_buf_mut_ptr(s);
    let dst = buf.add(h2w::FRAME_HEADER_LEN);
    let dst_cap = SEND_BUF_SIZE - h2w::FRAME_HEADER_LEN;
    let written = ws::write_frame(dst, dst_cap, true, opcode, payload, payload_len);
    h2w::write_data_frame_header(buf, written, stream_id, end_stream);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = (h2w::FRAME_HEADER_LEN + written) as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
}

unsafe fn queue_ws_close(s: &mut HttpState, code: u16) {
    let payload = [(code >> 8) as u8, (code & 0xFF) as u8];
    queue_ws_frame(s, ws::OP_CLOSE, payload.as_ptr(), 2, true);
    let ws_idx = slot_for_id(s, cur_h2(s).ws_stream_id);
    if ws_idx >= 0 {
        free_slot(s, ws_idx);
    }
    cur_h2_mut(s).ws_active = 0;
    cur_h2_mut(s).ws_stream_id = 0;
}

// ── Request dispatch ──────────────────────────────────────────────────────

/// Pick the next Pending slot that can be dispatched and arm it for
/// emission. Multiple Sending slots interleave — the only constraint
/// is the `file_owner` mutex for handlers that touch `file_chan` /
/// the body cache. Called after HEADERS / DATA arrival and after each
/// body completes.
unsafe fn try_dispatch_pending(s: &mut HttpState) {
    loop {
        let mut chosen: i8 = -1;
        let mut i = 0u8;
        while (i as usize) < MAX_STREAMS {
            let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
            if slot.state == SlotState::Pending {
                if needs_exclusive_for_request(s, i as i8) && cur_h2(s).file_owner != -1 {
                    // file_chan is busy with another stream; defer
                    // until the current owner finishes.
                    i += 1;
                    continue;
                }
                chosen = i as i8;
                break;
            }
            i += 1;
        }
        if chosen < 0 {
            return;
        }
        dispatch_request(s, chosen);
        // dispatch_request may have queued send_buf (404/501 single
        // frames), in which case we should bail and let the flush
        // happen.
        if cur_send_len(s) > 0 {
            return;
        }
        // Else loop and try to dispatch more inline streams.
    }
}

/// Returns true if the slot's request will need exclusive access to
/// `file_chan` / the body cache. Only one such slot can be in
/// Sending or Fetching state at a time.
///
/// Calls the same `match_route_path` matcher as `dispatch_request`
/// (exact match wins, prefix matches require trailing `/` and a
/// strictly longer request, longest prefix wins). A weaker
/// heuristic — say a first-byte-prefix scan — would mis-classify
/// `/files/x` as non-exclusive when a `/` static route is
/// registered first, letting both streams bypass the `file_owner`
/// mutex and race on FLUSH/NOTIFY.
unsafe fn needs_exclusive_for_request(s: &HttpState, slot_idx: i8) -> bool {
    let slot = &*cur_h2(s).streams.as_ptr().add(slot_idx as usize);
    let plen = slot.req_path_len as usize;
    if plen == 0 {
        return false;
    }
    let matched = super::match_route_path(s, slot.req_path.as_ptr(), plen);
    if matched < 0 {
        return false; // 404; no file/cache work
    }
    let r = &*s.server.routes.as_ptr().add(matched as usize);
    r.handler == HANDLER_FILE
        || ((r.handler == HANDLER_STATIC || r.handler == HANDLER_TEMPLATE) && r.source_index >= 0)
}

unsafe fn dispatch_request(s: &mut HttpState, slot_idx: i8) {
    let stream_id = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).id;
    let plen = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).req_path_len as usize;

    // Copy the slot's request path into the active conn slot's req_path
    // scratch — the route matcher and file-index parser both read from
    // there.
    let stream_ptr = cur_h2(s).streams.as_ptr().add(slot_idx as usize);
    if let Some(cur) = super::cur_slot_mut(s) {
        cur.req_path_len = plen as u8;
        let mut i = 0;
        while i < plen {
            cur.req_path[i] = (*stream_ptr).req_path[i];
            i += 1;
        }
    }

    let matched = super::match_route(s);
    if matched < 0 {
        emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
        free_slot(s, slot_idx);
        return;
    }
    let route = &*s.server.routes.as_ptr().add(matched as usize);
    let handler_kind = route.handler;
    let src_idx = route.source_index;
    if let Some(cur) = super::cur_slot_mut(s) {
        cur.matched_route = matched;
        cur.tmpl_pos = 0;
    }

    match handler_kind {
        HANDLER_STATIC => {
            if src_idx >= 0 {
                begin_cached_response(s, slot_idx, HANDLER_STATIC);
            } else {
                arm_slot_for_emission(s, slot_idx, HANDLER_STATIC, -1, matched);
            }
        }
        HANDLER_TEMPLATE => {
            if src_idx >= 0 {
                begin_cached_response(s, slot_idx, HANDLER_TEMPLATE);
            } else {
                arm_slot_for_emission(s, slot_idx, HANDLER_TEMPLATE, -1, matched);
            }
        }
        HANDLER_FILE => begin_file_response(s, slot_idx, matched),
        #[cfg(feature = "app")]
        HANDLER_APP => {
            // The stream stays Open (not Sending) while the application
            // thinks: h2's emitter is a single-slot round robin, and parking a
            // stream in Sending for the length of an application round trip
            // would stall every other stream on the connection — which is the
            // one thing h2 exists to avoid.
            match emit_app_request(s, slot_idx) {
                super::app::EmitResult::Sent => {
                    let now = super::dev_millis(&*s.syscalls);
                    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
                    slot.app_pending = 1;
                    slot.app_deadline_ms = now.saturating_add(super::app::APP_TIMEOUT_MS);
                    slot.state = SlotState::Open;
                }
                // Ring momentarily full: leave the stream Pending so the next
                // dispatch pass retries it.
                super::app::EmitResult::Full => {
                    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
                    slot.state = SlotState::Pending;
                }
                _ => {
                    emit_response(
                        s,
                        stream_id,
                        b"503",
                        b"text/plain",
                        b"No application wired to req_out\n",
                    );
                    free_slot(s, slot_idx);
                }
            }
        }
        HANDLER_GRPC => {
            // Canned unary response, NOT an echo. `handle_data` discards
            // request bodies for non-WS streams, so mirroring the caller's
            // message would need per-stream body buffering — a change to the
            // shared `streams[MAX_STREAMS]` state. A load route does not need
            // it: what a gRPC load probe measures is completed RPCs per second,
            // and grpcbin's simplest endpoint is a fixed reply too. An echoing
            // variant is a separate feature, not a bigger constant.
            //
            // The reply is one Length-Prefixed Message: [compressed:0]
            // [len:4 BE][payload]. Five bytes of prefix plus a 4-byte body, so
            // a client that mis-reads the prefix gets a length mismatch rather
            // than a plausible-but-wrong decode.
            const GRPC_REPLY: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x04, 0x0A, 0x02, b'h', b'i'];
            emit_grpc_response(s, stream_id, GRPC_REPLY, 0);
            free_slot(s, slot_idx);
        }
        _ => {
            emit_response(
                s,
                stream_id,
                b"501",
                b"text/plain",
                b"handler unsupported on h2\n",
            );
            free_slot(s, slot_idx);
        }
    }
}

/// Emit this stream's request on `req_out`.
///
/// Gathers the parts from the `StreamSlot` — a connection carries many requests
/// at once, so none of them live on the `ConnSlot` — and hands them to
/// `app::write_request_envelope`, which both generations share.
#[cfg(feature = "app")]
unsafe fn emit_app_request(s: &mut HttpState, slot_idx: i8) -> super::app::EmitResult {
    if s.server.app_out_chan < 0 {
        return super::app::EmitResult::Unwired;
    }
    let conn_id = super::cur_slot(s).map(|c| c.conn_id as u16).unwrap_or(0);
    let slot = &*cur_h2(s).streams.as_ptr().add(slot_idx as usize);
    // h2 stream ids are u32 and monotonically increasing, so a long-lived
    // connection can pass 65535. Refuse the dispatch rather than truncate two
    // live streams onto one correlation key.
    if !super::app::stream_id_fits(slot.id) {
        return super::app::EmitResult::TooLarge;
    }
    let empty = &[][..];
    super::app::write_request_envelope(
        s,
        conn_id,
        slot.id as u16,
        slot.method_kind,
        core::slice::from_raw_parts(
            slot.req_path.as_ptr(),
            (slot.req_path_len as usize).min(MAX_PATH),
        ),
        if slot.hdr_buf.is_null() {
            empty
        } else {
            core::slice::from_raw_parts(slot.hdr_buf, slot.hdr_len as usize)
        },
        if slot.body_buf.is_null() {
            empty
        } else {
            core::slice::from_raw_parts(slot.body_buf, slot.body_len as usize)
        },
    )
}

/// Find the h2 stream on this connection awaiting `stream_id`, if any.
#[cfg(feature = "app")]
pub(crate) unsafe fn find_app_stream(s: &HttpState, stream_id: u16) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
        if slot.app_pending != 0 && (slot.id as u16) == stream_id {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Serve an application response on an h2 stream.
///
/// `more` marks a streamed body whose continuation arrives in later envelopes.
/// h2 needs no `Content-Length` to frame one — END_STREAM on the final DATA
/// frame is the delimiter — so unlike h1, a streamed response here costs the
/// connection nothing.
#[cfg(feature = "app")]
pub(crate) unsafe fn deliver_app_response(
    s: &mut HttpState,
    slot_idx: i8,
    status: u16,
    content_type: &[u8],
    body: &[u8],
    more: bool,
) {
    let (stream_id, verb, head_sent) = {
        let slot = &*cur_h2(s).streams.as_ptr().add(slot_idx as usize);
        (slot.id, slot.method_kind, slot.headers_sent)
    };

    // HEAD, 204 and 304 carry no body on h2 for the same reason as on h1 —
    // except that on h2 the consequence is a stream-state violation rather
    // than a desynchronised connection, which a peer answers with a
    // PROTOCOL_ERROR that kills every other stream too.
    let allows = super::app::status_allows_body(status, verb);
    let out: &[u8] = if allows { body } else { &[] };
    let streaming = more && allows;

    if head_sent == 0 {
        let mut code = [b'0'; 3];
        let s3 = status.min(999);
        code[0] = b'0' + (s3 / 100) as u8;
        code[1] = b'0' + ((s3 / 10) % 10) as u8;
        code[2] = b'0' + (s3 % 10) as u8;
        let ct: &[u8] = if content_type.is_empty() {
            b"application/octet-stream"
        } else {
            content_type
        };
        emit_response_framed(s, stream_id, &code, ct, out, !streaming);
    } else {
        // Continuation: DATA only. Re-emitting HEADERS mid-body would be a
        // trailer section by h2's rules, and one carrying `:status` is a
        // protocol error.
        emit_data_chunk(s, stream_id, out, !streaming);
    }

    if streaming {
        let now = super::dev_millis(&*s.syscalls);
        let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
        slot.headers_sent = 1;
        slot.app_pending = 1;
        // Time since last progress, not since the request — see the h1
        // counterpart in `app::compose_stream_chunk`.
        slot.app_deadline_ms = now.saturating_add(super::app::APP_TIMEOUT_MS);
    } else {
        free_slot(s, slot_idx);
    }
}

/// Emit a DATA frame carrying `body` on `stream_id`, optionally ending the
/// stream.
#[cfg(feature = "app")]
unsafe fn emit_data_chunk(s: &mut HttpState, stream_id: u32, body: &[u8], end: bool) {
    let buf = cur_send_buf_mut_ptr(s);
    let cap = SEND_BUF_SIZE;
    if h2w::FRAME_HEADER_LEN + body.len() > cap {
        let n = h2w::write_rst_stream(buf, stream_id, h2w::ERR_INTERNAL_ERROR);
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = n as u16;
            cur.send_offset = 0;
        }
        return;
    }
    h2w::write_data_frame_header(buf, body.len(), stream_id, end);
    if !body.is_empty() {
        core::ptr::copy_nonoverlapping(body.as_ptr(), buf.add(h2w::FRAME_HEADER_LEN), body.len());
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = (h2w::FRAME_HEADER_LEN + body.len()) as u16;
        cur.send_offset = 0;
    }
}

/// Answer every stream whose application request has outlived the timeout.
///
/// Per stream rather than per connection: one unanswered request must not take
/// down the siblings sharing its connection.
#[cfg(feature = "app")]
pub(crate) unsafe fn sweep_app_timeouts(s: &mut HttpState) {
    if cur_h2_ptr_is_null(s) {
        return;
    }
    let now = super::dev_millis(&*s.syscalls);
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let (pending, deadline) = {
            let slot = &*cur_h2(s).streams.as_ptr().add(i as usize);
            (slot.app_pending, slot.app_deadline_ms)
        };
        if pending != 0 && deadline != 0 && now >= deadline {
            let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(i as usize);
            slot.app_pending = 0;
            let stream_id = slot.id;
            emit_response(s, stream_id, b"504", b"text/plain", b"Gateway Timeout\n");
            free_slot(s, i as i8);
            // One per pass: `emit_response` fills `send_buf`, and a second
            // would overwrite the first before it reached the wire.
            return;
        }
        i += 1;
    }
}

/// True when this connection has no h2 state — an h1 slot, or one that has not
/// yet seen the preface.
#[cfg(feature = "app")]
unsafe fn cur_h2_ptr_is_null(s: &HttpState) -> bool {
    super::cur_slot(s).map(|c| c.h2.is_null()).unwrap_or(true)
}

/// Populate slot's render state and mark Sending. The actual HEADERS
/// frame is emitted lazily by `step_sending_body` so multiple slots'
/// HEADERS can interleave on the wire.
unsafe fn arm_slot_for_emission(
    s: &mut HttpState,
    slot_idx: i8,
    handler: u8,
    file_index: i16,
    matched_route: i8,
) {
    let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
    slot.body_handler = handler;
    slot.matched_route = matched_route;
    slot.file_index = file_index;
    slot.tmpl_pos = 0;
    slot.headers_sent = 0;
    slot.state = SlotState::Sending;
    cur_h2_mut(s).sub = Sub::SendingBody;
}

/// Try the body cache; on hit, arm for emission. On miss, mark the
/// slot `Fetching`, claim `file_owner`, and stay in `Sub::SendingBody`
/// so `drive_cache_fetch` ticks each step until the cache is filled —
/// without blocking other in-flight inline streams.
unsafe fn begin_cached_response(s: &mut HttpState, slot_idx: i8, handler: u8) {
    use super::cache::{cache_try_or_fetch, CacheLookup};
    use super::cur_matched_route;
    let matched = cur_matched_route(s);
    match cache_try_or_fetch(s, matched) {
        CacheLookup::Hit | CacheLookup::NoSource => {
            arm_slot_for_emission(s, slot_idx, handler, -1, matched);
        }
        CacheLookup::Pending | CacheLookup::Busy => {
            // Pending — fetch issued, drive_cache_fetch will pump
            //   bytes until cache is full.
            // Busy   — another slot owns file_chan. Mark Fetching
            //   anyway; drive_cache_fetch retries cache_try_or_fetch
            //   each tick until the lock frees, then transitions to
            //   Pending and resumes normally.
            let slot = &mut *cur_h2_mut(s).streams.as_mut_ptr().add(slot_idx as usize);
            slot.state = SlotState::Fetching;
            slot.body_handler = handler;
            slot.matched_route = matched;
            slot.file_index = -1;
            slot.tmpl_pos = 0;
            slot.headers_sent = 0;
            cur_h2_mut(s).file_owner = slot_idx;
            cur_h2_mut(s).sub = Sub::SendingBody;
        }
    }
}

/// Open `file_chan` for the requested index (or list mode) and arm
/// the slot for streaming. Claims `file_owner` for the duration —
/// other HANDLER_FILE / cache slots wait Pending.
unsafe fn begin_file_response(s: &mut HttpState, slot_idx: i8, matched_route: i8) {
    let stream_id = (*cur_h2(s).streams.as_ptr().add(slot_idx as usize)).id;
    let fi = super::body::parse_file_index(s);
    if let Some(cur) = super::cur_slot_mut(s) {
        cur.file_index = fi;
    }
    let sys = &*s.syscalls;

    if fi == -1 {
        if s.server.file_chan >= 0 {
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_POLL_NOTIFY, count_ptr, 4);
            if r >= 0 {
                if let Some(cur) = super::cur_slot_mut(s) {
                    cur.file_count = count as u16;
                }
            }
        }
        if let Some(cur) = super::cur_slot_mut(s) {
            cur.index_pos = 0;
        }
        cur_h2_mut(s).file_owner = slot_idx;
        arm_slot_for_emission(s, slot_idx, HANDLER_FILE, -1, matched_route);
    } else if fi >= 0 {
        if s.server.file_chan < 0 {
            emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
            free_slot(s, slot_idx);
            return;
        }
        // Cross-slot serialisation: take the server-level
        // `file_chan_owner` lock before issuing FLUSH/NOTIFY.
        // h2 HANDLER_FILE doesn't have a Fetching-style retry
        // state, so on contention we emit 503 — the client can
        // retry. (h2 cache fetch uses `Busy → Fetching` for
        // graceful retry; HANDLER_FILE is a direct fetch and
        // doesn't fit that shape without a deeper rework.)
        if !super::try_acquire_file_chan_external(s) {
            emit_response(
                s,
                stream_id,
                b"503",
                b"text/plain",
                b"Service Unavailable: file channel busy\n",
            );
            free_slot(s, slot_idx);
            return;
        }
        dev_channel_ioctl(
            sys,
            s.server.file_chan,
            IOCTL_FLUSH,
            core::ptr::null_mut(),
            0,
        );
        let mut pos = fi as u32;
        let pos_ptr = &mut pos as *mut u32 as *mut u8;
        let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_NOTIFY, pos_ptr, 4);
        if r < 0 {
            super::release_file_chan_external(s);
            emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
            free_slot(s, slot_idx);
            return;
        }
        cur_h2_mut(s).file_owner = slot_idx;
        arm_slot_for_emission(s, slot_idx, HANDLER_FILE, fi, matched_route);
    } else {
        emit_response(s, stream_id, b"400", b"text/plain", b"Bad Request\n");
        free_slot(s, slot_idx);
    }
}

/// Build a HEADERS + DATA pair into `send_buf`. The DATA frame carries
/// END_STREAM. Caller must guarantee the combined payload fits within
/// `SEND_BUF_SIZE` (current bodies do; static routes are capped by the
/// body pool).
unsafe fn emit_response(
    s: &mut HttpState,
    stream_id: u32,
    status: &[u8],
    content_type: &[u8],
    body: &[u8],
) {
    emit_response_framed(s, stream_id, status, content_type, body, true)
}

/// As `emit_response`, but `end` chooses whether the DATA frame closes the
/// stream. A streamed application response leaves it open and delimits the
/// body with END_STREAM on its final chunk — h2 needs no `Content-Length` for
/// that, which is why a streamed response costs the connection nothing here
/// and costs h1 its keep-alive.
unsafe fn emit_response_framed(
    s: &mut HttpState,
    stream_id: u32,
    status: &[u8],
    content_type: &[u8],
    body: &[u8],
    end: bool,
) {
    let buf = cur_send_buf_mut_ptr(s);
    let cap = SEND_BUF_SIZE;

    // Encode the header block starting at offset 9 — leaving room for
    // the HEADERS frame header that comes back-filled below.
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;

    o += super::super::wire::hpack::encode_header(buf.add(o), cap - o, b":status", status);
    o += super::super::wire::hpack::encode_header(
        buf.add(o),
        cap - o,
        b"content-type",
        content_type,
    );

    // `content-length` only when this frame IS the whole body. Declaring the
    // first chunk's length on a streamed response would tell the peer the
    // transfer is complete after that chunk, and every DATA frame after it
    // would exceed the length the peer was told to expect. h2 delimits with
    // END_STREAM instead, so omitting it is correct rather than merely safe.
    if end {
        let mut clen = [0u8; 11];
        let n = super::super::fmt_u32_raw(clen.as_mut_ptr(), body.len() as u32);
        o += super::super::wire::hpack::encode_header(
            buf.add(o),
            cap - o,
            b"content-length",
            core::slice::from_raw_parts(clen.as_ptr(), n),
        );
    }

    let block_len = o - block_start;
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);

    // DATA frame follows immediately after the HEADERS frame.
    let data_hdr_off = o;
    let data_off = data_hdr_off + h2w::FRAME_HEADER_LEN;
    if data_off + body.len() > cap {
        // Body too large for our send buffer in this slice — close the
        // stream rather than emit a malformed frame.
        let n = h2w::write_rst_stream(buf, stream_id, h2w::ERR_INTERNAL_ERROR);
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = n as u16;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        return;
    }

    h2w::write_data_frame_header(buf.add(data_hdr_off), body.len(), stream_id, end);
    if !body.is_empty() {
        core::ptr::copy_nonoverlapping(body.as_ptr(), buf.add(data_off), body.len());
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = (data_off + body.len()) as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
}

/// Emit a complete gRPC unary response: HEADERS, DATA, then TRAILING HEADERS.
///
/// gRPC signals its status in trailers, not in `:status` — an RPC that failed
/// still carries `:status: 200`, and a client that reads only the HTTP status
/// sees success. So the trailing HEADERS frame is not optional decoration, it
/// IS the result, and it is the one thing the rest of this server never emits:
/// every other response puts END_STREAM on its DATA frame and is done.
///
/// Frame sequence (gRPC over HTTP/2, RFC 9113 §8.1 for the trailer rules):
///
/// ```text
///   HEADERS  END_HEADERS              :status 200, content-type application/grpc
///   DATA     (no END_STREAM)          the length-prefixed message
///   HEADERS  END_HEADERS|END_STREAM   grpc-status: <code>
/// ```
///
/// `body` is passed through verbatim — it is the caller's Length-Prefixed
/// Message (`[compressed:1][len:4 BE][message]`), matching the division of
/// labour the client path already documents in `client_h2.rs`: this module
/// owns TRANSPORT of the LPM, never its construction.
unsafe fn emit_grpc_response(s: &mut HttpState, stream_id: u32, body: &[u8], grpc_status: u8) {
    let buf = cur_send_buf_mut_ptr(s);
    let cap = SEND_BUF_SIZE;

    // ── HEADERS (response) ──
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;
    o += super::super::wire::hpack::encode_header(buf.add(o), cap - o, b":status", b"200");
    o += super::super::wire::hpack::encode_header(
        buf.add(o),
        cap - o,
        b"content-type",
        b"application/grpc",
    );
    // No content-length: the message is DATA-framed and the stream is closed by
    // the trailers, exactly as the client path does on the request side.
    let block_len = o - block_start;
    // END_STREAM deliberately FALSE — DATA and trailers still follow.
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);

    // ── DATA (the echoed LPM) ──
    let data_hdr_off = o;
    let data_off = data_hdr_off + h2w::FRAME_HEADER_LEN;

    // Trailer block is small and fixed-shape; reserve it before committing to
    // the body so a body that only just fits cannot leave the stream open with
    // no way to close it.
    const TRAILER_RESERVE: usize = 64;
    if data_off + body.len() + h2w::FRAME_HEADER_LEN + TRAILER_RESERVE > cap {
        let n = h2w::write_rst_stream(buf, stream_id, h2w::ERR_INTERNAL_ERROR);
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = n as u16;
            cur.send_offset = 0;
        }
        return;
    }

    h2w::write_data_frame_header(buf.add(data_hdr_off), body.len(), stream_id, false);
    if !body.is_empty() {
        core::ptr::copy_nonoverlapping(body.as_ptr(), buf.add(data_off), body.len());
    }
    o = data_off + body.len();

    // ── Trailing HEADERS (grpc-status) ──
    let tr_hdr_off = o;
    let tr_start = tr_hdr_off + h2w::FRAME_HEADER_LEN;
    let mut t = tr_start;
    let mut code = [0u8; 11];
    let cn = super::super::fmt_u32_raw(code.as_mut_ptr(), grpc_status as u32);
    t += super::super::wire::hpack::encode_header(
        buf.add(t),
        cap - t,
        b"grpc-status",
        core::slice::from_raw_parts(code.as_ptr(), cn),
    );
    let tr_len = t - tr_start;
    // END_STREAM lives HERE, on the trailers — this is what closes the RPC.
    h2w::write_headers_frame_header(buf.add(tr_hdr_off), tr_len, stream_id, true, true);

    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = t as u16;
        cur.send_offset = 0;
    }
}

// ── Connection-level error path ───────────────────────────────────────────

unsafe fn queue_goaway(s: &mut HttpState, code: u32) {
    let n = h2w::write_goaway(cur_send_buf_mut_ptr(s), cur_h2(s).last_stream_id, code);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    cur_h2_mut(s).sub = Sub::Closing;
}

// ── Outbound CMD_SEND helper (mirrors server.rs::net_send) ───────────────

unsafe fn net_send(s: &mut HttpState, data: *const u8, len: usize) -> i32 {
    if s.net_out_chan < 0 {
        return 0;
    }
    let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 1;
    let to_send = len.min(max_data);
    if to_send == 0 {
        return 0;
    }

    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let conn_id = cur_conn_id(s);
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 1 + to_send;
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    *scratch.add(3) = conn_id;
    core::ptr::copy_nonoverlapping(data, scratch.add(4), to_send);
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written >= total as i32 {
        to_send as i32
    } else {
        0
    }
}

#[inline(always)]
unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

/// Byte-by-byte slice equality using raw-pointer iteration. Slice
/// indexing in -O builds can be lifted to a memcmp call which the PIC
/// loader can't satisfy; raw-pointer arithmetic stays inline.
#[inline]
unsafe fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    let ap = a.as_ptr();
    let bp = b.as_ptr();
    let mut i = 0usize;
    while i < n {
        if *ap.add(i) != *bp.add(i) {
            return false;
        }
        i += 1;
    }
    true
}
