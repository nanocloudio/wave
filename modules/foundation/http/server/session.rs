//! Session anchor: the SessionCtrlV1 half of the fan-out WebSocket path.
//!
//! `http` already owns the client-visible transport for a WebSocket and
//! already hands each frame across the connection-addressed `WsFrame` seam
//! to whatever module owns the application protocol. That module is a
//! Fluxor *session worker* in everything but name; this file supplies the
//! name — the control plane by which the anchor attaches a session to a
//! worker, drains it, relays its opaque export to a standby, resumes it
//! there and detaches the old worker — so the worker can be replaced during
//! maintenance while the client's connection stays open
//! (`../fluxor/docs/architecture/protocol_surfaces.md` §Continuity Classes,
//! class `edge_anchored`; `docs/architecture/session_continuity.md`).
//!
//! # What moves and what does not
//!
//! Nothing this module holds for a connection moves. Close state, ping/pong
//! timing, outbound fragmentation and the admission outcome are anchor
//! state, and under `edge_anchored` the anchor never moves. What moves is
//! whatever the worker on the far side of `ws_in` has accumulated for the
//! connection, and that blob is opaque here: it is relayed verbatim.
//!
//! # Delivery cursors
//!
//! The one part of the export this module reads. `CMD_SC_EXPORT_BEGIN`
//! carries the envelope bytes the blob accounts for inbound and the
//! envelope bytes it has emitted outbound; the anchor keeps the same pair
//! per session (`sc_forwarded` advances when an envelope is accepted onto
//! the worker's data channel, `sc_relayed` when one from the worker is
//! queued onto the connection's send path — never on read, because an
//! envelope read and written back for a busy target is read again). At
//! export both pairs must agree, or the blob and the client have seen
//! different prefixes of the session and the handoff is refused with the
//! session left on the exporting worker (`cursors_admit`).
//!
//! # The hold
//!
//! A session being swapped forwards nothing: its frames stay in the slot's
//! receive buffer and the transport window closes behind them. Nothing is
//! dropped and no second buffer exists. A full receive buffer stalls the
//! inbound demux for every connection on the instance, so all of a
//! worker's sessions are swapped under one window, the window is bounded
//! by `session_drain_ms`, and on expiry the swap is abandoned with every
//! session returned to the old worker. A held session is exempt from the
//! idle policy for as long as the hold lasts, and the time it took is
//! credited to the clock when the hold lifts, so the silence a swap caused
//! is never counted against the client. `session_drain_ms` is validated at
//! init to sit under half the idle limit, so a swap that completes cannot
//! expire either side's keepalive. A session whose return path also goes
//! quiet is failed instead, and a failed session's connection closes.
//!
//! # Old output before new
//!
//! Envelopes on two channels have no order between them. Before the
//! exporting worker's control channel is read during a swap, its data
//! channel must poll empty: everything it emitted before `DRAINED` has
//! then been queued toward the client and counted, and after `DRAINED` it
//! emits nothing more for the session. The new worker cannot emit until
//! `RESUME`, so nothing of its output can overtake.
//!
//! # Identity
//!
//! `WsFrame` envelopes name the anchor's `conn_id`, which stays constant
//! across a swap because the connection does, but is a reused `u16`.
//! `session_id` is minted as `[anchor_id:8][conn_id:4 BE][generation:4 BE]`
//! with a server-wide monotonic generation: opaque to Fluxor, unique per
//! attach, and enough for a worker to recover the connection it is serving
//! from the identity alone.

use super::super::abi::contracts::net::session_ctrl as sc;
use super::super::abi::SyscallTable;
use super::routes::HANDLER_WEBSOCKET_FANOUT;
use super::{
    cur_slot, cur_slot_mut, dev_channel_port, dev_millis, dev_self_index, log, net_read_frame,
    net_write_frame, ConnSlot, HttpState, TableConsumer, TableSink, MAX_CONCURRENT_CONNS,
    MAX_DYN_PREFIX, NET_FRAME_HDR, POLL_IN,
};

// The handoff core: cursor encoding and the admission rule. Mounted for
// those alone — the chunk walk belongs to workers.
mod handoff {
    include!("../../../../target/fluxor/fluxor-abi/sdk/cores/session_handoff.rs");
}
pub(crate) use handoff::{cursors_admit, SessionCursors, HANDOFF_OK};

// ── Ports ─────────────────────────────────────────────────────────────────

/// Worker slots: 0 is the pair the existing `ws_out` / `ws_in` serve, 1 the
/// standby pair (`ws2_out` / `ws2_in`).
pub(crate) const SC_WORKERS: usize = 2;
/// `ctrl_in` / `ctrl2_in` (input indices), `ctrl_out` / `ctrl2_out` (output).
pub(crate) const CTRL_IN_PORT: [u8; SC_WORKERS] = [10, 11];
pub(crate) const CTRL_OUT_PORT: [u8; SC_WORKERS] = [3, 10];
/// The standby data pair.
pub(crate) const WS2_IN_PORT: u8 = 12;
pub(crate) const WS2_OUT_PORT: u8 = 11;
/// The input half of the swap-trigger self-edge. The graph wires
/// `sessions_sink` (out[12]) to it; this module only ever names the input,
/// because what it hands the store is the channel the store must write to.
pub(crate) const SESSIONS_IN_PORT: u8 = 13;

/// `sc_worker` when a slot carries no session.
pub(crate) const NO_WORKER: u8 = 0xFF;

// ── Per-session phase (`ConnSlot::sc_phase`) ──────────────────────────────

/// Not a session: a plain fan-out connection, or an instance with no anchor
/// control channel wired.
pub const SP_NONE: u8 = 0;
/// Minted and attached; waiting for `MSG_SC_ATTACHED`. Frames are held.
pub const SP_ATTACH_WAIT: u8 = 1;
/// Serving on `sc_worker`.
pub const SP_ACTIVE: u8 = 2;
/// `DRAIN` sent to `sc_worker`; waiting for `DRAINED` and the export.
pub const SP_DRAIN_WAIT: u8 = 3;
/// Export relayed to the standby; waiting for `IMPORT_END`.
pub const SP_IMPORT_WAIT: u8 = 4;
/// `RESUME` at epoch + 1 sent to the standby; waiting for `RESUMED`.
pub const SP_RESUME_WAIT: u8 = 5;
/// Refused or timed out: `RESUME` at the current epoch sent back to
/// `sc_worker`; waiting for its `RESUMED` before the hold is released.
pub const SP_RESUME_BACK_WAIT: u8 = 6;
/// `ATTACH` could not be written (control channel full); retried each step.
pub const SP_ATTACH_PENDING: u8 = 7;
/// The worker refused the session or the return path failed. Each
/// generation closes `1011` from its own step: the h1 connection, the h2
/// tunnel's stream, the h3 tunnel's stream.
pub const SP_FAILED: u8 = 8;

/// Control frames read per worker per step. Bounded so a worker that keeps
/// its channel full cannot own the tick.
const CTRL_BATCH: usize = 8;
/// Largest SessionCtrlV1 *payload* this anchor reads or relays; every read
/// and write is sized at this plus `NET_FRAME_HDR`, which is the `max_record`
/// the control ports declare. The export chunks a worker emits are capped by
/// the worker's own chunk size.
pub(crate) const CTRL_FRAME_MAX: usize = 1024;
/// `dev_mon_session` scratch.
const MON_BUF_SIZE: usize = 192;
/// Default `session_drain_ms`.
pub(crate) const DEFAULT_DRAIN_MS: u32 = 500;
/// Default anchor identity when the graph does not name one. Distinctive
/// enough to read on a `MON_SESSION` line; a deployment with more than one
/// anchor sets `anchor_id`.
const DEFAULT_ANCHOR_ID: [u8; sc::ANCHOR_ID_BYTES] = *b"WAVEHTTP";

/// Refusal of the WebSocket by a worker, reported to the client as an
/// RFC 6455 `1011 Internal Error`.
pub(crate) const WS_CLOSE_SESSION_FAILED: u16 = 1011;

// ── The swap trigger table ────────────────────────────────────────────────

/// The `sessions_prefix` subscription: one row, `<prefix>active = <0|1>`,
/// naming the worker new sessions should attach to. A change away from
/// the current active worker requests a swap; the anchor does the rest.
#[repr(C)]
pub(crate) struct DesiredWorker {
    pub(crate) live: u8,
    pub(crate) shadow: u8,
    /// Non-zero once a row has been applied at all (so a default of 0 does
    /// not read as "swap to worker 0" on subscribe).
    pub(crate) seen: u8,
    _pad: u8,
}

impl DesiredWorker {
    pub(crate) const fn new() -> Self {
        Self {
            live: 0,
            shadow: 0,
            seen: 0,
            _pad: 0,
        }
    }
}

impl TableSink for DesiredWorker {
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool) {
        let seg = match key.iter().rposition(|&b| b == b'/') {
            Some(i) => &key[i + 1..],
            None => key,
        };
        if seg != b"active" {
            return;
        }
        let w = super::dyn_u32(value);
        let w = if w >= SC_WORKERS as u32 { 0 } else { w as u8 };
        if shadow {
            self.shadow = w;
        } else {
            self.live = w;
            self.seen = 1;
        }
    }
    fn remove(&mut self, _key: &[u8], _shadow: bool) {}
    fn clear_shadow(&mut self) {}
    fn swap_shadow(&mut self) {
        self.live = self.shadow;
        self.seen = 1;
    }
}

// ── Anchor state ──────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct SessionAnchor {
    pub(crate) ctrl_in: [i32; SC_WORKERS],
    pub(crate) ctrl_out: [i32; SC_WORKERS],
    /// Worker → anchor envelopes (`ws_in`, `ws2_in`).
    pub(crate) data_in: [i32; SC_WORKERS],
    /// Anchor → worker envelopes (`ws_out`, `ws2_out`).
    pub(crate) data_out: [i32; SC_WORKERS],
    pub(crate) anchor_id: [u8; sc::ANCHOR_ID_BYTES],
    /// A configured `anchor_id` that was not sixteen hex characters. Kept so
    /// the instance can refuse to load rather than mint every session under
    /// the default identity because of a typo.
    pub(crate) anchor_id_bad: u8,
    /// The worker new sessions attach to.
    pub(crate) active_w: u8,
    pub(crate) swap_active: u8,
    pub(crate) swap_from: u8,
    pub(crate) swap_to: u8,
    /// Cached `dev_self_index`; `0xFF` until resolved.
    pub(crate) self_idx: u8,
    /// A swap has been asked for (parameter trigger or store row).
    pub(crate) swap_requested: u8,
    _pad0: [u8; 2],
    pub(crate) swap_deadline_ms: u64,
    /// `session_drain_ms`: the deadline every `DRAIN` carries and the bound
    /// on the hold.
    pub(crate) drain_ms: u32,
    /// `handoff_after_frames`: swap the workers every N forwarded envelopes
    /// (0 = never). The trigger the gates use.
    pub(crate) handoff_after_frames: u32,
    pub(crate) frames_since_swap: u32,
    /// Server-wide session generation; `conn_id` is reused, this is not.
    pub(crate) gen_next: u32,

    // Telemetry counters, exported as metric ids 24-28 (`manifest.toml`).
    pub(crate) sessions_attached: u32,
    pub(crate) sessions_moved: u32,
    pub(crate) swaps_completed: u32,
    pub(crate) swaps_refused: u32,
    /// Envelopes from a worker that does not own the session they name.
    pub(crate) envelopes_misowned: u32,

    // Swap-trigger subscription (`sessions_prefix`). Off when the prefix is
    // empty, like the route and listener tables.
    pub(crate) sessions_prefix: [u8; MAX_DYN_PREFIX],
    pub(crate) sessions_prefix_len: u16,
    _pad1: [u8; 2],
    pub(crate) sessions_sink: i32,
    pub(crate) stc: TableConsumer,
    pub(crate) desired: DesiredWorker,

    ctrl_buf: [u8; CTRL_FRAME_MAX + NET_FRAME_HDR],
    relay_buf: [u8; CTRL_FRAME_MAX + NET_FRAME_HDR],
    mon_buf: [u8; MON_BUF_SIZE],
}

impl SessionAnchor {
    pub(crate) fn init(&mut self) {
        self.ctrl_in = [-1; SC_WORKERS];
        self.ctrl_out = [-1; SC_WORKERS];
        self.data_in = [-1; SC_WORKERS];
        self.data_out = [-1; SC_WORKERS];
        self.anchor_id = DEFAULT_ANCHOR_ID;
        self.anchor_id_bad = 0;
        self.active_w = 0;
        self.swap_active = 0;
        self.swap_from = 0;
        self.swap_to = 0;
        self.self_idx = 0xFF;
        self.swap_requested = 0;
        self.swap_deadline_ms = 0;
        self.drain_ms = DEFAULT_DRAIN_MS;
        self.handoff_after_frames = 0;
        self.frames_since_swap = 0;
        self.gen_next = 0;
        self.sessions_attached = 0;
        self.sessions_moved = 0;
        self.swaps_completed = 0;
        self.swaps_refused = 0;
        self.envelopes_misowned = 0;
        self.sessions_prefix_len = 0;
        self.sessions_sink = -1;
        self.desired = DesiredWorker::new();
    }

    /// The anchor control channel to worker 0 is wired: sessions on this
    /// instance are anchored.
    #[inline]
    pub(crate) fn anchored(&self) -> bool {
        self.ctrl_out[0] >= 0 && self.ctrl_in[0] >= 0
    }

    /// A second worker is fully wired, so a swap has somewhere to go.
    #[inline]
    pub(crate) fn has_standby(&self) -> bool {
        self.ctrl_out[1] >= 0
            && self.ctrl_in[1] >= 0
            && self.data_out[1] >= 0
            && self.data_in[1] >= 0
    }
}

// ── Init and validation ───────────────────────────────────────────────────

/// Resolve the anchor ports. Worker 0's data pair IS the existing `ws_out`
/// / `ws_in`, resolved by the caller first.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn resolve_ports(s: &mut HttpState) {
    let sys = &*s.syscalls;
    let a = &mut s.server.sc;
    a.ctrl_in[0] = dev_channel_port(sys, 0, CTRL_IN_PORT[0]);
    a.ctrl_in[1] = dev_channel_port(sys, 0, CTRL_IN_PORT[1]);
    a.ctrl_out[0] = dev_channel_port(sys, 1, CTRL_OUT_PORT[0]);
    a.ctrl_out[1] = dev_channel_port(sys, 1, CTRL_OUT_PORT[1]);
    a.data_in[0] = s.server.ws_in_chan;
    a.data_out[0] = s.server.ws_out_chan;
    a.data_in[1] = dev_channel_port(sys, 0, WS2_IN_PORT);
    a.data_out[1] = dev_channel_port(sys, 1, WS2_OUT_PORT);
}

/// The composition rules an anchored instance must meet, checked once at
/// construction so a graph that cannot anchor fails to load rather than
/// serving sessions it cannot move. Returns 0, or the `module_new` error.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn validate(s: &mut HttpState) -> i32 {
    // Checked before the anchor test: a graph that names an identity meant
    // to name one, whether or not it wired the control ports.
    if s.server.sc.anchor_id_bad != 0 {
        log(s, b"[http] anchor_id must be 16 hex characters");
        return -10;
    }
    if !s.server.sc.anchored() {
        return 0;
    }
    // Single-client fan-out closes every other fan-out connection when a
    // new one arrives; that is displacement, not a session.
    if s.server.ws_multi_client == 0 {
        log(s, b"[http] session anchor needs ws_multi_client=1");
        return -7;
    }
    // Retention replay hands one connection's envelopes to the next. A
    // route that replays cannot be anchored, and its presence on an
    // anchored instance means the graph asked for two incompatible things.
    for i in 0..s.server.route_count as usize {
        if s.server.routes[i].handler == HANDLER_WEBSOCKET_FANOUT {
            log(s, b"[http] session anchor refuses a retain-replay route");
            return -8;
        }
    }
    // The hold suspends the idle clock, but the CLIENT's keepalive is not
    // ours to suspend: the window must end before a client that pings at
    // half the idle limit could conclude the server is gone.
    let idle = s.server.ws_idle_ms;
    if idle != 0 && (s.server.sc.drain_ms as u64).saturating_mul(2) >= idle as u64 {
        log(s, b"[http] session_drain_ms must be under half ws_idle_ms");
        return -9;
    }
    0
}

/// Param setter for `anchor_id` (16 hex chars → 8 bytes). Anything else is
/// recorded as malformed and refuses the instance at `validate`, because a
/// mistyped identity would otherwise be indistinguishable from not setting
/// one — every session minted under the default, on every anchor.
///
/// # Safety
/// `d` points at `len` readable bytes.
pub(crate) unsafe fn set_anchor_id(s: &mut HttpState, d: *const u8, len: usize) {
    // An absent parameter reaches the setter as an empty value: that is not
    // a malformed identity, it is no identity, and the default stands.
    if len == 0 {
        return;
    }
    if len != sc::ANCHOR_ID_BYTES * 2 {
        s.server.sc.anchor_id_bad = 1;
        return;
    }
    let mut id = [0u8; sc::ANCHOR_ID_BYTES];
    for (i, b) in id.iter_mut().enumerate() {
        let hi = super::hex_val(*d.add(i * 2));
        let lo = super::hex_val(*d.add(i * 2 + 1));
        match (hi, lo) {
            (Some(h), Some(l)) => *b = (h << 4) | l,
            _ => {
                s.server.sc.anchor_id_bad = 1;
                return;
            }
        }
    }
    s.server.sc.anchor_id = id;
    s.server.sc.anchor_id_bad = 0;
}

/// Param setter for `session_drain_ms`.
pub(crate) fn set_drain_ms(s: &mut HttpState, v: u32) {
    s.server.sc.drain_ms = v;
}

/// Param setter for `handoff_after_frames`.
pub(crate) fn set_handoff_after_frames(s: &mut HttpState, v: u32) {
    s.server.sc.handoff_after_frames = v;
}

/// The anchor's counters for the telemetry emitter:
/// `[attached, moved, swaps_completed, swaps_refused, misowned]`.
pub(crate) fn metrics(s: &HttpState) -> [u32; 5] {
    let a = &s.server.sc;
    [
        a.sessions_attached,
        a.sessions_moved,
        a.swaps_completed,
        a.swaps_refused,
        a.envelopes_misowned,
    ]
}

/// Param setter for `sessions_prefix`.
///
/// # Safety
/// `d` points at `len` readable bytes.
pub(crate) unsafe fn set_sessions_prefix(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(MAX_DYN_PREFIX);
    let dst = s.server.sc.sessions_prefix.as_mut_ptr();
    let mut i = 0;
    while i < n {
        *dst.add(i) = *d.add(i);
        i += 1;
    }
    s.server.sc.sessions_prefix_len = n as u16;
}

// ── Slot queries used by the fan-out path ─────────────────────────────────

/// Frames from the current slot may cross the seam: not a session, or a
/// session that is serving. Anything else is held in the receive buffer.
#[inline]
pub(crate) unsafe fn cur_may_forward(s: &HttpState) -> bool {
    match cur_slot(s) {
        Some(c) => c.sc_phase == SP_NONE || c.sc_phase == SP_ACTIVE,
        None => false,
    }
}

/// The data channel the current slot's frames go to.
#[inline]
pub(crate) unsafe fn cur_data_out(s: &HttpState) -> i32 {
    match cur_slot(s) {
        Some(c) if c.sc_phase != SP_NONE && (c.sc_worker as usize) < SC_WORKERS => {
            s.server.sc.data_out[c.sc_worker as usize]
        }
        _ => s.server.ws_out_chan,
    }
}

/// An envelope of `total` bytes was accepted onto the worker's channel.
#[inline]
pub(crate) unsafe fn cur_note_forwarded(s: &mut HttpState, total: usize) {
    let anchored = cur_slot(s).is_some_and(|c| c.sc_phase != SP_NONE);
    if !anchored {
        return;
    }
    if let Some(c) = cur_slot_mut(s) {
        c.sc_forwarded = c.sc_forwarded.wrapping_add(total as u64);
    }
    s.server.sc.frames_since_swap = s.server.sc.frames_since_swap.wrapping_add(1);
}

/// Whether worker `w` may speak for slot `idx`: a plain fan-out slot is
/// served by worker 0's channel only; a session by the worker that owns it.
pub(crate) unsafe fn envelope_admitted(s: &mut HttpState, idx: usize, w: usize) -> bool {
    let slot = &*s.server.slots.as_ptr().add(idx);
    let ok = if slot.sc_phase == SP_NONE {
        w == 0
    } else {
        slot.sc_worker as usize == w
            && slot.sc_phase != SP_ATTACH_WAIT
            && slot.sc_phase != SP_ATTACH_PENDING
    };
    if !ok {
        s.server.sc.envelopes_misowned = s.server.sc.envelopes_misowned.wrapping_add(1);
    }
    ok
}

/// An envelope of `total` bytes from the owning worker was queued onto
/// slot `idx`'s send path.
#[inline]
pub(crate) unsafe fn note_relayed(s: &mut HttpState, idx: usize, total: usize) {
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    if slot.sc_phase != SP_NONE {
        slot.sc_relayed = slot.sc_relayed.wrapping_add(total as u64);
    }
}

/// The current slot is inside a swap window, so the idle policy skips it.
/// The elapsed time is credited to the clock by `release_hold` on the way
/// out; a session that fails instead is closed, not credited.
#[inline]
pub(crate) unsafe fn cur_is_held(s: &HttpState) -> bool {
    cur_slot(s).is_some_and(|c| {
        matches!(
            c.sc_phase,
            SP_DRAIN_WAIT | SP_IMPORT_WAIT | SP_RESUME_WAIT | SP_RESUME_BACK_WAIT
        )
    })
}

/// The current slot's session failed: no worker will serve it, so the
/// connection or tunnel carrying it must close `1011`.
#[inline]
pub(crate) unsafe fn cur_failed(s: &HttpState) -> bool {
    cur_slot(s).is_some_and(|c| c.sc_phase == SP_FAILED)
}

// ── Lifecycle hooks ───────────────────────────────────────────────────────

/// The current slot's upgrade is committed on a fan-out route: attach it.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn on_ws_open(s: &mut HttpState) {
    if !s.server.sc.anchored() {
        return;
    }
    let Some(idx) = super::current_slot_index(s) else {
        return;
    };
    let conn = super::cur_conn_id(s);
    let gen = s.server.sc.gen_next;
    s.server.sc.gen_next = gen.wrapping_add(1);
    let w = s.server.sc.active_w;
    let sid = mint_session_id(&s.server.sc.anchor_id, conn as u32, gen);
    {
        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
        slot.sc_session_id = sid;
        slot.sc_epoch = 1;
        slot.sc_forwarded = 0;
        slot.sc_relayed = 0;
        slot.sc_hold_start_ms = 0;
        slot.sc_worker = w;
        slot.sc_phase = SP_ATTACH_PENDING;
    }
    try_attach(s, idx);
}

/// The identity this anchor mints: `[anchor_id:8][conn_id:4 BE][gen:4 BE]`.
/// This module OWNS the layout (`session_ctrl.rs` §Many sessions, one
/// control channel), which is why the two big-endian fields are composed
/// here and nowhere else.
pub(crate) fn mint_session_id(
    anchor_id: &[u8; sc::ANCHOR_ID_BYTES],
    conn: u32,
    gen: u32,
) -> [u8; sc::SESSION_ID_BYTES] {
    let mut sid = [0u8; sc::SESSION_ID_BYTES];
    sid[..sc::ANCHOR_ID_BYTES].copy_from_slice(anchor_id);
    sid[8..12].copy_from_slice(&conn.to_be_bytes());
    sid[12..16].copy_from_slice(&gen.to_be_bytes());
    sid
}

/// Send `ATTACH` for slot `idx`; leaves it pending when the channel is full.
unsafe fn try_attach(s: &mut HttpState, idx: usize) {
    let (sid, epoch, w) = {
        let slot = &*s.server.slots.as_ptr().add(idx);
        (slot.sc_session_id, slot.sc_epoch, slot.sc_worker as usize)
    };
    let mut payload = [0u8; sc::ATTACH_PAYLOAD_LEN];
    let anchor = s.server.sc.anchor_id;
    sc::put_attach(
        &mut payload,
        &sid,
        &anchor,
        epoch,
        sc::CC_EDGE_ANCHORED,
        &[0u8; sc::WORKER_ID_BYTES],
    );
    if sc_write(s, w, sc::CMD_SC_ATTACH, &payload) {
        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
        slot.sc_phase = SP_ATTACH_WAIT;
        mon(s, idx, super::super::MON_EV_ATTACH_REQ, b"", b"");
    }
}

/// Slot `idx` is closing (every close path converges here): detach the
/// session from whichever workers hold any of it.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn on_slot_close(s: &mut HttpState, idx: usize) {
    let (phase, w) = {
        let slot = &*s.server.slots.as_ptr().add(idx);
        (slot.sc_phase, slot.sc_worker as usize)
    };
    if phase == SP_NONE {
        return;
    }
    if matches!(
        phase,
        SP_ATTACH_WAIT
            | SP_ACTIVE
            | SP_DRAIN_WAIT
            | SP_IMPORT_WAIT
            | SP_RESUME_WAIT
            | SP_RESUME_BACK_WAIT
            | SP_FAILED
    ) && w < SC_WORKERS
    {
        send_detach(s, idx, w, sc::DETACH_CLIENT_GONE);
    }
    if matches!(phase, SP_IMPORT_WAIT | SP_RESUME_WAIT) {
        let to = s.server.sc.swap_to as usize;
        send_detach(s, idx, to, sc::DETACH_CLIENT_GONE);
    }
    mon(s, idx, super::super::MON_EV_DETACH_REQ, b"client_gone", b"");
    {
        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
        slot.sc_phase = SP_NONE;
        slot.sc_worker = NO_WORKER;
    }
    check_swap_done(s);
}

/// An h2 tunnel ended while its connection stays open (a CLOSE or a reset):
/// detach the session it was. The other two generations reach `on_slot_close`
/// on their own — closing an upgraded h1 connection closes its slot, and an
/// h3 tunnel's seat is a slot that is freed when the tunnel ends.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn on_ws_end(s: &mut HttpState) {
    if let Some(idx) = super::current_slot_index(s) {
        on_slot_close(s, idx);
    }
}

// ── The per-step pump ─────────────────────────────────────────────────────

/// One step of the anchor: the trigger subscription, pending attaches,
/// control frames from each worker, the deadline, and the trigger itself.
///
/// # Safety
/// Single-threaded module step; `s` is the live module state.
pub(crate) unsafe fn pump(s: &mut HttpState) {
    if !s.server.sc.anchored() {
        return;
    }
    pump_trigger_table(s);

    for idx in 0..MAX_CONCURRENT_CONNS {
        if (*s.server.slots.as_ptr().add(idx)).sc_phase == SP_ATTACH_PENDING {
            try_attach(s, idx);
        }
    }

    let sys = &*s.syscalls;
    for w in 0..SC_WORKERS {
        let chan = s.server.sc.ctrl_in[w];
        if chan < 0 {
            continue;
        }
        // Old output before new: the exporting worker's control channel is
        // read only once its data channel has been drained to empty.
        if s.server.sc.swap_active != 0 && w == s.server.sc.swap_from as usize {
            let d = s.server.sc.data_in[w];
            if d >= 0 {
                let poll = (sys.channel_poll)(d, POLL_IN);
                if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                    continue;
                }
            }
        }
        for _ in 0..CTRL_BATCH {
            let poll = (sys.channel_poll)(chan, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                break;
            }
            let buf = s.server.sc.ctrl_buf.as_mut_ptr();
            let (msg, len) = net_read_frame(sys, chan, buf, CTRL_FRAME_MAX + NET_FRAME_HDR);
            if msg == 0 {
                break;
            }
            dispatch_ctrl(s, w, msg, len);
        }
    }

    enforce_deadlines(s);
    maybe_start_swap(s);
}

/// Pump the `sessions_prefix` subscription and turn a changed `active` row
/// into a swap request.
unsafe fn pump_trigger_table(s: &mut HttpState) {
    let prefix_len = s.server.sc.sessions_prefix_len as usize;
    if prefix_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.server.sc.sessions_sink < 0 {
        s.server.sc.sessions_sink = dev_channel_port(sys, 0, SESSIONS_IN_PORT);
        if s.server.sc.sessions_sink < 0 {
            return;
        }
    }
    let sink = s.server.sc.sessions_sink;
    {
        let a = &mut s.server.sc;
        let prefix = &a.sessions_prefix[..prefix_len];
        let scratch = &mut s.server.routes_scratch;
        a.stc.step(sys, sink, prefix, scratch, &mut a.desired);
    }
    let a = &mut s.server.sc;
    if a.desired.seen != 0 && a.desired.live != a.active_w && a.swap_active == 0 {
        a.swap_requested = 1;
    }
}

/// Start a swap when one is due and possible: every session on the active
/// worker is drained under one window, and new sessions attach to the
/// standby from here on.
unsafe fn maybe_start_swap(s: &mut HttpState) {
    let a = &s.server.sc;
    if a.swap_active != 0 {
        return;
    }
    let due = a.swap_requested != 0
        || (a.handoff_after_frames != 0 && a.frames_since_swap >= a.handoff_after_frames);
    if !due {
        return;
    }
    if !a.has_standby() {
        // A trigger with nowhere to go is refused, once per request, rather
        // than re-logged every step.
        if a.swap_requested != 0 {
            s.server.sc.swap_requested = 0;
            log(s, b"[http] session swap refused: no standby worker wired");
        }
        s.server.sc.frames_since_swap = 0;
        return;
    }
    let from = s.server.sc.active_w;
    let to = 1 - from;
    let now = s.server.now_ms;
    s.server.sc.swap_from = from;
    s.server.sc.swap_to = to;
    s.server.sc.swap_active = 1;
    s.server.sc.swap_requested = 0;
    s.server.sc.frames_since_swap = 0;
    s.server.sc.swap_deadline_ms = now.wrapping_add(s.server.sc.drain_ms as u64);
    s.server.sc.active_w = to;
    let mut drained = 0u32;
    for idx in 0..MAX_CONCURRENT_CONNS {
        let (phase, w) = {
            let slot = &*s.server.slots.as_ptr().add(idx);
            (slot.sc_phase, slot.sc_worker)
        };
        if phase != SP_ACTIVE || w != from {
            continue;
        }
        if send_drain(s, idx, from as usize) {
            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
            slot.sc_phase = SP_DRAIN_WAIT;
            slot.sc_hold_start_ms = now;
            drained += 1;
            mon(s, idx, super::super::MON_EV_EXPORT_REQ, b"", b"");
        }
    }
    log(s, b"[http] session swap started");
    if drained == 0 {
        check_swap_done(s);
    }
}

/// The swap window has closed on sessions still short of `RESUMED`, or a
/// return path has gone quiet: every such session goes back to the old
/// worker, or is failed if the old worker will not take it.
unsafe fn enforce_deadlines(s: &mut HttpState) {
    let now = s.server.now_ms;
    let drain_ms = s.server.sc.drain_ms as u64;
    if s.server.sc.swap_active != 0 && now >= s.server.sc.swap_deadline_ms {
        for idx in 0..MAX_CONCURRENT_CONNS {
            let phase = (*s.server.slots.as_ptr().add(idx)).sc_phase;
            if matches!(phase, SP_DRAIN_WAIT | SP_IMPORT_WAIT | SP_RESUME_WAIT) {
                refuse_session(s, idx, b"drain_timeout");
            }
        }
        log(s, b"[http] session swap abandoned: deadline");
        check_swap_done(s);
    }
    for idx in 0..MAX_CONCURRENT_CONNS {
        let (phase, start) = {
            let slot = &*s.server.slots.as_ptr().add(idx);
            (slot.sc_phase, slot.sc_hold_start_ms)
        };
        // A hold is measured from the DRAIN, and a swap may use a whole
        // window before it is refused, so the return path is given two more
        // rather than one: a worker that is merely slow to take its session
        // back is not failed at the instant the swap deadline fires.
        if phase == SP_RESUME_BACK_WAIT && now.saturating_sub(start) > drain_ms.saturating_mul(3) {
            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
            slot.sc_phase = SP_FAILED;
            mon(s, idx, super::super::MON_EV_ERROR, b"", b"not_ready");
        }
    }
}

/// No session remains inside the swap: record it.
unsafe fn check_swap_done(s: &mut HttpState) {
    if s.server.sc.swap_active == 0 {
        return;
    }
    for idx in 0..MAX_CONCURRENT_CONNS {
        let phase = (*s.server.slots.as_ptr().add(idx)).sc_phase;
        if matches!(phase, SP_DRAIN_WAIT | SP_IMPORT_WAIT | SP_RESUME_WAIT) {
            return;
        }
    }
    s.server.sc.swap_active = 0;
    s.server.sc.swaps_completed = s.server.sc.swaps_completed.wrapping_add(1);
    log(s, b"[http] session swap done");
}

/// Leave the session on `sc_worker`: detach the standby if it holds any of
/// it, and return the exporting worker to service with `RESUME` at the
/// current epoch (`session_ctrl.rs` §Delivery cursors).
unsafe fn refuse_session(s: &mut HttpState, idx: usize, status: &[u8]) {
    let (phase, w) = {
        let slot = &*s.server.slots.as_ptr().add(idx);
        (slot.sc_phase, slot.sc_worker as usize)
    };
    if matches!(phase, SP_IMPORT_WAIT | SP_RESUME_WAIT) {
        let to = s.server.sc.swap_to as usize;
        send_detach(s, idx, to, sc::DETACH_NORMAL);
    }
    s.server.sc.swaps_refused = s.server.sc.swaps_refused.wrapping_add(1);
    mon(s, idx, super::super::MON_EV_ERROR, b"", status);
    let epoch = (*s.server.slots.as_ptr().add(idx)).sc_epoch;
    let now = s.server.now_ms;
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot.sc_phase = SP_RESUME_BACK_WAIT;
    // The hold began at the DRAIN, not here: the whole window is what the
    // idle clock is owed when the session is finally released.
    if slot.sc_hold_start_ms == 0 {
        slot.sc_hold_start_ms = now;
    }
    if send_resume(s, idx, w, epoch) {
        mon(s, idx, super::super::MON_EV_RESUME_REQ, b"", b"");
    }
    // A refused session is no longer inside the swap; the swap may be over.
    check_swap_done(s);
}

/// The hold on slot `idx` ends: the time it spent held is charged to the
/// idle clock as if the peer had been heard from, so a client that was
/// silent only because the anchor was not forwarding is not closed as idle.
unsafe fn release_hold(s: &mut HttpState, idx: usize) {
    let now = s.server.now_ms;
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    if slot.sc_hold_start_ms != 0 {
        let held = now.saturating_sub(slot.sc_hold_start_ms);
        slot.inbound_ms = slot.inbound_ms.wrapping_add(held);
        if slot.ws_ping_ms != 0 {
            slot.ws_ping_ms = slot.ws_ping_ms.wrapping_add(held);
        }
        slot.sc_hold_start_ms = 0;
    }
}

// ── Control-frame dispatch ────────────────────────────────────────────────

/// Find the slot carrying `sid`.
unsafe fn slot_for_session(s: &HttpState, sid: &[u8]) -> Option<usize> {
    for idx in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(idx);
        if slot.sc_phase != SP_NONE && slot.sc_session_id[..] == sid[..sc::SESSION_ID_BYTES] {
            return Some(idx);
        }
    }
    None
}

unsafe fn dispatch_ctrl(s: &mut HttpState, w: usize, msg: u8, payload_len: usize) {
    if payload_len < sc::SESSION_HEADER {
        return;
    }
    let p = s.server.sc.ctrl_buf.as_ptr().add(NET_FRAME_HDR);
    let payload = core::slice::from_raw_parts(p, payload_len);
    let Some(idx) = slot_for_session(s, payload) else {
        // A reply for a session that has already closed — ordinary after
        // a detach, and nothing to act on.
        return;
    };
    let (phase, owner, epoch) = {
        let slot = &*s.server.slots.as_ptr().add(idx);
        (slot.sc_phase, slot.sc_worker as usize, slot.sc_epoch)
    };
    let standby = s.server.sc.swap_to as usize;
    let status_at = sc::SESSION_HEADER;

    match msg {
        sc::MSG_SC_ATTACHED => {
            if phase == SP_ATTACH_WAIT && w == owner && payload_len > status_at {
                if sc::status(payload) == sc::STATUS_OK {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.sc_phase = SP_ACTIVE;
                    s.server.sc.sessions_attached = s.server.sc.sessions_attached.wrapping_add(1);
                } else {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.sc_phase = SP_FAILED;
                    mon(s, idx, super::super::MON_EV_ERROR, b"", b"no_capacity");
                }
            }
        }
        sc::MSG_SC_DRAINED => {
            // The export follows on this channel; nothing to record yet.
        }
        sc::CMD_SC_EXPORT_BEGIN => {
            if phase == SP_DRAIN_WAIT && w == owner && s.server.sc.swap_active != 0 {
                let cursors = sc::export_cursors(payload).and_then(SessionCursors::decode);
                let (fwd, rel) = {
                    let slot = &*s.server.slots.as_ptr().add(idx);
                    (slot.sc_forwarded, slot.sc_relayed)
                };
                let admit = match cursors {
                    Some(c) => cursors_admit(&c, fwd, rel),
                    None => handoff::HANDOFF_CURSOR_MISMATCH,
                };
                if admit != HANDOFF_OK {
                    log(s, b"[http] session export refused: cursors disagree");
                    refuse_session(s, idx, b"cursor_mismatch");
                    return;
                }
                if relay(s, standby, msg, payload_len) {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.sc_phase = SP_IMPORT_WAIT;
                } else {
                    refuse_session(s, idx, b"not_ready");
                }
            }
        }
        sc::CMD_SC_EXPORT_CHUNK | sc::CMD_SC_EXPORT_END => {
            if phase == SP_IMPORT_WAIT && w == owner && !relay(s, standby, msg, payload_len) {
                refuse_session(s, idx, b"not_ready");
            }
        }
        sc::MSG_SC_IMPORT_BEGIN => {
            if phase == SP_IMPORT_WAIT
                && w == standby
                && payload_len > status_at
                && sc::status(payload) != sc::STATUS_OK
            {
                refuse_session(s, idx, b"no_capacity");
            }
        }
        sc::MSG_SC_IMPORT_END => {
            if phase == SP_IMPORT_WAIT && w == standby && payload_len > status_at {
                if sc::status(payload) == sc::STATUS_OK {
                    if send_resume(s, idx, standby, epoch.wrapping_add(1)) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        slot.sc_phase = SP_RESUME_WAIT;
                        mon(s, idx, super::super::MON_EV_RESUME_REQ, b"", b"");
                    } else {
                        refuse_session(s, idx, b"not_ready");
                    }
                } else {
                    refuse_session(s, idx, b"corrupt");
                }
            }
        }
        sc::MSG_SC_RESUMED => {
            let got = sc::epoch(payload);
            if phase == SP_RESUME_WAIT && w == standby && got == epoch.wrapping_add(1) {
                // The swap: epoch advances, the standby owns the session,
                // the old worker is detached, the hold lifts.
                {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.sc_epoch = got;
                    slot.sc_worker = standby as u8;
                    slot.sc_phase = SP_ACTIVE;
                }
                send_detach(s, idx, owner, sc::DETACH_NORMAL);
                release_hold(s, idx);
                s.server.sc.sessions_moved = s.server.sc.sessions_moved.wrapping_add(1);
                mon(s, idx, super::super::MON_EV_EPOCH_BUMP, b"", b"ok");
                mon(s, idx, super::super::MON_EV_RELOCATED, b"", b"ok");
                check_swap_done(s);
            } else if phase == SP_RESUME_BACK_WAIT && w == owner && got == epoch {
                // The refusal's return: the old worker is back in service.
                {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.sc_phase = SP_ACTIVE;
                }
                release_hold(s, idx);
                mon(s, idx, super::super::MON_EV_RESUMED, b"", b"kept");
            }
        }
        sc::MSG_SC_DETACHED => {
            // Nothing to do: a detach is not acknowledged into any phase,
            // and the slot it named was released when it was sent.
        }
        sc::MSG_SC_ERROR => {
            if matches!(phase, SP_DRAIN_WAIT | SP_IMPORT_WAIT | SP_RESUME_WAIT) {
                refuse_session(s, idx, b"error");
            } else if phase == SP_RESUME_BACK_WAIT && w == owner {
                // The exporting worker will not take the session back: it
                // is unrecoverable on either side.
                let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                slot.sc_phase = SP_FAILED;
                mon(s, idx, super::super::MON_EV_ERROR, b"", b"stale_epoch");
            }
        }
        _ => {}
    }
}

// ── Emitters ──────────────────────────────────────────────────────────────

/// Write one SessionCtrlV1 frame to worker `w`. False when the channel is
/// unwired or full.
unsafe fn sc_write(s: &mut HttpState, w: usize, msg: u8, payload: &[u8]) -> bool {
    if w >= SC_WORKERS {
        return false;
    }
    let chan = s.server.sc.ctrl_out[w];
    if chan < 0 || payload.len() + NET_FRAME_HDR > CTRL_FRAME_MAX + NET_FRAME_HDR {
        return false;
    }
    let sys = &*s.syscalls;
    let scratch = s.server.sc.relay_buf.as_mut_ptr();
    net_write_frame(
        sys,
        chan,
        msg,
        payload.as_ptr(),
        payload.len(),
        scratch,
        CTRL_FRAME_MAX + NET_FRAME_HDR,
    ) > 0
}

/// Relay the frame in `ctrl_buf` verbatim to worker `w`: the blob stays
/// opaque, only the TLV header is re-derived.
unsafe fn relay(s: &mut HttpState, w: usize, msg: u8, payload_len: usize) -> bool {
    if w >= SC_WORKERS {
        return false;
    }
    let chan = s.server.sc.ctrl_out[w];
    if chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let src = s.server.sc.ctrl_buf.as_ptr().add(NET_FRAME_HDR);
    let scratch = s.server.sc.relay_buf.as_mut_ptr();
    net_write_frame(
        sys,
        chan,
        msg,
        src,
        payload_len,
        scratch,
        CTRL_FRAME_MAX + NET_FRAME_HDR,
    ) > 0
}

unsafe fn session_header(s: &HttpState, idx: usize, out: &mut [u8]) {
    let slot = &*s.server.slots.as_ptr().add(idx);
    sc::put_session_header(out, &slot.sc_session_id, slot.sc_epoch);
}

unsafe fn send_drain(s: &mut HttpState, idx: usize, w: usize) -> bool {
    let mut payload = [0u8; sc::DRAIN_PAYLOAD_LEN];
    session_header(s, idx, &mut payload);
    sc::put_u32_after_header(&mut payload, s.server.sc.drain_ms);
    sc_write(s, w, sc::CMD_SC_DRAIN, &payload)
}

unsafe fn send_detach(s: &mut HttpState, idx: usize, w: usize, reason: u8) -> bool {
    let mut payload = [0u8; sc::DETACH_PAYLOAD_LEN];
    session_header(s, idx, &mut payload);
    sc::put_status(&mut payload, reason);
    sc_write(s, w, sc::CMD_SC_DETACH, &payload)
}

unsafe fn send_resume(s: &mut HttpState, idx: usize, w: usize, epoch: u32) -> bool {
    let mut payload = [0u8; sc::RESUME_PAYLOAD_LEN];
    let sid = (*s.server.slots.as_ptr().add(idx)).sc_session_id;
    sc::put_session_header(&mut payload, &sid, epoch);
    sc_write(s, w, sc::CMD_SC_RESUME, &payload)
}

/// Emit a `MON_SESSION` line for slot `idx`.
unsafe fn mon(s: &mut HttpState, idx: usize, event: u8, reason: &[u8], status: &[u8]) {
    let sys = s.syscalls;
    if s.server.sc.self_idx == 0xFF {
        let i = dev_self_index(&*sys);
        if i >= 0 {
            s.server.sc.self_idx = i as u8;
        }
    }
    let (sid, epoch) = {
        let slot = &*s.server.slots.as_ptr().add(idx);
        (slot.sc_session_id, slot.sc_epoch)
    };
    let anchor = s.server.sc.anchor_id;
    let mon_ptr = s.server.sc.mon_buf.as_mut_ptr();
    let _ = super::super::dev_mon_session(
        &*sys,
        s.server.sc.self_idx,
        event,
        sid.as_ptr(),
        epoch,
        anchor.as_ptr(),
        core::ptr::null(),
        reason,
        status,
        mon_ptr,
        MON_BUF_SIZE,
    );
}

/// Mark a fresh slot as carrying no session. The id, epoch and cursors are
/// set together when one is minted (`on_ws_open`), so they are left alone
/// here rather than zeroed twice.
pub(crate) fn slot_init(slot: &mut ConnSlot) {
    slot.sc_phase = SP_NONE;
    slot.sc_worker = NO_WORKER;
}

// ── Host-test surface ─────────────────────────────────────────────────────

#[cfg(feature = "host-test")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionMetrics {
    pub sessions_attached: u32,
    pub sessions_moved: u32,
    pub swaps_completed: u32,
    pub swaps_refused: u32,
    pub envelopes_misowned: u32,
    pub swap_active: u8,
    pub active_w: u8,
}

#[cfg(feature = "host-test")]
/// # Safety
/// `state` must point to an initialised `HttpState`.
pub unsafe fn test_session_metrics(state: *mut u8) -> SessionMetrics {
    let s = &*(state as *const HttpState);
    SessionMetrics {
        sessions_attached: s.server.sc.sessions_attached,
        sessions_moved: s.server.sc.sessions_moved,
        swaps_completed: s.server.sc.swaps_completed,
        swaps_refused: s.server.sc.swaps_refused,
        envelopes_misowned: s.server.sc.envelopes_misowned,
        swap_active: s.server.sc.swap_active,
        active_w: s.server.sc.active_w,
    }
}

#[cfg(feature = "host-test")]
/// `(phase, worker, epoch, forwarded, relayed)` of the session on `conn`.
///
/// # Safety
/// `state` must point to an initialised `HttpState`.
pub unsafe fn test_session_of(state: *mut u8, conn: u16) -> Option<(u8, u8, u32, u64, u64)> {
    let s = &*(state as *const HttpState);
    let idx = super::find_slot_by_conn_id(s, conn)?;
    let slot = &*s.server.slots.as_ptr().add(idx);
    Some((
        slot.sc_phase,
        slot.sc_worker,
        slot.sc_epoch,
        slot.sc_forwarded,
        slot.sc_relayed,
    ))
}

#[cfg(feature = "host-test")]
/// Ask for a swap, as the store row would.
///
/// # Safety
/// `state` must point to an initialised `HttpState`.
pub unsafe fn test_request_swap(state: *mut u8) {
    let s = &mut *(state as *mut HttpState);
    s.server.sc.swap_requested = 1;
}
