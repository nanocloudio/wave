//! Dynamic listeners.
//!
//! A second table consumer beside `super::routes`: the anchor consumes
//! `/dataplane/edge-listeners/<port> = proto=tcp;tls=<0|1>` and binds each
//! listed port MID-LIFE — outside the Init→Binding→WaitBound path that serves
//! the single static `port`.
//!
//! Two halves, reconciled each tick. `ListenerRow` is what the store says is
//! DESIRED; `BoundListener` is what the kernel has actually granted. The gap
//! between them is the work: bind what is newly desired, close what has been
//! withdrawn.
//!
//! The kernel's endpoint-lease gate enforces
//! "bind ∈ lease set": a port the edge owner was not granted is refused with
//! `MSG_BIND_REFUSED`, so the listener never comes up. The grant model is a
//! pre-leased port POOL — the edge owner's plan carries one lease per pool port
//! (an `export` per port, ../fluxor/tools/src/compose.rs) and mid-life bind draws from it at
//! runtime, so no runtime lease-grant is needed.
//!
//! Scope is tcp / `tls=0`, where http drives linux_net directly. A `tls=1`
//! dynamic listener would need the fronting tls module to bind and accept a new
//! port mid-life too — the static 443 bind is forwarded through tls today — so
//! a `tls=1` row is recorded and reported but NOT bound.

use super::super::abi::SyscallTable;
use super::super::connection::{NET_BUF_SIZE, NET_CMD_BIND, NET_CMD_CLOSE};
use super::{
    close_net_conn, dev_channel_ioctl, dev_channel_port, dev_log, dev_owner_tag, dyn_field,
    dyn_u32, msg_read, net_write_frame, p_u16, HttpState, TableSink, MAX_DYN_KEY, MAX_DYN_PREFIX,
    MSG_HDR_SIZE, NET_FRAME_HDR, SOCK_TYPE_STREAM,
};

/// linux_net's bind-refusal opcode (`../fluxor/src/platform/linux/providers.rs`):
/// `[port:u16 LE][errno:u8]`.
///
/// Distinct from the metal `ip` module's 0x07 (RETRANSMIT), and acted on ONLY
/// when the dynamic-listener feature is configured (the linux edge), so the
/// metal path stays byte-identical.
pub(crate) const NET_MSG_BIND_REFUSED: u8 = 0x07;

/// Additional listeners beyond the static `port`, bound from the
/// pre-leased pool. Small: listener churn is operator-rate.
pub(crate) const MAX_DYN_LISTENERS: usize = 8;
/// Input port index carrying the self-edged listener change sink (in[5]).
pub(crate) const DYN_LISTENERS_PORT_INDEX: u8 = 5;

// Reconciler bind states for one pooled listener.
/// Desired, CMD_BIND not yet issued.
const LISTENER_IDLE: u8 = 0;
/// CMD_BIND issued; awaiting MSG_BOUND / MSG_BIND_REFUSED.
const LISTENER_BINDING: u8 = 1;
/// MSG_BOUND seen — accepts on this port are claimed.
const LISTENER_BOUND: u8 = 2;
/// MSG_BIND_REFUSED seen (port not leased) — not retried, never accepts.
const LISTENER_REFUSED: u8 = 3;

/// One desired listener row (table-consumer half). `tls=1` is recorded
/// but not bound in P3 (see the module comment).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ListenerRow {
    pub(crate) key: [u8; MAX_DYN_KEY],
    pub(crate) key_len: u8,
    pub(crate) port: u16,
    pub(crate) tls: u8,
    pub(crate) used: u8,
}

impl ListenerRow {
    const fn new() -> Self {
        Self {
            key: [0; MAX_DYN_KEY],
            key_len: 0,
            port: 0,
            tls: 0,
            used: 0,
        }
    }
    fn key(&self) -> &[u8] {
        &self.key[..self.key_len as usize]
    }
}

/// One runtime bind record (reconciler half). NOT part of the table, so
/// it survives a LOST shadow-swap of the desired set.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BoundListener {
    pub(crate) port: u16,
    pub(crate) state: u8,
    pub(crate) used: u8,
    /// linux_net listener conn_id from MSG_BOUND (teardown CMD_CLOSE).
    pub(crate) conn_id: i32,
}

impl BoundListener {
    const fn new() -> Self {
        Self {
            port: 0,
            state: LISTENER_IDLE,
            used: 0,
            conn_id: -1,
        }
    }
}

/// The desired-listener table (live + rebuild shadow, table-consumer
/// driven) plus the reconciler's runtime bind records. Default-off: an
/// unconfigured `listeners_prefix` leaves every field zero-init and the
/// pump a no-op, so the server is byte-identical.
#[repr(C)]
pub struct DynListeners {
    pub(crate) live: [ListenerRow; MAX_DYN_LISTENERS],
    pub(crate) shadow: [ListenerRow; MAX_DYN_LISTENERS],
    /// Runtime bind state — owned by `reconcile_listeners`, never by the
    /// TableSink swap.
    pub(crate) bound: [BoundListener; MAX_DYN_LISTENERS],
    /// Rows dropped on overflow; degradation goes to telemetry, never a store key.
    pub(crate) dropped: u32,
}

impl DynListeners {
    pub(crate) const fn new() -> Self {
        Self {
            live: [ListenerRow::new(); MAX_DYN_LISTENERS],
            shadow: [ListenerRow::new(); MAX_DYN_LISTENERS],
            bound: [BoundListener::new(); MAX_DYN_LISTENERS],
            dropped: 0,
        }
    }
    fn arena(&mut self, shadow: bool) -> &mut [ListenerRow; MAX_DYN_LISTENERS] {
        if shadow {
            &mut self.shadow
        } else {
            &mut self.live
        }
    }
}

/// The `<port>` tail of a `/dataplane/edge-listeners/<port>` key: the last
/// '/'-delimited segment parsed as a u16. 0 (unparseable) is ignored.
fn listener_port_of_key(key: &[u8]) -> u16 {
    let seg = match key.iter().rposition(|&b| b == b'/') {
        Some(i) => &key[i + 1..],
        None => key,
    };
    (dyn_u32(seg) & 0xFFFF) as u16
}

impl TableSink for DynListeners {
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool) {
        let port = listener_port_of_key(key);
        // `tls=1` recorded; only `tls=0` is bound in P3.
        let tls = dyn_field(value, b"tls=")
            .map(|v| dyn_u32(v) != 0)
            .unwrap_or(false);
        let arena = self.arena(shadow);
        let mut free: Option<usize> = None;
        let mut found: Option<usize> = None;
        for (i, r) in arena.iter().enumerate() {
            if r.used == 1 && r.key() == key {
                found = Some(i);
                break;
            }
            if r.used == 0 && free.is_none() {
                free = Some(i);
            }
        }
        let slot = match found.or(free) {
            Some(i) => i,
            None => {
                self.dropped = self.dropped.wrapping_add(1);
                return;
            }
        };
        let r = &mut arena[slot];
        *r = ListenerRow::new();
        let kn = key.len().min(MAX_DYN_KEY);
        r.key[..kn].copy_from_slice(&key[..kn]);
        r.key_len = kn as u8;
        r.port = port;
        r.tls = tls as u8;
        r.used = 1;
    }

    fn remove(&mut self, key: &[u8], shadow: bool) {
        let arena = self.arena(shadow);
        for r in arena.iter_mut() {
            if r.used == 1 && r.key() == key {
                r.used = 0;
                return;
            }
        }
    }

    fn clear_shadow(&mut self) {
        for r in self.shadow.iter_mut() {
            r.used = 0;
        }
    }

    fn swap_shadow(&mut self) {
        // Promote only the DESIRED set; the reconciler's `bound` records
        // are untouched, so a relist never drops a live listener.
        self.live = self.shadow;
    }
}

impl DynListeners {
    /// A bound (accepting) dynamic listener owns `port`?
    fn port_is_bound(&self, port: u16) -> bool {
        self.bound
            .iter()
            .any(|b| b.used == 1 && b.state == LISTENER_BOUND && b.port == port)
    }
    /// A pending (BINDING) dynamic listener for `port`, if any.
    fn bound_slot_for(&mut self, port: u16) -> Option<usize> {
        self.bound
            .iter()
            .position(|b| b.used == 1 && b.port == port)
    }

    /// A mid-life `CMD_BIND` succeeded: record the kernel's conn id for `port`.
    ///
    /// Both bind outcomes are reported here rather than reached into from the
    /// inbound demux, so `LISTENER_*` and the `bound` array stay private to the
    /// reconciler that owns them. Unknown ports are ignored: post-`bound`, a
    /// `MSG_BOUND` for a port this table never asked for is not ours.
    pub(crate) fn mark_bound(&mut self, port: u16, conn_id: i32) {
        if let Some(bi) = self.bound_slot_for(port) {
            let b = &mut self.bound[bi];
            b.state = LISTENER_BOUND;
            b.conn_id = conn_id;
        }
    }

    /// A mid-life `CMD_BIND` was refused — `port` is outside the edge owner's
    /// lease pool. Terminal: the reconciler does
    /// not retry, because the lease set does not change at runtime.
    pub(crate) fn mark_refused(&mut self, port: u16) {
        if let Some(bi) = self.bound_slot_for(port) {
            self.bound[bi].state = LISTENER_REFUSED;
        }
    }
}

#[cfg(feature = "host-test")]
impl DynListeners {
    pub fn test_new() -> Self {
        Self::new()
    }
    pub fn test_program(&mut self, key: &[u8], value: &[u8]) {
        self.upsert(key, value, false);
    }
    pub fn test_remove(&mut self, key: &[u8]) {
        self.remove(key, false);
    }
    /// `(state, conn_id)` of the runtime bind record for `port`, if any.
    pub fn test_bound_state(&self, port: u16) -> Option<(u8, i32)> {
        self.bound
            .iter()
            .find(|b| b.used == 1 && b.port == port)
            .map(|b| (b.state, b.conn_id))
    }
    pub const LISTENER_BINDING: u8 = LISTENER_BINDING;
    pub const LISTENER_BOUND: u8 = LISTENER_BOUND;
    pub const LISTENER_REFUSED: u8 = LISTENER_REFUSED;
}

#[cfg(feature = "host-test")]
/// Enable the dynamic-listener subsystem on a booted module (as if
/// `listeners_prefix` were configured), so `pump_listeners` reconciles
/// injected desired rows. `sink` is left resolved so the table_consumer
/// never touches the store in a harness.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_enable_listeners(state: *mut u8) {
    let s = &mut *(state as *mut HttpState);
    s.server.listeners_prefix[0] = b'/';
    s.server.listeners_prefix_len = 1;
    s.server.listeners_sink = i32::MAX; // non-negative: skip re-resolve
    s.server.ltc.subscribed = 1; // skip SUBSCRIBE/relist in the harness
}

#[cfg(feature = "host-test")]
/// Program one desired listener row (`/dataplane/edge-listeners/<port>` +
/// `proto=tcp;tls=<0|1>`) directly, as if the listener table_consumer
/// applied it.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_inject_listener(state: *mut u8, key: &[u8], value: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    s.server.listeners.upsert(key, value, false);
}

#[cfg(feature = "host-test")]
/// Withdraw a desired listener row by key.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_remove_listener(state: *mut u8, key: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    s.server.listeners.remove(key, false);
}

#[cfg(feature = "host-test")]
/// `(state, conn_id)` of the runtime bind record for `port`, if tracked.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_listener_state(state: *mut u8, port: u16) -> Option<(u8, i32)> {
    let s = &*(state as *mut HttpState);
    s.server.listeners.test_bound_state(port)
}

/// Listener bind-state discriminants for harness assertions.
#[cfg(feature = "host-test")]
pub const LISTENER_STATE_BINDING: u8 = LISTENER_BINDING;
#[cfg(feature = "host-test")]
pub const LISTENER_STATE_BOUND: u8 = LISTENER_BOUND;
#[cfg(feature = "host-test")]
pub const LISTENER_STATE_REFUSED: u8 = LISTENER_REFUSED;

/// Param setter for `listeners_prefix` (TLV tag 91). Empty leaves the
/// dynamic-listener feature off (byte-identical server). Copies up to
/// `MAX_DYN_PREFIX` bytes.
///
/// # Safety
/// `d` points at `len` readable bytes (the TLV value).
pub(crate) unsafe fn set_listeners_prefix(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(MAX_DYN_PREFIX);
    let dst = s.server.listeners_prefix.as_mut_ptr();
    let mut i = 0;
    while i < n {
        *dst.add(i) = *d.add(i);
        i += 1;
    }
    s.server.listeners_prefix_len = n as u16;
}

/// Pump the dynamic-listener table consumer one step, then reconcile the
/// desired listener set against the runtime bind records: bind newly
/// desired ports mid-life (`CMD_BIND`), tear down withdrawn ones
/// (`CMD_CLOSE`). No-op when the feature is off (`listeners_prefix_len ==
/// 0`), keeping the server byte-identical.
///
/// The mid-life bind is issued only once the static listener is bound
/// (`bound == 1`): the shared `net_out` / `net_in` pair carries the init
/// bind first, and its `MSG_BOUND`/`MSG_BIND_REFUSED` for a dynamic port
/// then arrives through `demux_inbound` (which runs post-`bound`).
pub(crate) unsafe fn pump_listeners(s: &mut HttpState) {
    let prefix_len = s.server.listeners_prefix_len as usize;
    if prefix_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.server.listeners_sink < 0 {
        s.server.listeners_sink = dev_channel_port(sys, 0, DYN_LISTENERS_PORT_INDEX);
        if s.server.listeners_sink < 0 {
            return; // port unwired — nothing to subscribe against
        }
    }
    let sink = s.server.listeners_sink;
    // Disjoint field borrows of `s.server`. The listener CHANGES relist
    // reuses `routes_scratch` — the two pumps run sequentially, never
    // mid-relist of the other, so the transient buffer is free to share.
    let prefix = &s.server.listeners_prefix[..prefix_len];
    let scratch = &mut s.server.routes_scratch;
    let ltc = &mut s.server.ltc;
    let listeners = &mut s.server.listeners;
    ltc.step(sys, sink, prefix, scratch, listeners);

    // Reconcile only after the static bind: the mid-life CMD_BIND rides
    // the same net_out, and its reply comes back through the demux.
    if s.server.bound != 0 {
        reconcile_listeners(s);
    }
}

/// Diff the desired listener set against the runtime bind records and act:
/// issue `CMD_BIND` for a newly desired `tls=0` port, `CMD_CLOSE` the
/// linux_net listener conn for a withdrawn one. Idempotent — a port
/// already tracked (any bind state) is left alone; the lease gate refuses
/// an unleased port and the refusal surfaces as `MSG_BIND_REFUSED` in the
/// demux (which flips the record to `LISTENER_REFUSED`, never retried).
unsafe fn reconcile_listeners(s: &mut HttpState) {
    // 1. Bind newly-desired ports. Skip `tls=1` (P3 scope: cleartext).
    for li in 0..MAX_DYN_LISTENERS {
        let (port, tls, used) = {
            let r = &s.server.listeners.live[li];
            (r.port, r.tls, r.used)
        };
        if used != 1 || port == 0 || tls != 0 {
            continue;
        }
        if port == s.server.port {
            continue; // the static listener already owns this port
        }
        if s.server.listeners.bound_slot_for(port).is_some() {
            continue; // already tracked (binding / bound / refused)
        }
        // Claim a free bind record.
        let Some(bi) = s.server.listeners.bound.iter().position(|b| b.used == 0) else {
            s.server.listeners.dropped = s.server.listeners.dropped.wrapping_add(1);
            continue;
        };
        s.server.listeners.bound[bi] = BoundListener {
            port,
            state: LISTENER_BINDING,
            used: 1,
            conn_id: -1,
        };
        if !listener_send_bind(s, port) {
            // net_out full — roll back so a later tick retries.
            s.server.listeners.bound[bi] = BoundListener::new();
        }
    }

    // 2. Tear down withdrawn ports: a bind record with no live desired row.
    for bi in 0..MAX_DYN_LISTENERS {
        let (port, state, conn_id, used) = {
            let b = &s.server.listeners.bound[bi];
            (b.port, b.state, b.conn_id, b.used)
        };
        if used != 1 {
            continue;
        }
        let still_desired = s
            .server
            .listeners
            .live
            .iter()
            .any(|r| r.used == 1 && r.port == port && r.tls == 0);
        if still_desired {
            continue;
        }
        if state == LISTENER_BOUND && conn_id >= 0 {
            close_net_conn(s, conn_id as u16);
        }
        s.server.listeners.bound[bi] = BoundListener::new();
    }
}

/// Fill a `NET_CMD_BIND` payload for `port`, owner-stamped when this instance
/// belongs to a workload that owns its own address.
///
/// The base payload is `[port:u16 LE]`, which binds the host or wildcard
/// address. An instance whose owner tag is non-zero appends
/// `[owner_tag:u16 LE]`; the `ip` module resolves that tag to the workload's
/// owned address and refuses an unowned one with `EACCES`. A host-owned
/// instance reads owner slot 0 and appends nothing, so its payload is the
/// two-byte form.
///
/// Returns the payload length, 2 or 4.
#[inline]
pub(crate) unsafe fn fill_bind_payload(sys: &SyscallTable, port: u16, out: &mut [u8; 4]) -> usize {
    out[0] = (port & 0xFF) as u8;
    out[1] = (port >> 8) as u8;
    let owner_tag = dev_owner_tag(sys);
    if owner_tag != 0 {
        out[2] = (owner_tag & 0xFF) as u8;
        out[3] = (owner_tag >> 8) as u8;
        4
    } else {
        2
    }
}

/// Issue a mid-life `CMD_BIND [port:u16 LE]` on `net_out` for a pooled
/// listener. Returns false when the channel is unwired or full.
unsafe fn listener_send_bind(s: &mut HttpState, port: u16) -> bool {
    if s.net_out_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 4];
    let plen = fill_bind_payload(sys, port, &mut payload);
    net_write_frame(
        sys,
        chan,
        NET_CMD_BIND,
        payload.as_ptr(),
        plen,
        buf,
        NET_BUF_SIZE,
    ) != 0
}

/// True when `port` is one of the anchor's live listen ports: the single
/// static listener, or a bound dynamic listener. Used by the accept demux
/// to claim only accepts on a port this anchor owns.
#[inline]
pub(crate) unsafe fn is_listen_port(s: &HttpState, port: u16) -> bool {
    port == s.server.port || s.server.listeners.port_is_bound(port)
}
