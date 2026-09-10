// ws_session_worker — the worker's half of Wave's session continuity, for a
// module that consumes `WsFrame` envelopes from an anchored `http`.
//
// Pure, `no_std`, zero-alloc, I/O-free: the module owns the channels and the
// application state; this core owns the SessionCtrlV1 bookkeeping that every
// such worker would otherwise re-derive — attach and detach by session id,
// the map from a `WsFrame`'s connection id to its session, the delivery
// cursors, the drain-to-dry rule, export gated on a message boundary,
// import into a caller-sized blob, the resume that follows an import, and the
// resume that returns a refused session to service (`protocol_surfaces.md`
// §Refused handoffs). Control frames are consumed through `handle_ctrl` and
// produced through `next_out`; the module moves the bytes.
//
// Mount order: `session_handoff.rs` first (the chunk walk and the cursors),
// then this file, with the `session_ctrl` contract reachable as `sc`:
//
//     use abi::contracts::net::session_ctrl as sc;
//     include!("../../../target/fluxor/fluxor-abi/sdk/cores/session_handoff.rs");
//     include!("../../common/ws_session_worker.rs");
//
// The blob is the application's. On `WswEvent::ExportRequested` the module
// serialises its per-session state into `blob_mut` and calls
// `export_committed`; on `WswEvent::Imported` it restores from `blob`. The
// core never interprets it, and neither does the anchor.

/// Where a session is in its life.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WswPhase {
    /// Slot free.
    Free = 0,
    /// Attached and serving.
    Active = 1,
    /// `DRAIN` received: consuming the inbound tail, then exporting.
    Draining = 2,
    /// The module has been asked for the blob (message boundary reached,
    /// inbound tail dry) and has not yet committed it.
    Exporting = 3,
    /// `DRAINED` and the export are queued or sent: consuming nothing until
    /// `RESUME` at the current epoch (refusal) or `DETACH` (handoff done).
    Drained = 4,
    /// Reassembling a relayed export.
    Importing = 5,
    /// Import committed; waiting for `RESUME` above the imported epoch.
    Imported = 6,
}

/// A control frame owed to the anchor, rendered by `next_out`.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WswPending {
    None = 0,
    Attached = 1,
    Drained = 2,
    ExportBegin = 3,
    ExportChunk = 4,
    ExportEnd = 5,
    ImportBegin = 6,
    ImportEnd = 7,
    Resumed = 8,
    Detached = 9,
    Error = 10,
}

/// What the module must act on after `handle_ctrl` or `data_idle`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WswEvent {
    None,
    /// Session `idx` is attached; envelopes for its connection will follow.
    Attached(usize),
    /// Serialise session `idx`'s state into `blob_mut(idx)` and call
    /// `export_committed(idx, len)`.
    ExportRequested(usize),
    /// Session `idx` arrived by import: restore from `blob(idx)`. It is not
    /// serving until `Resumed`.
    Imported(usize),
    /// Session `idx` is serving (a fresh import resumed, or a refused
    /// handoff returned it).
    Resumed(usize),
    /// Session `idx` is gone; its slot is free.
    Detached(usize),
}

/// Bytes of session id + epoch that head every session-scoped message.
const WSW_HDR: usize = sc::SESSION_HEADER;
/// Replies a session can owe at once: an import is BEGIN + END, an
/// export DRAINED + BEGIN + CHUNK… + END with the chunk walk held in one
/// entry, and a detach or error may follow either.
const WSW_PENDING_MAX: usize = 4;

/// One session's bookkeeping. `BLOB` is the largest state the module will
/// ever export for a session.
#[repr(C)]
pub struct WswSession<const BLOB: usize> {
    pub session_id: [u8; sc::SESSION_ID_BYTES],
    pub anchor_id: [u8; sc::ANCHOR_ID_BYTES],
    /// The connection this session's envelopes name, recovered from the
    /// identity the anchor minted (`[anchor:8][conn:4 BE][gen:4 BE]`).
    pub conn: u32,
    pub epoch: u32,
    pub phase: WswPhase,
    /// A partial message (a `fin = 0` frame) is being accumulated: the
    /// export waits for the boundary.
    pub msg_open: bool,
    /// Replies owed to the anchor, oldest first. Several commands can land
    /// in one step (an export is three frames), and each owes its reply in
    /// order.
    pending: [WswPending; WSW_PENDING_MAX],
    pending_len: u8,
    /// Delivery cursors: envelope bytes consumed from the anchor, envelope
    /// bytes emitted toward it.
    pub in_consumed: u64,
    pub out_produced: u64,
    pub blob_len: u32,
    import_epoch: u32,
    export: HandoffExport,
    import: HandoffImport,
    /// The epoch a pending `Error` names, and its status.
    err_epoch: u32,
    err_status: u8,
    attach_status: u8,
    import_status: u8,
    _pad1: u8,
    pub blob: [u8; BLOB],
}

impl<const BLOB: usize> WswSession<BLOB> {
    pub const fn new() -> Self {
        Self {
            session_id: [0; sc::SESSION_ID_BYTES],
            anchor_id: [0; sc::ANCHOR_ID_BYTES],
            conn: 0,
            epoch: 0,
            phase: WswPhase::Free,
            msg_open: false,
            pending: [WswPending::None; WSW_PENDING_MAX],
            pending_len: 0,
            in_consumed: 0,
            out_produced: 0,
            blob_len: 0,
            import_epoch: 0,
            export: HandoffExport::new(0),
            import: HandoffImport::new(),
            err_epoch: 0,
            err_status: 0,
            attach_status: 0,
            import_status: 0,
            _pad1: 0,
            blob: [0; BLOB],
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    /// Queue a reply. A full queue drops the oldest still-unrendered
    /// reply, which cannot happen at the anchor's pace: it reads a worker's
    /// replies every step and writes at most one export per session.
    fn owe(&mut self, p: WswPending) {
        let n = self.pending_len as usize;
        if n < WSW_PENDING_MAX {
            self.pending[n] = p;
            self.pending_len += 1;
        } else {
            self.pending.copy_within(1.., 0);
            self.pending[WSW_PENDING_MAX - 1] = p;
        }
    }

    /// The reply at the head of the queue.
    #[inline]
    fn head(&self) -> WswPending {
        if self.pending_len == 0 {
            WswPending::None
        } else {
            self.pending[0]
        }
    }

    /// Drop the head reply (it has been rendered).
    fn pop(&mut self) {
        if self.pending_len > 0 {
            self.pending.copy_within(1.., 0);
            self.pending_len -= 1;
            self.pending[WSW_PENDING_MAX - 1] = WswPending::None;
        }
    }

    /// Replace the head reply (the export walk advancing to its next frame).
    fn replace_head(&mut self, p: WswPending) {
        if self.pending_len > 0 {
            self.pending[0] = p;
        } else {
            self.owe(p);
        }
    }
}

impl<const BLOB: usize> Default for WswSession<BLOB> {
    fn default() -> Self {
        Self::new()
    }
}

/// The worker: `N` sessions of up to `BLOB` bytes of exported state each.
#[repr(C)]
pub struct WsSessionWorker<const N: usize, const BLOB: usize> {
    pub worker_id: [u8; sc::WORKER_ID_BYTES],
    /// Export chunk size. Small enough that a chunk always fits the
    /// anchor's control frame; the walk handles any blob.
    pub chunk: u32,
    pub sessions: [WswSession<BLOB>; N],
}

/// Read the connection id out of an anchor-minted session id.
#[inline]
pub fn wsw_conn_of(session_id: &[u8; sc::SESSION_ID_BYTES]) -> u32 {
    u32::from_be_bytes([session_id[8], session_id[9], session_id[10], session_id[11]])
}

impl<const N: usize, const BLOB: usize> WsSessionWorker<N, BLOB> {
    pub const fn new(worker_id: [u8; sc::WORKER_ID_BYTES], chunk: u32) -> Self {
        const fn init<const B: usize>() -> WswSession<B> {
            WswSession::new()
        }
        Self {
            worker_id,
            chunk,
            sessions: [const { init::<BLOB>() }; N],
        }
    }

    // ── Lookup ──────────────────────────────────────────────────────

    pub fn session_for_id(&self, sid: &[u8]) -> Option<usize> {
        if sid.len() < sc::SESSION_ID_BYTES {
            return None;
        }
        self.sessions.iter().position(|s| {
            s.phase != WswPhase::Free && s.session_id[..] == sid[..sc::SESSION_ID_BYTES]
        })
    }

    /// The session an envelope naming `conn` belongs to.
    pub fn session_for_conn(&self, conn: u32) -> Option<usize> {
        self.sessions
            .iter()
            .position(|s| s.phase != WswPhase::Free && s.conn == conn)
    }

    /// A slot that serves nothing and owes nothing. A detached session holds
    /// its slot until its `DETACHED` has been rendered, so a reply is never
    /// overwritten by the next attach.
    fn free_slot(&self) -> Option<usize> {
        self.sessions
            .iter()
            .position(|s| s.phase == WswPhase::Free && s.head() == WswPending::None)
    }

    /// Envelopes for session `idx` may be consumed: serving, or draining
    /// its inbound tail. A drained session consumes nothing until resumed.
    #[inline]
    pub fn may_consume(&self, idx: usize) -> bool {
        idx < N
            && matches!(
                self.sessions[idx].phase,
                WswPhase::Active | WswPhase::Draining
            )
    }

    #[inline]
    pub fn blob(&self, idx: usize) -> &[u8] {
        let n = (self.sessions[idx].blob_len as usize).min(BLOB);
        &self.sessions[idx].blob[..n]
    }

    #[inline]
    pub fn blob_mut(&mut self, idx: usize) -> &mut [u8; BLOB] {
        &mut self.sessions[idx].blob
    }

    // ── Data-plane hooks ────────────────────────────────────────────

    /// An envelope of `len` bytes for session `idx` was consumed from the
    /// anchor's data channel.
    #[inline]
    pub fn on_inbound(&mut self, idx: usize, len: usize) {
        if idx < N {
            let s = &mut self.sessions[idx];
            s.in_consumed = s.in_consumed.wrapping_add(len as u64);
        }
    }

    /// An envelope of `len` bytes for session `idx` was written toward the
    /// anchor.
    #[inline]
    pub fn on_outbound(&mut self, idx: usize, len: usize) {
        if idx < N {
            let s = &mut self.sessions[idx];
            s.out_produced = s.out_produced.wrapping_add(len as u64);
        }
    }

    /// A message boundary: `open` while a `fin = 0` fragment is held.
    #[inline]
    pub fn set_message_open(&mut self, idx: usize, open: bool) {
        if idx < N {
            self.sessions[idx].msg_open = open;
        }
    }

    /// The anchor's data channel polled empty this step. A draining
    /// session whose inbound tail is dry and whose message is closed is
    /// ready to export: the module is asked for the blob.
    pub fn data_idle(&mut self) -> WswEvent {
        for (i, s) in self.sessions.iter_mut().enumerate() {
            if s.phase == WswPhase::Draining && !s.msg_open {
                s.phase = WswPhase::Exporting;
                return WswEvent::ExportRequested(i);
            }
        }
        WswEvent::None
    }

    /// The module has written `len` bytes of session `idx`'s state into the
    /// blob: `DRAINED` and the export are queued.
    pub fn export_committed(&mut self, idx: usize, len: usize) {
        if idx >= N || self.sessions[idx].phase != WswPhase::Exporting {
            return;
        }
        let s = &mut self.sessions[idx];
        s.blob_len = len.min(BLOB) as u32;
        s.export = HandoffExport::new(s.blob_len);
        s.phase = WswPhase::Drained;
        s.owe(WswPending::Drained);
    }

    // ── Control plane ───────────────────────────────────────────────

    /// Consume one SessionCtrlV1 command from the anchor.
    pub fn handle_ctrl(&mut self, msg: u8, payload: &[u8]) -> WswEvent {
        if payload.len() < WSW_HDR {
            return WswEvent::None;
        }
        let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        match msg {
            sc::CMD_SC_ATTACH => {
                if payload.len() < sc::ATTACH_PAYLOAD_LEN {
                    return WswEvent::None;
                }
                // ATTACH: [sid:16][anchor:8][epoch:4][cc:1][hint:8].
                let attach_epoch =
                    u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
                if self.session_for_id(payload).is_some() {
                    return WswEvent::None;
                }
                let Some(i) = self.free_slot() else {
                    return WswEvent::None;
                };
                let s = &mut self.sessions[i];
                s.reset();
                s.session_id.copy_from_slice(&payload[..16]);
                s.anchor_id.copy_from_slice(&payload[16..24]);
                s.conn = wsw_conn_of(&s.session_id);
                s.epoch = attach_epoch;
                s.phase = WswPhase::Active;
                s.attach_status = sc::STATUS_OK;
                s.owe(WswPending::Attached);
                WswEvent::Attached(i)
            }
            sc::CMD_SC_DRAIN => {
                let Some(i) = self.session_for_id(payload) else {
                    return WswEvent::None;
                };
                let s = &mut self.sessions[i];
                if s.phase == WswPhase::Active && epoch == s.epoch {
                    s.phase = WswPhase::Draining;
                }
                WswEvent::None
            }
            sc::CMD_SC_DETACH => {
                let Some(i) = self.session_for_id(payload) else {
                    return WswEvent::None;
                };
                let s = &mut self.sessions[i];
                // Whatever the phase: a standby detached mid-import discards
                // the partial blob the same way a serving worker lets go.
                // Earlier replies are dropped with the session — the anchor
                // that detached it is not waiting on them.
                s.pending_len = 0;
                s.owe(WswPending::Detached);
                s.phase = WswPhase::Free;
                // Keep the id and epoch for the DETACHED reply; the slot is
                // reused only once that has been rendered.
                WswEvent::Detached(i)
            }
            sc::CMD_SC_EXPORT_BEGIN => {
                if payload.len() < sc::EXPORT_BEGIN_LEN {
                    return WswEvent::None;
                }
                // Import IS the attach for the incoming worker.
                if self.session_for_id(payload).is_some() {
                    return WswEvent::None;
                }
                let Some(i) = self.free_slot() else {
                    return WswEvent::None;
                };
                let total =
                    u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
                let s = &mut self.sessions[i];
                s.reset();
                s.session_id.copy_from_slice(&payload[..16]);
                s.conn = wsw_conn_of(&s.session_id);
                s.import_epoch = epoch;
                s.epoch = epoch;
                if let Some(c) = SessionCursors::decode(&payload[24..24 + CURSOR_PAIR_LEN]) {
                    s.in_consumed = c.in_consumed;
                    s.out_produced = c.out_produced;
                }
                let status = s.import.begin(total, BLOB as u32);
                s.import_status = status;
                s.owe(WswPending::ImportBegin);
                // Refused for capacity: the reply goes out, then the slot is
                // released once it has been rendered.
                s.phase = WswPhase::Importing;
                WswEvent::None
            }
            sc::CMD_SC_EXPORT_CHUNK => {
                let Some(i) = self.session_for_id(payload) else {
                    return WswEvent::None;
                };
                let s = &mut self.sessions[i];
                if s.phase != WswPhase::Importing || payload.len() <= WSW_HDR + 4 {
                    return WswEvent::None;
                }
                let offset =
                    u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
                let data = &payload[WSW_HDR + 4..];
                let mut dest = s.blob;
                let status = s.import.chunk(offset, data, &mut dest);
                s.blob = dest;
                if status != HANDOFF_OK {
                    s.import_status = status;
                    s.owe(WswPending::ImportEnd);
                    s.phase = WswPhase::Free;
                }
                WswEvent::None
            }
            sc::CMD_SC_EXPORT_END => {
                let Some(i) = self.session_for_id(payload) else {
                    return WswEvent::None;
                };
                let s = &mut self.sessions[i];
                if s.phase != WswPhase::Importing || payload.len() < WSW_HDR + 4 {
                    return WswEvent::None;
                }
                let crc = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
                let status = s.import.end(crc);
                s.import_status = status;
                s.owe(WswPending::ImportEnd);
                if status == HANDOFF_OK {
                    s.blob_len = s.import.total_len();
                    s.phase = WswPhase::Imported;
                    WswEvent::Imported(i)
                } else {
                    s.phase = WswPhase::Free;
                    WswEvent::None
                }
            }
            sc::CMD_SC_RESUME => {
                let Some(i) = self.session_for_id(payload) else {
                    return WswEvent::None;
                };
                let s = &mut self.sessions[i];
                match s.phase {
                    // The handoff: a fresh epoch above the imported one.
                    WswPhase::Imported if epoch > s.import_epoch => {
                        s.epoch = epoch;
                        s.phase = WswPhase::Active;
                        s.owe(WswPending::Resumed);
                        WswEvent::Resumed(i)
                    }
                    // The refusal: the session's own epoch, unchanged.
                    // The state this worker exported is still its own.
                    WswPhase::Draining | WswPhase::Exporting | WswPhase::Drained
                        if epoch == s.epoch =>
                    {
                        s.phase = WswPhase::Active;
                        s.owe(WswPending::Resumed);
                        WswEvent::Resumed(i)
                    }
                    _ => {
                        s.err_epoch = epoch;
                        s.err_status = sc::STATUS_STALE_EPOCH;
                        s.owe(WswPending::Error);
                        WswEvent::None
                    }
                }
            }
            _ => WswEvent::None,
        }
    }

    /// The smallest `out` [`Self::next_out`] renders into. The two largest
    /// frames are an `EXPORT_BEGIN` — a fixed header carrying the blob length
    /// and both cursors — and a full export chunk; which of them is larger
    /// depends on the configured chunk size, so the bound takes both.
    pub const fn out_min(&self) -> usize {
        let chunked = WSW_HDR + 4 + self.chunk as usize;
        if chunked > sc::EXPORT_BEGIN_LEN {
            chunked
        } else {
            sc::EXPORT_BEGIN_LEN
        }
    }

    /// Render the next control frame owed to the anchor into `out`, returning
    /// its message type and payload length. `None` when nothing is owed, or
    /// when `out` is shorter than [`Self::out_min`].
    pub fn next_out(&mut self, out: &mut [u8]) -> Option<(u8, usize)> {
        let chunk = self.chunk;
        let need = self.out_min();
        for s in self.sessions.iter_mut() {
            if s.head() == WswPending::None {
                continue;
            }
            if out.len() < need {
                return None;
            }
            out[..16].copy_from_slice(&s.session_id);
            out[16..20].copy_from_slice(&s.epoch.to_le_bytes());
            let frame = match s.head() {
                WswPending::Attached => {
                    out[20] = s.attach_status;
                    s.pop();
                    (sc::MSG_SC_ATTACHED, WSW_HDR + 1)
                }
                WswPending::Drained => {
                    s.replace_head(WswPending::ExportBegin);
                    (sc::MSG_SC_DRAINED, WSW_HDR)
                }
                WswPending::ExportBegin => {
                    out[20..24].copy_from_slice(&s.blob_len.to_le_bytes());
                    let mut c = [0u8; CURSOR_PAIR_LEN];
                    SessionCursors::new(s.in_consumed, s.out_produced).encode(&mut c);
                    out[24..24 + CURSOR_PAIR_LEN].copy_from_slice(&c);
                    s.replace_head(if s.blob_len == 0 {
                        WswPending::ExportEnd
                    } else {
                        WswPending::ExportChunk
                    });
                    (sc::CMD_SC_EXPORT_BEGIN, sc::EXPORT_BEGIN_LEN)
                }
                WswPending::ExportChunk => match s.export.next_chunk(chunk) {
                    Some((off, len)) => {
                        out[20..24].copy_from_slice(&off.to_le_bytes());
                        let base = WSW_HDR + 4;
                        out[base..base + len as usize]
                            .copy_from_slice(&s.blob[off as usize..(off + len) as usize]);
                        s.export.advance(len);
                        if s.export.done() {
                            s.replace_head(WswPending::ExportEnd);
                        }
                        (sc::CMD_SC_EXPORT_CHUNK, base + len as usize)
                    }
                    None => {
                        s.replace_head(WswPending::ExportEnd);
                        continue;
                    }
                },
                WswPending::ExportEnd => {
                    let n = (s.blob_len as usize).min(BLOB);
                    let crc = handoff_crc32(&s.blob[..n]);
                    out[20..24].copy_from_slice(&crc.to_le_bytes());
                    s.pop();
                    (sc::CMD_SC_EXPORT_END, WSW_HDR + 4)
                }
                WswPending::ImportBegin => {
                    out[16..20].copy_from_slice(&s.import_epoch.to_le_bytes());
                    out[20] = s.import_status;
                    s.pop();
                    if s.import_status != HANDOFF_OK {
                        s.phase = WswPhase::Free;
                    }
                    (sc::MSG_SC_IMPORT_BEGIN, WSW_HDR + 1)
                }
                WswPending::ImportEnd => {
                    out[16..20].copy_from_slice(&s.import_epoch.to_le_bytes());
                    out[20] = s.import_status;
                    s.pop();
                    (sc::MSG_SC_IMPORT_END, WSW_HDR + 1)
                }
                WswPending::Resumed => {
                    s.pop();
                    (sc::MSG_SC_RESUMED, WSW_HDR)
                }
                WswPending::Detached => {
                    let frame = (sc::MSG_SC_DETACHED, WSW_HDR);
                    // Rendered: the slot is free for reuse now.
                    s.reset();
                    frame
                }
                WswPending::Error => {
                    out[16..20].copy_from_slice(&s.err_epoch.to_le_bytes());
                    out[20] = s.err_status;
                    s.pop();
                    (sc::MSG_SC_ERROR, WSW_HDR + 1)
                }
                WswPending::None => continue,
            };
            return Some(frame);
        }
        None
    }
}
