//! The two caches a response reads from.
//!
//! Unrelated in mechanism, adjacent in purpose: both hold bytes a renderer
//! needs, and neither is on the request path's critical section.
//!
//! **The content cache** (`CacheEntry`, LRU) holds rendered or fetched route
//! bodies in `body_pool`. Entries are refcounted (`retain`) rather than merely
//! LRU-ordered, because a reader can outlive a tick — an h2 stream renders
//! chunks across many ticks, and h1 `SendBody` crosses into `DrainSend` — so
//! eviction must REFUSE a region someone is still reading from, not just prefer
//! not to take it.
//!
//! **The variable cache** (`VarEntry`) holds `{{name}}` substitutions drained
//! from `in[1]` each tick. Keyed by hash, fixed capacity, last write wins.
//!
//! `cache_try_or_fetch` / `cache_fetch_step` are the phase-agnostic half: they
//! answer "is this route's body here, and if not, is the fetch done yet?"
//! without knowing which generation asked — which is what lets h1, h2 and h3
//! share one fill path.

use super::routes::{HANDLER_FILE, HANDLER_STREAM, HANDLER_TEMPLATE};
use super::{
    cur_matched_route, cur_slot, cur_slot_mut, dev_channel_ioctl, dev_millis,
    dev_telemetry_enabled, log, msg_read, net_read_frame, release_file_chan, set_cur_phase,
    try_acquire_file_chan, HttpState, Phase, IOCTL_FLUSH, IOCTL_NOTIFY, MAX_CACHE, MAX_ROUTES,
    MAX_VARS, MAX_VAR_VALUE, MSG_HDR_SIZE, POLL_HUP, POLL_IN, SEND_BUF_SIZE,
};

/// The entry owns an allocated `body_pool` region for `route_index`.
const CACHE_VALID: u8 = 0x01;
/// The fill finished — the region holds the whole body, not a prefix.
pub(crate) const CACHE_COMPLETE: u8 = 0x02;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CacheEntry {
    pub(crate) route_index: u8,
    pub(crate) flags: u8,
    pub(crate) lru_tick: u8,
    /// Reader refcount. Bumped on cache hit / fill-complete, dropped
    /// on emission end. `cache_alloc` refuses to evict an entry with
    /// `retain > 0`, so a long-lived reader (h2 stream rendering
    /// chunks across many ticks; h1 SendBody crossing into
    /// DrainSend) can't have its `body_pool` region overwritten by
    /// a sibling cache miss.
    pub(crate) retain: u8,
    pub(crate) arena_offset: u32,
    pub(crate) length: u32,
}

impl CacheEntry {
    const fn new() -> Self {
        Self {
            route_index: 0,
            flags: 0,
            lru_tick: 0,
            retain: 0,
            arena_offset: 0,
            length: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct VarEntry {
    name_hash: u32,
    value_len: u8,
    _pad: [u8; 3],
    value: [u8; MAX_VAR_VALUE],
}

impl VarEntry {
    const fn new() -> Self {
        Self {
            name_hash: 0,
            value_len: 0,
            _pad: [0; 3],
            value: [0; MAX_VAR_VALUE],
        }
    }
}

pub(crate) unsafe fn drain_variables(s: &mut HttpState) {
    if s.server.var_chan < 0 {
        return;
    }

    let var_chan = s.server.var_chan;
    let syscalls = s.syscalls;
    let mut buf = [0u8; MSG_HDR_SIZE + MAX_VAR_VALUE];

    loop {
        let poll = ((*syscalls).channel_poll)(var_chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }

        let (msg_type, payload_len) = msg_read(&*syscalls, var_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 && payload_len == 0 {
            break;
        }

        let vlen = (payload_len as usize).min(MAX_VAR_VALUE);

        let var_count = s.server.var_count as usize;
        let mut slot: usize = var_count;
        let mut j = 0usize;
        while j < var_count {
            if (*s.server.vars.as_ptr().add(j)).name_hash == msg_type {
                slot = j;
                break;
            }
            j += 1;
        }

        if slot >= MAX_VARS {
            continue;
        }

        let var = &mut *s.server.vars.as_mut_ptr().add(slot);
        var.name_hash = msg_type;
        var.value_len = vlen as u8;
        let mut k = 0;
        let buf_ptr = buf.as_ptr();
        while k < vlen {
            *var.value.as_mut_ptr().add(k) = *buf_ptr.add(k);
            k += 1;
        }

        if slot == var_count {
            s.server.var_count += 1;
        }
    }
}

pub(crate) unsafe fn lookup_var(s: &HttpState, hash: u32) -> (*const u8, usize) {
    let count = s.server.var_count as usize;
    let mut i = 0usize;
    while i < count {
        let var = &*s.server.vars.as_ptr().add(i);
        if var.name_hash == hash {
            return (var.value.as_ptr(), var.value_len as usize);
        }
        i += 1;
    }
    (core::ptr::null(), 0)
}

/// Find a fully-filled cache entry for `route_idx`. Used by the hit
/// paths (`cache_try_or_fetch`, h1 inline `HANDLER_STATIC`/`TEMPLATE`)
/// — returns -1 for entries that are still mid-fill so a sibling
/// request doesn't render zero/partial bytes from `body_pool` while
/// the original fetch is in flight.
pub(crate) unsafe fn cache_lookup(s: &HttpState, route_idx: u8) -> i8 {
    let mut i = 0usize;
    while i < s.server.cache_count as usize {
        let e = &*s.server.cache_entries.as_ptr().add(i);
        let usable = e.flags & (CACHE_VALID | CACHE_COMPLETE);
        if usable == (CACHE_VALID | CACHE_COMPLETE) && e.route_index == route_idx {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Find any cache entry for `route_idx`, regardless of fill state.
/// Used by `cache_retain_for_route` / `cache_release_for_route` so
/// the refcount on an in-flight entry stays balanced even before
/// the fill completes (e.g. a stream is closed mid-fetch).
pub(crate) unsafe fn cache_lookup_any(s: &HttpState, route_idx: u8) -> i8 {
    let mut i = 0usize;
    while i < s.server.cache_count as usize {
        let e = &*s.server.cache_entries.as_ptr().add(i);
        if (e.flags & CACHE_VALID) != 0 && e.route_index == route_idx {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// True when no cache entry is currently held by an in-flight
/// reader. Callers that want to evict (or recycle the body_pool
/// arena offsets) must check this first; an evict-while-reading
/// would corrupt the reader's view of the body_pool region.
unsafe fn cache_evictable(s: &HttpState) -> bool {
    let mut i = 0usize;
    while i < s.server.cache_count as usize {
        let e = &*s.server.cache_entries.as_ptr().add(i);
        if (e.flags & CACHE_VALID) != 0 && e.retain > 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Increment the reader refcount on the cache entry currently
/// caching `route_idx`. Uses `cache_lookup_any` so retain works
/// even before `CACHE_COMPLETE` is set (matters for the
/// fetch-in-progress path: the fetch's eventual completion
/// retains, and concurrent retain/release on the same entry must
/// find it). No-op if no such entry exists.
pub(crate) unsafe fn cache_retain_for_route(s: &mut HttpState, route_idx: u8) {
    let ci = cache_lookup_any(s, route_idx);
    if ci < 0 {
        return;
    }
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
    e.retain = e.retain.saturating_add(1);
}

/// Decrement the reader refcount on the cache entry currently
/// caching `route_idx`. No-op if no such entry exists or the
/// counter is already zero (defensive — a misordered release
/// shouldn't underflow).
pub(crate) unsafe fn cache_release_for_route(s: &mut HttpState, route_idx: u8) {
    let ci = cache_lookup_any(s, route_idx);
    if ci < 0 {
        return;
    }
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
    if e.retain > 0 {
        e.retain -= 1;
    }
}

pub(crate) unsafe fn cache_evict_all(s: &mut HttpState) -> u32 {
    s.server.cache_count = 0;
    let mut inline_end: u32 = 0;
    let mut i = 0usize;
    while i < s.server.route_count as usize {
        let r = &*s.server.routes.as_ptr().add(i);
        if r.source_index < 0 && r.body_len > 0 {
            let end = r.body_offset + r.body_len;
            if end > inline_end {
                inline_end = end;
            }
        }
        i += 1;
    }
    inline_end
}

/// Returns -1 if any existing cache entry has `retain > 0` —
/// caller must defer (treat as Busy) and retry on a later tick.
/// Otherwise evicts all entries, allocates a fresh entry at idx 0
/// for `route_idx`, and returns 0.
pub(crate) unsafe fn cache_alloc(s: &mut HttpState, route_idx: u8) -> i32 {
    if !cache_evictable(s) {
        return -1;
    }
    let arena_end: u32 = cache_evict_all(s);

    let idx = 0usize;
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(idx);
    e.route_index = route_idx;
    e.flags = CACHE_VALID;
    e.retain = 0;
    s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
    e.lru_tick = s.server.cache_tick;
    e.arena_offset = arena_end;
    e.length = 0;
    s.server.cache_count = 1;
    idx as i32
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum CacheLookup {
    /// Cache hit; `route.body_offset` / `route.body_len` now point at
    /// the cached arena region. Caller can render immediately.
    Hit,
    /// Cache miss; an `IOCTL_NOTIFY` has been queued on `file_chan`.
    /// Caller must run `cache_fetch_step` until it returns `Ready`.
    Pending,
    /// `file_chan` isn't wired or `source_index < 0` — caller should
    /// fall back to inline body if any.
    NoSource,
    /// `file_chan` is currently held by another slot. Caller should
    /// mark the stream Fetching anyway and retry on subsequent ticks
    /// — `drive_cache_fetch` re-attempts `cache_try_or_fetch` until
    /// the lock frees, at which point it transitions to `Pending`
    /// and the normal fetch flow resumes.
    Busy,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum CacheStepResult {
    Pending,
    Ready,
    Error,
}

/// h2-friendly entry point: try cache first, otherwise kick off a fetch.
/// Mirrors the h1 path in `step()::DispatchRoute` for HANDLER_STATIC /
/// HANDLER_TEMPLATE with `source_index >= 0`.
pub(crate) unsafe fn cache_try_or_fetch(s: &mut HttpState, route_idx: i8) -> CacheLookup {
    let r = &*s.server.routes.as_ptr().add(route_idx as usize);
    let src_idx = r.source_index;
    if src_idx < 0 || s.server.file_chan < 0 {
        return CacheLookup::NoSource;
    }
    let ci = cache_lookup(s, route_idx as u8);
    if ci >= 0 {
        let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
        s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
        ce.lru_tick = s.server.cache_tick;
        // Retain the entry while emission is in flight — without
        // this, a sibling cache miss could evict and reuse the
        // body_pool region we're about to render from. Caller
        // releases via `cache_release_for_route` at end-of-emission.
        ce.retain = ce.retain.saturating_add(1);
        let r = &mut *s.server.routes.as_mut_ptr().add(route_idx as usize);
        r.body_offset = ce.arena_offset;
        r.body_len = ce.length;
        return CacheLookup::Hit;
    }
    // Cross-slot serialisation: only one slot may hold `file_chan`
    // at a time. If another slot is mid-fetch, return Busy without
    // issuing IOCTL or claiming a cache slot — caller marks the
    // stream Fetching and `drive_cache_fetch` will retry on the
    // next tick. Without this gate, two concurrent h2 streams or
    // an h1 + h2 race would both call FLUSH/NOTIFY and shred each
    // other's pending fetch.
    if !try_acquire_file_chan(s) {
        return CacheLookup::Busy;
    }
    // Cache_alloc returns -1 if the existing entry is retained by
    // an in-flight reader — in that case we can't repurpose the
    // body_pool region without corrupting the reader's view.
    // Defer (Busy) and release the file_chan lock so progress can
    // still happen elsewhere; we'll retry next tick.
    if cache_alloc(s, route_idx as u8) < 0 {
        release_file_chan(s);
        return CacheLookup::Busy;
    }
    dev_channel_ioctl(
        &*s.syscalls,
        s.server.file_chan,
        IOCTL_FLUSH,
        core::ptr::null_mut(),
        0,
    );
    let mut pos = src_idx as u32;
    let pos_ptr = &mut pos as *mut u32 as *mut u8;
    dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr, 4);
    CacheLookup::Pending
}

/// Drive one tick of the cache fetch loop. Mirrors `Phase::CacheStream`
/// without touching `s.server.phase`. On `Ready`, the matched route's
/// `body_offset` / `body_len` are updated to point at the cached arena.
pub(crate) unsafe fn cache_fetch_step(s: &mut HttpState) -> CacheStepResult {
    if s.server.file_chan < 0 || s.server.cache_count == 0 {
        return CacheStepResult::Error;
    }
    let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
    let in_ready = poll > 0 && (poll as u32 & POLL_IN) != 0;
    let hup_pre = poll > 0 && (poll as u32 & POLL_HUP) != 0;
    if !in_ready && !hup_pre {
        return CacheStepResult::Pending;
    }

    let ce_idx = 0usize;
    let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ce_idx);
    let arena_off = ce.arena_offset as usize;
    let cur_len = ce.length as usize;
    let pool_cap = s.server.body_pool_cap as usize;
    let used = arena_off.saturating_add(cur_len);
    let space = pool_cap.saturating_sub(used);
    if space > 0 && !s.server.body_pool.is_null() && in_ready {
        let dst = s.server.body_pool.add(arena_off + cur_len);
        let to_read = space.min(SEND_BUF_SIZE);
        let n = ((*s.syscalls).channel_read)(s.server.file_chan, dst, to_read);
        if n > 0 {
            ce.length += n as u32;
            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(n as u32);
        }
    }

    // Re-poll AFTER the read so HUP only counts as EOF when no
    // more bytes are pending. The pre-read poll can show POLL_IN +
    // POLL_HUP simultaneously when there's still data to drain
    // — taking that as EOF prematurely truncates files larger than
    // SEND_BUF_SIZE (one read per tick is the plumbing limit).
    // Mirrors the h1 `Phase::CacheStream` path, which has always
    // got this right.
    let poll_after = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
    let in_after = poll_after > 0 && (poll_after as u32 & POLL_IN) != 0;
    let hup_after = poll_after > 0 && (poll_after as u32 & POLL_HUP) != 0;
    let eof = hup_after && !in_after;

    let new_len = ce.length as usize;
    let full = (arena_off + new_len) >= pool_cap;
    if eof || full {
        ce.flags |= CACHE_COMPLETE;
        // Retain on behalf of the imminent reader (the stream that
        // requested this fetch). Without this, a sibling cache
        // miss arriving in the same tick before the reader runs
        // could evict and overwrite the body_pool region.
        ce.retain = ce.retain.saturating_add(1);
        // Resolve the route from the CACHE ENTRY, not from
        // `cur_matched_route` on the active slot. h2's
        // `dispatch_request` mutates the slot's matched_route every
        // time it picks up a new pending stream; if the slot has
        // moved on to dispatching another stream while this fetch
        // was completing, `cur_matched_route` would point at the
        // wrong route and we'd publish the cache body's offset/len
        // there. The cache entry remembers which route it was
        // allocated for — that's the canonical answer.
        let ri = ce.route_index as usize;
        if ri < MAX_ROUTES {
            let r = &mut *s.server.routes.as_mut_ptr().add(ri);
            r.body_offset = ce.arena_offset;
            r.body_len = ce.length;
        }
        return CacheStepResult::Ready;
    }
    CacheStepResult::Pending
}
