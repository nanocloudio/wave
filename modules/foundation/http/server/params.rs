//! Param-time decode: the TLV blob → `ServerState`.
//!
//! Everything the server is configured with arrives once, before the first
//! tick, as a length-prefixed TLV blob whose tag numbers are declared by
//! `params_def!` in the module root. This file is the other half of those
//! declarations — one setter per tag, each named for the tag it decodes.
//!
//! Kept apart from `super::routes` on purpose: routes owns the shape of a route
//! row and the match that picks one, this owns how a row gets built. The split
//! also means every `unsafe` raw-pointer TLV read in the server lives in one
//! file, where the shared invariant — `d` points at `len` readable bytes, and
//! `idx` is bounds-checked against `MAX_ROUTES` before any write — is checkable
//! by reading straight down.
//!
//! Route bodies are the exception worth knowing: `parse_route_body` appends
//! into the `body_pool` rather than a fixed field. The pool is sized before
//! any setter runs, from the bytes the params declare for every `body:`
//! route (`scan_declared_bodies`), and admitted against the instance's heap
//! cap (`admit_body_pool`): a config whose bodies the instance cannot hold
//! is refused at construction with the route and the figures named, never
//! served truncated. `body:` is `str_chunked` — any number of ≤ 255-byte
//! TLV elements appended to one route — so a route's size is bounded only
//! by the params, which the composer no longer caps; this admission is the
//! bound.

use super::routes::{HANDLER_FS_FILE, HANDLER_FS_LIST};
use super::{
    dev_log, fmt_u32_raw, heap_alloc, heap_free, heap_realloc, hex_val, log, p_u16, p_u32, p_u8,
    HttpState, DEFAULT_BODY_POOL_SIZE, MAX_CONTENT_TYPE, MAX_DYN_PREFIX, MAX_FS_PATH, MAX_PATH,
    MAX_ROUTES,
};

// ── Body-pool admission ───────────────────────────────────────────────────

/// Params TLV tag of the instance's heap cap — the graph's `heap.arena_bytes`,
/// a u32 LE (fluxor `scheduler::HEAP_ARENA_TAG`). The loader sizes the heap
/// from it; the body budget is read from the same figure.
const HEAP_ARENA_TAG: u8 = 0xEF;

/// The file-cache region every instance's pool keeps past its inline bodies:
/// a `source:` route streams its file into the pool tail (`cache.rs`).
pub(crate) const CACHE_REGION: u32 = DEFAULT_BODY_POOL_SIZE as u32;

/// Construction refused: the declared bodies do not fit the instance.
const E_BODIES_TOO_BIG: i32 = -27;

/// The route a `body` TLV tag stages into: tag 2 (`body`) and the
/// `route_N_body` tags `11 + 10·N` (`params_def` in the module root). `None`
/// for any other tag, and for a route past this profile's `MAX_ROUTES`,
/// whose body `parse_route_body` drops.
#[inline]
pub(crate) fn body_tag_route(tag: u8) -> Option<usize> {
    let idx = if tag == 2 {
        0
    } else if (11..=81).contains(&tag) && (tag - 11).is_multiple_of(10) {
        ((tag - 11) / 10) as usize
    } else {
        return None;
    };
    if idx < MAX_ROUTES {
        Some(idx)
    } else {
        None
    }
}

/// What a params blob declares for the body pool, read before any setter
/// runs.
pub(crate) struct DeclaredBodies {
    /// Inline body bytes per route, in route order.
    pub(crate) per_route: [u64; MAX_ROUTES],
    /// Their sum.
    pub(crate) total: u64,
    /// The instance's `heap.arena_bytes`, or 0 when the graph gives none
    /// (the type's `module_arena_size` is the cap then).
    pub(crate) heap_cap: u32,
}

impl DeclaredBodies {
    pub(crate) const NONE: Self = Self {
        per_route: [0; MAX_ROUTES],
        total: 0,
        heap_cap: 0,
    };
}

/// Walk a TLV params blob exactly as `define_params!`' `parse_tlv` does
/// (entries from offset 4, an entry dispatched only when it fits, `0xFF`
/// ends) and total the body bytes each route will be given.
///
/// # Safety
/// `p` points at `len` readable bytes.
pub(crate) unsafe fn scan_declared_bodies(p: *const u8, len: usize) -> DeclaredBodies {
    let mut d = DeclaredBodies::NONE;
    if p.is_null() || len < 4 {
        return d;
    }
    let mut off = 4usize;
    while off + 2 <= len {
        let tag = *p.add(off);
        let elen = *p.add(off + 1) as usize;
        off += 2;
        if tag == 0xFF {
            break;
        }
        if off + elen <= len {
            if let Some(idx) = body_tag_route(tag) {
                if let Some(r) = d.per_route.get_mut(idx) {
                    *r += elen as u64;
                }
                d.total += elen as u64;
            } else if tag == HEAP_ARENA_TAG && elen == 4 {
                let v = p.add(off);
                d.heap_cap = u32::from_le_bytes([*v, *v.add(1), *v.add(2), *v.add(3)]);
            }
        }
        off += elen;
    }
    d
}

/// The inline-body bytes an instance with heap cap `heap_cap` can hold: its
/// cap, less what the arena keeps for everything else
/// (`arena_non_body_reserve`), less the file-cache region.
pub(crate) fn inline_body_limit(heap_cap: u32) -> u32 {
    heap_cap
        .saturating_sub(super::super::arena_non_body_reserve())
        .saturating_sub(CACHE_REGION)
}

/// Size the body pool from what the params declare, or refuse the config.
///
/// The pool is the declared inline bodies plus the file-cache region, in one
/// allocation. It must fit the instance's body budget — its heap cap
/// (`heap.arena_bytes`, else `module_arena_size`) less the rest of the
/// arena's reservation — so serving the bodies never eats the connection
/// working set. A config past that is refused, naming the route that crosses
/// the budget, the totals and the cap that would hold it. A config with no
/// inline bodies keeps the default pool, admitted as before.
///
/// # Safety
/// `s.syscalls` is bound.
pub(crate) unsafe fn admit_body_pool(s: &HttpState, d: &DeclaredBodies) -> Result<u32, i32> {
    if d.total == 0 {
        return Ok(CACHE_REGION);
    }
    let cap = if d.heap_cap != 0 {
        d.heap_cap
    } else {
        super::super::module_arena_size()
    };
    let limit = inline_body_limit(cap) as u64;
    let pool = d.total + CACHE_REGION as u64;
    if d.total <= limit && pool <= u32::MAX as u64 {
        return Ok(pool as u32);
    }
    // The route whose body carries the running total past the limit.
    let mut route = 0usize;
    let mut run = 0u64;
    let mut i = 0usize;
    while i < MAX_ROUTES {
        if let Some(n) = d.per_route.get(i) {
            run += *n;
            if *n > 0 && run > limit {
                route = i;
                break;
            }
        }
        i += 1;
    }
    let need_cap =
        (pool + super::super::arena_non_body_reserve() as u64).min(u32::MAX as u64) as u32;
    let mut m = LogLine::new();
    m.push(b"[http] refused: route ");
    m.num(route as u64);
    m.push(b" body brings inline bodies to ");
    m.num(d.total);
    m.push(b" B, past the ");
    m.num(limit);
    m.push(b" B this instance holds (heap cap ");
    m.num(cap as u64);
    m.push(b" B; set heap.arena_bytes to at least ");
    m.num(need_cap as u64);
    m.push(b")");
    m.emit(s);
    Err(E_BODIES_TOO_BIG)
}

/// Log a body pool the heap could not give although the budget admitted it.
///
/// # Safety
/// `s.syscalls` is bound.
pub(crate) unsafe fn refuse_unallocated_pool(s: &HttpState, pool_bytes: u32) {
    let mut m = LogLine::new();
    m.push(b"[http] refused: the heap could not give the ");
    m.num(pool_bytes as u64);
    m.push(b" B body pool the inline routes need");
    m.emit(s);
}

/// A fixed log line built without a panic path: bytes past the end are
/// dropped, a number is written only when it fits whole.
pub(crate) struct LogLine {
    buf: [u8; 256],
    len: usize,
}

impl LogLine {
    pub(crate) fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, b: &[u8]) {
        let mut i = 0;
        while i < b.len() {
            if let (Some(dst), Some(src)) = (self.buf.get_mut(self.len), b.get(i)) {
                *dst = *src;
                self.len += 1;
            }
            i += 1;
        }
    }

    pub(crate) fn num(&mut self, v: u64) {
        if self.len + 10 > self.buf.len() {
            return;
        }
        let v = v.min(u32::MAX as u64) as u32;
        // SAFETY: at least 10 bytes (u32::MAX's digits) remain at `len`.
        self.len += unsafe { fmt_u32_raw(self.buf.as_mut_ptr().add(self.len), v) };
    }

    pub(crate) unsafe fn emit(&self, s: &HttpState) {
        dev_log(&*s.syscalls, 1, self.buf.as_ptr(), self.len);
    }
}

/// Param setter for `routes_prefix` (TLV tag 90). An empty value
/// leaves the feature off. Copies up to `MAX_DYN_PREFIX` bytes.
///
/// # Safety
/// `d` points at `len` readable bytes (the TLV value).
pub(crate) unsafe fn set_routes_prefix(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(MAX_DYN_PREFIX);
    let dst = s.server.routes_prefix.as_mut_ptr();
    let mut i = 0;
    while i < n {
        *dst.add(i) = *d.add(i);
        i += 1;
    }
    s.server.routes_prefix_len = n as u16;
}

pub(crate) unsafe fn parse_route_path(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 {
        return;
    }
    let route = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = len.min(MAX_PATH);
    let mut i = 0;
    while i < n {
        route.path[i] = *d.add(i);
        i += 1;
    }
    route.path_len = n as u8;
    if (idx + 1) as u8 > s.server.route_count {
        s.server.route_count = (idx + 1) as u8;
    }
}

pub(crate) unsafe fn parse_route_body(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 || s.server.inline_body_refused != 0 {
        return;
    }
    if s.server.body_pool.is_null() {
        log(s, b"[http] parse_route_body: body_pool NULL");
        s.server.inline_body_refused = 1;
        return;
    }
    let offset = s.server.body_pool_used as usize;
    let cap = s.server.body_pool_cap as usize;
    let needed = offset + len;
    if needed > cap {
        // Params never reach this: `admit_body_pool` sized the pool for
        // every byte the params declare before any setter ran. A body from
        // anywhere else (the host-test hook below; a future PUT or bank-fed
        // body) grows the pool by doubling, so many small appends converge
        // to amortised O(1). Pinned by
        // `tests/harness/tests/http.rs`,
        // growing_the_body_pool_preserves_bodies_already_staged.
        let mut new_cap = cap.max(1);
        while new_cap < needed {
            new_cap = new_cap.saturating_mul(2);
        }
        let sys = s.syscalls;
        let new_pool = if new_cap > u32::MAX as usize {
            core::ptr::null_mut()
        } else {
            heap_realloc(&*sys, s.server.body_pool, new_cap as u32)
        };
        if new_pool.is_null() {
            // Fail closed: a body served cut short is corrupt JS or an
            // empty document that reads as a working route.
            let mut m = LogLine::new();
            m.push(b"[http] refused: route ");
            m.num(idx as u64);
            m.push(b" body needs a ");
            m.num(needed as u64);
            m.push(b" B body pool; the heap could not grow it past ");
            m.num(cap as u64);
            m.push(b" B");
            m.emit(s);
            s.server.inline_body_refused = 1;
            return;
        }
        s.server.body_pool = new_pool;
        s.server.body_pool_cap = new_cap as u32;
    }
    let mut i = 0;
    while i < len {
        *s.server.body_pool.add(offset + i) = *d.add(i);
        i += 1;
    }
    let route = &mut *s.server.routes.as_mut_ptr().add(idx);
    if route.body_len == 0 {
        route.body_offset = offset as u32;
    }
    route.body_len += len as u32;
    s.server.body_pool_used = (offset + len) as u32;
}

// ── Param-time setter helpers (called from mod.rs::params_def) ────────────

#[inline]
pub(crate) unsafe fn set_route_handler(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).handler = p_u8(d, len, 0, 0);
    }
}

/// A route's request-body ceiling, in KiB. One past
/// `reqbody::MAX_BODY_KIB_CEILING` is recorded and refused at construction,
/// never clamped: a ceiling quietly lowered is a deployment that refuses
/// uploads it was configured to take.
#[inline]
pub(crate) unsafe fn set_route_max_body(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        let kib = p_u32(d, len, 0, 0);
        if kib > super::reqbody::MAX_BODY_KIB_CEILING {
            s.server.route_body_refused = 1;
            return;
        }
        (*s.server.routes.as_mut_ptr().add(idx)).max_body_kib = kib;
    }
}

#[inline]
pub(crate) unsafe fn set_route_proxy_ip(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).proxy_ip = p_u32(d, len, 0, 0);
    }
}

#[inline]
pub(crate) unsafe fn parse_route_content_type(
    s: &mut HttpState,
    idx: usize,
    d: *const u8,
    len: usize,
) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = len.min(MAX_CONTENT_TYPE);
    let mut i = 0;
    while i < n {
        r.content_type[i] = *d.add(i);
        i += 1;
    }
    r.content_type_len = n as u8;
}

#[inline]
pub(crate) unsafe fn set_route_proxy_port(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).proxy_port = p_u16(d, len, 0, 0);
    }
}

#[inline]
pub(crate) unsafe fn set_route_source(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).source_index = p_u16(d, len, 0, 0xFFFF) as i16;
    }
}

/// Set a route's `fs_path` (filesystem path served via FS_CONTRACT).
/// Also flips the handler to `HANDLER_FS_FILE` so a route with
/// `fs_path:` configured serves through the FS provider without any
/// other YAML setup.
pub(crate) unsafe fn set_route_fs_path(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = if len > MAX_FS_PATH { MAX_FS_PATH } else { len };
    let mut i = 0usize;
    while i < n {
        r.fs_path[i] = *d.add(i);
        i += 1;
    }
    r.fs_path_len = n as u8;
    if n > 0 {
        r.handler = HANDLER_FS_FILE;
    }
}

/// Set a route's `fs_list` directory path. Storage shares the `fs_path`
/// field with `set_route_fs_path` (they're mutually exclusive at the
/// route level — `fs_list:` lists a directory as JSON, `fs_path:`
/// streams a single file). Flips the handler to `HANDLER_FS_LIST` so
/// a GET against the route returns a fresh `FS_READDIR`-built JSON
/// payload.
pub(crate) unsafe fn set_route_fs_list(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = if len > MAX_FS_PATH { MAX_FS_PATH } else { len };
    let mut i = 0usize;
    while i < n {
        r.fs_path[i] = *d.add(i);
        i += 1;
    }
    r.fs_path_len = n as u8;
    if n > 0 {
        r.handler = HANDLER_FS_LIST;
    }
}

/// Set the per-route extension filter consumed by `HANDLER_FS_LIST`.
/// Comma-separated, case-insensitive. Empty = list every regular
/// file the FS provider returns. No-op when the route isn't an
/// `fs_list:` route.
pub(crate) unsafe fn set_route_fs_filter(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = if len > 64 { 64 } else { len };
    let mut i = 0usize;
    while i < n {
        r.fs_filter[i] = *d.add(i);
        i += 1;
    }
    r.fs_filter_len = n as u8;
}

// ── Host-test hooks ───────────────────────────────────────────────────────
//
// The body pool is the one param target that can GROW, and no parameter
// reaches its growth path: `admit_body_pool` sizes the pool for every body byte
// the params declare before any is staged. These hooks stage a body directly so
// the doubling path is exercised. No firmware symbol surface.

#[cfg(feature = "host-test")]
/// Stage `body` into route `idx`'s slot of the body pool, exactly as the
/// `body` parameter setter does — but WITHOUT the TLV wire format's
/// one-byte length cap.
///
/// This exists to reach the pool's doubling-growth path, which no
/// parameter can reach: the pool is sized from the declared bodies before
/// any is staged. Growth was once untested — which is how a host-harness
/// allocator that dropped the old contents on `heap_realloc` went unnoticed
/// in three repositories at once — so it is pinned here: it becomes live the
/// moment a body arrives from anything other than params.
///
/// # Safety
/// See [`super::routes::test_inject_dyn_route`].
pub unsafe fn test_stage_route_body(state: *mut u8, idx: usize, body: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    parse_route_body(s, idx, body.as_ptr(), body.len());
}

#[cfg(feature = "host-test")]
/// Byte offset / length / pool capacity recorded for route `idx`, so a
/// test can assert the pool actually grew rather than silently truncated.
///
/// # Safety
/// See [`super::routes::test_inject_dyn_route`].
pub unsafe fn test_route_body_extent(state: *mut u8, idx: usize) -> (u32, u32, u32) {
    let s = &*(state as *const HttpState);
    (
        s.server.routes[idx].body_offset,
        s.server.routes[idx].body_len,
        s.server.body_pool_cap,
    )
}

#[cfg(feature = "host-test")]
/// The inline-body bytes an instance with heap cap `heap_cap` admits —
/// [`inline_body_limit`] for tests that probe the boundary.
pub fn test_inline_body_limit(heap_cap: u32) -> u32 {
    inline_body_limit(heap_cap)
}

#[cfg(feature = "host-test")]
/// The file-cache region every pool keeps past its inline bodies.
pub fn test_cache_region() -> u32 {
    CACHE_REGION
}

#[cfg(feature = "host-test")]
/// The WebSocket retention buffer's capacity, 0 when none was allocated.
///
/// # Safety
/// See [`super::routes::test_inject_dyn_route`].
pub unsafe fn test_retained_cap(state: *mut u8) -> u32 {
    (*(state as *const HttpState)).server.retained_cap
}
