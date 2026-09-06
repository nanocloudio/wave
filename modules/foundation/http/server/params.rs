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
//! into the growable `body_pool` rather than a fixed field, so it is the one
//! setter that can allocate.

use super::routes::{HANDLER_FS_FILE, HANDLER_FS_LIST};
use super::{
    heap_alloc, heap_free, heap_realloc, hex_val, log, p_u16, p_u32, p_u8, HttpState,
    MAX_CONTENT_TYPE, MAX_DYN_PREFIX, MAX_FS_PATH, MAX_PATH, MAX_ROUTES,
};

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
    if idx >= MAX_ROUTES || len == 0 {
        return;
    }
    if s.server.body_pool.is_null() {
        log(s, b"[http] parse_route_body: body_pool NULL");
        return;
    }
    let offset = s.server.body_pool_used as usize;
    let cap = s.server.body_pool_cap as usize;
    let needed = offset + len;
    if needed > cap {
        // Grow the pool exponentially (doubling) until it fits, so
        // many small `parse_route_body` calls converge to amortised
        // O(1) regardless of total body size. Heap exhaustion drops
        // the bytes quietly — caller has no error path.
        //
        // CURRENTLY UNREACHABLE, and worth knowing before trusting it. Bodies
        // arrive only via `define_params!`, and the SDK's TLV element length is
        // one byte (`../fluxor/modules/sdk/runtime/params.rs`: `*p.add(off + 1) as usize`), so the
        // pool cannot exceed `MAX_ROUTES` × 255 ≈ 2 KB — against a
        // `DEFAULT_BODY_POOL_SIZE` of 256 KiB (host), 32 KiB (embedded), 48 KiB
        // (wasm). Nothing can make `needed > cap` true today, which is why this
        // branch cannot be entered by any parameter. It IS tested: the
        // `test_stage_route_body` hook below stages a body by length rather than
        // through a TLV, and
        // `tests/harness/tests/http.rs`, growing_the_body_pool_preserves_bodies_already_staged
        // drives growth through it and asserts an already-staged route still
        // serves its body afterwards. Kept and pinned rather than deleted because
        // a multi-byte length or a non-param body source (a PUT into a route, a
        // bank-fed body) makes it live immediately.
        let mut new_cap = cap.max(1);
        while new_cap < needed {
            new_cap = new_cap.saturating_mul(2);
        }
        let sys = s.syscalls;
        let new_pool = heap_realloc(&*sys, s.server.body_pool, new_cap as u32);
        if new_pool.is_null() {
            // Fall back to the truncate-at-cap behaviour so the
            // server still boots; the un-stored body bytes are
            // dropped.
            let remaining = cap - offset;
            if remaining == 0 {
                return;
            }
            let n = len.min(remaining);
            let mut i = 0;
            while i < n {
                *s.server.body_pool.add(offset + i) = *d.add(i);
                i += 1;
            }
            let route = &mut *s.server.routes.as_mut_ptr().add(idx);
            if route.body_len == 0 {
                route.body_offset = offset as u32;
            }
            route.body_len += n as u32;
            s.server.body_pool_used = (offset + n) as u32;
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
// The body pool is the one param target that GROWS, and no parameter can reach
// its growth path: `parse_tlv` reads each element length from a single byte
// (`../fluxor/modules/sdk/runtime/params.rs`), so params top out around `MAX_ROUTES` × 255 ≈ 2 KB
// against a `DEFAULT_BODY_POOL_SIZE` of 256 KiB. These hooks stage a body
// directly so the doubling path is exercised. No firmware symbol surface.

#[cfg(feature = "host-test")]
/// Stage `body` into route `idx`'s slot of the body pool, exactly as the
/// `body` parameter setter does — but WITHOUT the TLV wire format's
/// one-byte length cap.
///
/// This exists to reach the pool's doubling-growth path, which no
/// parameter can reach: `parse_tlv` reads its element length from a
/// single byte (`../fluxor/modules/sdk/runtime/params.rs`), so params top out at
/// `MAX_ROUTES` × 255 ≈ 2 KB against a `DEFAULT_BODY_POOL_SIZE` of
/// 256 KiB. Growth is therefore unreachable in production today and was
/// consequently untested — which is how a host-harness allocator that
/// dropped the old contents on `heap_realloc` went unnoticed in three
/// repositories at once — every one of them exercising the path only through
/// the same test double. The growth
/// code is real and becomes live the moment a body arrives from anything
/// other than a one-byte-length TLV, so it is pinned here rather than
/// left to be discovered.
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
