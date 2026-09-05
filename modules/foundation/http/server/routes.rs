//! Routing — the route table in both its forms, and the match that picks a row.
//!
//! Two arenas, one question. The STATIC arena (`Route`, `ServerState.routes`)
//! is programmed once from the TLV param blob and matched on path alone. The
//! DYNAMIC arena (`DynRoute`, `DynRoutes`) is programmed at runtime by a table
//! consumer off the `/dataplane/edge/<ns>/<name>` prefix and matched on host
//! *and* path, with weights and readiness per backend.
//!
//! A request consults them in that order: the static
//! arena first, then the dynamic table, so a compiled route always outranks a
//! programmed one. `HANDLER_*` names what a matched row does; the subsystem
//! that does it lives elsewhere (`super::body`, `super::proxy`, `super::ws`).
//!
//! Route rows are built by `super::params`, not here — this file owns their
//! shape and their matching, not their configuration.

use super::{
    cur_slot, dyn_field, dyn_u32, hex_val, HttpState, TableSink, MAX_CONTENT_TYPE, MAX_DYN_KEY,
    MAX_DYN_ROUTES, MAX_FS_PATH, MAX_PATH, MAX_ROUTES, MAX_ROUTE_BACKENDS,
};

// ── Handler kinds (stored in Route.handler) ───────────────────────────────

pub(crate) const HANDLER_STATIC: u8 = 0;
pub(crate) const HANDLER_TEMPLATE: u8 = 1;
pub(crate) const HANDLER_FILE: u8 = 2;
pub(crate) const HANDLER_PROXY: u8 = 3;
pub(crate) const HANDLER_WEBSOCKET: u8 = 4;
/// Like `HANDLER_WEBSOCKET` (101 upgrade and full RFC 6455 framing), but
/// instead of echoing data frames internally, route them to the module's
/// `ws_out` port as `WsFrame` records and queue outbound frames from the
/// `ws_in` port. Lets a downstream module own application-level WS
/// semantics (chat, command stream, raster bridge, …) while this module
/// keeps owning HTTP and the WS protocol envelope.
pub(crate) const HANDLER_WEBSOCKET_FANOUT: u8 = 5;
/// Like `HANDLER_FILE` but with a config-time fixed `source_index`
/// instead of one parsed from the URL. Streams the asset's bytes
/// straight through `send_buf` without staging them in `body_pool`,
/// so multi-MiB payloads (WASM bundles, large media) aren't capped
/// by the body-pool size. Used for routes declared with
/// `source: <port>` + `source_index: N` + `stream: true` in YAML.
pub(crate) const HANDLER_STREAM: u8 = 6;
/// Serve a file by path through the FS_CONTRACT provider (fat32 on
/// bare-metal, linux_fs_dispatch on the host). The route declares an
/// absolute `fs_path:` and the http module opens it via
/// `provider_call(-1, FS_OPEN, …)`, queries `FS_STAT` for the
/// Content-Length, then streams the body via `FS_READ` chunks
/// directly into `send_buf`.
pub(crate) const HANDLER_FS_FILE: u8 = 7;
/// Directory listing as JSON, served via the FS provider's
/// `FS_OPENDIR` / `FS_READDIR` ops. The route's `fs_path` holds the
/// directory path; `fs_filter` (optional) holds a comma-separated
/// case-insensitive extension list (`.mp3,.wav,.aac`) — empty means
/// every regular file is listed. The response is a one-shot JSON
/// payload (`{"items":["song1.mp3","song2.wav",…]}`) built into
/// `send_buf` at request time so new files dropped into the directory
/// appear on the next GET. Subdirectories are skipped. Used by the
/// browser-side image_viewer / audio_player launchers to enumerate
/// the asset bank without bespoke handler code.
pub(crate) const HANDLER_FS_LIST: u8 = 8;

/// gRPC unary echo — the server half of the gRPC transport composition whose
/// client half is `client_h2.rs` (`grpc` param). Answers any method on the
/// route with `:status 200`, `content-type: application/grpc`, the request's
/// Length-Prefixed Message echoed back, and a trailing `grpc-status: 0`.
///
/// Deliberately method-AGNOSTIC. `docs/specification.md` keeps "service
/// semantics, protobuf schemas, and method dispatch" with the application, so
/// this is a grpcbin-shaped echo for load and conformance work — not an RPC
/// framework. HTTP/2 only: gRPC has no HTTP/1 binding.
pub(crate) const HANDLER_GRPC: u8 = 10;

/// Hand the request to a downstream module and serve whatever it returns.
///
/// The counterpart to `HANDLER_WEBSOCKET_FANOUT` for ordinary request/response
/// HTTP: the request goes out on `req_out` as an `HttpRequest` envelope and the
/// answer comes back on `resp_in` as an `HttpResponse`, correlated by
/// `(conn_id, stream_id)`. This module keeps owning HTTP; the application keeps
/// owning what the request means.
///
/// Method-AGNOSTIC by design, and for the same reason `HANDLER_GRPC` is: the
/// route table matches on path, and `docs/specification.md` places method
/// dispatch with the application. A route declaring this handler receives GET,
/// PUT, DELETE and everything else alike, and answering 405 to the ones it does
/// not implement is the application's call, not the gateway's.
pub(crate) const HANDLER_APP: u8 = 11;

/// WebSocket fan-out for SESSION protocols: identical wiring to
/// `HANDLER_WEBSOCKET_FANOUT` (Upgrade accepted, inbound → `ws_out`,
/// outbound ← `ws_in`) but retention replay is suppressed — a new
/// connection must NEVER receive envelopes produced for a previous
/// session. Fan-out retention exists for idempotent presentation
/// state (rasters, telemetry snapshots); replaying a session
/// protocol's frames (e.g. an auth gate's AUTH_OK) to a fresh,
/// unauthenticated subscriber is wrong and surfaced live as one
/// session's replies delivered into the next.
pub(crate) const HANDLER_WEBSOCKET_SESSION: u8 = 9;

/// Like `HANDLER_WEBSOCKET_SESSION`, but the upgrade is not this module's
/// to grant: the request is reported on `ws_admit_out` and the 101 is
/// composed only when `ws_admit_in` answers accept.
///
/// The distinction that matters is WHEN. A gate downstream of a completed
/// upgrade can refuse to act on frames, but the socket is already open and
/// the peer already believes it is talking to the application. Here nothing
/// above ever sees a frame from a connection it did not admit, and a refusal
/// is an HTTP status the browser's `WebSocket` constructor reports as a
/// failure rather than a connection that opens and then goes quiet.
pub(crate) const HANDLER_WEBSOCKET_ADMIT: u8 = 12;

// ── The static route arena ────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct Route {
    pub(crate) proxy_ip: u32,
    /// Byte offset of this route's body within `body_pool`. Widened
    /// to u32 so the pool can grow past 64 KB on aarch64 hosts that
    /// configure many or large templates.
    pub(crate) body_offset: u32,
    pub(crate) body_len: u32,
    pub(crate) proxy_port: u16,
    pub(crate) path_len: u8,
    pub(crate) handler: u8,
    pub(crate) source_index: i16,
    pub(crate) content_type_len: u8,
    pub(crate) fs_path_len: u8,
    /// Length of `fs_filter`; 0 means accept every entry returned by
    /// `FS_READDIR`. Comma-separated, case-insensitive extension list.
    pub(crate) fs_filter_len: u8,
    pub(crate) path: [u8; MAX_PATH],
    pub(crate) content_type: [u8; MAX_CONTENT_TYPE],
    /// Absolute filesystem path served by `HANDLER_FS_FILE` (a single
    /// file) or `HANDLER_FS_LIST` (a directory to enumerate as JSON).
    /// Populated by `set_route_fs_path` / `set_route_fs_list`.
    pub(crate) fs_path: [u8; MAX_FS_PATH],
    /// Extension filter for `HANDLER_FS_LIST` (e.g. `.mp3,.wav,.aac`).
    /// Compared case-insensitively against each filename's tail.
    pub(crate) fs_filter: [u8; 64],
}

impl Route {
    pub(crate) const fn new() -> Self {
        Self {
            proxy_ip: 0,
            body_offset: 0,
            body_len: 0,
            proxy_port: 0,
            path_len: 0,
            handler: 0,
            source_index: -1,
            content_type_len: 0,
            fs_path_len: 0,
            fs_filter_len: 0,
            path: [0; MAX_PATH],
            content_type: [0; MAX_CONTENT_TYPE],
            fs_path: [0; MAX_FS_PATH],
            fs_filter: [0; 64],
        }
    }

    /// Per-route Content-Type bytes if the route declared one,
    /// otherwise the supplied default. Static-body routes typically
    /// pass `b"text/html"` as the default to preserve the historical
    /// behavior.
    pub(crate) fn content_type_or<'a>(&'a self, default: &'a [u8]) -> &'a [u8] {
        let n = self.content_type_len as usize;
        if n == 0 || n > MAX_CONTENT_TYPE {
            default
        } else {
            &self.content_type[..n]
        }
    }
}

pub(crate) unsafe fn match_route(s: &HttpState) -> i8 {
    let cur = match cur_slot(s) {
        Some(c) => c,
        None => return -1,
    };
    match_route_path(s, cur.req_path.as_ptr(), cur.req_path_len as usize)
}

/// Path-based variant of `match_route` for callers that need to
/// resolve a route without mutating `cur_slot.req_path` first
/// (notably H2's `needs_exclusive_for_request`, which must check
/// the same matching rules dispatch will apply but is called
/// before the active slot is committed to a particular stream's
/// path). Returns the route index, or -1 if no route matches.
pub(crate) unsafe fn match_route_path(s: &HttpState, req: *const u8, plen: usize) -> i8 {
    // Routes are exact-match by default. A route that ends in '/' is
    // treated as a prefix match (so `/api/` matches `/api/foo`), but a
    // bare `/` is exact-only — otherwise it would swallow every
    // unmatched path including `/favicon.ico`, returning the wrong
    // body on requests that should have 404'd. Among prefix-eligible
    // candidates the longest-matching wins; ties resolve to the lower
    // index. Returns -1 when no route matches → caller returns 404.
    let mut best: i8 = -1;
    let mut best_len: usize = 0;
    let mut i = 0u8;
    while (i as usize) < s.server.route_count as usize {
        let route = &*s.server.routes.as_ptr().add(i as usize);
        let rlen = route.path_len as usize;
        if rlen == 0 {
            i += 1;
            continue;
        }
        let path_ptr = route.path.as_ptr();
        // Exact match wins outright.
        if rlen == plen {
            let mut j = 0;
            let mut ok = true;
            while j < rlen {
                if *req.add(j) != *path_ptr.add(j) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok {
                return i as i8;
            }
        }
        // Prefix match: requires the route path to end with '/' AND
        // the request to be strictly longer. Skips short root '/'.
        //
        // ...except for HANDLER_APP, where a bare `/` IS a catch-all. The
        // exclusion exists because a bare `/` static route would swallow
        // `/favicon.ico` and answer it with the wrong body — a hazard that
        // needs a route to have a fixed body in the first place. An
        // application route has none: it forwards the path and the
        // application decides, so "everything under /" is a coherent and
        // useful configuration rather than an accident.
        let route_is_prefix =
            (rlen >= 2 || route.handler == HANDLER_APP) && *path_ptr.add(rlen - 1) == b'/';
        if route_is_prefix && plen > rlen && rlen > best_len {
            let mut j = 0;
            let mut ok = true;
            while j < rlen {
                if *req.add(j) != *path_ptr.add(j) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok {
                best = i as i8;
                best_len = rlen;
            }
        }
        // HANDLER_FS_LIST routes implicitly serve individual files at
        // `<route_path>/<filename>` (in addition to the JSON listing
        // they serve at the exact route path). The implicit-prefix
        // matcher fires only when the route path does NOT already
        // end in '/' (otherwise the explicit-prefix branch above
        // covers it) and the next byte after the prefix is '/'
        // (the listing-vs-file separator). The handler decides the
        // listing-vs-file split based on whether req == route_path.
        if !route_is_prefix
            && route.handler == HANDLER_FS_LIST
            && plen > rlen + 1
            && rlen > best_len
            && *req.add(rlen) == b'/'
        {
            let mut j = 0;
            let mut ok = true;
            while j < rlen {
                if *req.add(j) != *path_ptr.add(j) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok {
                best = i as i8;
                best_len = rlen;
            }
        }
        i += 1;
    }
    best
}

/// Map a request path's file-extension suffix to a MIME type.
/// Returns an empty slice when no extension is recognised — caller
/// falls back to `application/octet-stream`.
///
/// Used by the AwaitFsStat content-type resolver when the matched
/// route has no explicit `content_type:` (HANDLER_FS_LIST file-serve
/// path — see the dual-mode dispatch). Recognises the common image
/// / audio / web mime types the scenario host pages serve plus a
/// few generic text formats. Anything outside this small whitelist
/// falls through to octet-stream — sniffing arbitrary bytes is a
/// bigger ABI question we don't take a position on here.
pub(crate) unsafe fn content_type_from_path(path: *const u8, plen: usize) -> &'static [u8] {
    // Find the last '.' in the path (after the last '/').
    let mut dot: Option<usize> = None;
    let mut last_slash: usize = 0;
    let mut i = 0;
    while i < plen {
        let b = *path.add(i);
        if b == b'/' {
            last_slash = i + 1;
            dot = None;
        } else if b == b'.' {
            dot = Some(i);
        }
        i += 1;
    }
    let start = match dot {
        Some(d) if d + 1 > last_slash => d + 1,
        _ => return &[],
    };
    let ext_len = plen - start;
    if ext_len == 0 || ext_len > 8 {
        return &[];
    }
    // ASCII-lowercase scratch.
    let mut buf = [0u8; 8];
    for (k, slot) in buf.iter_mut().enumerate().take(ext_len) {
        let mut b = *path.add(start + k);
        if b.is_ascii_uppercase() {
            b += 32;
        }
        *slot = b;
    }
    let ext = &buf[..ext_len];
    match ext {
        b"html" | b"htm" => b"text/html",
        b"css" => b"text/css",
        b"js" | b"mjs" => b"application/javascript",
        b"json" => b"application/json",
        b"wasm" => b"application/wasm",
        b"png" => b"image/png",
        b"jpg" | b"jpeg" => b"image/jpeg",
        b"gif" => b"image/gif",
        b"bmp" => b"image/bmp",
        b"webp" => b"image/webp",
        b"svg" => b"image/svg+xml",
        b"ico" => b"image/x-icon",
        b"wav" => b"audio/wav",
        b"mp3" => b"audio/mpeg",
        b"aac" => b"audio/aac",
        b"ogg" => b"audio/ogg",
        b"mp4" => b"video/mp4",
        b"txt" => b"text/plain",
        b"xml" => b"application/xml",
        _ => &[],
    }
}

// ── The dynamic route arena ───────────────────────────────────────────────
//
// Rows are programmed at runtime by the table consumer from the compiled
// `/dataplane/edge/<ns>/<name>` prefix, one key per route carrying the full
// backend set:
//
//   host=<h>;path=<prefix>;be=<ip>:<port>:<w>:<r>,<ip>:<port>:<w>:<r>,…
//
// Host matching, weights and readiness are net-new capabilities the static
// matcher does not have. The relay (`HANDLER_PROXY`, `super::proxy`) dials the
// selected backend and streams both ways; this table
// is its runtime backend source.

/// Host header buffer per dynamic route.
pub(crate) const MAX_DYN_HOST: usize = 64;
/// One backend of a dynamic route.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Backend {
    pub(crate) ip: u32,
    pub(crate) port: u16,
    pub(crate) weight: u8,
    pub(crate) ready: bool,
}

impl Backend {
    const fn new() -> Self {
        Self {
            ip: 0,
            port: 0,
            weight: 0,
            ready: false,
        }
    }
}

/// A runtime-programmed proxy route: host + path prefix + a weighted,
/// readiness-gated backend set, plus a round-robin cursor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DynRoute {
    pub(crate) key: [u8; MAX_DYN_KEY],
    pub(crate) host: [u8; MAX_DYN_HOST],
    pub(crate) path: [u8; MAX_PATH],
    pub(crate) backends: [Backend; MAX_ROUTE_BACKENDS],
    pub(crate) key_len: u8,
    pub(crate) host_len: u8,
    pub(crate) path_len: u8,
    pub(crate) backend_count: u8,
    /// Weighted-round-robin cursor. u16 to keep modulo bias small; the
    /// distribution is best-effort under churn and converges.
    pub(crate) rr_cursor: u16,
    /// 1 when this slot holds a live route.
    pub(crate) used: u8,
}

impl DynRoute {
    pub(crate) const fn new() -> Self {
        Self {
            key: [0; MAX_DYN_KEY],
            host: [0; MAX_DYN_HOST],
            path: [0; MAX_PATH],
            backends: [Backend::new(); MAX_ROUTE_BACKENDS],
            key_len: 0,
            host_len: 0,
            path_len: 0,
            backend_count: 0,
            rr_cursor: 0,
            used: 0,
        }
    }

    fn key(&self) -> &[u8] {
        &self.key[..self.key_len as usize]
    }
    pub(crate) fn host(&self) -> &[u8] {
        &self.host[..self.host_len as usize]
    }
    pub(crate) fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    /// Weighted round-robin over `ready` backends with `weight > 0`.
    /// Advances `rr_cursor` by one each call; over `total_weight` calls
    /// the distribution matches the weights. Returns `(ip, port)` or
    /// `None` when no backend is ready.
    pub fn select_backend(&mut self) -> Option<(u32, u16)> {
        let mut total: u32 = 0;
        for b in &self.backends[..self.backend_count as usize] {
            if b.ready && b.weight > 0 {
                total += b.weight as u32;
            }
        }
        if total == 0 {
            return None;
        }
        let mut target = self.rr_cursor as u32 % total;
        self.rr_cursor = self.rr_cursor.wrapping_add(1);
        for b in &self.backends[..self.backend_count as usize] {
            if b.ready && b.weight > 0 {
                let w = b.weight as u32;
                if target < w {
                    return Some((b.ip, b.port));
                }
                target -= w;
            }
        }
        None
    }
}

/// The dynamic-route arena plus its rebuild shadow. The
/// table_consumer helper fills `shadow` during a relist and
/// `swap_shadow` promotes it atomically; live requests only ever see a
/// whole, consistent `live` table.
#[repr(C)]
pub struct DynRoutes {
    pub(crate) live: [DynRoute; MAX_DYN_ROUTES],
    pub(crate) shadow: [DynRoute; MAX_DYN_ROUTES],
    /// Cumulative rows/backends dropped on overflow — mirrored to the
    /// `http.routes.dropped` telemetry counter: a reader surfaces
    /// degradation through telemetry, never a store key.
    pub(crate) dropped: u32,
}

impl DynRoutes {
    pub(crate) const fn new() -> Self {
        Self {
            live: [DynRoute::new(); MAX_DYN_ROUTES],
            shadow: [DynRoute::new(); MAX_DYN_ROUTES],
            dropped: 0,
        }
    }

    fn arena(&mut self, shadow: bool) -> &mut [DynRoute; MAX_DYN_ROUTES] {
        if shadow {
            &mut self.shadow
        } else {
            &mut self.live
        }
    }
}

/// Parse a dotted-quad IPv4 (`a.b.c.d`) into a big-endian-packed u32
/// (`a<<24 | b<<16 | c<<8 | d`).
fn dyn_ipv4(b: &[u8]) -> u32 {
    let mut octets = [0u32; 4];
    let mut oi = 0usize;
    let mut cur = 0u32;
    let mut seen = false;
    for &c in b {
        if c == b'.' {
            if oi < 4 {
                octets[oi] = cur & 0xFF;
            }
            oi += 1;
            cur = 0;
            seen = false;
        } else if c.is_ascii_digit() {
            cur = cur.wrapping_mul(10).wrapping_add((c - b'0') as u32);
            seen = true;
        } else {
            break;
        }
    }
    if seen && oi < 4 {
        octets[oi] = cur & 0xFF;
    }
    (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
}

/// Fill a `DynRoute` slot from `key` + compact `value`
/// (`host=…;path=…;be=<ip>:<port>:<w>:<r>,…`). Returns the number of
/// backends dropped because the set exceeded `MAX_ROUTE_BACKENDS`.
fn dyn_fill(dst: &mut DynRoute, key: &[u8], value: &[u8]) -> u32 {
    *dst = DynRoute::new();
    let kn = key.len().min(MAX_DYN_KEY);
    dst.key[..kn].copy_from_slice(&key[..kn]);
    dst.key_len = kn as u8;

    if let Some(h) = dyn_field(value, b"host=") {
        let n = h.len().min(MAX_DYN_HOST);
        dst.host[..n].copy_from_slice(&h[..n]);
        dst.host_len = n as u8;
    }
    if let Some(p) = dyn_field(value, b"path=") {
        let n = p.len().min(MAX_PATH);
        dst.path[..n].copy_from_slice(&p[..n]);
        dst.path_len = n as u8;
    }

    let mut dropped = 0u32;
    if let Some(be) = dyn_field(value, b"be=") {
        let mut start = 0usize;
        while start <= be.len() {
            let end = be[start..]
                .iter()
                .position(|&b| b == b',')
                .map(|i| start + i)
                .unwrap_or(be.len());
            let seg = &be[start..end];
            if !seg.is_empty() {
                // `<ip>:<port>:<w>:<r>`
                let mut it = seg.split(|&b| b == b':');
                let ip = it.next().map(dyn_ipv4).unwrap_or(0);
                let port = it.next().map(dyn_u32).unwrap_or(0) as u16;
                let weight = it.next().map(dyn_u32).unwrap_or(1);
                let ready = it.next().map(dyn_u32).unwrap_or(1);
                if (dst.backend_count as usize) < MAX_ROUTE_BACKENDS {
                    let i = dst.backend_count as usize;
                    dst.backends[i] = Backend {
                        ip,
                        port,
                        weight: weight.min(255) as u8,
                        ready: ready != 0,
                    };
                    dst.backend_count += 1;
                } else {
                    dropped += 1;
                }
            }
            if end >= be.len() {
                break;
            }
            start = end + 1;
        }
    }
    dropped
}

impl TableSink for DynRoutes {
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool) {
        // Reuse an existing slot with this key, else the first free one.
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
                // Arena full — serve what fits, count the drop.
                self.dropped = self.dropped.wrapping_add(1);
                return;
            }
        };
        let dropped = dyn_fill(&mut arena[slot], key, value);
        arena[slot].used = 1;
        if dropped > 0 {
            self.dropped = self.dropped.wrapping_add(dropped);
        }
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
        // Atomic promotion: one whole-arena copy. Requests are only
        // served in separate step invocations, never mid-swap.
        self.live = self.shadow;
    }
}

// Host-test surface: the harness constructs and drives the DynRoute
// arena directly to exercise matching / selection / overflow without a
// full HttpState. No firmware symbol surface (the module is private
// off `host-test`).
#[cfg(feature = "host-test")]
impl DynRoutes {
    pub fn test_new() -> Self {
        Self::new()
    }
    /// Program one live route from a compiled key + value.
    pub fn test_program(&mut self, key: &[u8], value: &[u8]) {
        self.upsert(key, value, false);
    }
    /// Remove one live route by key.
    pub fn test_remove(&mut self, key: &[u8]) {
        self.remove(key, false);
    }
    pub fn test_dropped(&self) -> u32 {
        self.dropped
    }
    /// Mutable access to a live slot (for selection tests).
    pub fn test_live_mut(&mut self, i: usize) -> &mut DynRoute {
        &mut self.live[i]
    }
    /// Backend count on a live slot.
    pub fn test_backend_count(&self, i: usize) -> usize {
        self.live[i].backend_count as usize
    }
}

/// Match a request `host`/`path` against the dynamic-route table: host
/// must match exactly (byte-wise), then the longest path prefix wins
/// (an empty route path matches any path). Returns the live index, or
/// `-1` when none match. Consulted after the static arena.
pub fn match_dyn_route(dyn_routes: &DynRoutes, host: &[u8], path: &[u8]) -> i32 {
    let mut best: i32 = -1;
    let mut best_len: usize = 0;
    for (i, r) in dyn_routes.live.iter().enumerate() {
        if r.used != 1 || r.host() != host {
            continue;
        }
        let rp = r.path();
        let matches = rp.is_empty() || (path.len() >= rp.len() && &path[..rp.len()] == rp);
        if matches && (best < 0 || rp.len() > best_len) {
            best = i as i32;
            best_len = rp.len();
        }
    }
    best
}

#[cfg(feature = "host-test")]
/// Program one live dynamic route (`key` + compact `value`) directly
/// into a booted http module's arena, as if the table-consumer applied
/// it. `state` is the harness `module_state` pointer.
///
/// # Safety
/// `state` must point at a live `HttpState` (a booted http module's
/// state buffer).
pub unsafe fn test_inject_dyn_route(state: *mut u8, key: &[u8], value: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    s.server.dyn_routes.upsert(key, value, false);
}
