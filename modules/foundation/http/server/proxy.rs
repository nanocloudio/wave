//! Proxy relay.
//!
//! A `HANDLER_PROXY` static route (`proxy_ip`/`proxy_port`) or a dynamic-route
//! match dials an upstream backend and relays bytes both ways WITHIN THE SLOT'S
//! EXISTING ARENAS: `recv_buf` is the client→backend window, `send_buf` the
//! backend→client window. No transformation, no extra buffering — content-length
//! and chunked bodies pass through as bytes.
//!
//! Reusing the arenas is what keeps a relayed connection the same memory cost as
//! a served one, so proxying does not change the module's working set. It also
//! means a slot is either serving or relaying, never both, which the `Proxy*`
//! phases encode.
//!
//! Backend selection is `super::routes`; this file owns the dial, the failover,
//! and the byte pump.

use super::super::connection::{NET_BUF_SIZE, NET_CMD_CONNECT, NET_CMD_SEND};
use super::super::wire::ws;
use super::response::{build_error, put_bytes, put_ipv4_decimal, put_u32_decimal};
use super::routes::{match_dyn_route, HANDLER_PROXY};
use super::{
    cur_recv_buf_mut_ptr, cur_recv_buf_ptr, cur_send_buf_mut_ptr, cur_send_buf_ptr, cur_slot,
    cur_slot_mut, current_slot_index, dev_millis, dev_requester_tag, find_slot_by_conn_id, log,
    net_send_conn, net_write_frame, reset_connection, set_cur_phase, HttpState, Phase,
    MAX_CONCURRENT_CONNS, MAX_DYN_ROUTES, NET_FRAME_HDR, RECV_BUF_SIZE, SEND_BUF_SIZE,
    SOCK_TYPE_STREAM,
};

/// Wall-clock budget for a backend connect before failover / 502.
pub(crate) const PROXY_CONNECT_TIMEOUT_MS: u32 = 10_000;

/// Find the slot whose upstream `backend_conn_id` matches `conn`.
pub(crate) unsafe fn find_slot_by_backend_conn(s: &HttpState, conn: u16) -> Option<usize> {
    let needle = conn as i32;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.backend_conn_id == needle {
            return Some(i);
        }
    }
    None
}

/// True while a slot is in a byte-relay phase (request already
/// forwarded). Demux stages backend→client bytes into `send_buf` only
/// in these phases.
#[inline(always)]
pub(crate) fn is_proxy_relay_phase(p: Phase) -> bool {
    matches!(p, Phase::ProxyRelayHeaders | Phase::ProxyRelayBody)
}

/// Dial the active slot's selected backend via the runtime
/// `NET_CMD_CONNECT` primitive — the exact payload the client side
/// uses (`[sock_type][ip:4][port:2][requester_tag]`), reused
/// server-side. Returns `true` when the CONNECT frame was written.
pub(crate) unsafe fn proxy_dial(s: &mut HttpState) -> bool {
    if s.net_out_chan < 0 {
        return false;
    }
    let (ip, port) = match cur_slot(s) {
        Some(c) => (c.proxy_be_ip, c.proxy_be_port),
        None => return false,
    };
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let ip_bytes = ip.to_le_bytes();
    let mut payload = [0u8; 8];
    payload[0] = SOCK_TYPE_STREAM;
    payload[1] = ip_bytes[0];
    payload[2] = ip_bytes[1];
    payload[3] = ip_bytes[2];
    payload[4] = ip_bytes[3];
    payload[5] = (port & 0xFF) as u8;
    payload[6] = (port >> 8) as u8;
    payload[7] = dev_requester_tag(sys);
    let wrote = net_write_frame(
        sys,
        chan,
        NET_CMD_CONNECT,
        payload.as_ptr(),
        8,
        buf,
        NET_BUF_SIZE,
    );
    wrote != 0
}

/// Enter the proxy relay for the active slot against a chosen backend.
/// `dyn_idx` is the dynamic-route index (for failover reselection) or
/// `-1` for a static `HANDLER_PROXY` route. Proxy responses are
/// close-delimited in v1 (no response parsing / keep-alive).
pub(crate) unsafe fn begin_proxy(s: &mut HttpState, ip: u32, port: u16, dyn_idx: i16) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.proxy_be_ip = ip;
        cur.proxy_be_port = port;
        cur.proxy_dyn_idx = dyn_idx;
        cur.proxy_attempt = 0;
        cur.backend_conn_id = -1;
        cur.proxy_connected = 0;
        cur.proxy_connect_failed = 0;
        cur.backend_closed = 0;
        cur.proxy_creq_off = 0;
        cur.keepalive = 0; // v1 relay is close-delimited
        cur.phase = Phase::ProxyConnect;
    }
}

/// A backend connect failed (error or timeout): one retry against the
/// next `ready=1` dynamic backend (advancing `rr_cursor`), else a
/// terminal 502. Counts `http.proxy.retries` / `http.proxy.5xx`.
pub(crate) unsafe fn proxy_connect_failed(s: &mut HttpState) {
    if let Some(idx) = current_slot_index(s) {
        if s.server.proxy_connect_owner == idx as i16 {
            s.server.proxy_connect_owner = -1;
        }
    }
    let (attempt, dyn_idx) = match cur_slot(s) {
        Some(c) => (c.proxy_attempt, c.proxy_dyn_idx),
        None => (2, -1),
    };
    if attempt == 0 && dyn_idx >= 0 && (dyn_idx as usize) < MAX_DYN_ROUTES {
        let next = s.server.dyn_routes.live[dyn_idx as usize].select_backend();
        if let Some((ip, port)) = next {
            s.server.proxy_retries = s.server.proxy_retries.wrapping_add(1);
            if let Some(cur) = cur_slot_mut(s) {
                cur.proxy_be_ip = ip;
                cur.proxy_be_port = port;
                cur.proxy_attempt = 1;
                cur.backend_conn_id = -1;
                cur.proxy_connected = 0;
                cur.proxy_connect_failed = 0;
                cur.phase = Phase::ProxyConnect;
            }
            return;
        }
    }
    s.server.proxy_5xx = s.server.proxy_5xx.wrapping_add(1);
    build_error(s, b"502 Bad Gateway", b"Backend unavailable\n");
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = Phase::DrainSend;
    }
}

/// Build the request head to forward to the backend into `send_buf`:
/// the parsed request line + headers with an appended
/// `X-Forwarded-For: <client-ip>` (net-new serialization — the relay
/// owns it). The Host header passes through unchanged (v1). Any client
/// body bytes already buffered after the head are compacted to the
/// front of `recv_buf` for the client→backend relay.
pub(crate) unsafe fn proxy_build_forward_head(s: &mut HttpState) {
    let (heo, recv_len, client_ip) = match cur_slot(s) {
        Some(c) => (c.header_end_off as usize, c.recv_len as usize, c.client_ip),
        None => return,
    };
    let recv = cur_recv_buf_ptr(s);
    let send = cur_send_buf_mut_ptr(s);
    if recv.is_null() || send.is_null() || heo < 4 {
        return;
    }
    // Keep everything up to (but not including) the terminating blank
    // line, so XFF splices in as the final header.
    let head_body = heo - 2;
    let mut off = 0usize;
    off = put_bytes(
        send,
        SEND_BUF_SIZE,
        off,
        core::slice::from_raw_parts(recv, head_body),
    );
    off = put_bytes(send, SEND_BUF_SIZE, off, b"X-Forwarded-For: ");
    off = put_ipv4_decimal(send, SEND_BUF_SIZE, off, client_ip);
    off = put_bytes(send, SEND_BUF_SIZE, off, b"\r\n\r\n");
    let leftover = recv_len.saturating_sub(heo);
    if leftover > 0 {
        let rbuf = cur_recv_buf_mut_ptr(s);
        core::ptr::copy(rbuf.add(heo), rbuf, leftover);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
        cur.proxy_creq_off = 0;
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}

/// One bidirectional relay tick: drain buffered client bytes to the
/// backend (`recv_buf`) and buffered backend bytes to the client
/// (`send_buf`). Tears the slot down once the backend has closed and
/// its last bytes have flushed to the client.
pub(crate) unsafe fn proxy_relay_step(s: &mut HttpState) {
    let (backend, client, recv_len, creq_off, send_len, send_off) = match cur_slot(s) {
        Some(c) => (
            c.backend_conn_id,
            c.conn_id,
            c.recv_len,
            c.proxy_creq_off,
            c.send_len,
            c.send_offset,
        ),
        None => return,
    };
    // client → backend
    if backend >= 0 && recv_len > creq_off {
        let remaining = (recv_len - creq_off) as usize;
        let sent = net_send_conn(
            s,
            backend as u16,
            cur_recv_buf_ptr(s).add(creq_off as usize),
            remaining,
        );
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.proxy_creq_off += sent as u16;
                if cur.proxy_creq_off >= cur.recv_len {
                    cur.recv_len = 0;
                    cur.proxy_creq_off = 0;
                }
            }
        }
    }
    // backend → client
    if send_len > send_off {
        let remaining = (send_len - send_off) as usize;
        let sent = net_send_conn(
            s,
            client as u16,
            cur_send_buf_ptr(s).add(send_off as usize),
            remaining,
        );
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
                if cur.send_offset >= cur.send_len {
                    cur.send_len = 0;
                    cur.send_offset = 0;
                }
            }
        }
    }
    // Teardown: backend closed + its bytes fully flushed → close the
    // client (`edge_anchored`: no session migration, §5).
    let (backend_closed, send_len2, send_off2) = match cur_slot(s) {
        Some(c) => (c.backend_closed, c.send_len, c.send_offset),
        None => return,
    };
    if backend_closed != 0 && send_len2 == send_off2 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
    }
}

/// Consult the dynamic-route table for a proxy match on the active
/// slot's Host + path (§5: host exact, then longest path-prefix, then
/// readiness-gated backend selection). Returns `true` when it took
/// over dispatch (started a relay or emitted a 502); `false` when no
/// dynamic route matched (caller falls back to its fixed surface).
pub(crate) unsafe fn try_begin_dyn_proxy(s: &mut HttpState) -> bool {
    let (heo, rp_ptr, rp_len, recv_ptr) = match cur_slot(s) {
        Some(c) => (
            c.header_end_off as usize,
            c.req_path.as_ptr(),
            c.req_path_len as usize,
            c.recv_buf as *const u8,
        ),
        None => return false,
    };
    if recv_ptr.is_null() || heo == 0 {
        return false;
    }
    let host = match ws::find_header_value(recv_ptr, heo, b"Host") {
        Some((o, n)) => core::slice::from_raw_parts(recv_ptr.add(o), n),
        None => &[],
    };
    let path = core::slice::from_raw_parts(rp_ptr, rp_len);
    let di = match_dyn_route(&s.server.dyn_routes, host, path);
    if di < 0 {
        return false;
    }
    match s.server.dyn_routes.live[di as usize].select_backend() {
        Some((ip, port)) => {
            begin_proxy(s, ip, port, di as i16);
            true
        }
        None => {
            // Matched a route but no `ready=1` backend (§5 readiness gate).
            s.server.proxy_5xx = s.server.proxy_5xx.wrapping_add(1);
            build_error(s, b"502 Bad Gateway", b"No ready backend\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            true
        }
    }
}

// ── Host-test hooks ───────────────────────────────────────────────────────
//
// Reach into a booted module's opaque `module_state` buffer so the harness can
// seed the client source address the `X-Forwarded-For` assertion needs, and read
// the `http.proxy.*` counters. No firmware symbol surface.

#[cfg(feature = "host-test")]
/// Seed the client source address (`X-Forwarded-For`) for the slot
/// currently owning `conn_id`. No-op if no slot owns it yet.
///
/// # Safety
/// See [`super::routes::test_inject_dyn_route`].
pub unsafe fn test_set_client_ip(state: *mut u8, conn_id: u16, ip: u32) {
    let s = &mut *(state as *mut HttpState);
    if let Some(idx) = find_slot_by_conn_id(s, conn_id) {
        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
        slot.client_ip = ip;
    }
}

#[cfg(feature = "host-test")]
/// `(http.proxy.retries, http.proxy.5xx)` cumulative counters.
///
/// # Safety
/// See [`super::routes::test_inject_dyn_route`].
pub unsafe fn test_proxy_metrics(state: *mut u8) -> (u32, u32) {
    let s = &*(state as *mut HttpState);
    (s.server.proxy_retries, s.server.proxy_5xx)
}
