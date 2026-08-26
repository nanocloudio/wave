//! HTTP client — connects to a peer, issues a request, streams the
//! response body to the module's data output channel.
//!
//! This file is the core: `ClientState`, the phase enum, param decode, and the
//! small helpers every generation shares. Each generation's state machine is its
//! own file. Pure-byte parse and build helpers come from `super::wire`; framing
//! constants come from `super::connection`.

// Per-generation front ends onto this core, one file each — the same shape as
// `super::server`. `h3` rides Fluxor's `mux` contract rather than net_proto, so
// it shares this core's shape but not its `ClientState`.
pub(crate) mod h1;
#[cfg(feature = "h2")]
pub(crate) mod h2;
#[cfg(all(feature = "h3", not(feature = "host-test")))]
pub(crate) mod h3;
#[cfg(all(feature = "h3", feature = "host-test"))]
pub mod h3;

use super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_CLOSE, NET_CMD_CONNECT, NET_CMD_SEND, NET_MSG_CLOSED,
    NET_MSG_CONNECTED, NET_MSG_DATA, NET_MSG_ERROR,
};
use super::wire;
use super::HttpState;
use super::{
    dev_channel_port, dev_log, dev_millis, dev_requester_tag, net_read_frame,
    net_read_frame_aligned, net_write_frame, E_AGAIN, NET_FRAME_HDR, POLL_IN, POLL_OUT,
    SOCK_TYPE_STREAM,
};

// ── Sizes / capacities ─────────────────────────────────────────────────────

pub(crate) const RECV_BUF_SIZE: usize = 2048;
pub(crate) const MAX_PATH_LEN: usize = 128;
pub(crate) const REQUEST_BUF_SIZE: usize = 256;
pub(crate) const REQUEST_BODY_SIZE: usize = 256;

pub(crate) const CONNECT_TIMEOUT_MS: u64 = 10_000;

// ── Error codes returned from step ─────────────────────────────────────────

pub(crate) const E_NET_FAILED: i32 = -30;
pub(crate) const E_CONNECT_FAILED: i32 = -31;
pub(crate) const E_SEND_FAILED: i32 = -32;
pub(crate) const E_WRITE_FAILED: i32 = -34;

// ── Phase machine ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Phase {
    Init = 0,
    Connecting = 1,
    WaitConnect = 2,
    SendRequest = 3,
    WaitSend = 4,
    RecvHeaders = 5,
    RecvBody = 6,
    Writing = 7,
    Done = 8,
    Error = 255,
}

// ── Client state ──────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct ClientState {
    pub(crate) conn_id: u16,
    /// 1 once `MSG_CONNECTED` established a connection, 0 otherwise. Tracks
    /// connection PRESENCE separately from `conn_id`'s value because IP can
    /// legitimately assign `conn_id == 0`; keying "connected" off `conn_id != 0`
    /// would leak the first connection (its `CMD_CLOSE` suppressed).
    pub(crate) conn_present: u8,
    /// Set by `module_drain`. The client finishes the exchange it already
    /// admitted, then closes and reports quiescence — it does not abandon a
    /// request whose response a caller is waiting for, and it does not sit
    /// open once there is nothing left to finish.
    pub(crate) draining: u8,
    _conn_pad: [u8; 2],
    pub(crate) out_chan: i32,
    /// `in[1]` — when wired (≥ 0), the WS client reads outgoing
    /// payloads from this channel and emits them as WS TEXT frames.
    /// Channel HUP triggers a clean WS CLOSE. Unwired (−1) keeps the
    /// one-shot `request_body` behavior.
    pub(crate) data_in_chan: i32,

    pub(crate) host_ip: u32,
    pub(crate) port: u16,
    pub(crate) path_len: u16,

    pub(crate) phase: Phase,
    pub(crate) headers_done: u8,
    /// Wire protocol — 0 = HTTP/1.1, 1 = HTTP/2 cleartext (h2c).
    /// Read by `mod.rs::module_step` to pick the right state machine.
    pub(crate) protocol: u8,
    /// HTTP/2 client sub-state. Interpreted as `client_h2::H2Phase` when
    /// `protocol == 1`; ignored otherwise.
    pub(crate) h2_phase: u8,
    /// 1 = bootstrap a WebSocket session (RFC 8441 extended CONNECT)
    /// after the h2 handshake instead of issuing a GET/POST. Only
    /// honored when `protocol == 1`.
    pub(crate) websocket: u8,
    /// WS phase: 0 = haven't sent CLOSE, 1 = CLOSE queued, 2 = peer
    /// CLOSE echo observed → exit on next tick.
    pub(crate) ws_done: u8,
    /// 1 = issue a gRPC unary POST instead of a plain POST: the request
    /// carries `content-type: application/grpc` and `te: trailers`
    /// (RFC-required for gRPC-over-HTTP/2). Only honored when
    /// `protocol == 1` and a `request_body` (the length-prefixed message)
    /// is set. The body itself is passed through unframed — the caller
    /// supplies the gRPC `[compressed-flag:1][len:4 BE][message]` LPM.
    pub(crate) grpc: u8,
    /// 1 = a connection-level WINDOW_UPDATE should be queued in
    /// `request_buf` once it's free, refilling our recv flow-control
    /// window. Tracked per client (h2 only).
    pub(crate) window_update_pending: u8,

    pub(crate) connect_start_ms: u64,

    pub(crate) pending_offset: u16,
    pub(crate) recv_len: u16,

    pub(crate) content_length: u32,
    pub(crate) bytes_received: u32,

    pub(crate) request_len: u16,
    pub(crate) request_sent: u16,

    /// Optional request body (POST). Empty length means GET.
    pub(crate) request_body_len: u16,
    /// Bytes of the body already framed onto the wire. Used by the h2
    /// client to fragment large bodies across multiple DATA frames.
    pub(crate) request_body_sent: u16,
    /// Connection-level recv flow-control window for h2 (RFC 7540
    /// §6.9.1). Decremented as response DATA frames arrive; refilled
    /// via WINDOW_UPDATE when it crosses the threshold.
    pub(crate) recv_window: i32,

    pub(crate) path: [u8; MAX_PATH_LEN],
    pub(crate) recv_buf: [u8; RECV_BUF_SIZE],
    pub(crate) request_buf: [u8; REQUEST_BUF_SIZE],
    pub(crate) request_body: [u8; REQUEST_BODY_SIZE],
}

// ClientState lives inside HttpState, which the kernel allocates as a
// zeroed buffer of `module_state_size()` bytes. `init()` below sets
// only those fields whose default is not zero.

// ── Param parsers ─────────────────────────────────────────────────────────

pub(crate) unsafe fn parse_request_body(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(REQUEST_BODY_SIZE);
    let mut i = 0;
    while i < n {
        s.client.request_body[i] = *d.add(i);
        i += 1;
    }
    s.client.request_body_len = n as u16;
}

// ── Init / post-params ────────────────────────────────────────────────────

pub(crate) unsafe fn init(s: &mut HttpState) {
    s.client.out_chan = -1;
    s.client.data_in_chan = -1;
    s.client.port = 80;
    s.client.phase = Phase::Init;
    // h2 connection-level recv window starts at the spec default.
    s.client.recv_window = 65535;
}

pub(crate) unsafe fn post_params(s: &mut HttpState) {
    let sys = &*s.syscalls;
    s.client.out_chan = dev_channel_port(sys, 1, 1); // out[1]: body data
    s.client.data_in_chan = dev_channel_port(sys, 0, 1); // in[1]: outbound WS payload data

    if s.client.path_len == 0 {
        s.client.path[0] = b'/';
        s.client.path_len = 1;
    }

    log(s, b"[http] client configured");
}

#[inline(always)]
pub(crate) unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

pub(crate) unsafe fn build_request(s: &mut HttpState) {
    let len = wire::h1::write_request_line(
        s.client.request_buf.as_mut_ptr(),
        REQUEST_BUF_SIZE,
        s.client.path.as_ptr(),
        s.client.path_len as usize,
        s.client.host_ip,
    );
    s.client.request_len = len as u16;
    s.client.request_sent = 0;
}

/// Close the client's connection. Returns whether the transport took the
/// CLOSE — `true` also when there was nothing to close.
///
/// Ownership is released only on a confirmed write. Clearing it after a refused
/// one abandons a connection the peer still holds open, and nothing afterwards
/// knows the CLOSE is owed.
#[must_use]
pub(crate) unsafe fn send_close_frame(s: &mut HttpState) -> bool {
    if s.client.conn_present == 0 || s.net_out_chan < 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 2];
    net_proto::put_conn_id(&mut payload, s.client.conn_id);
    if net_write_frame(
        sys,
        chan,
        NET_CMD_CLOSE,
        payload.as_ptr(),
        2,
        buf,
        NET_BUF_SIZE,
    ) == 0
    {
        return false;
    }
    s.client.conn_id = 0;
    s.client.conn_present = 0;
    true
}

/// True when a just-read established-stream frame (`MSG_DATA` / `MSG_CLOSED` /
/// `MSG_ERROR`, all of which lead with `conn_id`) belongs to a DIFFERENT
/// connection than this client's. `ip.net_out` can be fanned to other stream
/// consumers, so a client must not consume another connection's bytes as its
/// own response. The frame has already been read (FIFO stays aligned); the
/// caller simply ignores it.
#[inline(always)]
pub(crate) unsafe fn is_foreign_frame(
    s: &HttpState,
    msg_type: u8,
    payload_len: usize,
    nbuf: *const u8,
) -> bool {
    matches!(msg_type, NET_MSG_DATA | NET_MSG_CLOSED | NET_MSG_ERROR)
        && payload_len >= 2
        && net_proto::conn_id(core::slice::from_raw_parts(
            nbuf.add(NET_FRAME_HDR),
            payload_len,
        )) != s.client.conn_id
}
