//! HTTP module — unified client + server.
//!
//! A single PIC module that operates in one of two modes:
//!
//! - **Server** (mode 0, default): routing, templating, file serving, and a
//!   reverse-proxy relay with backend selection, failover and 5xx accounting.
//! - **Client** (mode 1): fetches a URL, streams the response body to
//!   the data output channel.
//!
//! # Layout
//!
//! Three tiers, and the role split is a directory boundary:
//!
//! ```text
//! wire/     h1 h2 h3 ws hpack qpack huffman     I/O-free codecs, role-neutral
//! server/   mod                                 core: slots, phases, state, tick
//!           h1 h2 h3                            per-generation front ends
//!           routes listeners params             config and dispatch
//!           cache response body ws proxy        what a request is served from
//! client/   mod  h1 h2 h3                       same shape, fewer of each
//! connection.rs                                 IP-module framing constants
//! ```
//!
//! **A file is named for what it is; its directory for whose it is.**
//! `wire::h1` is the HTTP/1.1 codec, `server::h1` the HTTP/1.1 server,
//! `client::h1` the HTTP/1.1 client — one name, read in three contexts. Flat
//! names could not express that: `wire_h2.rs` and `h2.rs` were fighting over
//! `h2`, which is why the old code had to write `use super::wire_h2 as h2w`.
//!
//! **Within a role, `mod.rs` is the core and everything else is either a
//! generation or a subsystem.** A generation (`h1`, `h2`, `h3`) drives a
//! connection and is exclusive — a connection is served by exactly one. A
//! subsystem (`routes`, `cache`, `body`, …) is shared by all of them, which is
//! why a template renders identically on all three. Dependencies run one way:
//! generation → subsystem → core.
//!
//! `server/h1.rs` also carries the bind and accept phases. That lifecycle is
//! HTTP/1.1's — one connection, served to completion, then reused or closed —
//! and it is what `ConnSlot` implements; h2 and h3 reach their own front ends
//! through it.
//!
//! **A missing file is information.** There is no `client::ws` because the
//! WebSocket client is its own module (`modules/foundation/websocket`) — RFC
//! 6455's client role needs no HTTP server around it. The client has no
//! `routes`, `cache` or `proxy` either: it issues one request rather than
//! dispatching many. Those absences are decisions, and they are visible from
//! `ls` rather than only from prose.
//!
//! `client::h3` exists and `server::h3` does too, which is the boundary working
//! as intended: all HTTP logic is this module's, QUIC is Fluxor's, and the
//! codecs under `wire/` serve both directions rather than being written twice.
//! The client lived inside `server/h3.rs` for a while — h3 was server-only when
//! that file was written — which put the one capability three documents denied
//! having under the wrong role as well.
//!
//! Everything under `wire/` is pure: no syscalls, no channels, no clock. That is
//! the tier the RFC vectors pin, and the boundary is enforced by where the file
//! sits rather than by convention.
//!
//! # Server mode
//!
//! Each route maps a URL path prefix to a handler:
//!
//! | id | Handler | Description |
//! |----|---------|-------------|
//! | 0  | static | Serve an inline body as-is |
//! | 1  | template | Serve an inline body with `{{ var }}` substitution |
//! | 2  | file | Stream a file from storage, source index parsed from the URL |
//! | 3  | proxy | Relay to an upstream server — dial, forward, stream back |
//! | 4  | websocket | Accept the upgrade and echo frames internally |
//! | 5  | websocket_fanout | Upgrade, then route frames to the `ws_out` port |
//! | 6  | stream | Like `file` with a config-fixed source, straight through `send_buf` |
//! | 7  | fs_file | Serve an absolute `fs_path` through the FS_CONTRACT provider |
//! | 8  | fs_list | List a directory as one-shot JSON, built at request time |
//! | 9  | websocket_session | Fan-out with per-session isolation — no replay across sessions |
//! | 10 | grpc | gRPC unary: length-prefixed message echo + `grpc-status: 0` trailer |
//! | 11 | app | Hand the request to a downstream module via `req_out`/`resp_in` |
//!
//! WebSocket and HTTP routes share the same TCP/TLS listen socket: the
//! connection arrives, the request is parsed as HTTP/1, and routes
//! marked `handler=4` switch the connection into RFC 6455 frame mode
//! when the client sends an `Upgrade: websocket` request.
//!
//! # Client mode
//!
//! Fetches data from an HTTP URL and outputs the body to a channel.
//! From the consumer's perspective, this looks identical to the SD
//! module — just bytes flowing through a channel.
//!
//! # Parameters
//!
//! | Tag   | Name        | Type | Default | Description                                         |
//! |-------|-------------|------|---------|-----------------------------------------------------|
//! | 0     | mode        | u8   | 0       | 0=server, 1=client                                  |
//! | 1     | port        | u16  | 80      | TCP listen port (server) or target port (client)    |
//! | 2     | body        | str  | (none)  | Legacy inline body (server, backward compat)        |
//! | 3     | path        | str  | "/"     | URL path (client mode)                              |
//! | 4     | host_ip     | u32  | 0       | Target IP (client mode)                             |
//! | 10-45 | route_N_*   | —    | —       | Route params (server mode)                          |
//! | 101   | max_body_kib | u16 | 0       | Request-body cap in KiB (0 = 64 KiB default)        |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unsafe_code,
    reason = "PIC module: ABI shim and zero-copy buffer plumbing"
)]
// PIC library code must not panic; surface errors through the ABI.
#![deny(clippy::unwrap_used)]
#![allow(
    clippy::duplicate_mod,
    reason = "PIC build path-mounts sdk/* into each `.rs` file via `#[path = \"...\"] mod`; in the host workspace build the same file appears in multiple parents. Splitting into a shared `use` import would break the bare-metal compilation pattern where each .rs is its own rustc invocation."
)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the \
              runtime owns these pointers and their validity is the ABI's contract, and the \
              signature is fixed by that contract rather than chosen here. Same allow as \
              chronicle's and lattice's PIC modules carry. Newly required because \
              `fluxor ci` clippies modules/** directly now that Wave has no root manifest \
              for it to lint instead."
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// `pub` under host-test only, matching how `server` is exposed: the suites are
// separate crates and need real `pub` to reach in, while the firmware links one
// crate and keeps its symbol surface unchanged.
#[cfg(not(feature = "host-test"))]
mod client;
#[cfg(feature = "host-test")]
pub mod client;
mod connection;
#[cfg(not(feature = "host-test"))]
mod server;
// Exposed under host-test so the harness can unit-test the DynRoute
// arena matching/selection directly (rfc_dynamic_routes §3.2). The
// firmware symbol surface is unchanged (private otherwise).
#[cfg(feature = "host-test")]
pub mod server;

// Feature gates (RFC module_variants): HTTP/2 (h2 + hpack + wire_h2 +
// client_h2) and HTTP/3 (h3 + qpack + wire_h3) compile only when their
// feature is enabled. `[[variant]]` in manifest.toml drives which
// prebuilt fmod carries them — `http.fmod` (default = full) has both;
// `http-web.fmod` is h1+ws only, dropping ~4.65k LOC of flash the
// embedded single-connection targets never exercise. h1 and ws are
// always compiled (ws gating is deferred — its seams are ~10x wider;
// see rfc_module_variants.md §9 O1).
// Wire codecs live in `wire/`, one file per generation, all I/O-free. See
// `wire/mod.rs`; the per-generation feature gating is there rather than here.
#[cfg(not(feature = "host-test"))]
mod wire;
#[cfg(feature = "host-test")]
pub mod wire;

use client::ClientState;
use connection::NET_BUF_SIZE;
use server::ServerState;

// ── Mode constants ─────────────────────────────────────────────────────────

const MODE_SERVER: u8 = 0;
const MODE_CLIENT: u8 = 1;

// ── Top-level module state ─────────────────────────────────────────────────

#[repr(C)]
struct HttpState {
    syscalls: *const SyscallTable,
    mode: u8,
    /// 0 (default) — downstream is fluxor's `ip` module. `net_send`
    /// caps each `CMD_SEND` at one MSS so the IP segmenter never
    /// has to drop data past the effective send window.
    /// 1 — downstream is `linux_net` (Linux host). Kernel TCP
    /// handles segmentation, so we ship up to `NET_BUF_SIZE` per
    /// `CMD_SEND` and amortise the channel-write + syscall cost.
    host_tcp: u8,
    _mode_pad: [u8; 2],

    // Network channels are shared by both modes (in[0] = net_in,
    // out[0] = net_out). The IP module sees one client per http
    // instance regardless of role.
    net_in_chan: i32,
    net_out_chan: i32,
    net_buf: [u8; NET_BUF_SIZE],

    /// Server mode: serve HTTP/3 over the `mux` contract on the same
    /// `net_in`/`net_out` pair, instead of HTTP/1+2 over net_proto. Set by the
    /// `h3` parameter; the transport in front is Fluxor's `quic` with an `h3`
    /// ALPN (see docs/architecture/http3-ownership.md).
    h3_mode: u8,

    /// Monotonic step counter feeding the tlm cadence.
    step_count: u32,
    /// Hot-path counters emitted as `[http] tlm dt=… rx=… tx=… idle=… bp=…`
    /// every `HTTP_TLM_PERIOD` steps. `rx` counts MSG_DATA payload
    /// bytes drained off `net_in_chan`; `tx` counts response bytes
    /// pushed onto `net_out_chan` from the send-file / send-response
    /// paths. `bp` increments when `step_send_file` short-writes.
    tlm: TlmCounters,
    tlm_scratch: [u8; TLM_LINE_BUF_SIZE],

    server: ServerState,
    client: ClientState,

    /// Per-connection HTTP/3 state: the request-stream slot table and its
    /// emission cursor. Feature-gated, so the `web` variant does not carry it.
    #[cfg(feature = "h3")]
    h3: server::h3::H3State,

    /// Client-mode HTTP/3 exchange state. Feature-gated with the server side.
    #[cfg(feature = "h3")]
    h3_client: client::h3::H3Client,
}

/// Cadence for the `[http] tlm` line.
const HTTP_TLM_PERIOD: u32 = 5000;

// ── Parameter schema ───────────────────────────────────────────────────────
//
// Tags must be stable: external configs reference these by ID. Adding
// a new param appends a new tag; the macro emits PARAM_SCHEMA bytes
// embedded in the .fmod, which the host config tool reads to validate
// YAML against the runtime schema.

mod params_def {
    use super::client;
    use super::client::MAX_PATH_LEN;
    use super::server;
    use super::HttpState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32, p_u8};

    define_params! {
        HttpState;

        0, mode, u8, 0
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        1, port, u16, 80
            => |s, d, len| {
                let v = p_u16(d, len, 0, 80);
                s.server.port = v;
                s.client.port = v;
            };

        2, body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 0, d, len); };

        3, path, str, 0
            => |s, d, len| {
                let n = if len > MAX_PATH_LEN { MAX_PATH_LEN } else { len };
                s.client.path_len = n as u16;
                let mut i = 0;
                while i < n {
                    s.client.path[i] = *d.add(i);
                    i += 1;
                }
            };

        4, host_ip, u32, 0
            => |s, d, len| { s.client.host_ip = p_u32(d, len, 0, 0); };

        5, protocol, u8, 0
            => |s, d, len| { s.client.protocol = p_u8(d, len, 0, 0); };

        6, request_body, str, 0
            => |s, d, len| { client::parse_request_body(s, d, len); };

        7, websocket, u8, 0
            => |s, d, len| { s.client.websocket = p_u8(d, len, 0, 0); };

        // 0 (default) = downstream is fluxor's `ip` module — cap each
        // CMD_SEND at one MSS so the IP segmenter never drops past
        // cwnd. 1 = downstream is `linux_net` — kernel TCP handles
        // segmentation, so push the full per-call buffer to amortise
        // overhead across many MSSes.
        8, host_tcp, u8, 0
            => |s, d, len| { s.host_tcp = p_u8(d, len, 0, 0); };

        // Serve HTTP/3 over the `mux` contract on net_in/net_out instead of
    // HTTP/1+2 over net_proto. The transport in front is fluxor's `quic` with
    // an `h3` ALPN — see docs/architecture/http3-ownership.md.
    //
    // Tag 100, deliberately clear of the route block: route `n` occupies
    // `10*(n+1) + field` up to 89, 90/91 are the routes/listeners prefixes, and
    // 92/93 must stay UNDEFINED — `bounds_saturation.rs` configures a 9th route
    // at 92/93 to prove the TLV walk skips unknown tags instead of writing past
    // the table. Taking 92 turned that probe into `h3 = 1` and broke every h1
    // route in the test, which is exactly what the test is for.
    100, h3, u8, 0
        => |s, d, len| { s.h3_mode = p_u8(d, len, 0, 0); };

    // Largest request body accepted, in KiB. 0 (default) = the built-in
    // `reqbody::DEFAULT_MAX_BODY`. Tag 101 because 0-9 are taken, 10-89 belong
    // to the route block, 90/91 are the table prefixes, 92/93 must stay
    // undefined for `bounds_saturation.rs`, and 100 is h3.
    //
    // KiB rather than bytes because the TLV element is length-prefixed and a
    // one-byte value covering 1 KiB-255 KiB is more useful across that range
    // than a one-byte byte-count covering 255 B.
    101, max_body_kib, u16, 0
        => |s, d, len| {
            s.server.max_body = (p_u16(d, len, 0, 0) as u32).saturating_mul(1024);
        };

    9, grpc, u8, 0
            => |s, d, len| { s.client.grpc = p_u8(d, len, 0, 0); };

        10, route_0_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 0, d, len); };
        11, route_0_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 0, d, len); };
        12, route_0_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 0, d, len); };
        13, route_0_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 0, d, len); };
        14, route_0_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 0, d, len); };
        15, route_0_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 0, d, len); };
        16, route_0_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 0, d, len); };
        17, route_0_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 0, d, len); };
        18, route_0_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 0, d, len); };
        19, route_0_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 0, d, len); };

        20, route_1_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 1, d, len); };
        21, route_1_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 1, d, len); };
        22, route_1_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 1, d, len); };
        23, route_1_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 1, d, len); };
        24, route_1_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 1, d, len); };
        25, route_1_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 1, d, len); };
        26, route_1_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 1, d, len); };
        27, route_1_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 1, d, len); };
        28, route_1_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 1, d, len); };
        29, route_1_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 1, d, len); };

        30, route_2_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 2, d, len); };
        31, route_2_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 2, d, len); };
        32, route_2_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 2, d, len); };
        33, route_2_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 2, d, len); };
        34, route_2_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 2, d, len); };
        35, route_2_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 2, d, len); };
        36, route_2_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 2, d, len); };
        37, route_2_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 2, d, len); };
        38, route_2_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 2, d, len); };
        39, route_2_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 2, d, len); };

        40, route_3_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 3, d, len); };
        41, route_3_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 3, d, len); };
        42, route_3_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 3, d, len); };
        43, route_3_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 3, d, len); };
        44, route_3_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 3, d, len); };
        45, route_3_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 3, d, len); };
        46, route_3_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 3, d, len); };
        47, route_3_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 3, d, len); };
        48, route_3_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 3, d, len); };
        49, route_3_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 3, d, len); };

        50, route_4_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 4, d, len); };
        51, route_4_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 4, d, len); };
        52, route_4_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 4, d, len); };
        53, route_4_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 4, d, len); };
        54, route_4_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 4, d, len); };
        55, route_4_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 4, d, len); };
        56, route_4_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 4, d, len); };
        57, route_4_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 4, d, len); };
        58, route_4_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 4, d, len); };
        59, route_4_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 4, d, len); };

        60, route_5_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 5, d, len); };
        61, route_5_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 5, d, len); };
        62, route_5_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 5, d, len); };
        63, route_5_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 5, d, len); };
        64, route_5_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 5, d, len); };
        65, route_5_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 5, d, len); };
        66, route_5_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 5, d, len); };
        67, route_5_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 5, d, len); };
        68, route_5_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 5, d, len); };
        69, route_5_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 5, d, len); };

        70, route_6_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 6, d, len); };
        71, route_6_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 6, d, len); };
        72, route_6_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 6, d, len); };
        73, route_6_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 6, d, len); };
        74, route_6_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 6, d, len); };
        75, route_6_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 6, d, len); };
        76, route_6_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 6, d, len); };
        77, route_6_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 6, d, len); };
        78, route_6_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 6, d, len); };
        79, route_6_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 6, d, len); };

        80, route_7_path, str, 0
            => |s, d, len| { server::params::parse_route_path(s, 7, d, len); };
        81, route_7_body, str, 0
            => |s, d, len| { server::params::parse_route_body(s, 7, d, len); };
        82, route_7_handler, u8, 0
            => |s, d, len| { server::params::set_route_handler(s, 7, d, len); };
        83, route_7_proxy_ip, u32, 0
            => |s, d, len| { server::params::set_route_proxy_ip(s, 7, d, len); };
        84, route_7_proxy_port, u16, 0
            => |s, d, len| { server::params::set_route_proxy_port(s, 7, d, len); };
        85, route_7_source, u16, 0xFFFF
            => |s, d, len| { server::params::set_route_source(s, 7, d, len); };
        86, route_7_content_type, str, 0
            => |s, d, len| { server::params::parse_route_content_type(s, 7, d, len); };
        87, route_7_fs_path, str, 0
            => |s, d, len| { server::params::set_route_fs_path(s, 7, d, len); };
        88, route_7_fs_list, str, 0
            => |s, d, len| { server::params::set_route_fs_list(s, 7, d, len); };
        89, route_7_fs_filter, str, 0
            => |s, d, len| { server::params::set_route_fs_filter(s, 7, d, len); };

        // Dynamic-route prefix (rfc_dynamic_routes §3.2). Not a
        // `route_N_*` slot — it configures the store prefix the
        // table_consumer subscribes to (e.g. `/dataplane/edge/`). Empty
        // (default) leaves the whole dyn-route subsystem off, so an
        // unconfigured server is byte-identical.
        90, routes_prefix, str, 0
            => |s, d, len| { server::params::set_routes_prefix(s, d, len); };

        // Dynamic-listener prefix (rfc_workload_ingress §4.2). Configures
        // the store prefix a SECOND table_consumer subscribes to (e.g.
        // `/dataplane/edge-listeners/`) for mid-life bind of pooled ports.
        // Empty (default) leaves the mid-life-bind subsystem off, so an
        // unconfigured server is byte-identical.
        91, listeners_prefix, str, 0
            => |s, d, len| { server::listeners::set_listeners_prefix(s, d, len); };
    }
}

// ── Exported PIC interface ────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<HttpState>() as u32
}

/// Heap arena size — sized for the **working set**, not the slot
/// table ceiling. The slot table (`MAX_CONCURRENT_CONNS`) is the
/// architectural cap on simultaneous in-flight connections; the
/// arena (`ARENA_WORKING_SET_CONNS`) is the realistic peak number
/// of *active* connections the system serves at once. When the
/// arena fills, `alloc_free_slot` returns `None` and the demux
/// closes the new conn cleanly — graceful overload behaviour, no
/// silent drops.
///
/// Decoupling these means a 1024-slot table on aarch64 doesn't
/// require 16+ MiB of pre-reserved arena that's idle 99% of the
/// time. The arena holds:
///   - the server's body pool (initial `DEFAULT_BODY_POOL_SIZE`,
///     grown via `heap_realloc` doubling — accounted for by
///     doubling the body budget here),
///   - per-active-conn `recv_buf` + `send_buf` allocated on accept,
///   - per-active-conn `H2State` (~3 KB) allocated lazily on the
///     h2c preface,
///   - allocator overhead.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    // Reserve room for the body pool plus headroom for `heap_realloc`
    // doubling under big inline-template configurations.
    let body_budget = (server::DEFAULT_BODY_POOL_SIZE as u32).saturating_mul(2);
    let per_slot_buffers = (server::RECV_BUF_SIZE + server::SEND_BUF_SIZE) as u32;
    let working_set = server::ARENA_WORKING_SET_CONNS as u32;
    let conns_buffers = per_slot_buffers.saturating_mul(working_set);
    // h2's per-connection state joins the arena budget only when the
    // feature is compiled in — the web variant's request shrinks by
    // ~3 KB × working set.
    #[cfg(feature = "h2")]
    let h2_state_size = core::mem::size_of::<server::h2::H2State>() as u32;
    #[cfg(not(feature = "h2"))]
    let h2_state_size = 0u32;
    let h2_buffers = h2_state_size.saturating_mul(working_set);
    // 16 bytes of allocator overhead per heap_alloc call (8-byte
    // header + alignment padding). Up to 3 allocs per active conn
    // (recv_buf, send_buf, h2).
    let alloc_overhead = (16u32 * 3).saturating_mul(working_set);
    body_budget
        .saturating_add(conns_buffers)
        .saturating_add(h2_buffers)
        .saturating_add(alloc_overhead)
        .saturating_add(2048) // slack for body_pool resize + headers
}

/// PIC module ABI entry: one-time initialisation. No state to bind yet.
///
/// # Safety
/// `_syscalls` is currently unused; the kernel guarantees ABI binding has
/// completed before this call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// PIC module ABI entry: construct module state in `state`.
///
/// # Safety
/// `state` / `params` / `syscalls` are kernel-owned buffers; the loader
/// passes `state_size` ≥ `module_state_size()` and `params_len` ≥ the
/// declared TLV size, both zero-init.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: kernel-owned buffers; null-checked + size-checked before use,
    // and the kernel guarantees `state` is zero-initialised at `state_size`.
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<HttpState>() {
            return -6;
        }

        let s = &mut *(state as *mut HttpState);
        s.syscalls = syscalls as *const SyscallTable;
        s.mode = MODE_SERVER;
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        s.h3_mode = 0;
        #[cfg(feature = "h3")]
        {
            s.h3 = server::h3::H3State::new();
            s.h3_client = client::h3::H3Client::new();
        }

        // Pre-init both modes so the body pool is ready before TLV
        // params (which may call parse_route_body) are dispatched.
        server::init(s);
        client::init(s);

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        if s.mode == MODE_CLIENT {
            client::post_params(s);
        } else {
            server::post_params(s);
        }

        0
    }
}

/// PIC module ABI entry: per-tick cooperative step.
///
/// # Safety
/// `state` must point to an initialised `HttpState`; the scheduler
/// guarantees no concurrent step invocation.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: `state` was initialised by `module_new`; the scheduler
    // serialises module_step calls so the `&mut *` re-borrow is unique.
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut HttpState);
        if s.syscalls.is_null() {
            return -1;
        }

        s.step_count = s.step_count.wrapping_add(1);
        let rx_pre = s.tlm.bytes_in;
        let tx_pre = s.tlm.bytes_out;
        let bp_pre = s.tlm.bp_steps;

        // Retention idle-tick: bumped every step; reset to 0 in
        // `ws_drain_fanout_input` on a fresh capture. Lets the next
        // captured envelope decide whether to wipe the buffer (idle
        // gap exceeded → new producer state) or append (still
        // streaming the same burst). Server-mode only — client mode
        // never enters the retention path.
        if s.mode == MODE_SERVER {
            s.server.retained_idle_ticks = s.server.retained_idle_ticks.saturating_add(1);
        }

        // A CLOSE the transport refused leaves `conn_present` set; retry it
        // here so every terminal path in the protocol steps gets the retry for
        // free rather than each having to carry one.
        if s.mode == MODE_CLIENT
            && s.client.conn_present != 0
            && matches!(s.client.phase, client::Phase::Done | client::Phase::Error)
        {
            let _ = client::send_close_frame(s);
        }

        let rc = if s.mode == MODE_CLIENT {
            // HTTP/3 client: the request rides the `mux` contract, exactly as
            // the server path does, so the transport stays protocol-free.
            #[cfg(feature = "h3")]
            if s.h3_mode != 0 {
                let r = client::h3::step_mux_client(s);
                tlm_idle_if_unchanged(&mut s.tlm, rx_pre, tx_pre, bp_pre);
                return r;
            }
            #[cfg(feature = "h2")]
            let r = if s.client.protocol == 1 {
                client::h2::step(s)
            } else {
                client::h1::step(s)
            };
            // Without h2, `protocol: 1` (h2c client) cannot be served;
            // config validation should have rejected it, but fail
            // closed rather than silently speaking h1 on an h2 wire.
            #[cfg(not(feature = "h2"))]
            let r = if s.client.protocol == 1 {
                -1
            } else {
                client::h1::step(s)
            };
            // Drain completion. The step above ran first, so an exchange that
            // was one frame from finishing has already finished.
            //
            // Anything still in flight is then FAILED rather than waited on. A
            // one-shot client mid-exchange is waiting on a peer, and drain is
            // the graph being reconfigured underneath both of them — so waiting
            // means waiting on a clock, and a client whose deadline has not yet
            // fired would hold the reconfiguration open until the scheduler's
            // forced-drain timeout. Failing explicitly gives the caller the one
            // terminal outcome it is owed and makes the drain bounded without
            // depending on a clock at all.
            if s.client.draining != 0 {
                if !matches!(
                    s.client.phase,
                    client::Phase::Init | client::Phase::Done | client::Phase::Error
                ) {
                    s.client.phase = client::Phase::Error;
                }
                // Quiescence is also the CLOSE having been taken: a refused one
                // retries next step rather than abandoning the connection.
                if client::send_close_frame(s) {
                    1
                } else {
                    0
                }
            } else {
                r
            }
        } else {
            // Server mode. With `h3 = 1` the module speaks HTTP/3 over the
            // `mux` contract instead of HTTP/1+2 over net_proto — same ports,
            // disjoint opcode ranges (../fluxor/modules/sdk/contracts/net/mux.rs).
            #[cfg(feature = "h3")]
            let r = if s.h3_mode != 0 {
                server::h3::step_mux(s)
            } else {
                server::step(s)
            };
            #[cfg(not(feature = "h3"))]
            // Without the h3 feature there is no HTTP/3 to serve; fail closed
            // rather than silently serving h1 on a graph that asked for h3.
            let r = if s.h3_mode != 0 { -1 } else { server::step(s) };
            r
        };

        tlm_idle_if_unchanged(&mut s.tlm, rx_pre, tx_pre, bp_pre);
        let sys = &*s.syscalls;
        let scratch_ptr = s.tlm_scratch.as_mut_ptr();
        let scratch_len = s.tlm_scratch.len();
        dev_tlm_maybe_emit(
            sys,
            b"[http]",
            &mut s.tlm,
            s.step_count,
            HTTP_TLM_PERIOD,
            scratch_ptr,
            scratch_len,
        );

        // Module-scope telemetry: emit cumulative counters to the kernel
        // telemetry ring on the tlm cadence (no-op when no consumer is
        // subscribed). ids follow `[observability].metrics`: 0=bytes_in, 1=bytes_out.
        if dev_telemetry_enabled(&*s.syscalls) && s.step_count.is_multiple_of(HTTP_TLM_PERIOD) {
            let me = dev_self_index(sys);
            if me >= 0 {
                let midx = me as u16;
                let t = dev_micros(sys);
                let counter = abi::contracts::telemetry::METRIC_COUNTER;
                dev_telemetry_metric(sys, -1, midx, t, counter, 0, s.tlm.bytes_in as u64);
                dev_telemetry_metric(sys, -1, midx, t, counter, 1, s.tlm.bytes_out as u64);
                // id 2 = http.routes.dropped — dynamic-route arena /
                // backend-set overflow (rfc_dynamic_routes §2.5, §6:
                // a store reader surfaces degradation through
                // telemetry, never a store key). Cumulative; 0 when the
                // dyn-route feature is off.
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    2,
                    s.server.dyn_routes.dropped as u64,
                );
                // id 3 = http.proxy.retries, id 4 = http.proxy.5xx —
                // proxy-relay failover / terminal 5xx (rfc_workload_ingress
                // §3; a reader surfaces these via telemetry, never a
                // store key). Cumulative; 0 when no relay is configured.
                dev_telemetry_metric(sys, -1, midx, t, counter, 3, s.server.proxy_retries as u64);
                dev_telemetry_metric(sys, -1, midx, t, counter, 4, s.server.proxy_5xx as u64);
                // id 5 = http.backpressure.steps. Counted at every send seam
                // and, until now, read only by the idle heuristic — so a
                // module quietly refusing work looked BUSY to the scheduler
                // and looked fine to the operator. It is the single most
                // informative load signal a bounded module has: the
                // difference between "fast" and "shedding".
                dev_telemetry_metric(sys, -1, midx, t, counter, 5, s.tlm.bp_steps as u64);
                // ids 6/7 = http.conns.refused.slots / .arena. Two different
                // ceilings with two different fixes; reported as one number
                // they are unactionable (see `alloc_free_slot`).
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    6,
                    s.server.conns_refused_slots as u64,
                );
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    7,
                    s.server.conns_refused_arena as u64,
                );
                // id 8 = http.demux.stalls — head-of-line blocking, which does
                // not show in throughput until it is already severe.
                dev_telemetry_metric(sys, -1, midx, t, counter, 8, s.server.demux_stalls as u64);
                // ids 9..11 = the application fan-out's shed paths. `lost` is
                // never expected in a healthy graph: it means a response was
                // dropped rather than delayed.
                dev_telemetry_metric(sys, -1, midx, t, counter, 9, s.server.app_timeouts as u64);
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    10,
                    s.server.app_envelopes_lost as u64,
                );
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    11,
                    s.server.app_envelopes_oversize as u64,
                );
                // id 12 = http.ws.envelopes.dropped, id 13 =
                // http.h2.streams.refused.
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    12,
                    s.server.ws_envelopes_dropped as u64,
                );
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    13,
                    s.server.h2_streams_refused as u64,
                );
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    14,
                    s.server.h3_handler_unavailable as u64,
                );
                dev_telemetry_metric(
                    sys,
                    -1,
                    midx,
                    t,
                    counter,
                    15,
                    s.server.h3_field_limit_refused as u64,
                );
            }
        }

        // Phase-machine snapshot — fires every tlm period so when the
        // server appears unresponsive we can see exactly which Phase
        // it sat in (e.g. ph=19 = WsActive, pca>0 = stale WS holding
        // queued accepts). The structured tlm line shows bytes/idle
        // but doesn't surface the FSM state, and the wedge surface
        // recurs often enough that having this on by default is the
        // only cheap way to characterise the next regression without
        // round-tripping a redeploy.
        if s.mode == MODE_SERVER && s.step_count.is_multiple_of(HTTP_TLM_PERIOD) {
            let mut buf = [0u8; 128];
            let p = buf.as_mut_ptr();
            let prefix = b"[http] state ph=";
            let mut q = 0usize;
            while q < prefix.len() {
                *p.add(q) = prefix[q];
                q += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_phase(s) as u32);
            let mc = b" conn=";
            let mut t = 0usize;
            while t < mc.len() {
                *p.add(q) = mc[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_conn_id(s) as u32);
            let mpc = b" pc=";
            let mut t = 0usize;
            while t < mpc.len() {
                *p.add(q) = mpc[t];
                q += 1;
                t += 1;
            }
            let peer_closed = server::cur_slot(s).map(|c| c.peer_closed).unwrap_or(0);
            q += fmt_u32_raw(p.add(q), peer_closed as u32);
            let mrl = b" rl=";
            let mut t = 0usize;
            while t < mrl.len() {
                *p.add(q) = mrl[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_recv_len(s) as u32);
            let mso = b" so=";
            let mut t = 0usize;
            while t < mso.len() {
                *p.add(q) = mso[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_send_offset(s) as u32);
            let msl = b" sl=";
            let mut t = 0usize;
            while t < msl.len() {
                *p.add(q) = msl[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_send_len(s) as u32);
            let mac = b" act=";
            let mut t = 0usize;
            while t < mac.len() {
                *p.add(q) = mac[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::active_slot_count(s) as u32);
            dev_log(sys, 3, p, q);
        }
        // §6 work signal (RFC adaptive_tick_extra): if the request/response path
        // moved bytes this step, keep the pacer hot. Redundant-but-harmless when
        // the sub-step already returned Burst (rc==2); fixes the case where it
        // did work but returned Continue.
        if s.tlm.bytes_in != rx_pre || s.tlm.bytes_out != tx_pre {
            dev_report_step_effect(sys, step_effect::WORK_DONE);
        }
        rc
    }
}

/// Drain marks the server for graceful shutdown — the next time it
/// returns to `WaitAccept` it reports done instead of looping. Client
/// mode is one-shot and ignores drain.
///
/// # Safety
/// `state` must point to an initialised `HttpState`.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub unsafe extern "C" fn module_drain(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: state non-null per the check above; module_new initialised
    // it as `HttpState` so the cast is sound.
    unsafe {
        let s = &mut *(state as *mut HttpState);
        if s.mode == MODE_SERVER {
            // `server::step` checks the drain flag at the top of
            // every tick and returns 1 once no in-flight conns
            // remain, so no specific slot needs to be poked.
            s.server.draining = 1;
        } else {
            // Client mode participates too. It is one-shot, so draining means
            // "finish the exchange already admitted, then go" — abandoning it
            // would leave a caller waiting on a response that was still coming,
            // and ignoring drain entirely left the instance to be torn down by
            // the scheduler's forced-drain timeout even when it was idle.
            s.client.draining = 1;
        }
    }
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `../fluxor/modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
