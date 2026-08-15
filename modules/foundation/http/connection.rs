//! Connection framing constants.
//!
//! Wraps the `IP module`'s on-channel framing protocol. HTTP versions
//! and WebSocket all share the same connection-level transport (TCP or
//! TLS), so the byte-shape of `NET_MSG_*` / `NET_CMD_*` frames lives
//! here, version-blind.
//!
//! The actual frame I/O helpers (`net_write_frame`, `net_read_frame`,
//! `NET_FRAME_HDR`) live in `../fluxor/modules/sdk/runtime.rs` and are pulled into
//! the top-level module's scope by `include!`. Submodules reach them
//! via `super::net_write_frame` etc.

// ── Inbound messages from the IP module ──
pub(crate) const NET_MSG_ACCEPTED: u8 = 0x01;
pub(crate) const NET_MSG_DATA: u8 = 0x02;
pub(crate) const NET_MSG_CLOSED: u8 = 0x03;
pub(crate) const NET_MSG_BOUND: u8 = 0x04;
pub(crate) const NET_MSG_CONNECTED: u8 = 0x05;
pub(crate) const NET_MSG_ERROR: u8 = 0x06;
/// Observability trace context (see ../fluxor/modules/sdk/contracts/net/net_proto.rs). Received from
/// IP (plain HTTP) or TLS (HTTPS) to parent `http.server.request` under the
/// upstream span. 0x07/0x08 are the IP-private RETRANSMIT/ACK opcodes.
pub(crate) const NET_MSG_TRACE_CTX: u8 = 0x09;

// ── Outbound commands to the IP module ──
pub(crate) const NET_CMD_BIND: u8 = 0x10;
pub(crate) const NET_CMD_SEND: u8 = 0x11;
pub(crate) const NET_CMD_CLOSE: u8 = 0x12;
pub(crate) const NET_CMD_CONNECT: u8 = 0x13;

/// Scratch buffer size for assembling outbound and reading inbound
/// frames. Must be ≥ the IP module's largest single MSG_DATA payload
/// (linux_net writes up to 1500 + framing) — otherwise channel reads
/// truncate mid-MSG and h2 frame parsing breaks.
///
/// Also caps the per-`net_send` outbound payload (one CMD_SEND
/// header + one conn_id + N data bytes). The IP module segments
/// internally on receipt, so a single 8 KiB CMD_SEND emits up to
/// 5 × MSS-sized TCP segments per IP step — gigabit-class
/// throughput on a single connection.
///
/// **aarch64** — 8 KiB. Lets `net_send` push up to ~5 MSS-worth of
/// payload per call, multiplying per-tick segment output by ~5×
/// over the embedded path.
///
/// **rp2350 / rp2040 / wasm32** — 1600 (legacy). Embedded targets
/// rarely sustain MSS-class flows, and a 1600-byte stack buffer
/// fits inside the constrained per-step budget.
#[cfg(target_arch = "aarch64")]
pub(crate) const NET_BUF_SIZE: usize = 8192;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const NET_BUF_SIZE: usize = 1600;

/// Largest `data` portion of one `MSG_DATA` frame (mirrors
/// `net_proto::MAX_DATA_FRAGMENT`). The receive-side admission threshold uses
/// THIS — not `NET_BUF_SIZE` (the much larger outbound scratch) — so an h2
/// client with a small `recv_buf` still admits inbound frames.
pub(crate) const MAX_DATA_FRAGMENT: usize = 1460;

// ── Multiplexed-session contract (HTTP/3) ──
//
// Mounted here rather than inside either role because it is neither role's: it
// is the transport surface QUIC exposes, and both `server::h3` and `client::h3`
// speak it. It lived in `server::h3` while h3 was server-only, which made the
// client — once it existed — import from the server to reach the transport
// contract, exactly the wrong direction.
//
// Frames share the `[msg_type u8][len u16 LE][payload]` TLV header with
// net_proto and the datagram surface, and the mux opcode range (0xB0..0xCF) is
// disjoint from theirs — which is why h3 needs no new ports: one channel pair
// carries both contracts unambiguously.
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/net/mux.rs"]
pub mod mux;

/// Header shared by every contract on a net channel.
pub const FRAME_HDR: usize = 3;
