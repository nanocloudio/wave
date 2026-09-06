//! RTP PIC Module (TX + RX)
//!
//! Combined RTP transmitter and receiver using a single UDP socket.
//!
//! - **TX path** (when in_chan is wired): Reads G.711 u-law from input,
//!   packetizes into RTP (RFC 3550), and sends via UDP.
//! - **RX path** (when out_chan is wired): Receives RTP from UDP, validates
//!   headers, extracts payload, and writes to output channel.
//!
//! **Control channel support:** If ctrl_chan is wired, the module starts idle
//! and waits for SET_ENDPOINT + START commands. Without ctrl_chan, it requires
//! peer_ip and auto-starts.
//!
//! **Params (TLV v2):**
//!   tag 1: peer_ip    (u32, required without ctrl — peer IPv4 network byte order)
//!   tag 2: peer_port  (u16, default 5004)
//!   tag 3: local_port (u16, default 5004)
//!   tag 4: ssrc       (u32, default 0x46585254 — TX only)
//!   tag 5: ptime      (u8, default 20 — TX packet interval in ms)
//!   tag 6: payload_type (u8, default 0 — negotiated RTP PT for TX and RX)
//!   tag 7: rx_ssrc    (u32, default 0 — accept any inbound SSRC)
//!   tag 8: srtp_key   (16 bytes, optional AES-128-GCM master key)
//!   tag 9: srtp_salt  (12 bytes, optional AES-128-GCM master salt)
//!   tag 10: srtp_auth_key (20 bytes, optional AES-CM/SHA1 auth key)
//!   tag 11: srtp_cm_salt (14 bytes, optional AES-CM session salt)
//!   tag 12: srtp_profile (u8, 0 = GCM, 1 = AES-CM/SHA1-80)
//!   tag 13: turn_relay_ip (u32, optional relay server)
//!   tag 14: turn_relay_port (u16, default 3478)
//!   tag 15: turn_peer_ip (u32, peer permitted at relay)
//!   tag 16: turn_peer_port (u16, default 5004)
//!   tag 17: dtls_srtp_export (56 bytes, DTLS-SRTP exporter material)
//!   tag 18: dtls_srtp_role (u8, 0 = client, 1 = server)
//!   tag 19: route (40 bytes: mid_len, MID[32], PT, SSRC, codec index)
//!   tag 20: dtls_srtp_cm_export (60 bytes, AES-CM master key/salt material)
//!   tag 21: turn_channel (u16, optional bound TURN channel number)

#![cfg_attr(not(feature = "host-test"), no_std)]
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
              chronicle's and lattice's PIC modules carry, and required here because \
              `fluxor ci` clippies modules/** directly."
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// RFC 3550 header decode, shared with `sip` so both sides agree on which bytes
// of a packet are payload. Mounted as a module, and by the same `#[path]` +
// host-test-pub pattern `sip` uses, so one core is not reached two different
// ways. Public under host-test only: the vectors in `tests/` pin it directly,
// and the firmware's symbol surface is unchanged.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtp_core.rs"]
mod rtp_core;
#[cfg(feature = "host-test")]
#[path = "../../common/rtp_core.rs"]
pub mod rtp_core;
use rtp_core::{rtp_mid, rtp_parse, RTP_HEADER_SIZE};

// Shared hex codec, for the bounded bind-evidence line — the same core `s3`,
// `smtp` and `websocket` already consume, rather than a module-local formatter.
#[path = "../../common/hex_core.rs"]
mod hex_core;
use hex_core::hex_encode;

// The receive-record seam to `jitter` — one owner for the layout.
#[cfg(not(feature = "host-test"))]
#[path = "../../common/rtp_wire.rs"]
mod rtp_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/rtp_wire.rs"]
pub mod rtp_wire;
use rtp_wire::{
    put_rtcp_stat_rx_meta, put_rtcp_stat_tx, put_rtp_rx_meta, put_rtp_rx_meta_mid, REC_RTP_RX_META,
    REC_RTP_RX_META_MID, RTCP_STAT_MAX_LEN, RTP_RX_META_LEN, RTP_RX_META_MID_LEN,
};

mod turn_wire {
    mod sdkcrypto {
        include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs");
    }
    use sdkcrypto::sha1;
    include!("../../common/stun_core.rs");
    include!("../../common/turn_core.rs");
    include!("../../common/turn_media.rs");
}

// Shared media-plane mechanics are mounted in the production RTP module as
// well as the host harness. Keeping these bounded cores available here lets a
// graph compose negotiated routing, packetization, pacing, feedback control,
// clock alignment, and replay protection without duplicating state machines.
#[path = "../../common/dtls_srtp_wire.rs"]
pub mod dtls_srtp_wire;
#[path = "../../common/rtp_congestion.rs"]
pub mod rtp_congestion;
#[path = "../../common/rtp_h264.rs"]
pub mod rtp_h264;
#[path = "../../common/rtp_media.rs"]
pub mod rtp_media;
#[path = "../../common/rtp_media_wire.rs"]
pub mod rtp_media_wire;
#[path = "../../common/rtp_pacer.rs"]
pub mod rtp_pacer;
#[path = "../../common/rtp_route.rs"]
pub mod rtp_route;
#[path = "../../common/rtp_sync.rs"]
pub mod rtp_sync;
#[path = "../../common/rtp_video.rs"]
pub mod rtp_video;
#[path = "../../common/rtp_vp8.rs"]
pub mod rtp_vp8;
#[path = "../../common/srtp_core.rs"]
pub mod srtp_core;

// `sframe_core` and `webrtc_sdp` are NOT mounted here. Nothing in this
// module uses them, and a core mounted merely to give tests a production
// path overstates the module. Their conformance
// fixtures reach them directly in the harness.

// Host-build equivalents of the ARM EABI memory intrinsics.
//
// The SDK defines `__aeabi_memcpy` / `__aeabi_memmove` inside
// `mod _pic_intrinsics`, gated `#[cfg(any(target_os = "none", target_arch =
// "wasm32"))]` — correctly, since a Linux host already has libc's. `rtp` is the
// only module that calls them directly, so it is the only one that needs a host
// equivalent in order to link into the test harness.
//
// Semantically identical to the SDK versions (copy / overlapping-safe copy);
// they are private and un-mangled, so they cannot collide with libc. Gated to
// `host-test` so the PIC build continues to use the SDK's.
#[cfg(feature = "host-test")]
#[inline]
unsafe fn __aeabi_memcpy(dest: *mut u8, src: *const u8, n: usize) {
    core::ptr::copy_nonoverlapping(src, dest, n);
}

#[cfg(feature = "host-test")]
#[inline]
unsafe fn __aeabi_memmove(dest: *mut u8, src: *const u8, n: usize) {
    core::ptr::copy(src, dest, n);
}

// ============================================================================
// Constants
// ============================================================================

// datagram opcodes / DG_V4_PREFIX / DG_AF_INET come from
// ../fluxor/modules/sdk/runtime.rs (shared across consumers).

/// Framing scratch: the largest metadata-bearing receive record plus its
/// NetProto envelope.
///
/// Sized for a full PCMU packet and its metadata prefix, not for the control
/// frames alone — a scratch that fits only the latter refuses ordinary media
/// silently, which reads as a dead receive path rather than as a buffer bound.
const NET_BUF_SIZE: usize = 2048;

/// Maximum payload per RTP packet we TRANSMIT (up to 40ms @ 8kHz)
const MAX_PAYLOAD: usize = 320;

/// Total packet buffer (header + max payload)
const PKT_BUF_SIZE: usize = RTP_HEADER_SIZE + MAX_PAYLOAD + srtp_core::SRTP_AUTH_TAG_LEN;
const MAX_RX_SSRC: usize = 4;

#[derive(Clone, Copy)]
struct RxSsrcState {
    ssrc: u32,
    last_seq: u16,
    valid: u8,
    replay: srtp_core::SrtpReplay,
}

impl RxSsrcState {
    const fn empty() -> Self {
        Self {
            ssrc: 0,
            last_seq: 0,
            valid: 0,
            replay: srtp_core::SrtpReplay::new(),
        }
    }
}

/// Maximum payload per RTP packet we ACCEPT, which is not the same number.
///
/// What we send is a policy choice; what we must parse is decided by the peer.
/// RFC 3551 puts no ceiling on packet duration, and real senders use far more
/// than 40 ms: ffmpeg's RTP muxer defaults to 1024-byte PCMU payloads (128 ms),
/// measured in `tests/harness/tests/rtp_interop.rs`. Sizing the receive path to
/// the transmit ceiling silently truncated such a packet to 309 bytes and
/// desynchronised every packet after it.
///
/// Sized for one Ethernet MTU: a 1500-byte frame carries at most 1472 bytes of
/// UDP payload after the IPv4 and UDP headers, so nothing arriving unfragmented
/// on a standard link can exceed this.
const RX_MAX_PAYLOAD: usize = 1472 - RTP_HEADER_SIZE;

/// Receive scratch: NetProto frame header + datagram source prefix + packet.
const RX_BUF_SIZE: usize = NET_FRAME_HDR + DG_V4_PREFIX + RTP_HEADER_SIZE + RX_MAX_PAYLOAD;
const MEDIA_BUF_SIZE: usize = rtp_media_wire::FRAME_HEADER_LEN + rtp_media_wire::MAX_ENCODED_FRAME;

// ============================================================================
// Control Channel Protocol (8-byte messages, little-endian)
// ============================================================================

const CTRL_SET_ENDPOINT: u8 = 0x01;
const CTRL_START: u8 = 0x02;
const CTRL_STOP: u8 = 0x03;
const CTRL_MSG_SIZE: usize = 8;

// ============================================================================
// State Machine
// ============================================================================

/// RTP transport lifecycle phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum RtpPhase {
    Init = 0,
    BindWait = 1,
    Running = 3,
    Error = 4,
    Idle = 5,
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct RtpState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    net_in_chan: i32,
    net_out_chan: i32,
    encoded_chan: i32,
    /// datagram endpoint id assigned by IP module on CMD_DG_BIND.
    /// `0xFF` means unallocated.
    ep_id: u8,
    phase: RtpPhase,
    ptime: u8,
    payload_type: u8,
    ctrl_mode: u8,
    _pad0: u8,
    peer_ip: u32,
    peer_port: u16,
    local_port: u16,
    /// Beat rate limiter (`dbg_beat`): steps since the last emission. Counted
    /// in steps, not milliseconds — this module attests `timer_class =
    /// "agnostic"` and must not read a clock for telemetry pacing.
    dbg_steps: u32,
    ssrc: u32,
    // TX state
    seq_num: u16,
    ptime_bytes: u16,
    timestamp: u32,
    acc_len: u16,
    _pad_tx: u16,
    tx_marker: u8,
    // RX state
    last_seq: u16,
    seq_valid: u8,
    _pad_rx: u8,
    /// Inbound SSRC negotiated for this leg. Zero is the explicit wildcard.
    rx_ssrc: u32,
    srtp_key: [u8; 16],
    srtp_salt: [u8; 12],
    srtp_key_set: u8,
    srtp_salt_set: u8,
    srtp_auth_key: [u8; 20],
    srtp_cm_salt: [u8; 14],
    srtp_auth_set: u8,
    srtp_cm_salt_set: u8,
    srtp_profile: u8,
    turn_relay_ip: u32,
    turn_relay_port: u16,
    turn_peer_ip: u32,
    turn_peer_port: u16,
    turn_channel: u16,
    dtls_srtp_export: [u8; 56],
    dtls_srtp_export_set: u8,
    dtls_srtp_cm_export: [u8; 60],
    dtls_srtp_cm_export_set: u8,
    dtls_srtp_role: u8,
    dtls_session: u32,
    dtls_generation: u32,
    route_table: rtp_route::RtpRouteTable,
    rx_sources: [RxSsrcState; MAX_RX_SSRC],
    packets_received: u32,
    packets_lost: u32,
    /// Inbound packets refused for exceeding `RX_MAX_PAYLOAD`.
    rx_truncated: u32,
    /// Frames addressed to this endpoint, consumed while the receive output
    /// is unwired. Counted, never silent.
    rx_unrouted: u32,
    /// out[2]: `rtcp_stats`. −1 when no `rtcp` module is wired, which is the
    /// ordinary media-only graph.
    stats_chan: i32,
    /// Stats records the channel had no room for. Best-effort by design (see
    /// `emit_rtcp_stats`), but never silent.
    stats_dropped: u32,
    /// Transmit counters, for the sender information in an RFC 3550 Sender
    /// Report. `rtp` does not build the report — it does not know the time —
    /// but it is the only place that knows these numbers.
    packets_sent: u32,
    octets_sent: u32,
    pending_out: u16,
    pending_offset: u16,
    pending_type: u8,
    // Buffers
    ctrl_buf: [u8; CTRL_MSG_SIZE],
    acc_buf: [u8; MAX_PAYLOAD],
    pkt_buf: [u8; PKT_BUF_SIZE],
    rx_buf: [u8; RX_BUF_SIZE],
    out_buf: [u8; RTP_RX_META_MID_LEN + RX_MAX_PAYLOAD],
    net_buf: [u8; NET_BUF_SIZE],
    media_buf: [u8; MEDIA_BUF_SIZE],
    media_len: u16,
}

impl RtpState {
    fn rx_source(&mut self, ssrc: u32) -> Option<usize> {
        for i in 0..MAX_RX_SSRC {
            if self.rx_sources[i].valid != 0 && self.rx_sources[i].ssrc == ssrc {
                return Some(i);
            }
        }
        for i in 0..MAX_RX_SSRC {
            if self.rx_sources[i].valid == 0 {
                self.rx_sources[i] = RxSsrcState {
                    ssrc,
                    ..RxSsrcState::empty()
                };
                self.rx_sources[i].valid = 1;
                return Some(i);
            }
        }
        None
    }

    /// Install the RFC 5764/DTLS-SRTP AES-128-GCM exporter layout. The
    /// exporter is supplied by the DTLS owner (typically Fluxor/Kagi); Wave
    /// never performs a handshake or retains DTLS private state.
    fn install_dtls_srtp_export(&mut self) {
        if self.dtls_srtp_export_set == 0 {
            return;
        }
        let (key_off, salt_off) = if self.dtls_srtp_role == 0 {
            (0, 32)
        } else {
            (16, 44)
        };
        let mut master_key = [0u8; 16];
        let mut master_salt = [0u8; 12];
        master_key.copy_from_slice(&self.dtls_srtp_export[key_off..key_off + 16]);
        master_salt.copy_from_slice(&self.dtls_srtp_export[salt_off..salt_off + 12]);
        srtp_core::derive_aead_key_salt(
            &master_key,
            &master_salt,
            0,
            2,
            &mut self.srtp_key,
            &mut self.srtp_salt,
        );
        self.srtp_key_set = 1;
        self.srtp_salt_set = 1;
        self.srtp_profile = 0;
    }

    fn install_dtls_srtp_cm_export(&mut self) {
        if self.dtls_srtp_cm_export_set == 0 {
            return;
        }
        let (key_off, salt_off) = if self.dtls_srtp_role == 0 {
            (0, 32)
        } else {
            (16, 46)
        };
        let mut master_key = [0u8; 16];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&self.dtls_srtp_cm_export[key_off..key_off + 16]);
        master_salt.copy_from_slice(&self.dtls_srtp_cm_export[salt_off..salt_off + 14]);
        srtp_core::derive_aes_cm_session_keys(
            &master_key,
            &master_salt,
            &mut self.srtp_key,
            &mut self.srtp_auth_key,
            &mut self.srtp_cm_salt,
        );
        self.srtp_key_set = 1;
        self.srtp_auth_set = 1;
        self.srtp_cm_salt_set = 1;
        self.srtp_profile = 1;
    }

    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.out_chan = -1;
        self.ctrl_chan = -1;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.encoded_chan = -1;
        self.ep_id = 0xFF;
        self.phase = RtpPhase::Init;
        self.ptime = 20;
        self.payload_type = 0; // PCMU
        self.ctrl_mode = 0;
        self._pad0 = 0;
        self.peer_ip = 0;
        self.peer_port = 5004;
        self.local_port = 5004;
        self.dbg_steps = 0;
        self.ssrc = 0x46585254; // "FXRT"
        self.seq_num = 0;
        self.ptime_bytes = 160; // 20ms * 8 samples/ms
        self._pad_tx = 0;
        self.timestamp = 0;
        self.acc_len = 0;
        self.last_seq = 0;
        self.seq_valid = 0;
        self._pad_rx = 0;
        self.rx_ssrc = 0;
        self.srtp_key = [0; 16];
        self.srtp_salt = [0; 12];
        self.srtp_key_set = 0;
        self.srtp_salt_set = 0;
        self.srtp_auth_key = [0; 20];
        self.srtp_cm_salt = [0; 14];
        self.srtp_auth_set = 0;
        self.srtp_cm_salt_set = 0;
        self.srtp_profile = 0;
        self.turn_relay_ip = 0;
        self.turn_relay_port = 3478;
        self.turn_peer_ip = 0;
        self.turn_peer_port = 5004;
        self.turn_channel = 0;
        self.dtls_srtp_export = [0; 56];
        self.dtls_srtp_export_set = 0;
        self.dtls_srtp_cm_export = [0; 60];
        self.dtls_srtp_cm_export_set = 0;
        self.dtls_srtp_role = 0;
        self.dtls_session = 0;
        self.dtls_generation = 0;
        self.route_table = rtp_route::RtpRouteTable::new();
        self.rx_sources = [RxSsrcState::empty(); MAX_RX_SSRC];
        self.packets_received = 0;
        self.packets_lost = 0;
        self.rx_truncated = 0;
        self.rx_unrouted = 0;
        self.stats_chan = -1;
        self.stats_dropped = 0;
        self.packets_sent = 0;
        self.octets_sent = 0;
        self.pending_out = 0;
        self.pending_offset = 0;
        self.pending_type = REC_RTP_RX_META;
        self.media_len = 0;
        self.tx_marker = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::dtls_srtp_wire;
    use super::rtp_route;
    use super::RtpState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32, p_u8};

    define_params! {
        RtpState;

        1, peer_ip, u32, 0
            => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0); };

        2, peer_port, u16, 5004
            => |s, d, len| { s.peer_port = p_u16(d, len, 0, 5004); };

        3, local_port, u16, 5004
            => |s, d, len| { s.local_port = p_u16(d, len, 0, 5004); };

        4, ssrc, u32, 0x46585254
            => |s, d, len| { s.ssrc = p_u32(d, len, 0, 0x46585254); };

        5, ptime, u8, 20
            => |s, d, len| {
                let v = p_u8(d, len, 0, 20);
                s.ptime = if v == 0 { 20 } else { v };
                s.ptime_bytes = (s.ptime as u16) * 8;
            };

        6, payload_type, u8, 0
            => |s, d, len| { s.payload_type = p_u8(d, len, 0, 0); };

        7, rx_ssrc, u32, 0
            => |s, d, len| { s.rx_ssrc = p_u32(d, len, 0, 0); };

        8, srtp_key, u8, 0
            => |s, d, len| {
                if len == 16 { core::ptr::copy_nonoverlapping(d, s.srtp_key.as_mut_ptr(), 16); s.srtp_key_set = 1; }
            };

        9, srtp_salt, u8, 0
            => |s, d, len| {
                if len == 12 { core::ptr::copy_nonoverlapping(d, s.srtp_salt.as_mut_ptr(), 12); s.srtp_salt_set = 1; }
            };

        10, srtp_auth_key, u8, 0
            => |s, d, len| {
                if len == 20 { core::ptr::copy_nonoverlapping(d, s.srtp_auth_key.as_mut_ptr(), 20); s.srtp_auth_set = 1; }
            };

        11, srtp_cm_salt, u8, 0
            => |s, d, len| {
                if len == 14 { core::ptr::copy_nonoverlapping(d, s.srtp_cm_salt.as_mut_ptr(), 14); s.srtp_cm_salt_set = 1; }
            };

        12, srtp_profile, u8, 0
            => |s, d, len| { s.srtp_profile = p_u8(d, len, 0, 0).min(1); };

        13, turn_relay_ip, u32, 0
            => |s, d, len| { s.turn_relay_ip = p_u32(d, len, 0, 0); };
        14, turn_relay_port, u16, 3478
            => |s, d, len| { s.turn_relay_port = p_u16(d, len, 0, 3478); };
        15, turn_peer_ip, u32, 0
            => |s, d, len| { s.turn_peer_ip = p_u32(d, len, 0, 0); };
        16, turn_peer_port, u16, 5004
            => |s, d, len| { s.turn_peer_port = p_u16(d, len, 0, 5004); };

        17, dtls_srtp_export, u8, 0
            => |s, d, len| {
                if len == 56 {
                    core::ptr::copy_nonoverlapping(d, s.dtls_srtp_export.as_mut_ptr(), 56);
                    s.dtls_srtp_export_set = 1;
                    s.install_dtls_srtp_export();
                }
            };

        18, dtls_srtp_role, u8, 0
            => |s, d, len| {
                s.dtls_srtp_role = p_u8(d, len, 0, 0).min(1);
                s.install_dtls_srtp_export();
                s.install_dtls_srtp_cm_export();
            };

        20, dtls_srtp_cm_export, u8, 0 => |s, d, len| {
            if len == 60 {
                unsafe { core::ptr::copy_nonoverlapping(d, s.dtls_srtp_cm_export.as_mut_ptr(), 60); }
                s.dtls_srtp_cm_export_set = 1;
                s.install_dtls_srtp_cm_export();
            }
        };

        22, dtls_srtp_context, u8, 0 => |s, d, len| {
            if let Some(ctx) = dtls_srtp_wire::DtlsSrtpWireContext::decode(core::slice::from_raw_parts(d, len)) {
                // A context is a generation fence: stale handshake output must
                // never replace keys from a newer ICE/DTLS generation.
                if ctx.session != 0 && s.dtls_session != 0 && ctx.session != s.dtls_session { return; }
                if ctx.generation < s.dtls_generation { return; }
                s.dtls_session = ctx.session;
                s.dtls_generation = ctx.generation;
                s.dtls_srtp_role = ctx.role;
                if ctx.profile == dtls_srtp_wire::DTLS_SRTP_PROFILE_AES_CM_SHA1_80 {
                    s.dtls_srtp_cm_export.copy_from_slice(&ctx.exporter);
                    s.dtls_srtp_cm_export_set = 1;
                    s.install_dtls_srtp_cm_export();
                } else {
                    s.dtls_srtp_export[..56].copy_from_slice(&ctx.exporter[..56]);
                    s.dtls_srtp_export_set = 1;
                    s.install_dtls_srtp_export();
                }
            }
        };

        19, route, u8, 0
            => |s, d, len| {
                if len == 40 {
                    let d = core::slice::from_raw_parts(d, len);
                    if d[0] as usize > rtp_route::RTP_MID_MAX { return; }
                    let mut mid = [0u8; rtp_route::RTP_MID_MAX];
                    let mid_len = d[0];
                    mid.copy_from_slice(&d[1..33]);
                    let route = rtp_route::RtpRoute {
                        mid,
                        mid_len,
                        payload_type: d[33],
                        ssrc: u32::from_le_bytes([d[34], d[35], d[36], d[37]]),
                        codec_index: d[38],
                    };
                    let _ = s.route_table.upsert(route);
                }
            };

        21, turn_channel, u16, 0
            => |s, d, len| { s.turn_channel = p_u16(d, len, 0, 0); };

    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<RtpState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<RtpState>() {
            return -5;
        }

        let s = &mut *(state as *mut RtpState);
        s.init(syscalls as *const SyscallTable);

        let sys = &*s.syscalls;

        // Net channels: in[0] = net_in (from IP), in[1] = g711 audio data
        // out[0] = net_out (to IP), out[1] = packets (audio out)
        // Primary in/out are net channels; audio ports are secondary
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        // Discover additional ports: in[1] = g711 audio input
        let ch = dev_channel_port(sys, 0, 1); // in[1]
        if ch >= 0 {
            s.in_chan = ch;
        }
        // Optional encoded-media input (in[3]). A graph that wires it gets
        // codec-aware packetization; one that wires only `g711` sends raw PCMU
        // and pays for no packetizer. Wiring both is legal — encoded media
        // takes the step whenever it has a frame ready, so `g711` becomes the
        // fallback rather than a second source competing for the same SSRC.
        s.encoded_chan = dev_channel_port(sys, 0, 3);

        // out[1] = decoded packets output
        let ch = dev_channel_port(sys, 1, 1); // out[1]
        if ch >= 0 {
            s.out_chan = ch;
        }

        // out[2] = per-packet reception stats for an `rtcp` module. Optional:
        // a media-only graph wires nothing here and pays one branch per packet.
        s.stats_chan = dev_channel_port(sys, 1, 2);

        // ctrl channel
        s.ctrl_chan = ctrl_chan;

        // Parse params
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        if ctrl_chan >= 0 {
            // Ctrl mode: start idle, wait for commands
            s.ctrl_mode = 1;
            s.phase = RtpPhase::Idle;
            dev_log(sys, 3, b"[rtp] ctrl mode".as_ptr(), 15);
        } else {
            // Static mode: the peer comes from parameters, so it must be
            // there before the endpoint can start.
            if s.peer_ip == 0 {
                dev_log(sys, 1, b"[rtp] no peer_ip".as_ptr(), 16);
                return -10;
            }
        }

        dev_log(sys, 3, b"[rtp] ready".as_ptr(), 11);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut RtpState);
        if s.syscalls.is_null() {
            return -1;
        }

        dbg_beat(s);
        match s.phase {
            RtpPhase::Idle => step_idle(s),
            RtpPhase::Init => step_init(s),
            RtpPhase::BindWait => step_bind_wait(s),
            RtpPhase::Running => step_running(s),
            RtpPhase::Error => -1,
            _ => -1,
        }
    }
}

/// Bounded state beat: `[rtp] ph=<phase> ep=<id> p=<port>` once per
/// `DBG_BEAT_STEPS` steps (~1 s at the audio graph's 1 ms tick; a relaxed
/// cadence stretches the interval, which telemetry tolerates — this module is
/// `timer_class = "agnostic"` and reads no clock). Startup and bind evidence
/// must ride the beat, because one-shot records at module_new ([rtp] ready)
/// are emitted before DHCP binds and never leave the board over UDP telemetry
/// (rig run 2026-08-26). Phase, endpoint id and local port only — never
/// payload.
const DBG_BEAT_STEPS: u32 = 1024;

unsafe fn dbg_beat(s: &mut RtpState) {
    let sys = &*s.syscalls;
    s.dbg_steps = s.dbg_steps.wrapping_add(1);
    if !s.dbg_steps.is_multiple_of(DBG_BEAT_STEPS) {
        return;
    }
    let mut l = [0u8; 26];
    l[..9].copy_from_slice(b"[rtp] ph=");
    l[9] = b'0' + s.phase as u8;
    l[10..14].copy_from_slice(b" ep=");
    let _ = hex_encode(&[s.ep_id], &mut l[14..16]);
    l[16..19].copy_from_slice(b" p=");
    let _ = hex_encode(&s.local_port.to_be_bytes(), &mut l[19..23]);
    dev_log(sys, 3, l.as_ptr(), 23);
}

// ============================================================================
// State: Idle — wait for control commands (ctrl_mode only)
// ============================================================================

unsafe fn step_idle(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;

    let poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return 0;
    }

    let read = (sys.channel_read)(s.ctrl_chan, s.ctrl_buf.as_mut_ptr(), CTRL_MSG_SIZE);
    if read < CTRL_MSG_SIZE as i32 {
        return 0;
    }

    let cmd = s.ctrl_buf[0];
    match cmd {
        CTRL_SET_ENDPOINT => {
            let port = u16::from_le_bytes([s.ctrl_buf[2], s.ctrl_buf[3]]);
            let addr =
                u32::from_le_bytes([s.ctrl_buf[4], s.ctrl_buf[5], s.ctrl_buf[6], s.ctrl_buf[7]]);
            s.peer_ip = addr;
            s.peer_port = port;
        }
        CTRL_START => {
            if s.peer_ip == 0 {
                dev_log(sys, 2, b"[rtp] no endpoint".as_ptr(), 17);
                return 0;
            }
            dev_log(sys, 3, b"[rtp] starting".as_ptr(), 14);
            s.phase = RtpPhase::Init;
            return 2; // Burst — open socket immediately
        }
        _ => {}
    }
    0
}

// ============================================================================
// State: Init — send CMD_DG_BIND via net channel
// ============================================================================

unsafe fn step_init(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;

    if s.net_out_chan < 0 {
        dev_log(sys, 1, b"[rtp] no net chan".as_ptr(), 16);
        s.phase = RtpPhase::Error;
        return -1;
    }

    // CMD_DG_BIND payload: [port: u16 LE] [flags: u8 = 0]
    let port_le = s.local_port.to_le_bytes();
    let payload = [port_le[0], port_le[1], 0u8];
    let wrote = net_write_frame(
        sys,
        s.net_out_chan,
        DG_CMD_BIND,
        payload.as_ptr(),
        3,
        s.net_buf.as_mut_ptr(),
        NET_BUF_SIZE,
    );
    if wrote == 0 {
        return 0; // Channel full, retry next tick
    }

    // Bind evidence: the request left this module, with
    // the local port it named. Distinguishes a wiring fault before the IP
    // module from a bind refusal after it (`[rtp] bound` / `[rtp] bind fail`).
    let mut l = [0u8; 20];
    l[..13].copy_from_slice(b"[rtp] bind p=");
    let _ = hex_encode(&s.local_port.to_be_bytes(), &mut l[13..17]);
    dev_log(sys, 3, l.as_ptr(), 17);

    s.phase = RtpPhase::BindWait;
    2 // Burst — handle MSG_DG_BOUND immediately
}

// ============================================================================
// State: BindWait — wait for MSG_DG_BOUND, then transition to Running.
// datagram has no "connect" step: CMD_DG_SEND_TO always carries the
// destination explicitly, so we leave peer_ip / peer_port on the state and
// attach them to each packet.
// ============================================================================

unsafe fn step_bind_wait(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;

    if s.net_in_chan < 0 {
        return 0;
    }

    let poll = (sys.channel_poll)(s.net_in_chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return 0;
    }

    let buf = s.net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(sys, s.net_in_chan, buf, NET_BUF_SIZE);

    if msg_type == DG_MSG_ERROR {
        dev_log(sys, 1, b"[rtp] bind fail".as_ptr(), 15);
        s.phase = RtpPhase::Error;
        return -1;
    }
    if msg_type != DG_MSG_BOUND || payload_len < 3 {
        return 0;
    }

    // Port-matched claim: a fanned provider output delivers every BOUND to
    // every leg, and taking the first one claims another module's endpoint
    // (Pi 5 rig, 2026-08-26). A BOUND for a port we did not ask for is
    // another consumer's answer — keep waiting for ours.
    let (ep, port) = abi::contracts::net::datagram::dg_bound_parts(core::slice::from_raw_parts(
        buf.add(NET_FRAME_HDR),
        payload_len,
    ));
    if port != s.local_port {
        return 0;
    }
    s.ep_id = ep;
    dev_log(sys, 3, b"[rtp] bound".as_ptr(), 11);
    s.phase = RtpPhase::Running;
    2 // Burst — start data flow immediately
}

// ============================================================================
// State: Running — TX and RX paths
// ============================================================================

unsafe fn step_running(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;

    // Check for STOP command on ctrl channel
    if s.ctrl_mode != 0 {
        let ctrl_poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
        if ctrl_poll > 0 && ((ctrl_poll as u32) & POLL_IN) != 0 {
            let read = (sys.channel_read)(s.ctrl_chan, s.ctrl_buf.as_mut_ptr(), CTRL_MSG_SIZE);
            if read >= CTRL_MSG_SIZE as i32 {
                let cmd = s.ctrl_buf[0];
                if cmd == CTRL_STOP {
                    close_connection(s);
                    dev_log(sys, 3, b"[rtp] stopped".as_ptr(), 13);
                    s.phase = RtpPhase::Idle;
                    return 0;
                } else if cmd == CTRL_SET_ENDPOINT {
                    let port = u16::from_le_bytes([s.ctrl_buf[2], s.ctrl_buf[3]]);
                    let addr = u32::from_le_bytes([
                        s.ctrl_buf[4],
                        s.ctrl_buf[5],
                        s.ctrl_buf[6],
                        s.ctrl_buf[7],
                    ]);
                    s.peer_ip = addr;
                    s.peer_port = port;
                }
            }
        }
    }

    // TX path
    if s.in_chan >= 0 {
        step_tx(s);
    }

    // RX path — ALWAYS, even when the receive output is unwired. `net_in` is
    // one leg of the ingress fan-out, so it receives every inbound datagram
    // including those addressed to other endpoints; a leg nobody drains fills
    // its ring and stalls ingress for EVERY module on the fan-out. That is
    // not hypothetical: on the Pi 5 rig the undrained ring stalled the edge
    // for 42 s and the peer's BYE never reached sip (2026-08-26).
    step_rx(s);

    0
}

// ============================================================================
// TX: accumulate G.711, build RTP packets, send
// ============================================================================

unsafe fn step_tx(s: &mut RtpState) {
    if s.encoded_chan >= 0 && ((*s.syscalls).channel_poll)(s.encoded_chan, POLL_IN) > 0 {
        step_encoded_tx(s);
        return;
    }
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;

    let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
    if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 {
        return;
    }

    let space = MAX_PAYLOAD - s.acc_len as usize;
    if space == 0 {
        send_rtp_packet(s);
        return;
    }

    let read = (sys.channel_read)(
        in_chan,
        s.acc_buf.as_mut_ptr().add(s.acc_len as usize),
        space,
    );
    if read <= 0 {
        return;
    }
    s.acc_len += read as u16;

    while s.acc_len >= s.ptime_bytes {
        send_rtp_packet(s);
    }
}

/// Consume one bounded encoded-media record and send its H264/VP8 RTP
/// fragments through the same SRTP/TURN transport path as PCMU.
unsafe fn step_encoded_tx(s: &mut RtpState) {
    let state_ptr = s as *mut RtpState;
    let sys = &*s.syscalls;
    if (sys.channel_poll)(s.encoded_chan, POLL_IN) <= 0 {
        return;
    }
    let room = MEDIA_BUF_SIZE - s.media_len as usize;
    if room == 0 {
        s.media_len = 0;
        return;
    }
    let n = (sys.channel_read)(
        s.encoded_chan,
        s.media_buf.as_mut_ptr().add(s.media_len as usize),
        room,
    );
    if n <= 0 {
        return;
    }
    s.media_len += n as u16;
    let Some(frame) = rtp_media_wire::decode(&s.media_buf[..s.media_len as usize]) else {
        if s.media_len as usize >= MEDIA_BUF_SIZE {
            s.media_len = 0;
        }
        return;
    };
    let Some(mut packets) =
        rtp_media::EncodedPacketizer::new(frame, MAX_PAYLOAD - 2, s.seq_num, s.ssrc)
    else {
        s.media_len = 0;
        return;
    };
    let saved_ptime = s.ptime_bytes;
    let saved_ts = s.timestamp;
    let pt = match frame.codec {
        rtp_media_wire::CODEC_H264 => 102,
        rtp_media_wire::CODEC_VP8 => 96,
        _ => s.payload_type,
    };
    s.payload_type = pt;
    let mut payload = [0u8; MAX_PAYLOAD];
    while let Some(meta) = packets.next(&mut payload) {
        s.acc_buf[..meta.len].copy_from_slice(&payload[..meta.len]);
        s.acc_len = meta.len as u16;
        s.tx_marker = u8::from(meta.marker);
        s.timestamp = meta.timestamp;
        // `packets` borrows the bounded media buffer. The transport sender
        // touches only the independent packet/net buffers; use the module's
        // established raw ABI boundary to avoid copying a video access unit.
        send_rtp_packet(&mut *state_ptr);
    }
    s.payload_type = pt;
    s.ptime_bytes = saved_ptime;
    s.timestamp = saved_ts.wrapping_add(1);
    s.tx_marker = 0;
    s.media_len = 0;
}

// ============================================================================
// RX: receive RTP, validate, extract payload, write to channel
// ============================================================================

/// Frames consumed from the ingress fan-out per step. Bounds the drain loop
/// (no unbounded loop in a module step) while comfortably outrunning any
/// admitted media cadence: at a 1 ms tick this is 4000 frames/s against a
/// 50/s PCMU stream.
const RX_DRAIN_BUDGET: u32 = 4;

unsafe fn step_rx(s: &mut RtpState) {
    let sys = &*s.syscalls;
    let out_chan = s.out_chan;

    // Re-offer a record a full channel refused. While a packet of OURS is
    // parked on backpressure, nothing more is read — the ring holds the
    // ordering. The record is re-framed whole (`net_write_frame` is
    // all-or-nothing), so a refusal leaves the FIFO aligned.
    if out_chan >= 0 && s.pending_out != 0 {
        let wrote = net_write_frame(
            sys,
            out_chan,
            s.pending_type,
            s.out_buf.as_ptr(),
            s.pending_out as usize,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
        if wrote == 0 {
            return;
        }
        s.pending_out = 0;
    }

    if s.net_in_chan < 0 {
        return;
    }

    let mut budget = RX_DRAIN_BUDGET;
    while budget > 0 {
        budget -= 1;
        if !step_rx_one(s) {
            break;
        }
    }
}

/// Consume one frame from the ingress fan-out. Returns whether the caller may
/// read another this step.
/// One `[seq:u16 LE][rtp_ts:u32 LE]` per accepted packet, for a module that
/// builds RFC 3550 reception reports.
///
/// **Best-effort, and deliberately so.** A stats record the channel cannot
/// take is dropped and counted, never retried: media must not stall because a
/// report consumer fell behind, and jitter is a smoothed estimate that a
/// missing sample perturbs rather than corrupts.
///
/// No arrival time is carried, because this module reads no clock and is
/// attested `agnostic`. The consumer stamps arrival from its own clock; §A.8
/// takes a difference of differences, so a constant offset between the two
/// modules' views of "now" cancels exactly.
unsafe fn emit_stat(s: &mut RtpState, rec: &[u8]) {
    if s.stats_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.stats_chan, POLL_OUT);
    if poll <= 0 || (poll as u32) & POLL_OUT == 0 {
        s.stats_dropped = s.stats_dropped.wrapping_add(1);
        return;
    }
    if (sys.channel_write)(s.stats_chan, rec.as_ptr(), rec.len()) != rec.len() as i32 {
        s.stats_dropped = s.stats_dropped.wrapping_add(1);
    }
}

/// One reception record per accepted packet.
unsafe fn emit_rtcp_stats(s: &mut RtpState, seq: u16, rtp_ts: u32, ssrc: u32) {
    if s.stats_chan < 0 {
        return;
    }
    let mut rec = [0u8; RTCP_STAT_MAX_LEN];
    let Some(n) = put_rtcp_stat_rx_meta(&mut rec, seq, rtp_ts, ssrc) else {
        return;
    };
    emit_stat(s, &rec[..n]);
}

/// The transmit counters, after each packet goes out.
///
/// A LATEST-VALUE record, which is why dropping one costs nothing: the next
/// packet supersedes it, and the consumer only ever needs the counters as they
/// stood when it composes a report. That is also why this is emitted per
/// packet rather than accumulated — there is no request channel on which a
/// report could ask.
unsafe fn emit_rtcp_tx_stats(s: &mut RtpState, sent_ts: u32) {
    if s.stats_chan < 0 {
        return;
    }
    let mut rec = [0u8; RTCP_STAT_MAX_LEN];
    let Some(n) = put_rtcp_stat_tx(&mut rec, s.packets_sent, s.octets_sent, sent_ts) else {
        return;
    };
    emit_stat(s, &rec[..n]);
}

unsafe fn step_rx_one(s: &mut RtpState) -> bool {
    let sys = &*s.syscalls;
    let out_chan = s.out_chan;

    let poll = (sys.channel_poll)(s.net_in_chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return false;
    }

    let buf = s.rx_buf.as_mut_ptr();
    // Frame-ALIGNED: a payload larger than `rx_buf` has its tail drained from
    // the channel rather than left in the FIFO. Plain `net_read_frame` leaves
    // it, so the next read would start mid-payload and every following packet
    // would be misparsed: one oversized datagram costing the whole stream
    // rather than itself.
    let (msg_type, payload_len, declared_len) =
        net_read_frame_aligned(sys, s.net_in_chan, buf, RX_BUF_SIZE);
    if declared_len > payload_len {
        // Loud, not silent: a truncated packet is a lost audio frame, and a
        // receiver that drops media quietly turns a peer misconfiguration into
        // an unexplained quality problem.
        s.rx_truncated = s.rx_truncated.wrapping_add(1);
        dev_log(sys, 2, b"[rtp] rx pkt too large".as_ptr(), 22);
        return true;
    }

    // MSG_DG_RX_FROM payload:
    //   [ep_id:1][af:1=4][src_addr:4 BE][src_port:2 LE][rtp_data...]
    if msg_type != DG_MSG_RX_FROM || payload_len < DG_V4_PREFIX + RTP_HEADER_SIZE {
        return true;
    }
    // Another endpoint's datagram: the fan-out delivers every inbound frame
    // to every leg, and this one is addressed elsewhere. Consuming and
    // skipping it IS the routing contract — the addressed module holds its
    // own copy on its own leg.
    if s.ep_id != 0xFF && *buf.add(NET_FRAME_HDR) != s.ep_id {
        return true;
    }
    // Verify address family is IPv4
    if *buf.add(NET_FRAME_HDR + 1) != DG_AF_INET {
        return true;
    }
    // Ours, but the receive path is unwired in this graph (transmit-only
    // role, e.g. the voice-echo composition where sip owns receive). Counted,
    // never silent — and never left in the ring, which would stall the
    // fan-out for everyone.
    if out_chan < 0 {
        s.rx_unrouted = s.rx_unrouted.wrapping_add(1);
        return true;
    }
    // Output backpressured: leave the frame processing to a later step. The
    // frame is already consumed, so it must be processed now or counted; the
    // pending mechanism below parks the extracted payload, so proceed.

    let pkt_len = payload_len - DG_V4_PREFIX;
    let data_start = NET_FRAME_HDR + DG_V4_PREFIX;
    let source_ip = u32::from_be_bytes([
        *buf.add(NET_FRAME_HDR + 2),
        *buf.add(NET_FRAME_HDR + 3),
        *buf.add(NET_FRAME_HDR + 4),
        *buf.add(NET_FRAME_HDR + 5),
    ]);
    let source_port =
        u16::from_le_bytes([*buf.add(NET_FRAME_HDR + 6), *buf.add(NET_FRAME_HDR + 7)]);
    __aeabi_memmove(
        s.rx_buf.as_mut_ptr(),
        s.rx_buf.as_ptr().add(data_start),
        pkt_len,
    );

    if pkt_len < RTP_HEADER_SIZE {
        return true;
    }

    let mut media_len = pkt_len;
    if s.turn_relay_ip != 0 && source_ip == s.turn_relay_ip && source_port == s.turn_relay_port {
        let media = match turn_wire::parse(core::slice::from_raw_parts(s.rx_buf.as_ptr(), pkt_len))
        {
            turn_wire::TurnMedia::Channel { payload, .. }
            | turn_wire::TurnMedia::Indication { payload } => payload,
            turn_wire::TurnMedia::Invalid => return true,
        };
        if media.len() > s.rx_buf.len() {
            return true;
        }
        core::ptr::copy(media.as_ptr(), s.rx_buf.as_mut_ptr(), media.len());
        media_len = media.len();
    }

    // Validate the header and locate the payload — version, CSRC list, §5.3.1
    // extension and §5.1 padding, all in the shared core.
    let pkt = s.rx_buf.as_mut_ptr();
    let Some(mut h) = rtp_parse(core::slice::from_raw_parts(pkt, media_len)) else {
        return true;
    };
    if h.payload_type != s.payload_type || (s.rx_ssrc != 0 && h.ssrc != s.rx_ssrc) {
        return true;
    }
    // Keep replay and loss state independent for each admitted SSRC. A
    // wildcard receiver may carry several tracks (for example audio and
    // video); one global sequence window would reject valid packets and
    // manufacture loss whenever the streams interleave.
    let Some(source_idx) = s.rx_source(h.ssrc) else {
        return true;
    };
    let mut authenticated_len = media_len;
    if s.srtp_profile == 1 && s.srtp_key_set != 0 && s.srtp_auth_set != 0 && s.srtp_cm_salt_set != 0
    {
        let prior = s.rx_sources[source_idx]
            .replay
            .highest()
            .unwrap_or(h.seq as u64);
        let roc = srtp_core::estimate_roc(prior, h.seq) as u32;
        let index = srtp_core::packet_index(roc, h.seq);
        let Some(plain_len) = srtp_core::unprotect_aes_cm_sha1_80(
            &s.srtp_key,
            &s.srtp_auth_key,
            &s.srtp_cm_salt,
            h.ssrc,
            index,
            core::slice::from_raw_parts_mut(pkt, media_len),
            RTP_HEADER_SIZE,
        ) else {
            return true;
        };
        if !s.rx_sources[source_idx].replay.accept(index) {
            return true;
        }
        authenticated_len = plain_len;
        h = match rtp_parse(core::slice::from_raw_parts(pkt, authenticated_len)) {
            Some(v) => v,
            None => return true,
        };
    } else if s.srtp_profile == 0 && s.srtp_key_set != 0 && s.srtp_salt_set != 0 {
        let prior = s.rx_sources[source_idx]
            .replay
            .highest()
            .unwrap_or(h.seq as u64);
        let roc = srtp_core::estimate_roc(prior, h.seq) as u32;
        let index = srtp_core::packet_index(roc, h.seq);
        let Some(plain_len) = srtp_core::unprotect_aes128_gcm(
            &s.srtp_key,
            &s.srtp_salt,
            h.ssrc,
            index,
            core::slice::from_raw_parts_mut(pkt, media_len),
            RTP_HEADER_SIZE,
        ) else {
            return true;
        };
        if !s.rx_sources[source_idx].replay.accept(index) {
            return true;
        }
        authenticated_len = plain_len;
        h = match rtp_parse(core::slice::from_raw_parts(pkt, authenticated_len)) {
            Some(header) => header,
            None => return true,
        };
    }
    // Payload type and SSRC identify the negotiated media stream. Reject
    // mismatches before sequence/loss accounting so another codec or
    // participant cannot contaminate the admitted stream's statistics.
    let header_len = h.payload_start;
    let payload_end = h.payload_end;
    let seq = h.seq;

    // Track sequence numbers for loss detection
    if s.rx_sources[source_idx].valid != 0 {
        let expected = s.rx_sources[source_idx].last_seq.wrapping_add(1);
        if seq != expected {
            let gap = seq
                .wrapping_sub(s.rx_sources[source_idx].last_seq)
                .wrapping_sub(1);
            if gap > 0 && gap < 1000 {
                s.packets_lost = s.packets_lost.wrapping_add(gap as u32);
            }
        }
    }
    s.rx_sources[source_idx].last_seq = seq;
    s.packets_received = s.packets_received.wrapping_add(1);

    // Extract payload
    let payload_len = payload_end - header_len;
    // Bound by what we ACCEPT, not by what we transmit. `out_buf` is
    // `RX_MAX_PAYLOAD`, and the buffer sizing above already makes this
    // unreachable for an unfragmented datagram — it stays as the bound that
    // makes the copy provably in-range rather than as live clamping.
    let copy_len = if payload_len > RX_MAX_PAYLOAD {
        RX_MAX_PAYLOAD
    } else {
        payload_len
    };

    // One `rtcp_stats` record per accepted packet, for whatever builds
    // reception reports. Emitted before the media record because it describes
    // THIS packet and must not be reordered against the next one.
    emit_rtcp_stats(s, seq, h.timestamp, h.ssrc);

    // One `packets` record, framed with the shared TLV so records never
    // concatenate on the byte-stream channel: payload is `[seq][audio]`.
    let mid = rtp_mid(core::slice::from_raw_parts(pkt, authenticated_len), &h);
    if !s.route_table.is_empty() && s.route_table.resolve(mid, h.payload_type, h.ssrc).is_none() {
        return true;
    }
    let (record_type, prefix_len) = if mid.is_empty() {
        (
            REC_RTP_RX_META,
            put_rtp_rx_meta(
                &mut s.out_buf,
                seq,
                h.timestamp,
                h.ssrc,
                h.payload_type,
                h.marker,
            ),
        )
    } else {
        (
            REC_RTP_RX_META_MID,
            put_rtp_rx_meta_mid(
                &mut s.out_buf,
                seq,
                h.timestamp,
                h.ssrc,
                h.payload_type,
                h.marker,
                mid,
            ),
        )
    };
    let Some(prefix_len) = prefix_len else {
        return true;
    };
    __aeabi_memcpy(
        s.out_buf.as_mut_ptr().add(prefix_len),
        pkt.add(header_len),
        copy_len,
    );
    let rec_len = prefix_len + copy_len;
    let wrote = net_write_frame(
        sys,
        out_chan,
        record_type,
        s.out_buf.as_ptr(),
        rec_len,
        s.net_buf.as_mut_ptr(),
        NET_BUF_SIZE,
    );
    if wrote == 0 {
        // Refused whole: park the payload; the retry above re-offers it.
        // Reading further frames this step would overwrite `out_buf`.
        s.pending_out = rec_len as u16;
        s.pending_type = record_type;
        return false;
    }
    true
}

// ============================================================================
// Close connection and reset streaming state
// ============================================================================

unsafe fn close_connection(s: &mut RtpState) {
    if s.net_out_chan >= 0 && s.ep_id != 0xFF {
        let sys = &*s.syscalls;
        let payload = [s.ep_id];
        net_write_frame(
            sys,
            s.net_out_chan,
            DG_CMD_CLOSE,
            payload.as_ptr(),
            1,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
    }
    s.ep_id = 0xFF;
    // Reset TX state
    s.seq_num = 0;
    s.timestamp = 0;
    s.acc_len = 0;
    // Reset RX state
    s.last_seq = 0;
    s.seq_valid = 0;
    s.rx_sources = [RxSsrcState::empty(); MAX_RX_SSRC];
    s.packets_received = 0;
    s.packets_lost = 0;
    s.rx_truncated = 0;
    s.pending_out = 0;
    s.pending_offset = 0;
}

// ============================================================================
// RTP Packet Construction and Send
// ============================================================================

unsafe fn send_rtp_packet(s: &mut RtpState) {
    let sys = &*s.syscalls;

    let payload_len = if s.acc_len < s.ptime_bytes {
        s.acc_len as usize
    } else {
        s.ptime_bytes as usize
    };

    if payload_len == 0 {
        return;
    }

    // Build RTP header (RFC 3550)
    let pkt = s.pkt_buf.as_mut_ptr();

    // Byte 0: V=2, P=0, X=0, CC=0 → 0x80
    *pkt = 0x80;
    // Byte 1: marker bit plus negotiated payload type.
    *pkt.add(1) = (s.payload_type & 0x7F) | if s.tx_marker != 0 { 0x80 } else { 0 };
    // Bytes 2-3: sequence number (big-endian)
    *pkt.add(2) = (s.seq_num >> 8) as u8;
    *pkt.add(3) = (s.seq_num & 0xFF) as u8;
    // Bytes 4-7: timestamp (big-endian)
    *pkt.add(4) = (s.timestamp >> 24) as u8;
    *pkt.add(5) = ((s.timestamp >> 16) & 0xFF) as u8;
    *pkt.add(6) = ((s.timestamp >> 8) & 0xFF) as u8;
    *pkt.add(7) = (s.timestamp & 0xFF) as u8;
    // Bytes 8-11: SSRC (big-endian)
    *pkt.add(8) = (s.ssrc >> 24) as u8;
    *pkt.add(9) = ((s.ssrc >> 16) & 0xFF) as u8;
    *pkt.add(10) = ((s.ssrc >> 8) & 0xFF) as u8;
    *pkt.add(11) = (s.ssrc & 0xFF) as u8;

    // Copy payload after header
    __aeabi_memcpy(pkt.add(RTP_HEADER_SIZE), s.acc_buf.as_ptr(), payload_len);

    // Send packet via CMD_DG_SEND_TO:
    //   [0x21][len_lo][len_hi][ep_id:1][af:1=4][dst_addr:4 BE][dst_port:2 LE][rtp_packet...]
    let plain_len = RTP_HEADER_SIZE + payload_len;
    let total = if s.srtp_profile == 1
        && s.srtp_key_set != 0
        && s.srtp_auth_set != 0
        && s.srtp_cm_salt_set != 0
    {
        srtp_core::protect_aes_cm_sha1_80(
            &s.srtp_key,
            &s.srtp_auth_key,
            &s.srtp_cm_salt,
            s.ssrc,
            s.seq_num as u64,
            core::slice::from_raw_parts_mut(pkt, PKT_BUF_SIZE),
            RTP_HEADER_SIZE,
            plain_len,
        )
        .unwrap_or(0)
    } else if s.srtp_profile == 0 && s.srtp_key_set != 0 && s.srtp_salt_set != 0 {
        srtp_core::protect_aes128_gcm(
            &s.srtp_key,
            &s.srtp_salt,
            s.ssrc,
            s.seq_num as u64,
            core::slice::from_raw_parts_mut(pkt, PKT_BUF_SIZE),
            RTP_HEADER_SIZE,
            plain_len,
        )
        .unwrap_or(0)
    } else {
        plain_len
    };
    if total == 0 {
        return;
    }
    let mut wire_total = total;
    let mut dest_ip = s.peer_ip;
    let mut dest_port = s.peer_port;
    if s.turn_relay_ip != 0 && s.turn_peer_ip != 0 {
        // Preserve the encrypted RTP while the packet buffer is reused for
        // the TURN indication envelope. The relay receives the indication;
        // its XOR-PEER-ADDRESS identifies the actual media peer.
        core::ptr::copy_nonoverlapping(pkt, s.net_buf.as_mut_ptr(), total);
        let mut txn = [0u8; 12];
        txn[..2].copy_from_slice(&s.seq_num.to_be_bytes());
        txn[2..6].copy_from_slice(&s.ssrc.to_be_bytes());
        txn[6..10].copy_from_slice(&s.timestamp.to_be_bytes());
        txn[10] = s.payload_type;
        txn[11] = 0;
        wire_total = if s.turn_channel != 0 {
            // A bound channel uses the compact ChannelData framing. The
            // channel is selected only after TURN ChannelBind succeeds;
            // otherwise retain the authenticated Send Indication path.
            turn_wire::write_channel_data(
                s.turn_channel,
                &s.net_buf[..total],
                core::slice::from_raw_parts_mut(pkt, PKT_BUF_SIZE),
            )
        } else {
            turn_wire::write_send_indication(
                &txn,
                s.turn_peer_ip.to_be_bytes(),
                s.turn_peer_port,
                &s.net_buf[..total],
                core::slice::from_raw_parts_mut(pkt, PKT_BUF_SIZE),
            )
        }
        .unwrap_or(0);
        if wire_total == 0 {
            return;
        }
        dest_ip = s.turn_relay_ip;
        dest_port = s.turn_relay_port;
    }
    let scratch = s.net_buf.as_mut_ptr();
    let frame_payload_len = DG_V4_PREFIX + wire_total;
    if s.ep_id != 0xFF && frame_payload_len + NET_FRAME_HDR <= NET_BUF_SIZE {
        *scratch = DG_CMD_SEND_TO;
        *scratch.add(1) = (frame_payload_len & 0xFF) as u8;
        *scratch.add(2) = ((frame_payload_len >> 8) & 0xFF) as u8;
        *scratch.add(NET_FRAME_HDR) = s.ep_id;
        *scratch.add(NET_FRAME_HDR + 1) = DG_AF_INET;
        let ip_bytes = dest_ip.to_be_bytes();
        *scratch.add(NET_FRAME_HDR + 2) = ip_bytes[0];
        *scratch.add(NET_FRAME_HDR + 3) = ip_bytes[1];
        *scratch.add(NET_FRAME_HDR + 4) = ip_bytes[2];
        *scratch.add(NET_FRAME_HDR + 5) = ip_bytes[3];
        let port_bytes = dest_port.to_le_bytes();
        *scratch.add(NET_FRAME_HDR + 6) = port_bytes[0];
        *scratch.add(NET_FRAME_HDR + 7) = port_bytes[1];
        core::ptr::copy_nonoverlapping(pkt, scratch.add(NET_FRAME_HDR + DG_V4_PREFIX), wire_total);
        let frame_total = NET_FRAME_HDR + frame_payload_len;
        let sent = (sys.channel_write)(s.net_out_chan, scratch, frame_total);
        if sent < 0 && sent != E_AGAIN {
            dev_log(sys, 2, b"[rtp] send err".as_ptr(), 14);
        }
    }

    // The timestamp of the packet just sent, captured BEFORE the advance
    // below. A Sender Report says "this RTP timestamp and this wallclock name
    // the same instant", and the advanced value names the NEXT packet — one
    // packet time in the future, which is a 20 ms lie at the default ptime.
    let sent_ts = s.timestamp;

    // Advance sequence and timestamp
    s.seq_num = s.seq_num.wrapping_add(1);
    s.timestamp = s.timestamp.wrapping_add(payload_len as u32);

    // §6.4.1's sender counters, advancing WITH the sequence number rather than
    // with the transport's verdict on the write above. That write can be
    // skipped or refused, and it is logged when it is — but the sequence
    // number has already moved, so a count that disagreed with the stream's
    // own numbering would describe a stream nobody sent.
    s.packets_sent = s.packets_sent.wrapping_add(1);
    s.octets_sent = s.octets_sent.wrapping_add(payload_len as u32);
    emit_rtcp_tx_stats(s, sent_ts);

    // Shift remaining data in accumulator
    let remaining = s.acc_len as usize - payload_len;
    if remaining > 0 {
        __aeabi_memmove(
            s.acc_buf.as_mut_ptr(),
            s.acc_buf.as_ptr().add(payload_len),
            remaining,
        );
    }
    s.acc_len = remaining as u16;
}

// ============================================================================
// Panic Handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `../fluxor/modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
