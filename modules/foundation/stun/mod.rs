//! STUN Binding server — tells a peer the address its packets arrived from.
//!
//! That one fact is what a peer behind a NAT cannot learn any other way, and
//! it is the first thing an ICE agent gathers. The message mechanics live in
//! the host-tested `modules/common/stun_core.rs`; this module is the pump: bind
//! a datagram endpoint, answer Binding requests, and nothing else.
//!
//! **What this module is not.** It is not an ICE agent. It gathers no
//! candidates, forms no pairs, schedules no connectivity checks and nominates
//! nothing — those are decisions about reachability, and reachability policy
//! belongs to Wormhole rather than to a protocol codec. This module answers a
//! question; it does not decide what to do with the answer.
//!
//! Ports:  net_in/net_out (the datagram surface).
//! Params: `port` (UDP port to bind, default 3478).

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK + shared cores are include!'d wholesale; each module consumes only a subset"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the \
              runtime owns these pointers and their validity is the ABI's contract, and the \
              signature is fixed by that contract rather than chosen here."
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "shared SDK surface across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// SHA-1 for MESSAGE-INTEGRITY. Mounted before the core, which calls it by
// bare name — the same arrangement `modules/foundation/http/wire/ws.rs` uses for the WebSocket accept
// value, and for the same reason: the SDK is the repo set's one crypto owner.
mod sdkcrypto {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs");
}
use sdkcrypto::sha1;

// The message mechanics, included FLAT rather than mounted as a submodule.
// The core computes MESSAGE-INTEGRITY and calls `sha1` by bare name, which is
// how `modules/foundation/http/wire/ws.rs` mounts the WebSocket frame core: a
// submodule would put the
// SDK's crypto out of the core's scope.
include!("../../common/stun_core.rs");

// The relay extension, mounted here because TURN IS STUN: it reuses this
// module's header, attribute walk and integrity machinery wholesale, and a
// second module mounting `stun_core.rs` again would compile two copies of the
// same message mechanics. This responder does not itself relay anything; the
// codec is here so that whatever holds an allocation has one spelling to use.
include!("../../common/turn_core.rs");

const NET_BUF: usize = 1600;
const MSG_BUF: usize = 1500;

/// Attributes this responder understands. A comprehension-required attribute
/// outside this set is refused with 420 rather than ignored: answering a
/// request whose terms were not understood claims an agreement that was not
/// reached.
const KNOWN_REQUIRED: &[u16] = &[
    ATTR_USERNAME,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_PRIORITY,
    ATTR_USE_CANDIDATE,
];

#[repr(C)]
struct StunState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,

    port: u16,
    bound: u8,
    ep_id: u8,

    /// The reply this module owes, held until the channel takes it.
    ///
    /// One request is answered at a time: a reply dropped because the channel
    /// was briefly full leaves a peer retransmitting against a responder that
    /// already decided.
    reply: [u8; MSG_BUF],
    reply_len: u16,
    reply_owed: u8,
    reply_ip: u32,
    reply_port: u16,

    msg: [u8; MSG_BUF],
    net_buf: [u8; NET_BUF],

    requests: u32,
    answered: u32,
    refused: u32,
    dropped: u32,
    draining: u8,
}

define_params! {
    StunState;

    1, port, u16, 3478
        => |s, d, len| { s.port = p_u16(d, len, 0, 3478); };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<StunState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut StunState)).draining = 1;
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<StunState>() {
            return -2;
        }
        let s = &mut *(state as *mut StunState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.bound = 0;
        s.ep_id = 0xFF;
        s.reply_len = 0;
        s.reply_owed = 0;
        s.reply_ip = 0;
        s.reply_port = 0;
        s.requests = 0;
        s.answered = 0;
        s.refused = 0;
        s.dropped = 0;
        s.draining = 0;
        set_defaults(s);
        parse_tlv(s, params, params_len);
        dev_log(sys, 3, b"[stun] init".as_ptr(), 11);
        0
    }
}

/// Bind the endpoint, then learn its id.
unsafe fn ensure_bound(s: &mut StunState) -> bool {
    let sys = &*s.syscalls;
    if s.bound == 0 {
        if s.net_out < 0 {
            return false;
        }
        let port = s.port.to_le_bytes();
        let payload = [port[0], port[1], 0u8];
        if net_write_frame(
            sys,
            s.net_out,
            DG_CMD_BIND,
            payload.as_ptr(),
            3,
            s.net_buf.as_mut_ptr(),
            NET_BUF,
        ) != 0
        {
            s.bound = 1;
        }
        return false;
    }
    if s.ep_id == 0xFF {
        if s.net_in < 0 {
            return false;
        }
        let poll = (sys.channel_poll)(s.net_in, POLL_IN);
        if poll > 0 && (poll as u32) & POLL_IN != 0 {
            let (msg_type, plen) = net_read_frame(sys, s.net_in, s.net_buf.as_mut_ptr(), NET_BUF);
            if msg_type == DG_MSG_BOUND && plen >= 1 {
                s.ep_id = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
            }
        }
        return false;
    }
    true
}

/// Build the success response for a Binding request from `(ip, port)`.
unsafe fn build_success(s: &mut StunState, header: &StunHeader, ip: u32, port: u16) -> bool {
    let mut out = [0u8; MSG_BUF];
    let Some(mut at) = write_stun_header(STUN_CLASS_SUCCESS, header.method, &header.txn, &mut out)
    else {
        return false;
    };
    // The address the request arrived FROM, which is the whole point of the
    // exchange: after a NAT it is not the address the peer believes it has.
    let Some(next) = append_xor_mapped_address_v4(ip.to_be_bytes(), port, &mut out, at) else {
        return false;
    };
    at = next;
    let Some(next) = append_fingerprint(&mut out, at) else {
        return false;
    };
    at = next;
    s.reply[..at].copy_from_slice(&out[..at]);
    s.reply_len = at as u16;
    s.reply_ip = ip;
    s.reply_port = port;
    s.reply_owed = 1;
    true
}

/// Build an error response.
unsafe fn build_error(
    s: &mut StunState,
    header: &StunHeader,
    code: u16,
    reason: &[u8],
    ip: u32,
    port: u16,
) -> bool {
    let mut out = [0u8; MSG_BUF];
    let Some(mut at) = write_stun_header(STUN_CLASS_ERROR, header.method, &header.txn, &mut out)
    else {
        return false;
    };
    let Some(next) = append_error_code(code, reason, &mut out, at) else {
        return false;
    };
    at = next;
    let Some(next) = append_fingerprint(&mut out, at) else {
        return false;
    };
    at = next;
    s.reply[..at].copy_from_slice(&out[..at]);
    s.reply_len = at as u16;
    s.reply_ip = ip;
    s.reply_port = port;
    s.reply_owed = 1;
    true
}

/// Hand the owed reply to the transport, retrying while it refuses.
unsafe fn flush_reply(s: &mut StunState) {
    if s.reply_owed == 0 || s.net_out < 0 || s.ep_id == 0xFF {
        return;
    }
    let sys = &*s.syscalls;
    let len = s.reply_len as usize;
    let mut staged = [0u8; MSG_BUF];
    staged[..len].copy_from_slice(&s.reply[..len]);
    let sent = dev_dg_send_to_v4(
        sys,
        s.net_out,
        s.ep_id,
        s.reply_ip,
        s.reply_port,
        staged.as_ptr(),
        len,
        s.net_buf.as_mut_ptr(),
        NET_BUF,
    );
    if sent != 0 {
        s.reply_owed = 0;
        s.answered = s.answered.wrapping_add(1);
    }
}

/// Read one datagram and decide what it deserves.
unsafe fn pump(s: &mut StunState) {
    if s.reply_owed != 0 || s.net_in < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.net_in, POLL_IN);
    if poll <= 0 || (poll as u32) & POLL_IN == 0 {
        return;
    }
    let (msg_type, plen) = net_read_frame(sys, s.net_in, s.net_buf.as_mut_ptr(), NET_BUF);
    if msg_type != DG_MSG_RX_FROM {
        return;
    }
    // The SDK's own parser rather than hand-read offsets: the datagram surface
    // carries the address big-endian and the port little-endian, and reading
    // the port the same way as the address yields a byte-swapped port that
    // still looks like a port.
    let Some((_ep, ip, port, data_ptr, raw_len)) = parse_dg_rx_from_v4(s.net_buf.as_ptr(), plen)
    else {
        return;
    };
    let data_len = raw_len.min(MSG_BUF);
    core::ptr::copy_nonoverlapping(data_ptr, s.msg.as_mut_ptr(), data_len);

    // Not STUN at all: this endpoint may carry other traffic, and dropping
    // silently is the only correct answer to a datagram that was never
    // addressed to this protocol.
    if !stun_is_plausible(&s.msg[..data_len]) {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    let Some(header) = parse_stun_header(&s.msg[..data_len]) else {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    };
    // Only requests are answered. A response or an indication arriving here
    // belongs to a transaction this module did not start.
    if header.class != STUN_CLASS_REQUEST {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    s.requests = s.requests.wrapping_add(1);

    if header.method != STUN_METHOD_BINDING {
        s.refused = s.refused.wrapping_add(1);
        build_error(s, &header, 400, b"unsupported method", ip, port);
        return;
    }
    // A fingerprint is optional, but one that is present and wrong means the
    // bytes are not what the sender sent.
    let mut copy = [0u8; MSG_BUF];
    copy[..data_len].copy_from_slice(&s.msg[..data_len]);
    if find_attribute(&copy[..data_len], &header, ATTR_FINGERPRINT).is_some()
        && !verify_fingerprint(&copy[..data_len], &header)
    {
        s.dropped = s.dropped.wrapping_add(1);
        return;
    }
    if let Some(unknown) = first_unknown_required(&copy[..data_len], &header, KNOWN_REQUIRED) {
        let _ = unknown;
        s.refused = s.refused.wrapping_add(1);
        build_error(s, &header, 420, b"unknown attribute", ip, port);
        return;
    }
    build_success(s, &header, ip, port);
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut StunState);
        if s.syscalls.is_null() {
            return -1;
        }
        if !ensure_bound(s) {
            return 0;
        }
        pump(s);
        flush_reply(s);
        if s.draining == 1 && s.reply_owed == 0 {
            return 1;
        }
        0
    }
}
