//! Client exchange mode: HTTP as an ordered-ack exchange provider.
//!
//! A request arrives on `publish_in`, the client's existing phase machine
//! performs it, and the response leaves on `reply_out` under the same
//! correlation:
//!
//!   publish_in  ->  a request record  ->  the phase machine
//!   reply_out   <-  the response, correlated by `corr`, keyed by `msg_key`
//!
//! Nothing here speaks HTTP. It fills `method` / `path` / `request_body`,
//! re-arms the phase machine, and frames whatever the machine produced.
//!
//! # The request record
//!
//! `Publish.payload` carries:
//!
//! ```text
//! [method:u8][path_len:u16 LE][body_len:u16 LE][path…][body…]
//! ```
//!
//! `method` is a `wire::method` verb code — the same byte an `HttpRequest`
//! envelope carries on `req_out`, so one vocabulary describes a request in
//! either direction. A producer composes this at a pipeline edge, which is
//! framing rather than protocol work, so nothing upstream needs HTTP logic to
//! ask a question here.
//!
//! # Correlation and concurrency
//!
//! One request is in flight at a time: `exchange_corr` is the whole table. The
//! client opens a connection per request and closes it (`Connection: close`),
//! so there is no session on which a second request could overlap. A producer
//! wanting concurrency asks for more instances, which is also how it gets more
//! sockets.
//!
//! `corr` is never 0 on a publish — the contract says so and `Publish::decode`
//! enforces it — which is what lets a zero `exchange_corr` mean idle.

use super::super::exchange::{
    Publish, Reply, FLAG_BROADCAST, MSG_PUBLISH, MSG_REPLY, REFUSE_OVERSIZE, REFUSE_UNROUTABLE,
    STATUS_OK,
};
use super::super::HttpState;
use super::{Phase, EXCHANGE_KEY_MAX, EXCHANGE_REPLY_MAX};

/// Fixed head of a request record: `method` + the two lengths.
const REQ_HEAD: usize = 1 + 2 + 2;

/// The 3-byte channel envelope (`[msg_type][len:u16 LE]`) every frame on this
/// pair rides, as `net_read_frame`/`net_write_frame` compose it elsewhere.
const ENVELOPE: usize = 3;

/// Wire the exchange ports. Both are optional: a graph using the client in
/// its one-shot param form wires neither, and `armed()` stays false.
pub(crate) unsafe fn init(s: &mut HttpState) {
    let sys = &*s.syscalls;
    s.client.exchange_in_chan = super::super::dev_channel_port(sys, 0, 8);
    s.client.exchange_out_chan = super::super::dev_channel_port(sys, 1, 9);
    s.client.exchange_corr = 0;
}

/// Is this client driven by the graph rather than by params?
pub(crate) fn armed(s: &HttpState) -> bool {
    s.client.exchange_in_chan >= 0 && s.client.exchange_out_chan >= 0
}

/// Is a request in flight?
pub(crate) fn busy(s: &HttpState) -> bool {
    s.client.exchange_corr != 0
}

/// Adopt a publish as the request in flight, so it can be answered.
unsafe fn adopt(s: &mut HttpState, corr: u64, key: &[u8]) {
    let n = key.len().min(EXCHANGE_KEY_MAX);
    s.client.exchange_key[..n].copy_from_slice(&key[..n]);
    s.client.exchange_key_len = n as u16;
    s.client.exchange_corr = corr;
    s.client.exchange_reply_len = 0;
    s.client.exchange_oversize = 0;
}

/// Take one request off `publish_in` and arm the phase machine for it.
///
/// Returns true when a request was accepted, which is the caller's signal to
/// start stepping. A frame that does not decode is dropped rather than
/// refused: without a `corr` there is nobody to answer. A frame that decodes
/// but asks for something unperformable IS answered, because by then there is.
pub(crate) unsafe fn poll_request(s: &mut HttpState) -> bool {
    if !armed(s) || busy(s) {
        return false;
    }
    let sys = &*s.syscalls;
    let chan = s.client.exchange_in_chan;

    // `net_read_frame_aligned` owns the 3-byte envelope: it decodes the length
    // field and, when a frame is larger than the buffer, drains the tail so the
    // next read starts on a real header instead of mid-payload. `exchange_stage`
    // is sized for envelope + `PUBLISH_FRAME_MAX`, so `copied < declared` means
    // the producer sent a frame above the contract's ceiling — dropped here,
    // with the channel still aligned behind it.
    let stage = s.client.exchange_stage.as_mut_ptr();
    let cap = s.client.exchange_stage.len();
    let (msg_type, copied, declared) = super::super::net_read_frame_aligned(sys, chan, stage, cap);
    if declared == 0 || copied < declared || msg_type != MSG_PUBLISH {
        return false;
    }
    let body = &s.client.exchange_stage[ENVELOPE..ENVELOPE + copied];
    let Some(publish) = Publish::decode(body) else {
        return false;
    };

    let corr = publish.corr;
    let flags = publish.flags;
    let p = publish.payload;

    // The key is copied out once, up front: `publish` borrows the staging
    // buffer, and every path below hands the state a mutable borrow that ends
    // that one. 512 bytes on the stack, once per request.
    let key_len = publish.msg_key.len().min(EXCHANGE_KEY_MAX);
    let mut key = [0u8; EXCHANGE_KEY_MAX];
    key[..key_len].copy_from_slice(&publish.msg_key[..key_len]);
    let key = &key[..key_len];

    // Everything below answers rather than drops: the frame decoded, so the
    // producer is owed exactly one reply and would otherwise wait out its own
    // timeout for a request this client will never perform.
    //
    // `broadcast = "unsupported"` in the manifest, and delivering a broadcast
    // to the one origin this client dials would ack a fan-out that did not
    // happen.
    let broadcast = flags & FLAG_BROADCAST != 0;

    let (method, path_len, body_len) = if p.len() >= REQ_HEAD {
        (
            p[0],
            u16::from_le_bytes([p[1], p[2]]) as usize,
            u16::from_le_bytes([p[3], p[4]]) as usize,
        )
    } else {
        (super::super::wire::method::METHOD_NONE, 0, 0)
    };

    // A path or body past this client's bounds is OVERSIZE, not UNROUTABLE:
    // the request is well formed and this provider is simply too small for it,
    // which is the distinction that tells a producer whether to shrink the
    // record or change the graph.
    let malformed = broadcast
        || p.len() < REQ_HEAD
        || REQ_HEAD + path_len + body_len != p.len()
        || path_len == 0
        || super::super::wire::method::method_name(method).is_empty();
    let oversize = path_len > super::MAX_PATH_LEN || body_len > super::REQUEST_BODY_SIZE;
    if malformed || oversize {
        let status = if malformed {
            REFUSE_UNROUTABLE
        } else {
            REFUSE_OVERSIZE
        };
        adopt(s, corr, key);
        send_reply(s, status, 0);
        return false;
    }

    s.client.method = method;
    s.client.path[..path_len].copy_from_slice(&p[REQ_HEAD..REQ_HEAD + path_len]);
    s.client.path_len = path_len as u16;
    s.client.request_body[..body_len]
        .copy_from_slice(&p[REQ_HEAD + path_len..REQ_HEAD + path_len + body_len]);
    s.client.request_body_len = body_len as u16;
    s.client.request_body_sent = 0;

    adopt(s, corr, key);

    // Re-arm the phase machine: a fresh connection per exchange, which is what
    // `Connection: close` on every request already implies.
    s.client.recv_len = 0;
    s.client.pending_offset = 0;
    s.client.headers_done = 0;
    s.client.phase = Phase::Init;
    true
}

/// Accumulate `len` response bytes read from `src`.
///
/// An overrun is recorded, not truncated: the reply becomes OVERSIZE, because
/// a short body that looks complete is the failure a consumer cannot detect.
///
/// Takes a raw pointer because every caller's bytes live in another field of
/// the same state — copying them to the stack first would cost a buffer per
/// call site to say something the borrow checker already knows.
///
/// # Safety
/// `src` must be valid for reads of `len` bytes and must not alias
/// `exchange_reply`.
pub(crate) unsafe fn accumulate(s: &mut HttpState, src: *const u8, len: usize) {
    if s.client.exchange_oversize != 0 || len == 0 {
        return;
    }
    let have = s.client.exchange_reply_len as usize;
    if have + len > EXCHANGE_REPLY_MAX {
        s.client.exchange_oversize = 1;
        return;
    }
    core::ptr::copy_nonoverlapping(src, s.client.exchange_reply.as_mut_ptr().add(have), len);
    s.client.exchange_reply_len = (have + len) as u16;
}

/// Answer the request in flight and go idle.
pub(crate) unsafe fn complete(s: &mut HttpState) {
    if !busy(s) {
        return;
    }
    if s.client.exchange_oversize != 0 {
        send_reply(s, REFUSE_OVERSIZE, 0);
        return;
    }
    send_reply(s, STATUS_OK, s.client.exchange_reply_len as usize);
}

/// Answer with a typed refusal because the exchange itself failed.
pub(crate) unsafe fn fail(s: &mut HttpState) {
    if busy(s) {
        send_reply(s, REFUSE_UNROUTABLE, 0);
    }
}

/// Emit one `[MSG_REPLY][len:u16][Reply…]` envelope and go idle.
///
/// `payload_len` names a prefix of `exchange_reply` rather than a slice, so the
/// reply is framed straight out of state — the body is up to `PAYLOAD_MAX` and
/// a copy of it, on the stack, on the way to a channel, would be the largest
/// allocation in the module for no purpose.
///
/// Idle is set even when the write fails. Holding the corr would wedge the
/// client on a full ring with nobody to retry it, and the contract's answer to
/// a lost answer is the producer's timeout, not an unbounded wait here.
unsafe fn send_reply(s: &mut HttpState, status: u8, payload_len: usize) {
    let sys = &*s.syscalls;
    let chan = s.client.exchange_out_chan;
    let key_len = s.client.exchange_key_len as usize;
    let plen = payload_len.min(EXCHANGE_REPLY_MAX);

    // Composed in `exchange_stage`, which held the inbound publish and is free
    // once its fields were copied out. `exchange_key`, `exchange_reply` and
    // `exchange_stage` are three disjoint fields, so the frame is built where
    // it will be written from without a copy through the stack.
    let encoded = Reply {
        corr: s.client.exchange_corr,
        status,
        msg_key: &s.client.exchange_key[..key_len],
        payload: &s.client.exchange_reply[..plen],
    }
    .encode(&mut s.client.exchange_stage[ENVELOPE..]);

    if let Some(n) = encoded {
        // The envelope is written in place rather than through
        // `net_write_frame`, which copies a payload into a separate scratch —
        // here the payload was composed in that very buffer, so the copy would
        // overlap itself. One `channel_write` still carries the whole message,
        // which is the property that matters: a reader never sees a partial
        // frame.
        s.client.exchange_stage[0] = MSG_REPLY;
        s.client.exchange_stage[1..ENVELOPE].copy_from_slice(&(n as u16).to_le_bytes());
        let _ = (sys.channel_write)(chan, s.client.exchange_stage.as_ptr(), ENVELOPE + n);
    }

    s.client.exchange_corr = 0;
    s.client.exchange_reply_len = 0;
    s.client.exchange_oversize = 0;
}
