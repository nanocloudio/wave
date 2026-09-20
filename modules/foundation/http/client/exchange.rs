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
//! The records themselves are fluxor's `http_exchange` contract, which
//! this module mounts and a producer outside Wave mounts too -- so the
//! layouts are written once and the two ends cannot drift. What is here is
//! what this client DOES with them.
//!
//! # Asking for the whole response
//!
//! The verb's high bit marks an extended record: answer me with the response
//! and not its body alone. The reply carries the head and goes first; the
//! BODY streams on `file_ctrl` as it arrives and ends with a zero-length
//! chunk.
//!
//! A reply is one record on a surface whose ceiling every provider
//! sizes its buffers from (`exchange::PAYLOAD_MAX`), so a response of any
//! length cannot be one: streaming the body is what keeps the reply inside
//! that ceiling and leaves the response unbounded.
//!
//! Both are what a caller answering somebody else needs and a body cannot
//! supply: a status tells a 204 from a 200 and a redirect from either, and
//! the headers carry the content type, the location, the entity tag. Without
//! them a consumer holds bytes and no account of what they are.
//!
//! The caller's block is spliced into the request head, so its own bytes
//! decide where that head ends, and it is checked before the record is
//! accepted: each line a field ending CRLF, none of them empty. A block
//! carrying a blank line would end the head early and put whatever followed
//! on the wire as a second request the origin would answer.
//!
//! `surface_status` mints a refusal from a status of 400 or above, so that a
//! producer can tell a 503 worth retrying from a 404 worth dropping without
//! parsing a body. An extended reply already carries the status, so the bit
//! takes precedence: surfacing the code instead would answer a caller that
//! asked for the whole response with two bytes of it.
//!
//! An extended record is an HTTP/1.1 arrangement — the block is spliced into
//! an HTTP/1.1 head and the reply is composed from that generation's response
//! decoder — so a client configured for h2c or HTTP/3 refuses one rather than
//! perform a lesser request under its name.
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
//!
//! # Where a request goes
//!
//! A record may end with the authority it is for. A client whose `authority`
//! parameter is set is PINNED: a record naming nothing or naming the same
//! bytes is performed there, and one naming anything else is refused as
//! unroutable — the graph fixed where this client goes, and a record does
//! not get to move it. A client with no `authority` is OPEN: it goes where
//! each record says, keeping ONE connection, so a record for a different
//! authority than the connection in hand closes that connection and dials
//! the new one before the request is sent. A record naming nothing on an
//! open client has nowhere to go and is refused.

use super::super::connection::net_proto::Target;
use super::super::exchange::{
    Publish, Reply, FLAG_BROADCAST, MSG_PUBLISH, MSG_REPLY, REFUSE_OVERSIZE, REFUSE_UNROUTABLE,
    REFUSE_UPSTREAM, STATUS_OK,
};
use super::super::HttpState;
use super::{log, Phase, EXCHANGE_KEY_MAX, EXCHANGE_REPLY_MAX};

// The records this module reads and writes. Mounted rather than restated:
// a producer outside Wave mounts the same file, so an offset written here
// would be an offset that could disagree with one written there.
// The record layouts are the `http_exchange` contract, mounted once in
// `http/mod.rs`. Re-exported rather than imported so `h1.rs` reaches
// `super::exchange::CHUNK_HEAD` through this module as it always has.
pub(crate) use super::super::http_exchange::*;

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
    s.client.exchange_pending = 0;
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
    // Cleared with the rest of the per-exchange state. A response that never
    // reaches its status line — a connection closed mid-headers — would
    // otherwise be answered with the code the PREVIOUS exchange saw, and a
    // producer would retry or discard on a status this peer never sent.
    s.client.last_status = 0;
    s.client.exchange_head_sent = 0;
    s.client.exchange_terminated = 0;
}

/// Take one request off `publish_in` and arm the phase machine for it.
///
/// Returns true when a request was accepted, which is the caller's signal to
/// start stepping. A frame that does not decode is dropped rather than
/// refused: without a `corr` there is nobody to answer. A frame that decodes
/// but asks for something unperformable IS answered, because by then there is.
pub(crate) unsafe fn poll_request(s: &mut HttpState) -> bool {
    if !armed(s)
        || busy(s)
        || (s.client.conn_present != 0
            && (s.client.keep_alive == 0
                || s.client.phase != Phase::Done
                || !s.client.response.reusable))
        || s.client.draining != 0
    {
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
    // buffer, and `adopt` and `send_reply` below both take the state
    // mutably, which ends that borrow. 512 bytes on the stack, once per
    // request.
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

    // The record itself is read by the core that owns its layout, which the
    // producer composing it mounts too. What is left here is what this client
    // does about the answer: which refusal, and where the fields go.
    let parsed = parse_request(
        p,
        &Limits {
            path: super::MAX_PATH_LEN,
            headers: super::REQUEST_HEADERS_MAX,
            body: super::REQUEST_BODY_SIZE,
        },
    );
    // A path or body past this client's bounds is OVERSIZE, not UNROUTABLE:
    // the request is well formed and this provider is simply too small for it,
    // which is the distinction that tells a producer whether to shrink the
    // record or change the graph.
    let request = match parsed {
        RequestParse::Ok(request) => request,
        RequestParse::Oversize => {
            adopt(s, corr, key);
            send_reply(s, REFUSE_OVERSIZE, 0);
            return false;
        }
        RequestParse::Malformed => {
            adopt(s, corr, key);
            send_reply(s, REFUSE_UNROUTABLE, 0);
            return false;
        }
    };
    let method = request.method;
    let extended = request.extended;
    // The caller's headers are spliced into an HTTP/1.1 request head and the
    // answer is composed from the HTTP/1.1 response decoder, so an extended
    // record is refused on the other generations rather than performed as a
    // lesser request under its name: a graph that asked for the whole response
    // and silently got a header-less one cannot tell that from an origin that
    // sent no headers.
    let wrong_generation = extended && (s.h3_mode != 0 || s.client.protocol != 0);
    // The body of an extended response goes out on `file_ctrl`. Unwired, there
    // is nowhere to put it, and performing the request anyway would answer a
    // caller with a head and a status while dropping every byte the response
    // carried.
    let no_body_port = extended && s.client.out_chan < 0;
    if broadcast
        || wrong_generation
        || no_body_port
        || super::super::wire::method::method_name(method).is_empty()
    {
        adopt(s, corr, key);
        send_reply(s, REFUSE_UNROUTABLE, 0);
        return false;
    }
    // Where this request goes. A pinned client refuses a record that names
    // anywhere else; an open client goes where the record says, and refuses
    // one that says nothing or names what no dial can carry.
    let module_authority = &s.client.authority[..s.client.authority_len as usize];
    let record_authority = request.authority;
    let refused = if !module_authority.is_empty() {
        !record_authority.is_empty() && record_authority != module_authority
    } else {
        record_authority.is_empty() || Target::parse(record_authority).is_none()
    };
    if refused {
        log(
            s,
            b"[http] record authority refused: pinned or not host[:port]",
        );
        adopt(s, corr, key);
        send_reply(s, REFUSE_UNROUTABLE, 0);
        return false;
    }
    if record_authority.len() > super::AUTHORITY_MAX {
        adopt(s, corr, key);
        send_reply(s, REFUSE_OVERSIZE, 0);
        return false;
    }
    let (path_len, headers_len, body_len) = (
        request.path.len(),
        request.headers.len(),
        request.body.len(),
    );

    // An open client takes the record's authority as the authority of the
    // connection in hand. If a connection to another one is being held open
    // it is marked stale, and `Init` closes it before dialling the new one.
    // A pinned client's connection authority is its own and never moves.
    if module_authority.is_empty() {
        let n = record_authority.len();
        if s.client.conn_present != 0
            && &s.client.conn_authority[..s.client.conn_authority_len as usize] != record_authority
        {
            s.client.conn_stale = 1;
            s.client.response.reusable = false;
        }
        s.client.conn_authority[..n].copy_from_slice(record_authority);
        s.client.conn_authority_len = n as u16;
    }

    s.client.method = method;
    s.client.exchange_extended = u8::from(extended);
    s.client.path[..path_len].copy_from_slice(request.path);
    s.client.path_len = path_len as u16;
    s.client.request_headers[..headers_len].copy_from_slice(request.headers);
    s.client.request_headers_len = headers_len as u16;
    s.client.request_body[..body_len].copy_from_slice(request.body);
    s.client.request_body_len = body_len as u16;
    s.client.request_body_sent = 0;

    adopt(s, corr, key);

    // Re-arm the phase machine: a fresh connection per exchange, which is what
    // `Connection: close` on every request already implies.
    s.client.recv_len = 0;
    s.client.pending_offset = 0;
    s.client.headers_done = 0;
    s.client.phase = Phase::Init;
    s.client.h2_phase = 0;
    #[cfg(feature = "h3")]
    if s.h3_mode != 0 {
        super::h3::next_request(s);
    }
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
    if pending(s) {
        flush_reply(s);
        return;
    }
    if s.client.last_status == 0 {
        fail(s);
        return;
    }
    if s.client.exchange_oversize != 0 {
        send_reply(s, REFUSE_OVERSIZE, 0);
        return;
    }
    // With status surfacing armed, a response of 400 or above answers as a
    // typed refusal carrying the code rather than as a successful exchange
    // carrying an error body. That is what lets a producer tell a 503 worth
    // retrying from a 404 worth dropping, which it cannot do from a payload
    // whose shape it does not know.
    //
    // Off by default, because for most consumers an error body IS the answer:
    // a 404 with a problem document is a result, not a transport failure.
    if s.client.exchange_extended == 0
        && s.client.surface_status != 0
        && s.client.last_status >= 400
    {
        let code = s.client.last_status.to_le_bytes();
        s.client.exchange_reply[0] = code[0];
        s.client.exchange_reply[1] = code[1];
        send_reply(s, REFUSE_UPSTREAM, 2);
        return;
    }
    // A caller that asked for the whole response is answered with it. A
    // status and a header block are not decoration: without them a consumer
    // cannot tell a 204 from a 200, cannot read a content type, and cannot
    // follow a redirect -- it has the body and no idea what the body is.
    if s.client.exchange_extended != 0 {
        // Already answered, when the head was known. Nothing is owed here:
        // the body's own stream carried the rest and its terminator said
        // where it ended.
        s.client.exchange_corr = 0;
        s.client.exchange_key_len = 0;
        s.client.exchange_extended = 0;
        s.client.exchange_head_sent = 0;
        s.client.exchange_terminated = 0;
        return;
    }
    send_reply(s, STATUS_OK, s.client.exchange_reply_len as usize);
}

/// Answer an extended exchange with the head, as soon as there is one.
///
/// The body has not arrived and is not waited for: it streams on `file_ctrl`
/// and ends with a zero-length chunk. Answering here is what lets a consumer
/// read the body as it comes rather than after it is all in, which is the
/// whole reason the body is not in this frame.
pub(crate) unsafe fn send_head(s: &mut HttpState) {
    if !busy(s) || s.client.exchange_head_sent != 0 {
        return;
    }
    // There has to be a head to answer with. The decoder is fed every byte as
    // it arrives and a status line and its block can span several reads, so a
    // status below 200 means either nothing has parsed yet or what has is
    // informational — and an interim response is not the answer. Answering
    // either would spend the one reply this exchange has on a status the peer
    // never finished sending.
    if s.client.last_status < 200 {
        return;
    }
    let head_len = s.client.response.head_len as usize;
    // Whole or not at all. A block clipped to fit still parses as a block, so
    // a consumer cannot tell that the field it wanted is the one that did not
    // fit.
    if RESP_HEAD + head_len > super::super::exchange::PAYLOAD_MAX {
        s.client.exchange_head_sent = 1;
        send_reply(s, REFUSE_OVERSIZE, 0);
        return;
    }
    // Composed by the core that owns the layout: the status, the block's
    // length, and the block itself, into the reply buffer in one go.
    let Some(_) = write_reply_head(
        s.client.last_status,
        core::slice::from_raw_parts(s.client.response.head_bytes.as_ptr(), head_len),
        &mut s.client.exchange_reply,
    ) else {
        s.client.exchange_head_sent = 1;
        send_reply(s, REFUSE_OVERSIZE, 0);
        return;
    };
    s.client.exchange_head_sent = 1;
    // The reply is spent, but the exchange is not over: the body is still
    // arriving and the client is stepped only while an exchange is in
    // flight. So the correlation is put back after the frame is composed --
    // `busy` means "a response is still coming", and the reply owed against
    // it has simply already gone.
    let corr = s.client.exchange_corr;
    send_reply(s, STATUS_OK, RESP_HEAD + head_len);
    s.client.exchange_corr = corr;
}

/// Answer with a typed refusal because the exchange itself failed.
pub(crate) unsafe fn fail(s: &mut HttpState) {
    if !busy(s) {
        return;
    }
    if s.client.exchange_head_sent == 0 {
        send_reply(s, REFUSE_UNROUTABLE, 0);
        return;
    }
    // An extended exchange whose head was already answered cannot be answered
    // again: the reply is exactly one record and it has been spent. What a
    // consumer sees is the body ending early, which is what a failed response
    // is — and the closing chunk the caller writes before reaching here is
    // what makes that an ending rather than a pause.
    //
    // The correlation is released here because nothing else will release it.
    // Held, it would mean "a response is still coming" for ever: no later
    // request would be taken off `publish_in`, and this instance would answer
    // nobody again.
    s.client.exchange_corr = 0;
    s.client.exchange_reply_len = 0;
    s.client.exchange_oversize = 0;
}

/// Emit one `[MSG_REPLY][len:u16][Reply…]` envelope and go idle.
///
/// `payload_len` names a prefix of `exchange_reply` rather than a slice, so the
/// reply is framed straight out of state — the body is up to `PAYLOAD_MAX` and
/// a copy of it, on the stack, on the way to a channel, would be the largest
/// allocation in the module for no purpose.
///
/// Once framed, a reply is immutable until the channel accepts it. The
/// correlation stays occupied, preventing a retry from executing another request.
unsafe fn send_reply(s: &mut HttpState, status: u8, payload_len: usize) {
    if pending(s) {
        flush_reply(s);
        return;
    }
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
        s.client.exchange_pending = (ENVELOPE + n) as u16;
    }

    flush_reply(s);
}

pub(crate) fn pending(s: &HttpState) -> bool {
    s.client.exchange_pending != 0
}

pub(crate) unsafe fn flush_reply(s: &mut HttpState) {
    let n = s.client.exchange_pending as usize;
    if n == 0 {
        return;
    }
    if ((*s.syscalls).channel_write)(
        s.client.exchange_out_chan,
        s.client.exchange_stage.as_ptr(),
        n,
    ) != n as i32
    {
        return;
    }
    s.client.exchange_pending = 0;
    s.client.exchange_corr = 0;
    s.client.exchange_reply_len = 0;
    s.client.exchange_oversize = 0;
}
