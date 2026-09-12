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
//! # Asking for the whole response
//!
//! The verb's high bit marks an extended record. Verb codes are small, so the
//! bit is free, and a producer that leaves it clear composes and reads the
//! plain record above.
//!
//! ```text
//! [method|0x80][path_len:u16 LE][body_len:u16 LE][hdr_len:u16 LE]
//! [path…][headers…][body…]
//! ```
//!
//! `headers` is the caller's own block as it goes on the wire, each line
//! ending CRLF. The reply to such a record carries the response rather than
//! its body alone:
//!
//! ```text
//! [status:u16 LE][hdr_len:u16 LE][headers…][body…]
//! ```
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

use super::super::exchange::{
    Publish, Reply, FLAG_BROADCAST, MSG_PUBLISH, MSG_REPLY, REFUSE_OVERSIZE, REFUSE_UNROUTABLE,
    REFUSE_UPSTREAM, STATUS_OK,
};
use super::super::HttpState;
use super::{Phase, EXCHANGE_KEY_MAX, EXCHANGE_REPLY_MAX};

/// Fixed head of a request record: `method` + the two lengths.
const REQ_HEAD: usize = 1 + 2 + 2;

/// The bit on the verb that marks an extended record: one carrying a header
/// block, and asking to be answered with the whole response.
pub(crate) const EXTENDED: u8 = 0x80;

/// Fixed head of an extended reply: the status, and the length of the header
/// block that follows it.
///
/// ```text
/// [status:u16 LE][hdr_len:u16 LE][headers…][body…]
/// ```
pub(crate) const RESP_HEAD: usize = 2 + 2;

/// The 3-byte channel envelope (`[msg_type][len:u16 LE]`) every frame on this
/// pair rides, as `net_read_frame`/`net_write_frame` compose it elsewhere.
const ENVELOPE: usize = 3;

/// ASCII case-insensitive comparison against an already-lower-case name.
fn eq_name(name: &[u8], lower: &[u8]) -> bool {
    if name.len() != lower.len() {
        return false;
    }
    let mut i = 0;
    while i < name.len() {
        if name[i].to_ascii_lowercase() != lower[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether a field name may appear in a caller's block.
///
/// Token characters only — no space, tab, control or DEL. Space is the one
/// that matters: `Host : x` reads as the name `Host` to a peer that trims and
/// as `Host ` to one that does not, and a rule keyed on the name has to agree
/// with whoever reads it next.
///
/// Then the four this module frames the request with. A second
/// `Content-Length`, or a `Transfer-Encoding` beside the one computed from
/// the record's body, leaves two readings of where the request ends, and a
/// pair of peers that disagree take the next request off the connection as
/// this one's body. `Host` is the origin's routing key and `Connection` is
/// what this client's own keep-alive state is read from. `Content-Type` is
/// deliberately not among them: naming the body it is sending is the main
/// thing a caller wants the block for.
///
/// Each name is compared against its own literal rather than looked up in a
/// table of references: a table of `&[u8]` is the shape that compiles to
/// pointers a flat module image cannot relocate
/// (`tools/ci/fmod_pic_relocs.sh`).
fn field_name_ok(name: &[u8]) -> bool {
    let mut i = 0;
    while i < name.len() {
        if name[i] <= 0x20 || name[i] == 0x7F {
            return false;
        }
        i += 1;
    }
    !eq_name(name, b"content-length")
        && !eq_name(name, b"transfer-encoding")
        && !eq_name(name, b"host")
        && !eq_name(name, b"connection")
}

/// Whether a caller's header block may be spliced into a request head.
///
/// The block goes onto the wire between this module's own fields and the
/// blank line that ends the head, so its bytes decide where the head ends. A
/// block carrying a blank line of its own ends it early and everything after
/// that becomes a second request the origin will answer — the producer names
/// one request and two arrive. A bare CR or LF does the same to any peer that
/// splits on one.
///
/// So a block is a sequence of field lines: each ends CRLF, none is empty,
/// none holds a stray CR or LF, and each is a name this module will emit
/// ([`field_name_ok`]) followed by a colon and a value of printable bytes. A
/// smuggled request line fails on the name: `GET http://elsewhere/ HTTP/1.1`
/// carries a colon, so the colon alone would admit it, but no field name
/// holds a space.
///
/// The value rule is the counterpart of the module's own inbound parser,
/// which refuses a control byte in a field it reads (`wire::response`): a
/// block this client would not accept from a peer is not one it should put on
/// the wire toward one.
fn header_block_ok(b: &[u8]) -> bool {
    if b.is_empty() {
        return true;
    }
    if b.len() < 2 || &b[b.len() - 2..] != b"\r\n" {
        return false;
    }
    let mut line_start = 0usize;
    let mut colon = false;
    let mut i = 0usize;
    while i + 1 < b.len() {
        match b[i] {
            b'\r' => {
                // A CRLF with nothing before it is the blank line that ends a
                // head; a CR without its LF splits a line on some peers and
                // not others, which is the same ambiguity by a shorter route.
                if b[i + 1] != b'\n' || i == line_start || !colon {
                    return false;
                }
                line_start = i + 2;
                colon = false;
                i += 2;
            }
            b'\n' => return false,
            b':' if !colon => {
                // The first colon on the line ends the name, and a name must
                // precede it.
                if i == line_start || !field_name_ok(&b[line_start..i]) {
                    return false;
                }
                colon = true;
                i += 1;
            }
            // Inside a value: horizontal tab is legal there, nothing else
            // below a space is.
            c if colon && c < 0x20 && c != b'\t' => return false,
            c if colon && c == 0x7F => return false,
            _ => i += 1,
        }
    }
    line_start == b.len()
}

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

    // The verb's high bit asks to be answered with the whole response rather
    // than with its body alone, and says the record carries a header block of
    // its own. Verb codes are small, so the bit is free, and a producer that
    // leaves it clear composes and reads the plain record.
    let (raw, path_len, body_len) = if p.len() >= REQ_HEAD {
        (
            p[0],
            u16::from_le_bytes([p[1], p[2]]) as usize,
            u16::from_le_bytes([p[3], p[4]]) as usize,
        )
    } else {
        (super::super::wire::method::METHOD_NONE, 0, 0)
    };
    let extended = raw & EXTENDED != 0;
    let method = raw & !EXTENDED;
    let head = if extended { REQ_HEAD + 2 } else { REQ_HEAD };
    let headers_len = if extended && p.len() >= head {
        u16::from_le_bytes([p[REQ_HEAD], p[REQ_HEAD + 1]]) as usize
    } else {
        0
    };

    // A path or body past this client's bounds is OVERSIZE, not UNROUTABLE:
    // the request is well formed and this provider is simply too small for it,
    // which is the distinction that tells a producer whether to shrink the
    // record or change the graph.
    let headers_at_check = head + path_len;
    // The caller's headers are spliced into an HTTP/1.1 request head and the
    // answer is composed from the HTTP/1.1 response decoder, so an extended
    // record is refused on the other generations rather than performed as a
    // lesser request under its name: a graph that asked for the whole response
    // and silently got a header-less one cannot tell that from an origin that
    // sent no headers.
    let wrong_generation = extended && (s.h3_mode != 0 || s.client.protocol != 0);
    let malformed = broadcast
        || wrong_generation
        || p.len() < head
        || head + path_len + headers_len + body_len != p.len()
        || path_len == 0
        || super::super::wire::method::method_name(method).is_empty()
        || !header_block_ok(&p[headers_at_check..headers_at_check + headers_len]);
    let oversize = path_len > super::MAX_PATH_LEN
        || body_len > super::REQUEST_BODY_SIZE
        || headers_len > super::REQUEST_HEADERS_MAX;
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
    s.client.exchange_extended = u8::from(extended);
    let path_at = head;
    let headers_at = path_at + path_len;
    let body_at = headers_at + headers_len;
    s.client.path[..path_len].copy_from_slice(&p[path_at..headers_at]);
    s.client.path_len = path_len as u16;
    s.client.request_headers[..headers_len].copy_from_slice(&p[headers_at..body_at]);
    s.client.request_headers_len = headers_len as u16;
    s.client.request_body[..body_len].copy_from_slice(&p[body_at..body_at + body_len]);
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
        let body_len = s.client.exchange_reply_len as usize;
        let head_len = s.client.response.head_len as usize;
        // Whole or not at all, as for the body. A block clipped to fit still
        // parses as a block, so a consumer cannot tell that the field it
        // wanted is the one that did not fit.
        if RESP_HEAD + head_len + body_len <= super::super::exchange::PAYLOAD_MAX {
            // The body is already at the front of the buffer, so it moves up
            // to make room for the head it is being described by.
            core::ptr::copy(
                s.client.exchange_reply.as_ptr(),
                s.client
                    .exchange_reply
                    .as_mut_ptr()
                    .add(RESP_HEAD + head_len),
                body_len,
            );
            let status = s.client.last_status.to_le_bytes();
            s.client.exchange_reply[0] = status[0];
            s.client.exchange_reply[1] = status[1];
            let hl = (head_len as u16).to_le_bytes();
            s.client.exchange_reply[2] = hl[0];
            s.client.exchange_reply[3] = hl[1];
            core::ptr::copy_nonoverlapping(
                s.client.response.head_bytes.as_ptr(),
                s.client.exchange_reply.as_mut_ptr().add(RESP_HEAD),
                head_len,
            );
            send_reply(s, STATUS_OK, RESP_HEAD + head_len + body_len);
            return;
        }
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
