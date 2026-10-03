//! Request bodies on HTTP/1.1 — deciding there is one, bounding it, and moving
//! it on without holding it.
//!
//! The inbound counterpart of `body.rs`, which renders response bodies. A body
//! is never held whole: it is decoded out of `recv_buf` a record at a time and
//! either forwarded to the application (`forward`) or read and dropped
//! (`discard`), and the bytes still in `recv_buf` are all this server holds of
//! it. When nothing is taking them, `recv_buf` fills, the demux stops reading
//! the connection, and the transport's receive window closes on the peer.
//!
//! **Framing is a security decision, not a parsing convenience.** Which header
//! delimits the body — and what to do when two disagree — is RFC 9112 §6.3, and
//! the reason it is written so firmly is request smuggling: if this server and
//! the proxy in front of it resolve a `Content-Length` + `Transfer-Encoding`
//! conflict differently, one request becomes two. `wire::h1::body_framing`
//! therefore returns `Invalid` rather than a best guess, and this module answers
//! 400 and closes.
//!
//! **An unread body is not an ignored body.** Bytes left in the receive buffer
//! are read as the beginning of the next request on a keep-alive connection. So
//! a body is consumed even when the matched route has no use for it — a static
//! route answering a POST still drains what the client sent, or the GET that
//! follows begins mid-payload.
//!
//! **The ceiling is the route's and the refusal is explicit.** Every route
//! declares the largest body it accepts (`route_N_max_body_kib`, 64 KiB when it
//! declares none). A `Content-Length` past it is 413 before a byte is read; a
//! body that grows past it is refused at the byte that crosses it. Never a
//! truncation, which the receiver cannot detect.

use super::super::wire::h1::{self, BodyDecoder, BodyFraming};
use super::super::wire::method;
use super::{cur_recv_buf_mut_ptr, cur_recv_len, cur_slot, cur_slot_mut, HttpState};

/// The body ceiling of a route that declares none: 64 KiB.
///
/// Useful for form posts and JSON APIs while staying affordable on the smallest
/// target this module builds for. A route that takes uploads declares its own.
pub(crate) const DEFAULT_MAX_BODY: u64 = 64 * 1024;

/// The highest body ceiling a route may declare, in KiB: 1 TiB.
///
/// A body is streamed and never held, so this bounds no buffer; it is the
/// sanity bound on the declaration itself, below the parameter's type maximum
/// so a saturated value is refused rather than read as a deliberate choice.
pub(crate) const MAX_BODY_KIB_CEILING: u32 = 1 << 30;

/// What the head said about this request's body.
pub(crate) enum BodyPlan {
    /// No body.
    None,
    /// A body is coming. `declared` is its `Content-Length` when it has one.
    /// `continue_first` means the client is waiting for a `100 Continue`
    /// before it sends anything.
    Read {
        decoder: BodyDecoder,
        declared: Option<u64>,
        continue_first: bool,
    },
    /// Framing headers contradict each other or do not parse. 400, close.
    Invalid,
    /// A method that must carry a body did not say how long it is. 411.
    LengthRequired,
}

/// Decide what the head says about this request's body. Nothing is armed:
/// whether the body fits is the matched route's question.
///
/// `head` is the request head through its terminating blank line.
pub(crate) unsafe fn plan_body(s: &HttpState, head: &[u8]) -> BodyPlan {
    let framing = h1::body_framing(head);
    let verb = cur_slot(s).map(|c| c.req_method).unwrap_or(0);
    match framing {
        BodyFraming::Invalid => BodyPlan::Invalid,
        // A method defined to carry a body, sent without framing, is not a
        // zero-length request — it is a request whose length the sender failed
        // to state. RFC 9110 §15.5.12 gives 411 for exactly this.
        BodyFraming::None if method::method_expects_request_body(verb) => BodyPlan::LengthRequired,
        other => match BodyDecoder::new(other) {
            None => BodyPlan::None,
            Some(decoder) => BodyPlan::Read {
                decoder,
                declared: match other {
                    BodyFraming::Length(n) => Some(n),
                    _ => None,
                },
                continue_first: h1::expects_continue(head),
            },
        },
    }
}

/// The body ceiling of route `ri`, in bytes.
pub(crate) unsafe fn route_limit(s: &HttpState, ri: i8) -> u64 {
    if ri < 0 {
        return DEFAULT_MAX_BODY;
    }
    match (*s.server.routes.as_ptr().add(ri as usize)).max_body_kib {
        0 => DEFAULT_MAX_BODY,
        kib => kib as u64 * 1024,
    }
}

/// Arm the slot to read the planned body, bounded by `limit`.
pub(crate) unsafe fn arm(s: &mut HttpState, decoder: BodyDecoder, limit: u64) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_decoder = decoder;
        cur.body_active = 1;
        cur.body_total = 0;
        cur.body_limit = limit;
    }
}

/// What one pass of the body reader came to.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum BodyStep {
    /// Bytes moved; there may be more to do.
    Progress,
    /// Nothing to do until the peer sends more, or credit arrives.
    Wait,
    /// The body is complete.
    Done,
    /// Malformed framing, or a framing line longer than `recv_buf`. 400.
    Bad,
    /// The body passed the route's ceiling. 413.
    TooLarge,
}

/// The body bytes still in `recv_buf`, just past the request head.
unsafe fn pending(s: &mut HttpState) -> (*mut u8, usize) {
    let base = cur_slot(s).map(|c| c.header_end_off as usize).unwrap_or(0);
    let len = (cur_recv_len(s) as usize).saturating_sub(base);
    (cur_recv_buf_mut_ptr(s).add(base), len)
}

/// Drop `n` body bytes, sliding what follows down against the head. The head
/// stays in place: it is the request's only copy until the response is chosen.
unsafe fn consume(s: &mut HttpState, n: usize) {
    if n == 0 {
        return;
    }
    let base = cur_slot(s).map(|c| c.header_end_off as usize).unwrap_or(0);
    let len = cur_recv_len(s) as usize;
    let n = n.min(len.saturating_sub(base));
    let buf = cur_recv_buf_mut_ptr(s);
    let left = len - base - n;
    if left > 0 {
        core::ptr::copy(buf.add(base + n), buf.add(base), left);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = (base + left) as u16;
    }
}

/// Whether `recv_buf` is full with no complete framing line in it — the case a
/// decoder can never make progress from.
unsafe fn wedged(s: &HttpState) -> bool {
    cur_slot(s)
        .map(|c| c.recv_len as usize >= c.recv_cap as usize)
        .unwrap_or(false)
}

/// Body bytes decoded but not yet committed: the decoder as it would stand,
/// and how much input it took. Committed with [`commit`] once whatever the
/// bytes were decoded for has taken them; dropped otherwise, and the same
/// bytes are decoded again next time.
#[derive(Clone, Copy)]
pub(crate) struct Peek {
    next: BodyDecoder,
    consumed: usize,
    /// Body bytes written at the caller's offset.
    pub(crate) produced: usize,
    /// They end the body.
    pub(crate) done: bool,
}

/// Decode body bytes into `buf[at..]` without committing anything.
pub(crate) unsafe fn peek(s: &mut HttpState, buf: &mut [u8], at: usize) -> Result<Peek, BodyStep> {
    let (decoder, total, limit, active) = match cur_slot(s) {
        Some(c) => (c.body_decoder, c.body_total, c.body_limit, c.body_active),
        None => return Err(BodyStep::Bad),
    };
    if active == 0 {
        return Err(BodyStep::Done);
    }
    let (ptr, len) = pending(s);
    let input = core::slice::from_raw_parts(ptr, len);
    // One byte past the ceiling is decoded if the peer sent it, so a body
    // that crosses the ceiling is refused at the byte that crosses it rather
    // than left waiting for credit it will never be granted.
    let room = limit.saturating_sub(total).saturating_add(1);
    let take = ((buf.len() - at) as u64).min(room) as usize;
    let mut next = decoder;
    let d = next.decode(input, &mut buf[at..at + take]);
    if d.bad {
        return Err(BodyStep::Bad);
    }
    if total + d.produced as u64 > limit {
        return Err(BodyStep::TooLarge);
    }
    let done = next.is_done();
    if d.consumed == 0 && !done {
        return Err(if wedged(s) {
            BodyStep::Bad
        } else {
            BodyStep::Wait
        });
    }
    Ok(Peek {
        next,
        consumed: d.consumed,
        produced: d.produced,
        done,
    })
}

/// Commit a [`peek`]: advance the decoder and consume its input.
pub(crate) unsafe fn commit(s: &mut HttpState, p: Peek) -> BodyStep {
    consume(s, p.consumed);
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_decoder = p.next;
        cur.body_total += p.produced as u64;
        if p.done {
            cur.body_active = 0;
        }
    }
    if p.done {
        BodyStep::Done
    } else {
        BodyStep::Progress
    }
}

/// Read and drop as much of the body as `recv_buf` holds, within the route's
/// ceiling. For a route that answers without the body.
pub(crate) unsafe fn discard(s: &mut HttpState) -> BodyStep {
    let mut scratch = [0u8; 512];
    loop {
        match peek(s, &mut scratch, 0) {
            Ok(p) => {
                if commit(s, p) == BodyStep::Done {
                    return BodyStep::Done;
                }
            }
            Err(step) => return step,
        }
    }
}

/// Disarm the reader at the end of a request, so a keep-alive connection does
/// not carry one request's body state into the next.
pub(crate) unsafe fn reset_body(s: &mut HttpState) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_active = 0;
        cur.body_total = 0;
        cur.body_limit = 0;
        cur.body_continue = 0;
    }
}
