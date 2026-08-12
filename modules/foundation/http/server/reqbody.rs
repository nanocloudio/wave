//! Request bodies — deciding there is one, then reading it.
//!
//! The inbound counterpart of `body.rs`, which renders response bodies. Three
//! things make this more than a byte loop:
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
//! **The buffer is bounded and the refusal is explicit.** The decoded body is
//! heap-allocated per connection, so without a cap any client decides how much
//! of the device's memory to take. Over the cap is 413: a refusal the client can
//! act on, unlike a truncation, which it cannot detect.

use super::super::wire::h1::{self, BodyFraming, ChunkHeader};
use super::super::wire::method;
use super::{
    cur_recv_buf_mut_ptr, cur_recv_len, cur_slot, cur_slot_mut, heap_alloc, heap_free, HttpState,
};

// ── Body framing modes (ConnSlot.body_mode) ───────────────────────────────

pub(crate) const BODY_MODE_NONE: u8 = 0;
pub(crate) const BODY_MODE_LENGTH: u8 = 1;
pub(crate) const BODY_MODE_CHUNKED: u8 = 2;

// ── Chunked sub-state (ConnSlot.chunk_state) ──────────────────────────────

/// Waiting for a chunk-size line.
pub(crate) const CHUNK_SIZE: u8 = 0;
/// Mid-chunk: `body_remaining` data bytes still to copy.
pub(crate) const CHUNK_DATA: u8 = 1;
/// Chunk data complete; consuming the CRLF that follows it.
pub(crate) const CHUNK_CRLF: u8 = 2;
/// Terminating zero-size chunk seen; consuming the trailer section.
pub(crate) const CHUNK_TRAILER: u8 = 3;

/// Default cap when `max_body_kib` is not configured: 64 KiB.
///
/// Chosen to be useful for form posts and JSON APIs while staying affordable
/// on the smallest target this module builds for. A graph that ingests
/// artefacts raises it deliberately — a default large enough for a container
/// layer would put every rp2350 deployment one request away from exhaustion.
pub(crate) const DEFAULT_MAX_BODY: u32 = 64 * 1024;

/// What the head said about this request's body.
pub(crate) enum BodyPlan {
    /// No body — dispatch immediately.
    None,
    /// A body is coming. `continue_first` means the client is waiting for a
    /// `100 Continue` before it sends anything.
    Read { continue_first: bool },
    /// Framing headers contradict each other or do not parse. 400, close.
    Invalid,
    /// The declared length exceeds the cap. 413, close.
    TooLarge,
    /// A method that must carry a body did not say how long it is. 411.
    LengthRequired,
}

/// Decide what to do about this request's body, and arm the slot's decoder.
///
/// `head` is the request head through its terminating blank line.
pub(crate) unsafe fn plan_body(s: &mut HttpState, head: &[u8]) -> BodyPlan {
    let framing = h1::body_framing(head);
    let wants_continue = h1::expects_continue(head);
    let cap = body_cap(s);
    let verb = cur_slot(s).map(|c| c.req_method).unwrap_or(0);

    match framing {
        BodyFraming::Invalid => BodyPlan::Invalid,
        BodyFraming::None => {
            // A method defined to carry a body, sent without framing, is not a
            // zero-length request — it is a request whose length the sender
            // failed to state. RFC 9110 §15.5.12 gives 411 for exactly this,
            // and it is more useful to the client than silently dispatching an
            // empty body it never meant to send.
            if method::method_expects_request_body(verb) {
                return BodyPlan::LengthRequired;
            }
            arm(s, BODY_MODE_NONE, 0);
            BodyPlan::None
        }
        BodyFraming::Length(0) => {
            arm(s, BODY_MODE_NONE, 0);
            BodyPlan::None
        }
        BodyFraming::Length(n) => {
            if n > cap as u64 {
                return BodyPlan::TooLarge;
            }
            // The declared length is known and within the cap, so the buffer
            // is sized exactly once rather than grown as bytes arrive.
            if !ensure_capacity(s, n as u32) {
                return BodyPlan::TooLarge;
            }
            arm(s, BODY_MODE_LENGTH, n);
            BodyPlan::Read {
                continue_first: wants_continue,
            }
        }
        BodyFraming::Chunked => {
            arm(s, BODY_MODE_CHUNKED, 0);
            if let Some(cur) = cur_slot_mut(s) {
                cur.chunk_state = CHUNK_SIZE;
            }
            BodyPlan::Read {
                continue_first: wants_continue,
            }
        }
    }
}

fn body_cap(s: &HttpState) -> u32 {
    if s.server.max_body == 0 {
        DEFAULT_MAX_BODY
    } else {
        s.server.max_body
    }
}

unsafe fn arm(s: &mut HttpState, mode: u8, remaining: u64) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_mode = mode;
        cur.body_remaining = remaining;
        cur.body_len = 0;
        cur.chunk_state = CHUNK_SIZE;
    }
}

/// Grow the slot's body buffer to hold at least `want` bytes, never past the
/// cap. Returns false if the cap would be exceeded or the heap is exhausted.
///
/// Growth doubles rather than fitting exactly: a chunked sender delivering
/// 8 KiB in 16-byte chunks would otherwise reallocate 512 times.
unsafe fn ensure_capacity(s: &mut HttpState, want: u32) -> bool {
    let cap = body_cap(s);
    if want > cap {
        return false;
    }
    let (have, buf) = match cur_slot(s) {
        Some(c) => (c.body_cap, c.body_buf),
        None => return false,
    };
    if have >= want && !buf.is_null() {
        return true;
    }
    let mut next = if have == 0 { 1024 } else { have };
    while next < want {
        next = next.saturating_mul(2);
    }
    if next > cap {
        next = cap;
    }

    let sys = s.syscalls;
    let fresh = heap_alloc(&*sys, next);
    if fresh.is_null() {
        return false;
    }
    // Copy what has already been decoded. `heap_realloc` exists, but the
    // body buffer is the one allocation whose old contents MUST survive a
    // grow, and an explicit copy makes that a property of this function
    // rather than of the allocator's implementation.
    let (old, old_len) = match cur_slot(s) {
        Some(c) => (c.body_buf, c.body_len as usize),
        None => {
            heap_free(&*sys, fresh);
            return false;
        }
    };
    if !old.is_null() {
        if old_len > 0 {
            core::ptr::copy_nonoverlapping(old, fresh, old_len.min(next as usize));
        }
        heap_free(&*sys, old);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_buf = fresh;
        cur.body_cap = next;
    }
    true
}

/// Append decoded body bytes. Returns false if the cap is reached — the
/// caller answers 413.
unsafe fn append(s: &mut HttpState, src: *const u8, n: usize) -> bool {
    if n == 0 {
        return true;
    }
    let have = match cur_slot(s) {
        Some(c) => c.body_len,
        None => return false,
    };
    let want = match have.checked_add(n as u32) {
        Some(w) => w,
        None => return false,
    };
    if !ensure_capacity(s, want) {
        return false;
    }
    let (buf, len) = match cur_slot(s) {
        Some(c) => (c.body_buf, c.body_len as usize),
        None => return false,
    };
    if buf.is_null() {
        return false;
    }
    core::ptr::copy_nonoverlapping(src, buf.add(len), n);
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_len = want;
    }
    true
}

/// Outcome of one pass of the body reader.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum BodyStep {
    /// The body is complete; dispatch.
    Done,
    /// More bytes needed from the peer.
    NeedMore,
    /// Malformed chunked framing. 400, close.
    Bad,
    /// The body outgrew the cap. 413, close.
    TooLarge,
}

/// Consume as much of the pending body as `recv_buf` currently holds.
///
/// The body begins at `header_end_off`, and the request HEAD stays in place in
/// front of it for the whole read. That costs one offset in every buffer
/// calculation below and buys the only copy of the request headers there is:
/// `HANDLER_APP` forwards them verbatim at dispatch, which happens after the
/// body is whole. Shifting the head away would be simpler here and would leave
/// the application unable to see an `Authorization` header.
pub(crate) unsafe fn step_recv_body(s: &mut HttpState) -> BodyStep {
    let mode = match cur_slot(s) {
        Some(c) => c.body_mode,
        None => return BodyStep::Bad,
    };
    match mode {
        BODY_MODE_NONE => BodyStep::Done,
        BODY_MODE_LENGTH => step_length(s),
        BODY_MODE_CHUNKED => step_chunked(s),
        _ => BodyStep::Bad,
    }
}

/// Where the body starts in `recv_buf`: just past the request head.
fn base(s: &HttpState) -> usize {
    unsafe { cur_slot(s).map(|c| c.header_end_off as usize).unwrap_or(0) }
}

/// How many unconsumed body bytes `recv_buf` holds.
unsafe fn avail(s: &HttpState) -> usize {
    (cur_recv_len(s) as usize).saturating_sub(base(s))
}

/// Pointer to the first unconsumed body byte.
unsafe fn body_ptr(s: &mut HttpState) -> *mut u8 {
    cur_recv_buf_mut_ptr(s).add(base(s))
}

/// Drop `n` body bytes, sliding what follows down against the head. The head
/// itself is never moved — see `step_recv_body`.
unsafe fn consume(s: &mut HttpState, n: usize) {
    let b = base(s);
    let len = cur_recv_len(s) as usize;
    let n = n.min(len.saturating_sub(b));
    if n == 0 {
        return;
    }
    let buf = cur_recv_buf_mut_ptr(s);
    let left = len - b - n;
    if left > 0 {
        core::ptr::copy(buf.add(b + n), buf.add(b), left);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = (b + left) as u16;
    }
}

unsafe fn step_length(s: &mut HttpState) -> BodyStep {
    let have = avail(s);
    let remaining = cur_slot(s).map(|c| c.body_remaining).unwrap_or(0);
    if remaining == 0 {
        return BodyStep::Done;
    }
    if have == 0 {
        return BodyStep::NeedMore;
    }
    let take = have.min(remaining as usize);
    let src = body_ptr(s);
    if !append(s, src, take) {
        return BodyStep::TooLarge;
    }
    consume(s, take);
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_remaining = remaining - take as u64;
    }
    if cur_slot(s).map(|c| c.body_remaining).unwrap_or(0) == 0 {
        BodyStep::Done
    } else {
        BodyStep::NeedMore
    }
}

unsafe fn step_chunked(s: &mut HttpState) -> BodyStep {
    // One pass consumes as many complete chunks as the buffer holds, so a
    // body that arrived in a single read completes in a single tick rather
    // than one chunk per scheduler pass.
    loop {
        let state = match cur_slot(s) {
            Some(c) => c.chunk_state,
            None => return BodyStep::Bad,
        };
        let have = avail(s);

        match state {
            CHUNK_SIZE => {
                if have == 0 {
                    return BodyStep::NeedMore;
                }
                let buf = core::slice::from_raw_parts(body_ptr(s), have);
                match h1::parse_chunk_header(buf) {
                    ChunkHeader::Need => return BodyStep::NeedMore,
                    ChunkHeader::Bad => return BodyStep::Bad,
                    ChunkHeader::Ok { size, consumed } => {
                        consume(s, consumed);
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.body_remaining = size;
                            cur.chunk_state = if size == 0 { CHUNK_TRAILER } else { CHUNK_DATA };
                        }
                    }
                }
            }
            CHUNK_DATA => {
                let remaining = cur_slot(s).map(|c| c.body_remaining).unwrap_or(0);
                if remaining == 0 {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.chunk_state = CHUNK_CRLF;
                    }
                    continue;
                }
                if have == 0 {
                    return BodyStep::NeedMore;
                }
                let take = have.min(remaining as usize);
                let src = body_ptr(s);
                if !append(s, src, take) {
                    return BodyStep::TooLarge;
                }
                consume(s, take);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.body_remaining = remaining - take as u64;
                    if cur.body_remaining == 0 {
                        cur.chunk_state = CHUNK_CRLF;
                    }
                }
            }
            CHUNK_CRLF => {
                if have < 2 {
                    return BodyStep::NeedMore;
                }
                let buf = body_ptr(s);
                if *buf != b'\r' || *buf.add(1) != b'\n' {
                    return BodyStep::Bad;
                }
                consume(s, 2);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.chunk_state = CHUNK_SIZE;
                }
            }
            CHUNK_TRAILER => {
                // After the zero chunk comes an optional trailer section,
                // terminated by a blank line. Trailer FIELDS are discarded:
                // none of this server's handlers consume them, and a trailer
                // that arrived after the response was already dispatched
                // could not affect it anyway.
                if have < 2 {
                    return BodyStep::NeedMore;
                }
                let buf = body_ptr(s);
                if *buf == b'\r' && *buf.add(1) == b'\n' {
                    consume(s, 2);
                    return BodyStep::Done;
                }
                // A trailer field line: skip to its CRLF, then look again.
                let slice = core::slice::from_raw_parts(buf, have);
                let mut i = 0usize;
                while i + 1 < have {
                    if slice[i] == b'\r' && slice[i + 1] == b'\n' {
                        break;
                    }
                    i += 1;
                }
                if i + 1 >= have {
                    // Incomplete line. Bound it: a trailer section larger
                    // than the receive buffer is refused rather than waited
                    // on forever.
                    if have >= cur_slot(s).map(|c| c.recv_cap as usize).unwrap_or(0) {
                        return BodyStep::Bad;
                    }
                    return BodyStep::NeedMore;
                }
                consume(s, i + 2);
            }
            _ => return BodyStep::Bad,
        }
    }
}

/// Release the decoded body and disarm the reader. Called when a request
/// finishes, so a keep-alive connection does not carry one request's body
/// into the next.
pub(crate) unsafe fn reset_body(s: &mut HttpState) {
    let sys = s.syscalls;
    let buf = match cur_slot(s) {
        Some(c) => c.body_buf,
        None => return,
    };
    if !buf.is_null() {
        heap_free(&*sys, buf);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.body_buf = core::ptr::null_mut();
        cur.body_cap = 0;
        cur.body_len = 0;
        cur.body_mode = BODY_MODE_NONE;
        cur.body_remaining = 0;
        cur.chunk_state = CHUNK_SIZE;
        cur.body_continue = 0;
    }
}
