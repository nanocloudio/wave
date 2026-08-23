//! Mail parser — turns an inbound RFC 5322 message into bounded FORMAT FACTS
//! and a streamed body.
//!
//! A message arrives as `MailChunk` records on `message_in`, as large as it
//! happens to be. The header block is held (bounded) until it is complete and
//! parsed once; everything after it is forwarded on `body_out` as it arrives.
//! Neither this module nor its caller assembles a whole message.
//!
//! **Facts, not meaning.** What leaves on `facts_out` is what the format says:
//! the addresses that parsed, the subject and date as written, and the
//! `Message-ID` / `In-Reply-To` / `References` identifiers verbatim. Which
//! conversation a message belongs to, which principal an address stands for,
//! and whether an attachment is retained are Conclave's decisions. A parser
//! that chose a thread would be deciding conversation membership from a header
//! the sender picked.
//!
//! **Refuse, never repair.** A header block that does not parse, a header block
//! larger than this module holds, or an address field that does not parse are
//! each reported as a status with no guess attached. A `From` invented from
//! something that looked close is how a message comes to claim a sender it
//! never had.
//!
//! Ports:  message_in (inbound message spans), facts_out (one facts record per
//!         message), body_out (the body, streamed).

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

#[cfg(not(feature = "host-test"))]
#[path = "../../common/rfc5322.rs"]
mod rfc5322;
#[cfg(feature = "host-test")]
#[path = "../../common/rfc5322.rs"]
pub mod rfc5322;
use rfc5322::{
    find_header, header_name_is, scan_address, scan_header, scan_msg_id, unfold_value, AddrScan,
    HeaderScan, HeaderSpan, MsgIdScan,
};

#[cfg(not(feature = "host-test"))]
#[path = "../../common/mime.rs"]
mod mime;
#[cfg(feature = "host-test")]
#[path = "../../common/mime.rs"]
pub mod mime;
use mime::{
    ascii_eq_ignore_case, find_param, media_top_type_is, parse_content_type, parse_encoding,
    scan_boundary, unquote_param, BoundaryScan, Encoding, MAX_BOUNDARY_LEN,
};

#[cfg(not(feature = "host-test"))]
#[path = "../../common/mail_wire.rs"]
mod mail_wire;
#[cfg(feature = "host-test")]
#[path = "../../common/mail_wire.rs"]
pub mod mail_wire;
use mail_wire::{
    append_fact, mail_op_is_known, parse_mail_chunk, write_mail_chunk, write_mail_facts,
    MAIL_CHUNK_HDR, MAIL_FACTS_HDR, MAIL_FLAG_MORE, MAIL_F_CC_ADDR, MAIL_F_CONTENT_TYPE,
    MAIL_F_DATE, MAIL_F_FROM_ADDR, MAIL_F_FROM_DISPLAY, MAIL_F_IN_REPLY_TO, MAIL_F_MESSAGE_ID,
    MAIL_F_REFERENCE, MAIL_F_REPLY_TO_ADDR, MAIL_F_SENDER_ADDR, MAIL_F_SUBJECT, MAIL_F_TO_ADDR,
    MAIL_OP_BODY, MAIL_OP_MESSAGE, MAIL_ST_ADDRESS_MALFORMED, MAIL_ST_HEADERS_TOO_LARGE,
    MAIL_ST_MALFORMED, MAIL_ST_OK, MAIL_ST_TOO_MANY_FIELDS,
};
use mail_wire::{
    write_mail_facts_op, write_mail_part, MAIL_F_PART_CONTENT_ID, MAIL_F_PART_DISPOSITION,
    MAIL_F_PART_ENCODING, MAIL_F_PART_FILENAME, MAIL_F_PART_INDEX, MAIL_F_PART_TYPE,
    MAIL_OP_PART_FACTS, MAIL_PART_HDR,
};

/// Header block held while it is being completed. A block larger than this is
/// refused rather than parsed as far as it fits: a truncated block can end in
/// the middle of a recipient list.
const HDR_BUF: usize = 16 * 1024;
/// Body bytes moved per record.
const BODY_BUF: usize = 4096;
/// Serialised facts. A message with more recipients than fit is reported as
/// such rather than silently losing one.
const FACTS_BUF: usize = 4096;
/// One unfolded header value.
const VALUE_BUF: usize = 2048;
/// One part's header block. Smaller than the message's: a part header block
/// this large is not a part header block.
const PART_HDR_BUF: usize = 4096;
/// Body bytes held back while they might still be the start of a boundary
/// delimiter. A delimiter is at most `CRLF -- boundary -- CRLF`.
const BOUNDARY_MARGIN: usize = MAX_BOUNDARY_LEN + 8;
/// Body bytes being scanned for a delimiter.
const SCAN_BUF: usize = BODY_BUF + 2 * BOUNDARY_MARGIN;
/// Inbound record staging.
const REC_BUF: usize = 2 * (MAIL_CHUNK_HDR + BODY_BUF);

/// Where the walk through a multipart body currently stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Not a multipart message; the body is forwarded as it is.
    Flat,
    /// Before the first delimiter. RFC 2046 calls this the preamble, and it is
    /// not part of any part.
    Preamble,
    /// Collecting one part's header block.
    PartHeaders,
    /// Forwarding one part's body.
    PartBody,
    /// Past the closing delimiter. The epilogue belongs to no part either.
    Done,
}

#[repr(C)]
struct MailState {
    syscalls: *const SyscallTable,
    message_in: i32,
    facts_out: i32,
    body_out: i32,

    /// 1 while a message is being read.
    active: u8,
    cid: u32,
    /// 1 once the header block has been parsed and its facts emitted.
    headers_done: u8,
    /// 1 while further records are expected for this message.
    more: u8,

    hdr: [u8; HDR_BUF],
    hdr_len: u32,
    /// 1 once the header block overflowed `hdr`.
    hdr_overflow: u8,

    /// The facts record awaiting `facts_out`.
    facts: [u8; MAIL_FACTS_HDR + FACTS_BUF],
    facts_len: u32,
    facts_owed: u8,

    /// The body record awaiting `body_out`. Sized for the larger of the two
    /// shapes it holds: a flat body record or a part-body record.
    body: [u8; MAIL_PART_HDR + BODY_BUF],
    body_len: u32,
    body_owed: u8,

    /// The multipart boundary, when the message declared one.
    boundary: [u8; MAX_BOUNDARY_LEN],
    boundary_len: u8,
    walk: Walk,
    /// Which part is being walked, counted from 0.
    part_index: u16,
    /// The part header block being collected.
    part_hdr: [u8; PART_HDR_BUF],
    part_hdr_len: u32,
    /// Body bytes not yet resolved against a delimiter.
    scan: [u8; SCAN_BUF],
    scan_len: u32,

    /// The part-facts record awaiting `facts_out`.
    part_facts: [u8; MAIL_FACTS_HDR + FACTS_BUF],
    part_facts_len: u32,
    part_facts_owed: u8,

    rec: [u8; REC_BUF],
    rec_len: u32,
    rec_taken: u32,

    messages: u32,
    malformed: u32,
    draining: u8,
}

define_params! {
    MailState;
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<MailState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    unsafe {
        (*(state as *mut MailState)).draining = 1;
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
        if state_size < core::mem::size_of::<MailState>() {
            return -2;
        }
        let s = &mut *(state as *mut MailState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.message_in = in_chan;
        s.facts_out = out_chan;
        s.body_out = dev_channel_port(sys, 1, 1);
        s.active = 0;
        s.cid = 0;
        s.headers_done = 0;
        s.more = 0;
        s.hdr_len = 0;
        s.hdr_overflow = 0;
        s.facts_len = 0;
        s.facts_owed = 0;
        s.body_len = 0;
        s.body_owed = 0;
        s.boundary_len = 0;
        s.walk = Walk::Flat;
        s.part_index = 0;
        s.part_hdr_len = 0;
        s.scan_len = 0;
        s.part_facts_len = 0;
        s.part_facts_owed = 0;
        s.rec_len = 0;
        s.rec_taken = 0;
        s.messages = 0;
        s.malformed = 0;
        s.draining = 0;
        parse_tlv(s, params, params_len);
        dev_log(sys, 3, b"[mail] init".as_ptr(), 11);
        0
    }
}

// ── emitting ──────────────────────────────────────────────────────────────

/// Hand a parked record to `chan`, retrying while the channel refuses it.
///
/// The channel takes a record whole or not at all, so a rejected write leaves
/// it intact and nothing is reported twice.
unsafe fn flush(sys: &SyscallTable, chan: i32, bytes: &[u8]) -> bool {
    if chan < 0 {
        return true;
    }
    let poll = (sys.channel_poll)(chan, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    (sys.channel_write)(chan, bytes.as_ptr(), bytes.len()) == bytes.len() as i32
}

/// Park the facts record for this message.
unsafe fn emit_facts(s: &mut MailState, status: u8, field_count: u16, fields_len: usize) {
    if s.facts_owed != 0 {
        return;
    }
    let Some(total) = write_mail_facts(s.cid, status, field_count, fields_len, &mut s.facts[..])
    else {
        return;
    };
    s.facts_len = total as u32;
    s.facts_owed = 1;
    if status != MAIL_ST_OK {
        s.malformed = s.malformed.wrapping_add(1);
    }
}

/// Park a body span for this message.
unsafe fn emit_body(s: &mut MailState, chunk: &[u8], more: bool) {
    if s.body_owed != 0 || s.body_out < 0 {
        return;
    }
    let flags = if more { MAIL_FLAG_MORE } else { 0 };
    let mut staged = [0u8; MAIL_CHUNK_HDR + BODY_BUF];
    let Some(total) = write_mail_chunk(MAIL_OP_BODY, s.cid, flags, chunk, &mut staged) else {
        return;
    };
    s.body[..total].copy_from_slice(&staged[..total]);
    s.body_len = total as u32;
    s.body_owed = 1;
}

// ── header parsing ────────────────────────────────────────────────────────

/// Copy one unfolded header value into `out`, returning its length.
unsafe fn value_of(s: &MailState, span: HeaderSpan, out: &mut [u8]) -> Option<usize> {
    unfold_value(&s.hdr[..s.hdr_len as usize], span, out)
}

/// Append every address of an address field as facts of `kind`.
///
/// Returns `None` if the field does not parse: the caller reports that and
/// emits no address at all, rather than the ones that happened to parse before
/// the one that did not.
unsafe fn append_addresses(
    s: &MailState,
    name: &[u8],
    kind: u8,
    display_kind: Option<u8>,
    fields: &mut [u8],
    p: &mut usize,
    count: &mut u16,
) -> Option<bool> {
    // A field the message does not carry is not a field that failed to
    // parse. Whether a missing `From` matters is the reader's call.
    let Some(span) = find_header(&s.hdr[..s.hdr_len as usize], name) else {
        return Some(true);
    };
    let mut value = [0u8; VALUE_BUF];
    let len = value_of(s, span, &mut value)?;
    let mut at = 0usize;
    loop {
        match scan_address(&value, at, len) {
            AddrScan::Addr(addr, next) => {
                append_fact(
                    kind,
                    &value[addr.addr_at..addr.addr_at + addr.addr_len],
                    fields,
                    p,
                )?;
                *count += 1;
                if let Some(dk) = display_kind {
                    if addr.display_len > 0 {
                        append_fact(
                            dk,
                            &value[addr.display_at..addr.display_at + addr.display_len],
                            fields,
                            p,
                        )?;
                        *count += 1;
                    }
                }
                at = next;
            }
            AddrScan::End => return Some(true),
            AddrScan::Malformed => return Some(false),
        }
    }
}

/// Append every identifier of an identifier field as facts of `kind`.
unsafe fn append_ids(
    s: &MailState,
    name: &[u8],
    kind: u8,
    fields: &mut [u8],
    p: &mut usize,
    count: &mut u16,
) -> Option<bool> {
    let Some(span) = find_header(&s.hdr[..s.hdr_len as usize], name) else {
        return Some(true);
    };
    let mut value = [0u8; VALUE_BUF];
    let len = value_of(s, span, &mut value)?;
    let mut at = 0usize;
    loop {
        match scan_msg_id(&value, at, len) {
            MsgIdScan::Id(id_at, id_len, next) => {
                append_fact(kind, &value[id_at..id_at + id_len], fields, p)?;
                *count += 1;
                at = next;
            }
            MsgIdScan::End => return Some(true),
            MsgIdScan::Malformed => return Some(false),
        }
    }
}

/// Append one unfolded text header as a fact, if present.
unsafe fn append_text(
    s: &MailState,
    name: &[u8],
    kind: u8,
    fields: &mut [u8],
    p: &mut usize,
    count: &mut u16,
) -> Option<()> {
    let Some(span) = find_header(&s.hdr[..s.hdr_len as usize], name) else {
        return Some(());
    };
    let mut value = [0u8; VALUE_BUF];
    let len = value_of(s, span, &mut value)?;
    append_fact(kind, &value[..len], fields, p)?;
    *count += 1;
    Some(())
}

/// Parse the completed header block and park the facts it yields.
unsafe fn parse_headers(s: &mut MailState) {
    if s.hdr_overflow != 0 {
        emit_facts(s, MAIL_ST_HEADERS_TOO_LARGE, 0, 0);
        return;
    }
    // The block must parse in full before any of it is believed.
    let mut at = 0usize;
    loop {
        match scan_header(&s.hdr[..s.hdr_len as usize], at) {
            HeaderScan::Field(_, next) => at = next,
            HeaderScan::End(_) => break,
            HeaderScan::Incomplete | HeaderScan::Malformed => {
                emit_facts(s, MAIL_ST_MALFORMED, 0, 0);
                return;
            }
        }
    }

    let mut fields = [0u8; FACTS_BUF];
    let mut p = 0usize;
    let mut count = 0u16;
    let mut status = MAIL_ST_OK;

    let mut ok = true;
    for (name, kind, display) in [
        (&b"From"[..], MAIL_F_FROM_ADDR, Some(MAIL_F_FROM_DISPLAY)),
        (&b"Sender"[..], MAIL_F_SENDER_ADDR, None),
        (&b"Reply-To"[..], MAIL_F_REPLY_TO_ADDR, None),
        (&b"To"[..], MAIL_F_TO_ADDR, None),
        (&b"Cc"[..], MAIL_F_CC_ADDR, None),
    ] {
        match append_addresses(s, name, kind, display, &mut fields, &mut p, &mut count) {
            None => {
                emit_facts(s, MAIL_ST_TOO_MANY_FIELDS, 0, 0);
                return;
            }
            Some(false) => ok = false,
            Some(true) => {}
        }
    }
    if !ok {
        // An address field that did not parse is reported with no address
        // attached at all.
        emit_facts(s, MAIL_ST_ADDRESS_MALFORMED, 0, 0);
        return;
    }

    for (name, kind) in [
        (&b"Message-ID"[..], MAIL_F_MESSAGE_ID),
        (&b"In-Reply-To"[..], MAIL_F_IN_REPLY_TO),
        (&b"References"[..], MAIL_F_REFERENCE),
    ] {
        match append_ids(s, name, kind, &mut fields, &mut p, &mut count) {
            None => {
                emit_facts(s, MAIL_ST_TOO_MANY_FIELDS, 0, 0);
                return;
            }
            Some(false) => status = MAIL_ST_MALFORMED,
            Some(true) => {}
        }
    }

    for (name, kind) in [
        (&b"Subject"[..], MAIL_F_SUBJECT),
        (&b"Date"[..], MAIL_F_DATE),
        (&b"Content-Type"[..], MAIL_F_CONTENT_TYPE),
    ] {
        if append_text(s, name, kind, &mut fields, &mut p, &mut count).is_none() {
            emit_facts(s, MAIL_ST_TOO_MANY_FIELDS, 0, 0);
            return;
        }
    }

    if status != MAIL_ST_OK {
        emit_facts(s, status, 0, 0);
        return;
    }
    s.facts[MAIL_FACTS_HDR..MAIL_FACTS_HDR + p].copy_from_slice(&fields[..p]);
    emit_facts(s, MAIL_ST_OK, count, p);
    s.messages = s.messages.wrapping_add(1);
    adopt_boundary(s);
}

/// Note the multipart boundary, if the message declared one.
///
/// A `multipart/*` type with no usable boundary parameter is walked as a flat
/// body: there is no structure to follow, and inventing a delimiter would
/// split the body at bytes the message never marked.
unsafe fn adopt_boundary(s: &mut MailState) {
    s.walk = Walk::Flat;
    s.boundary_len = 0;
    let Some(span) = find_header(&s.hdr[..s.hdr_len as usize], b"Content-Type") else {
        return;
    };
    let mut value = [0u8; VALUE_BUF];
    let Some(len) = value_of(s, span, &mut value) else {
        return;
    };
    let Some(mt) = parse_content_type(&value[..len]) else {
        return;
    };
    if !media_top_type_is(&value[..len], &mt, b"multipart") {
        return;
    }
    let Some(param) = find_param(&value[..len], mt.params_at, b"boundary") else {
        return;
    };
    let mut boundary = [0u8; MAX_BOUNDARY_LEN];
    let Some(n) = unquote_param(&value[..len], param, &mut boundary) else {
        return;
    };
    if n == 0 {
        return;
    }
    s.boundary[..n].copy_from_slice(&boundary[..n]);
    s.boundary_len = n as u8;
    s.walk = Walk::Preamble;
    s.part_index = 0;
    s.scan_len = 0;
}

/// Park the facts describing one part.
unsafe fn emit_part_facts(s: &mut MailState, status: u8, field_count: u16, fields_len: usize) {
    if s.part_facts_owed != 0 {
        return;
    }
    let Some(total) = write_mail_facts_op(
        MAIL_OP_PART_FACTS,
        s.cid,
        status,
        field_count,
        fields_len,
        &mut s.part_facts[..],
    ) else {
        return;
    };
    s.part_facts_len = total as u32;
    s.part_facts_owed = 1;
}

/// Write a decimal number into `out`, returning its length.
fn decimal(mut value: u32, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    while value > 0 {
        digits[n] = b'0' + (value % 10) as u8;
        value /= 10;
        n += 1;
    }
    for k in 0..n {
        out[k] = digits[n - 1 - k];
    }
    n
}

/// Parse the collected part header block and park its facts.
unsafe fn parse_part_headers(s: &mut MailState) {
    let mut fields = [0u8; FACTS_BUF];
    let mut p = 0usize;
    let mut count = 0u16;
    let mut status = MAIL_ST_OK;

    let mut index_text = [0u8; 10];
    let n = decimal(u32::from(s.part_index), &mut index_text);
    if append_fact(MAIL_F_PART_INDEX, &index_text[..n], &mut fields, &mut p).is_none() {
        emit_part_facts(s, MAIL_ST_TOO_MANY_FIELDS, 0, 0);
        return;
    }
    count += 1;

    let hdr_len = s.part_hdr_len as usize;
    // A part with no headers at all is legal: it is `text/plain` by default,
    // and saying nothing about it is more honest than asserting a default the
    // message did not write.
    let mut ok = true;
    if let Some(span) = find_header(&s.part_hdr[..hdr_len], b"Content-Type") {
        let mut value = [0u8; VALUE_BUF];
        if let Some(len) = unfold_value(&s.part_hdr[..hdr_len], span, &mut value) {
            if let Some(mt) = parse_content_type(&value[..len]) {
                let mut ty = [0u8; 128];
                let tlen = mt.type_len + 1 + mt.sub_len;
                if tlen <= ty.len() {
                    ty[..mt.type_len].copy_from_slice(&value[mt.type_at..mt.type_at + mt.type_len]);
                    ty[mt.type_len] = b'/';
                    ty[mt.type_len + 1..tlen]
                        .copy_from_slice(&value[mt.sub_at..mt.sub_at + mt.sub_len]);
                    ok &= append_fact(MAIL_F_PART_TYPE, &ty[..tlen], &mut fields, &mut p).is_some();
                    count += 1;
                }
                if let Some(param) = find_param(&value[..len], mt.params_at, b"name") {
                    let mut name = [0u8; 256];
                    if let Some(nlen) = unquote_param(&value[..len], param, &mut name) {
                        ok &= append_fact(MAIL_F_PART_FILENAME, &name[..nlen], &mut fields, &mut p)
                            .is_some();
                        count += 1;
                    }
                }
            } else {
                status = MAIL_ST_MALFORMED;
            }
        }
    }

    if let Some(span) = find_header(&s.part_hdr[..hdr_len], b"Content-Transfer-Encoding") {
        let mut value = [0u8; VALUE_BUF];
        if let Some(len) = unfold_value(&s.part_hdr[..hdr_len], span, &mut value) {
            let mut code = [0u8; 10];
            let clen = decimal(u32::from(parse_encoding(&value[..len]).code()), &mut code);
            ok &= append_fact(MAIL_F_PART_ENCODING, &code[..clen], &mut fields, &mut p).is_some();
            count += 1;
        }
    }

    if let Some(span) = find_header(&s.part_hdr[..hdr_len], b"Content-Disposition") {
        let mut value = [0u8; VALUE_BUF];
        if let Some(len) = unfold_value(&s.part_hdr[..hdr_len], span, &mut value) {
            let mut end = 0usize;
            while end < len && value[end] != b';' && value[end] != b' ' {
                end += 1;
            }
            if end > 0 {
                ok &= append_fact(MAIL_F_PART_DISPOSITION, &value[..end], &mut fields, &mut p)
                    .is_some();
                count += 1;
            }
            if let Some(param) = find_param(&value[..len], end, b"filename") {
                let mut name = [0u8; 256];
                if let Some(nlen) = unquote_param(&value[..len], param, &mut name) {
                    ok &= append_fact(MAIL_F_PART_FILENAME, &name[..nlen], &mut fields, &mut p)
                        .is_some();
                    count += 1;
                }
            }
        }
    }

    if let Some(span) = find_header(&s.part_hdr[..hdr_len], b"Content-ID") {
        let mut value = [0u8; VALUE_BUF];
        if let Some(len) = unfold_value(&s.part_hdr[..hdr_len], span, &mut value) {
            if let MsgIdScan::Id(at, id_len, _) = scan_msg_id(&value, 0, len) {
                ok &= append_fact(
                    MAIL_F_PART_CONTENT_ID,
                    &value[at..at + id_len],
                    &mut fields,
                    &mut p,
                )
                .is_some();
                count += 1;
            }
        }
    }

    if !ok {
        emit_part_facts(s, MAIL_ST_TOO_MANY_FIELDS, 0, 0);
        return;
    }
    s.part_facts[MAIL_FACTS_HDR..MAIL_FACTS_HDR + p].copy_from_slice(&fields[..p]);
    emit_part_facts(s, status, count, p);
}

/// Park a span of one part's body.
unsafe fn emit_part_body(s: &mut MailState, chunk: &[u8], more: bool) {
    if s.body_owed != 0 || s.body_out < 0 {
        return;
    }
    let flags = if more { MAIL_FLAG_MORE } else { 0 };
    let mut staged = [0u8; MAIL_PART_HDR + BODY_BUF];
    let Some(total) = write_mail_part(s.cid, s.part_index, flags, chunk, &mut staged) else {
        return;
    };
    s.body[..total].copy_from_slice(&staged[..total]);
    s.body_len = total as u32;
    s.body_owed = 1;
}

/// Take message bytes: fill the header block until it ends, then forward the
/// rest as body.
unsafe fn take_bytes(s: &mut MailState, chunk_at: usize, chunk_len: usize, more: bool) {
    let mut i = 0usize;
    if s.headers_done == 0 {
        while i < chunk_len {
            if (s.hdr_len as usize) >= HDR_BUF {
                s.hdr_overflow = 1;
                break;
            }
            s.hdr[s.hdr_len as usize] = s.rec[chunk_at + i];
            s.hdr_len += 1;
            i += 1;
            // The block ends at the first empty line.
            let n = s.hdr_len as usize;
            if n >= 4 && &s.hdr[n - 4..n] == b"\r\n\r\n" {
                s.headers_done = 1;
                parse_headers(s);
                break;
            }
        }
        if s.hdr_overflow != 0 {
            s.headers_done = 1;
            parse_headers(s);
            return;
        }
        if s.headers_done == 0 {
            // Still inside the header block. If this was the last record the
            // message has no body separator, which is a malformed block.
            if !more {
                s.headers_done = 1;
                emit_facts(s, MAIL_ST_MALFORMED, 0, 0);
            }
            return;
        }
    }
    if s.walk == Walk::Flat {
        if i < chunk_len {
            let take = (chunk_len - i).min(BODY_BUF);
            let mut span = [0u8; BODY_BUF];
            span[..take].copy_from_slice(&s.rec[chunk_at + i..chunk_at + i + take]);
            emit_body(s, &span[..take], more);
        } else if !more {
            // A message whose body is empty still gets its terminal body
            // record, so a reader knows the message ended rather than waiting
            // on one.
            emit_body(s, &[], false);
        }
        return;
    }
    // Multipart: the bytes join the scan buffer and are resolved against the
    // delimiter before any of them are attributed to a part.
    let take = (chunk_len - i).min(SCAN_BUF - s.scan_len as usize);
    if take > 0 {
        let at = s.scan_len as usize;
        s.scan[at..at + take].copy_from_slice(&s.rec[chunk_at + i..chunk_at + i + take]);
        s.scan_len += take as u32;
    }
    walk_parts(s, !more);
}

/// Resolve the scan buffer against the multipart delimiter.
///
/// Bytes are only attributed to a part once they cannot be the start of a
/// delimiter, which is what keeps the walk streaming: at most one delimiter's
/// worth is ever held back.
///
/// Consumption follows attribution. The delimiter is only stepped over once
/// the bytes ahead of it have been given to the part they belong to —
/// consuming to the far side of a delimiter first is how a part's body
/// disappears between the header block that introduced it and the next
/// delimiter.
unsafe fn walk_parts(s: &mut MailState, final_span: bool) {
    if s.boundary_len == 0 {
        return;
    }
    loop {
        if s.body_owed != 0 || s.part_facts_owed != 0 {
            // Nothing more can be attributed until what is already decided has
            // been handed over.
            return;
        }
        if matches!(s.walk, Walk::Done | Walk::Flat) {
            return;
        }
        let len = s.scan_len as usize;
        let blen = s.boundary_len as usize;
        let mut boundary = [0u8; MAX_BOUNDARY_LEN];
        boundary[..blen].copy_from_slice(&s.boundary[..blen]);

        // How much of the buffer belongs to the current part, and whether a
        // delimiter follows it.
        let (content_end, delim_len, last, at_delim) =
            match scan_boundary(&s.scan[..len], 0, &boundary[..blen]) {
                BoundaryScan::Found {
                    part_end,
                    next,
                    last,
                } => (part_end, next - part_end, last, true),
                BoundaryScan::Incomplete => {
                    let safe = if final_span {
                        len
                    } else {
                        len.saturating_sub(BOUNDARY_MARGIN)
                    };
                    (safe, 0, false, false)
                }
            };
        if content_end == 0 && !at_delim {
            return;
        }

        match s.walk {
            Walk::Preamble => {
                // Whatever precedes the first delimiter belongs to no part.
                consume_scan(s, content_end);
                if !at_delim {
                    return;
                }
                consume_scan(s, delim_len);
                if last {
                    s.walk = Walk::Done;
                    return;
                }
                s.walk = Walk::PartHeaders;
                s.part_hdr_len = 0;
            }
            Walk::PartHeaders => {
                let (used, ended) = feed_part_headers(s, content_end);
                consume_scan(s, used);
                if ended {
                    s.walk = Walk::PartBody;
                } else if at_delim {
                    // The header block never ended before the delimiter: the
                    // part is all headers and no body.
                    parse_part_headers(s);
                    s.walk = Walk::PartBody;
                } else {
                    return;
                }
            }
            Walk::PartBody => {
                let take = content_end.min(BODY_BUF);
                let complete = at_delim && take == content_end;
                let mut span = [0u8; BODY_BUF];
                span[..take].copy_from_slice(&s.scan[..take]);
                emit_part_body(s, &span[..take], !complete);
                consume_scan(s, take);
                if !complete {
                    continue;
                }
                consume_scan(s, delim_len);
                if last {
                    s.walk = Walk::Done;
                    return;
                }
                s.part_index = s.part_index.wrapping_add(1);
                s.walk = Walk::PartHeaders;
                s.part_hdr_len = 0;
            }
            Walk::Done | Walk::Flat => return,
        }
    }
}

/// Move `n` bytes off the front of the scan buffer.
unsafe fn consume_scan(s: &mut MailState, n: usize) {
    let len = s.scan_len as usize;
    let take = n.min(len);
    let remaining = len - take;
    if remaining > 0 {
        core::ptr::copy(s.scan.as_ptr().add(take), s.scan.as_mut_ptr(), remaining);
    }
    s.scan_len = remaining as u32;
}

/// Feed up to `available` scan bytes into the current part's header block.
///
/// Returns how many bytes were taken and whether the block ended, parking the
/// part's facts if it did. The caller consumes: attribution and consumption
/// are kept apart so a delimiter is never stepped over early.
unsafe fn feed_part_headers(s: &mut MailState, available: usize) -> (usize, bool) {
    let mut i = 0usize;
    while i < available {
        if (s.part_hdr_len as usize) >= PART_HDR_BUF {
            // A part header block this large is not a part header block.
            parse_part_headers(s);
            return (i, true);
        }
        s.part_hdr[s.part_hdr_len as usize] = s.scan[i];
        s.part_hdr_len += 1;
        i += 1;
        let n = s.part_hdr_len as usize;
        // The block ends at an empty line: either the part opened with one
        // (no headers at all) or a CRLF pair closed it. The `n >= 4` guard is
        // load-bearing — at n == 3 the four-byte window starts before the
        // buffer.
        let ends_block = (n == 2 && &s.part_hdr[..2] == b"\r\n")
            || (n >= 4 && &s.part_hdr[n - 4..n] == b"\r\n\r\n");
        if ends_block {
            parse_part_headers(s);
            return (i, true);
        }
    }
    (available, false)
}

/// Retire a finished message so the next one can start.
unsafe fn finish(s: &mut MailState) {
    if s.facts_owed != 0 || s.body_owed != 0 || s.part_facts_owed != 0 {
        return;
    }
    s.active = 0;
    s.cid = 0;
    s.headers_done = 0;
    s.more = 0;
    s.hdr_len = 0;
    s.hdr_overflow = 0;
    s.facts_len = 0;
    s.body_len = 0;
    s.part_facts_len = 0;
    s.boundary_len = 0;
    s.walk = Walk::Flat;
    s.part_index = 0;
    s.part_hdr_len = 0;
    s.scan_len = 0;
}

/// Total length the record at the front of `buf` declares.
fn declared_len(buf: &[u8]) -> Option<u64> {
    if buf.len() < MAIL_CHUNK_HDR {
        return None;
    }
    let chunk_len = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]) as u64;
    Some(MAIL_CHUNK_HDR as u64 + chunk_len)
}

/// Take at most one record off `message_in`.
unsafe fn pump_requests(s: &mut MailState) {
    let sys = &*s.syscalls;
    if s.message_in < 0 {
        return;
    }
    // Nothing is taken while a message still owes output: the next record's
    // bytes would have nowhere to go.
    if s.facts_owed != 0 || s.body_owed != 0 || s.part_facts_owed != 0 {
        return;
    }
    // Retire the record just consumed.
    if s.rec_taken > 0 {
        let taken = (s.rec_taken as usize).min(s.rec_len as usize);
        let remaining = s.rec_len as usize - taken;
        if remaining > 0 {
            core::ptr::copy(s.rec.as_ptr().add(taken), s.rec.as_mut_ptr(), remaining);
        }
        s.rec_len = remaining as u32;
        s.rec_taken = 0;
    }
    // Top up while the front is short of a whole record.
    loop {
        let have = s.rec_len as usize;
        let whole = match declared_len(&s.rec[..have]) {
            Some(need) if need > REC_BUF as u64 => break,
            Some(need) => (have as u64) >= need,
            None => false,
        };
        if whole || s.draining != 0 || have >= REC_BUF {
            break;
        }
        let poll = (sys.channel_poll)(s.message_in, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let n = (sys.channel_read)(s.message_in, s.rec.as_mut_ptr().add(have), REC_BUF - have);
        if n <= 0 {
            break;
        }
        s.rec_len = (have + n as usize) as u32;
    }

    let n = s.rec_len as usize;
    let Some(view) = parse_mail_chunk(&s.rec[..n]) else {
        // A record declaring more than this module holds can never complete.
        if declared_len(&s.rec[..n]).is_some_and(|need| need > REC_BUF as u64) {
            s.rec_len = 0;
        }
        return;
    };
    let total = MAIL_CHUNK_HDR + view.chunk_len;
    if !mail_op_is_known(view.op) {
        s.rec_taken = total as u32;
        return;
    }
    match view.op {
        MAIL_OP_MESSAGE if s.active == 0 => {
            s.active = 1;
            s.cid = view.cid;
            s.headers_done = 0;
            s.hdr_len = 0;
            s.hdr_overflow = 0;
            s.more = u8::from(view.more());
            take_bytes(s, view.chunk_at, view.chunk_len, view.more());
            s.rec_taken = total as u32;
        }
        _ if s.active != 0 && view.cid == s.cid => {
            s.more = u8::from(view.more());
            take_bytes(s, view.chunk_at, view.chunk_len, view.more());
            s.rec_taken = total as u32;
        }
        _ => {
            // A record for a message this parser is not reading. It stays where
            // it is if it may yet become current.
        }
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut MailState);
        let sys = &*s.syscalls;

        pump_requests(s);

        if s.facts_owed != 0 {
            let len = s.facts_len as usize;
            let mut staged = [0u8; MAIL_FACTS_HDR + FACTS_BUF];
            staged[..len].copy_from_slice(&s.facts[..len]);
            if flush(sys, s.facts_out, &staged[..len]) {
                s.facts_owed = 0;
            }
        }
        if s.part_facts_owed != 0 {
            let len = s.part_facts_len as usize;
            let mut staged = [0u8; MAIL_FACTS_HDR + FACTS_BUF];
            staged[..len].copy_from_slice(&s.part_facts[..len]);
            if flush(sys, s.facts_out, &staged[..len]) {
                s.part_facts_owed = 0;
            }
        }
        if s.body_owed != 0 {
            let len = s.body_len as usize;
            let mut staged = [0u8; MAIL_PART_HDR + BODY_BUF];
            staged[..len].copy_from_slice(&s.body[..len]);
            if flush(sys, s.body_out, &staged[..len]) {
                s.body_owed = 0;
            }
        }

        // A multipart walk continues from what is already buffered even when
        // no new record arrived: one step can only decide as much as its
        // output ports will take.
        if s.active != 0 && s.walk != Walk::Flat && s.walk != Walk::Done {
            walk_parts(s, s.more == 0);
        }

        if s.active != 0
            && s.headers_done != 0
            && s.more == 0
            && matches!(s.walk, Walk::Flat | Walk::Done)
        {
            finish(s);
        }

        if s.draining == 1
            && s.facts_owed == 0
            && s.body_owed == 0
            && s.part_facts_owed == 0
            && s.active == 0
        {
            return 1;
        }
        0
    }
}
