// Wire format for the `smtp` connector's driven request/result ports.
//
// A long-running mail connector submits many messages through one graph and
// has to learn precisely what happened to each. These two records are that
// seam, shaped like `s3_wire`'s request/result pair: a graph node ISSUES
// submissions and a connector performs them.
//
// The result carries more than a status because SMTP failure is not one fact.
// The phase says how far the conversation got, the reply code and its enhanced
// triple say what the server objected to, and the text carries the server's own
// words — which is what distinguishes a rejection to act on from a deferral to
// retry.
//
// Layouts (multi-byte ints LE):
//
//   SmtpRequest [op:u8][cid:u32][flags:u8][from_len:u16][rcpt_len:u16]
//               [chunk_len:u32][from:from_len][rcpt:rcpt_len][chunk:chunk_len]
//
//   SmtpResult  [op:u8][cid:u32][outcome:u8][phase:u8][code:u16]
//               [enh_class:u8][enh_subject:u16][enh_detail:u16]
//               [peer_ip:4][peer_port:u16][text_len:u16][text:text_len]
//
// `cid` is a caller-chosen operation id echoed on the result, so a caller may
// track several submissions without keeping per-call state here. It is opaque:
// this module never interprets it, it only returns it.
//
// One request carries ONE recipient. A message to several recipients is
// several submissions, which keeps every result recipient-scoped by
// construction — a server refusing one recipient says nothing about another.
// An envelope carrying several recipients is a later mail profile, and it must
// keep that scoping rather than collapsing to one verdict.
//
// A body larger than one record streams: set `SMTP_FLAG_MORE_BODY` and follow
// with `SMTP_OP_BODY` records under the same `cid`. Neither this module nor its
// caller assembles a whole large message in a fixed buffer.
//
// The ports are `OctetStream` rather than a registered content type, for the
// reason `s3_wire` gives: a new entry in Fluxor's `CONTENT_TYPES` moves the ABI
// surface digest and re-stamps every `.fmod` in every workspace member. A
// request/result pair between two modules that already agree does not earn that
// cost.

/// Begin a submission: `from` and `rcpt` are present, `chunk` is the first
/// (possibly only, possibly empty) span of the message.
pub const SMTP_OP_SUBMIT: u8 = 0x60;
/// Continue the message of an in-flight submission. `from_len` and `rcpt_len`
/// are 0; `chunk` is the next span.
pub const SMTP_OP_BODY: u8 = 0x61;
/// Abandon an in-flight submission. The connector still owes exactly one
/// result for it.
pub const SMTP_OP_CANCEL: u8 = 0x62;
/// The op byte every result carries.
pub const SMTP_OP_RESULT: u8 = 0x6F;

/// More body records follow for this `cid`.
pub const SMTP_FLAG_MORE_BODY: u8 = 0x01;

/// Fixed prefix of an `SmtpRequest`.
pub const SMTP_REQ_HDR: usize = 1 + 4 + 1 + 2 + 2 + 4;
/// Fixed prefix of an `SmtpResult`.
pub const SMTP_RES_HDR: usize = 1 + 4 + 1 + 1 + 2 + 1 + 2 + 2 + 4 + 2 + 2;

// ---- outcome classification -------------------------------------------------
//
// The classification exists so a caller can decide whether its policy permits a
// retry. It states what the protocol showed and stops there: none of these
// values claims a person received or read anything.

/// The addressed server accepted the message: it answered 250 to end-of-data.
///
/// This is latched when that reply arrives. A later failure to QUIT cleanly
/// does not remove it, because the server has already taken responsibility for
/// the message and a second submission would deliver it twice.
pub const SMTP_OUT_ACCEPTED: u8 = 0;
/// A permanent refusal (5xx). Resubmitting the same message unchanged will
/// fail the same way.
pub const SMTP_OUT_REJECTED_PERM: u8 = 1;
/// A transient refusal (4xx). A later attempt may succeed.
pub const SMTP_OUT_REJECTED_TEMP: u8 = 2;
/// A reply that does not fit the command sequence at all.
pub const SMTP_OUT_PROTOCOL_ERROR: u8 = 3;
/// The connection could not be established.
pub const SMTP_OUT_CONNECT_FAILED: u8 = 4;
/// A deadline passed with no reply.
pub const SMTP_OUT_TIMEOUT: u8 = 5;
/// The connection closed before a terminal reply arrived.
pub const SMTP_OUT_CLOSED: u8 = 6;
/// The caller abandoned the submission.
pub const SMTP_OUT_CANCELLED: u8 = 7;
/// The request record itself could not be used.
pub const SMTP_OUT_MALFORMED: u8 = 8;

/// Classify a final reply code for a caller's retry policy.
///
/// 2xx and 3xx are progress rather than refusal; only the end-of-data 250
/// means acceptance, and that is decided by phase, not by this function.
pub fn smtp_classify_code(code: u16) -> u8 {
    match code {
        400..=499 => SMTP_OUT_REJECTED_TEMP,
        500..=599 => SMTP_OUT_REJECTED_PERM,
        _ => SMTP_OUT_PROTOCOL_ERROR,
    }
}

// ---- enhanced status codes (RFC 3463) ---------------------------------------

/// A parsed enhanced status code, `class.subject.detail`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SmtpEnhanced {
    pub class: u8,
    pub subject: u16,
    pub detail: u16,
}

/// Parse a leading enhanced status code out of reply text.
///
/// A server that advertises ENHANCEDSTATUSCODES prefixes its reply text with
/// `class.subject.detail`, as in `550 5.7.1 relay denied`. The prefix is
/// recognised only in the exact shape RFC 3463 defines: class 2, 4 or 5,
/// subject and detail of one to three digits each, followed by a space or the
/// end of the text. Anything else is ordinary reply text, because misreading
/// free text as a status code would report a failure reason the server never
/// gave.
pub fn smtp_enhanced_status(text: &[u8]) -> Option<SmtpEnhanced> {
    let class = match text.first() {
        Some(&b'2') => 2u8,
        Some(&b'4') => 4u8,
        Some(&b'5') => 5u8,
        _ => return None,
    };
    if text.get(1) != Some(&b'.') {
        return None;
    }
    let (subject, after_subject) = smtp_take_digits(text, 2)?;
    if text.get(after_subject) != Some(&b'.') {
        return None;
    }
    let (detail, after_detail) = smtp_take_digits(text, after_subject + 1)?;
    match text.get(after_detail) {
        None | Some(&b' ') => Some(SmtpEnhanced {
            class,
            subject,
            detail,
        }),
        _ => None,
    }
}

/// Read one to three digits at `at`, returning the value and the index after
/// them.
fn smtp_take_digits(text: &[u8], at: usize) -> Option<(u16, usize)> {
    let mut value = 0u16;
    let mut i = at;
    while i < text.len() && text[i].is_ascii_digit() && i - at < 3 {
        value = value * 10 + u16::from(text[i] - b'0');
        i += 1;
    }
    if i == at {
        return None;
    }
    Some((value, i))
}

// ---- request parsing --------------------------------------------------------

/// A parsed `SmtpRequest`, as offsets into the caller's buffer.
///
/// Offsets rather than slices, for `s3_wire`'s reason: the module reads into a
/// fixed state-owned array and then builds commands out of that same array.
#[derive(Clone, Copy)]
pub struct SmtpReqView {
    pub op: u8,
    pub cid: u32,
    pub flags: u8,
    pub from_at: usize,
    pub from_len: usize,
    pub rcpt_at: usize,
    pub rcpt_len: usize,
    pub chunk_at: usize,
    pub chunk_len: usize,
}

impl SmtpReqView {
    /// Whether more body records follow for this operation.
    pub fn more_body(&self) -> bool {
        self.flags & SMTP_FLAG_MORE_BODY != 0
    }
}

/// Parse an `SmtpRequest`. `None` when the buffer is shorter than the header,
/// or shorter than the lengths that header declares — a truncated record is
/// dropped rather than read past.
pub fn parse_smtp_request(buf: &[u8]) -> Option<SmtpReqView> {
    if buf.len() < SMTP_REQ_HDR {
        return None;
    }
    let op = buf[0];
    let cid = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let flags = buf[5];
    let from_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let rcpt_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let chunk_len = u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]) as usize;

    let need = SMTP_REQ_HDR
        .checked_add(from_len)?
        .checked_add(rcpt_len)?
        .checked_add(chunk_len)?;
    if buf.len() < need {
        return None;
    }
    let from_at = SMTP_REQ_HDR;
    let rcpt_at = from_at + from_len;
    let chunk_at = rcpt_at + rcpt_len;
    Some(SmtpReqView {
        op,
        cid,
        flags,
        from_at,
        from_len,
        rcpt_at,
        rcpt_len,
        chunk_at,
        chunk_len,
    })
}

/// Whether an op is one this connector performs. An unknown op is answered
/// with a malformed result rather than dropped, so a caller learns its request
/// was refused instead of waiting out a timeout.
pub fn smtp_op_is_known(op: u8) -> bool {
    matches!(op, SMTP_OP_SUBMIT | SMTP_OP_BODY | SMTP_OP_CANCEL)
}

/// Build an `SmtpRequest` into `out`, returning its length.
///
/// Present so a caller — a test, or a connector on the host side — writes the
/// same bytes the module reads, rather than restating the layout.
pub fn write_smtp_request(
    op: u8,
    cid: u32,
    flags: u8,
    from: &[u8],
    rcpt: &[u8],
    chunk: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = SMTP_REQ_HDR
        .checked_add(from.len())?
        .checked_add(rcpt.len())?
        .checked_add(chunk.len())?;
    if out.len() < total || from.len() > u16::MAX as usize || rcpt.len() > u16::MAX as usize {
        return None;
    }
    out[0] = op;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5] = flags;
    out[6..8].copy_from_slice(&(from.len() as u16).to_le_bytes());
    out[8..10].copy_from_slice(&(rcpt.len() as u16).to_le_bytes());
    out[10..14].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    let mut p = SMTP_REQ_HDR;
    out[p..p + from.len()].copy_from_slice(from);
    p += from.len();
    out[p..p + rcpt.len()].copy_from_slice(rcpt);
    p += rcpt.len();
    out[p..p + chunk.len()].copy_from_slice(chunk);
    Some(total)
}

// ---- result building and reading --------------------------------------------

/// Everything a result states, other than its bounded reply text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SmtpResultHead {
    pub cid: u32,
    pub outcome: u8,
    pub phase: u8,
    pub code: u16,
    pub enhanced: Option<SmtpEnhanced>,
    pub peer_ip: [u8; 4],
    pub peer_port: u16,
    pub text_len: usize,
}

/// Stamp an `SmtpResult` header into `out`. The reply text, if any, follows at
/// `SMTP_RES_HDR`; the caller writes it there and passes its length here.
pub fn write_smtp_result(head: &SmtpResultHead, out: &mut [u8]) -> Option<usize> {
    let total = SMTP_RES_HDR.checked_add(head.text_len)?;
    if out.len() < total || head.text_len > u16::MAX as usize {
        return None;
    }
    let (class, subject, detail) = match head.enhanced {
        Some(enhanced) => (enhanced.class, enhanced.subject, enhanced.detail),
        None => (0u8, 0u16, 0u16),
    };
    out[0] = SMTP_OP_RESULT;
    out[1..5].copy_from_slice(&head.cid.to_le_bytes());
    out[5] = head.outcome;
    out[6] = head.phase;
    out[7..9].copy_from_slice(&head.code.to_le_bytes());
    out[9] = class;
    out[10..12].copy_from_slice(&subject.to_le_bytes());
    out[12..14].copy_from_slice(&detail.to_le_bytes());
    out[14..18].copy_from_slice(&head.peer_ip);
    out[18..20].copy_from_slice(&head.peer_port.to_le_bytes());
    out[20..22].copy_from_slice(&(head.text_len as u16).to_le_bytes());
    Some(total)
}

/// Offset of the reply text within an `SmtpResult`.
pub const SMTP_RES_TEXT_AT: usize = SMTP_RES_HDR;

/// Read an `SmtpResult` header. `None` if the record is shorter than the
/// header, or than the text length it declares.
pub fn parse_smtp_result(buf: &[u8]) -> Option<SmtpResultHead> {
    if buf.len() < SMTP_RES_HDR || buf[0] != SMTP_OP_RESULT {
        return None;
    }
    let text_len = u16::from_le_bytes([buf[20], buf[21]]) as usize;
    if buf.len() < SMTP_RES_HDR + text_len {
        return None;
    }
    let class = buf[9];
    let enhanced = if class == 0 {
        None
    } else {
        Some(SmtpEnhanced {
            class,
            subject: u16::from_le_bytes([buf[10], buf[11]]),
            detail: u16::from_le_bytes([buf[12], buf[13]]),
        })
    };
    Some(SmtpResultHead {
        cid: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        outcome: buf[5],
        phase: buf[6],
        code: u16::from_le_bytes([buf[7], buf[8]]),
        enhanced,
        peer_ip: [buf[14], buf[15], buf[16], buf[17]],
        peer_port: u16::from_le_bytes([buf[18], buf[19]]),
        text_len,
    })
}
