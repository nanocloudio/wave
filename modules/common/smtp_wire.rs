// The answer the `smtp` connector gives a submission, and how it is
// classified.
//
// The connector is an exchange provider (`abi::contracts::exchange`): a
// submission arrives as a request — method POST, `target` the one recipient,
// a `mail-from` header naming the envelope sender, the message (headers and
// body) as the request body — and is answered once. The answer's body is the
// `SmtpResult` below.
//
// The result carries more than a status because SMTP failure is not one fact.
// The phase says how far the conversation got, the reply code and its enhanced
// triple say what the server objected to, and the text carries the server's own
// words — which is what distinguishes a rejection to act on from a deferral to
// retry.
//
// Layout (multi-byte ints LE):
//
//   SmtpResult  [op:u8][outcome:u8][phase:u8][code:u16]
//               [enh_class:u8][enh_subject:u16][enh_detail:u16]
//               [peer_ip:4][peer_port:u16][text_len:u16][text:text_len]
//
// The exchange id is the correlation: the result names no submission of its
// own.
//
// One request carries ONE recipient. A message to several recipients is
// several submissions, which keeps every result recipient-scoped by
// construction — a server refusing one recipient says nothing about another.

/// The op byte every result carries.
pub const SMTP_OP_RESULT: u8 = 0x6F;

/// Fixed prefix of an `SmtpResult`.
pub const SMTP_RES_HDR: usize = 1 + 1 + 1 + 2 + 1 + 2 + 2 + 4 + 2 + 2;

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
/// Credentials were configured but could not be sent: the graph did not
/// declare the channel confidential, or the server offered no mechanism this
/// module speaks.
///
/// Distinct from a refusal because the server never saw a credential — nothing
/// about the message or the account is in question, only the deployment. A
/// retry policy should not repeat the submission; an operator should read the
/// graph.
pub const SMTP_OUT_AUTH_UNAVAILABLE: u8 = 9;

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

// ---- result building and reading --------------------------------------------

/// Everything a result states, other than its bounded reply text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SmtpResultHead {
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
    out[1] = head.outcome;
    out[2] = head.phase;
    out[3..5].copy_from_slice(&head.code.to_le_bytes());
    out[5] = class;
    out[6..8].copy_from_slice(&subject.to_le_bytes());
    out[8..10].copy_from_slice(&detail.to_le_bytes());
    out[10..14].copy_from_slice(&head.peer_ip);
    out[14..16].copy_from_slice(&head.peer_port.to_le_bytes());
    out[16..18].copy_from_slice(&(head.text_len as u16).to_le_bytes());
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
    let text_len = u16::from_le_bytes([buf[16], buf[17]]) as usize;
    if buf.len() < SMTP_RES_HDR + text_len {
        return None;
    }
    let class = buf[5];
    let enhanced = if class == 0 {
        None
    } else {
        Some(SmtpEnhanced {
            class,
            subject: u16::from_le_bytes([buf[6], buf[7]]),
            detail: u16::from_le_bytes([buf[8], buf[9]]),
        })
    };
    Some(SmtpResultHead {
        outcome: buf[1],
        phase: buf[2],
        code: u16::from_le_bytes([buf[3], buf[4]]),
        enhanced,
        peer_ip: [buf[10], buf[11], buf[12], buf[13]],
        peer_port: u16::from_le_bytes([buf[14], buf[15]]),
        text_len,
    })
}
