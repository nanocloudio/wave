// Wire format for the `mail` parser's ports.
//
// Inbound mail arrives as bytes and leaves as two things: a bounded set of
// FORMAT FACTS, and the body as a stream. The split is the whole point. A
// message can be arbitrarily large, so nothing here assembles one; and the
// facts are what the format actually says, never what it might mean.
//
// In particular this module reports `Message-ID`, `In-Reply-To` and
// `References` as the identifiers they are, and stops. Which conversation a
// message belongs to is Conclave's decision, made from this evidence and its
// own bindings — a parser that picked a thread would be deciding membership
// from a header a sender chose.
//
// Layouts (multi-byte ints LE):
//
//   MailChunk  [op:u8][cid:u32][flags:u8][chunk_len:u32][chunk:chunk_len]
//
//   MailFacts  [op:u8][cid:u32][status:u8][field_count:u16][fields_len:u32]
//              [fields:fields_len]
//              where each field is [kind:u8][len:u16][bytes:len]
//
//   MailBody   [op:u8][cid:u32][flags:u8][chunk_len:u32][chunk:chunk_len]
//
// `cid` is the caller's correlation id, echoed on everything this module emits
// for that message.

/// Begin a message: `chunk` is its first span.
pub const MAIL_OP_MESSAGE: u8 = 0x70;
/// Continue the message begun under this `cid`.
pub const MAIL_OP_MORE: u8 = 0x71;
/// The op byte on a facts record.
pub const MAIL_OP_FACTS: u8 = 0x7E;
/// The op byte on a body record.
pub const MAIL_OP_BODY: u8 = 0x7F;
/// The op byte on a facts record describing one part of a multipart message.
pub const MAIL_OP_PART_FACTS: u8 = 0x7D;
/// The op byte on a part-body record.
pub const MAIL_OP_PART_BODY: u8 = 0x7C;

/// More records follow for this `cid`.
pub const MAIL_FLAG_MORE: u8 = 0x01;

/// Fixed prefix of a `MailChunk` and of a `MailBody`.
pub const MAIL_CHUNK_HDR: usize = 1 + 4 + 1 + 4;
/// Fixed prefix of a `MailFacts`.
pub const MAIL_FACTS_HDR: usize = 1 + 4 + 1 + 2 + 4;
/// Fixed prefix of a `MailPart`: like a chunk record, plus the index of the
/// part its bytes belong to.
///
///   MailPart [op:u8][cid:u32][part:u16][flags:u8][chunk_len:u32][chunk]
///
/// The index is in the record rather than implied by what came before it on
/// another port: two ports whose ordering has to be assumed against each other
/// is a bug waiting for a busy channel.
pub const MAIL_PART_HDR: usize = 1 + 4 + 2 + 1 + 4;

// ---- status -----------------------------------------------------------------

/// The header block parsed and every address field in it was well formed.
pub const MAIL_ST_OK: u8 = 0;
/// The header block is not a header block.
pub const MAIL_ST_MALFORMED: u8 = 1;
/// The header block is larger than this module will hold.
///
/// Reported rather than parsed as far as it fits: a truncated header block
/// can end in the middle of a recipient list, and half a recipient list names
/// the wrong recipients.
pub const MAIL_ST_HEADERS_TOO_LARGE: u8 = 2;
/// An address field did not parse.
///
/// The message is reported with this status and WITHOUT a guess at the
/// address, because an identity-bearing field repaired into something
/// plausible is how a message comes to claim a sender it never had.
pub const MAIL_ST_ADDRESS_MALFORMED: u8 = 3;
/// More facts were found than one record carries.
pub const MAIL_ST_TOO_MANY_FIELDS: u8 = 4;

// ---- fact kinds -------------------------------------------------------------
//
// Wire positions: append new kinds, never renumber an existing one.

/// The `From` address, as `local@domain`.
pub const MAIL_F_FROM_ADDR: u8 = 1;
/// The display name on `From`, if it carried one.
pub const MAIL_F_FROM_DISPLAY: u8 = 2;
/// One `To` address. Repeated per recipient.
pub const MAIL_F_TO_ADDR: u8 = 3;
/// One `Cc` address. Repeated per recipient.
pub const MAIL_F_CC_ADDR: u8 = 4;
/// The `Subject`, unfolded.
pub const MAIL_F_SUBJECT: u8 = 5;
/// The `Date`, verbatim. Not parsed into a timestamp here: a date is a claim
/// by the sender, and turning it into one number hides how much of one.
pub const MAIL_F_DATE: u8 = 6;
/// The `Message-ID`, without its angle brackets.
pub const MAIL_F_MESSAGE_ID: u8 = 7;
/// One `In-Reply-To` identifier, without its angle brackets.
pub const MAIL_F_IN_REPLY_TO: u8 = 8;
/// One `References` identifier, without its angle brackets, in field order.
pub const MAIL_F_REFERENCE: u8 = 9;
/// The `Content-Type`, unfolded.
pub const MAIL_F_CONTENT_TYPE: u8 = 10;
/// The `Reply-To` address.
pub const MAIL_F_REPLY_TO_ADDR: u8 = 11;
/// The `Sender` address, where it differs from `From`.
pub const MAIL_F_SENDER_ADDR: u8 = 12;
/// Which part of a multipart message these facts describe, as decimal text.
pub const MAIL_F_PART_INDEX: u8 = 13;
/// A part's declared `type/subtype`.
///
/// What the part DECLARES. Whether the bytes are that is not checked here.
pub const MAIL_F_PART_TYPE: u8 = 14;
/// A part's transfer encoding, as the decimal `Encoding::code`.
pub const MAIL_F_PART_ENCODING: u8 = 15;
/// A part's `Content-Disposition` disposition token, such as `attachment`.
pub const MAIL_F_PART_DISPOSITION: u8 = 16;
/// A part's declared filename, exactly as the message wrote it.
///
/// Not sanitised, not resolved, not decoded: a filename repaired into
/// something that looks safe is a filename the message did not send, and
/// deciding what is safe belongs where the file is written.
pub const MAIL_F_PART_FILENAME: u8 = 17;
/// A part's `Content-ID`, without its angle brackets.
pub const MAIL_F_PART_CONTENT_ID: u8 = 18;

/// A parsed chunk record, as offsets into the caller's buffer.
#[derive(Clone, Copy)]
pub struct MailChunkView {
    pub op: u8,
    pub cid: u32,
    pub flags: u8,
    pub chunk_at: usize,
    pub chunk_len: usize,
}

impl MailChunkView {
    /// Whether more records follow for this message.
    pub fn more(&self) -> bool {
        self.flags & MAIL_FLAG_MORE != 0
    }
}

/// Parse a `MailChunk`. `None` when the buffer is shorter than the header, or
/// than the length that header declares.
pub fn parse_mail_chunk(buf: &[u8]) -> Option<MailChunkView> {
    if buf.len() < MAIL_CHUNK_HDR {
        return None;
    }
    let chunk_len = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;
    let need = MAIL_CHUNK_HDR.checked_add(chunk_len)?;
    if buf.len() < need {
        return None;
    }
    Some(MailChunkView {
        op: buf[0],
        cid: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        flags: buf[5],
        chunk_at: MAIL_CHUNK_HDR,
        chunk_len,
    })
}

/// Build a chunk-shaped record (`MailChunk` or `MailBody`) into `out`.
pub fn write_mail_chunk(
    op: u8,
    cid: u32,
    flags: u8,
    chunk: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = MAIL_CHUNK_HDR.checked_add(chunk.len())?;
    if out.len() < total {
        return None;
    }
    out[0] = op;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5] = flags;
    out[6..10].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    out[MAIL_CHUNK_HDR..total].copy_from_slice(chunk);
    Some(total)
}

/// Whether an op is one the parser accepts.
pub fn mail_op_is_known(op: u8) -> bool {
    matches!(op, MAIL_OP_MESSAGE | MAIL_OP_MORE)
}

/// A parsed part-body record.
#[derive(Clone, Copy)]
pub struct MailPartView {
    pub cid: u32,
    pub part: u16,
    pub flags: u8,
    pub chunk_at: usize,
    pub chunk_len: usize,
}

/// Build a `MailPart` record into `out`.
pub fn write_mail_part(
    cid: u32,
    part: u16,
    flags: u8,
    chunk: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = MAIL_PART_HDR.checked_add(chunk.len())?;
    if out.len() < total {
        return None;
    }
    out[0] = MAIL_OP_PART_BODY;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5..7].copy_from_slice(&part.to_le_bytes());
    out[7] = flags;
    out[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    out[MAIL_PART_HDR..total].copy_from_slice(chunk);
    Some(total)
}

/// Read a `MailPart` record.
pub fn parse_mail_part(buf: &[u8]) -> Option<MailPartView> {
    if buf.len() < MAIL_PART_HDR || buf[0] != MAIL_OP_PART_BODY {
        return None;
    }
    let chunk_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
    if buf.len() < MAIL_PART_HDR + chunk_len {
        return None;
    }
    Some(MailPartView {
        cid: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        part: u16::from_le_bytes([buf[5], buf[6]]),
        flags: buf[7],
        chunk_at: MAIL_PART_HDR,
        chunk_len,
    })
}

// ---- facts ------------------------------------------------------------------

/// Append one `[kind][len][bytes]` field to a fields buffer at `*p`.
///
/// `None` when it would not fit, so a caller reports too-many-fields rather
/// than emitting a record that silently omits one.
pub fn append_fact(kind: u8, value: &[u8], out: &mut [u8], p: &mut usize) -> Option<()> {
    if value.len() > u16::MAX as usize {
        return None;
    }
    let end = p.checked_add(3)?.checked_add(value.len())?;
    if end > out.len() {
        return None;
    }
    out[*p] = kind;
    out[*p + 1..*p + 3].copy_from_slice(&(value.len() as u16).to_le_bytes());
    out[*p + 3..end].copy_from_slice(value);
    *p = end;
    Some(())
}

/// Stamp a `MailFacts` header into `out`. The fields follow at
/// `MAIL_FACTS_HDR`.
pub fn write_mail_facts(
    cid: u32,
    status: u8,
    field_count: u16,
    fields_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    write_mail_facts_op(MAIL_OP_FACTS, cid, status, field_count, fields_len, out)
}

/// As [`write_mail_facts`], for a facts record of a stated op.
pub fn write_mail_facts_op(
    op: u8,
    cid: u32,
    status: u8,
    field_count: u16,
    fields_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    let total = MAIL_FACTS_HDR.checked_add(fields_len)?;
    if out.len() < total {
        return None;
    }
    out[0] = op;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5] = status;
    out[6..8].copy_from_slice(&field_count.to_le_bytes());
    out[8..12].copy_from_slice(&(fields_len as u32).to_le_bytes());
    Some(total)
}

/// Everything a facts record states, other than the fields themselves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MailFactsHead {
    pub op: u8,
    pub cid: u32,
    pub status: u8,
    pub field_count: u16,
    pub fields_at: usize,
    pub fields_len: usize,
}

/// Read a `MailFacts` header.
pub fn parse_mail_facts(buf: &[u8]) -> Option<MailFactsHead> {
    if buf.len() < MAIL_FACTS_HDR || !matches!(buf[0], MAIL_OP_FACTS | MAIL_OP_PART_FACTS) {
        return None;
    }
    let fields_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
    if buf.len() < MAIL_FACTS_HDR + fields_len {
        return None;
    }
    Some(MailFactsHead {
        op: buf[0],
        cid: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        status: buf[5],
        field_count: u16::from_le_bytes([buf[6], buf[7]]),
        fields_at: MAIL_FACTS_HDR,
        fields_len,
    })
}

/// Read the field at `at` within a fields buffer, returning it and the offset
/// just past it.
pub fn next_fact(fields: &[u8], at: usize) -> Option<(u8, usize, usize, usize)> {
    if at + 3 > fields.len() {
        return None;
    }
    let kind = fields[at];
    let len = u16::from_le_bytes([fields[at + 1], fields[at + 2]]) as usize;
    let value_at = at + 3;
    let end = value_at.checked_add(len)?;
    if end > fields.len() {
        return None;
    }
    Some((kind, value_at, len, end))
}
