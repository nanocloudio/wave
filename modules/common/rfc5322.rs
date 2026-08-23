// Bounded, no_std, no-alloc RFC 5322 message-format mechanics: the header
// block, address fields, and the identifier fields that relate one message to
// another. `include!`d by the host crate (tests) and by any module that reads
// or writes mail.
//
// Wave owns these wire and format facts. What an address means — which
// principal it stands for, which conversation a thread belongs to, whether an
// attachment is retained — is Conclave's, and none of it is decided here.
//
// Three rules shape the whole file:
//
//   * SPANS, NOT COPIES. Every parse returns offsets into the caller's buffer.
//     A message is read into one fixed array and referred to from there, so a
//     large message never needs a second one.
//
//   * INCOMPLETE IS NOT MALFORMED. A scan over bytes that have not all arrived
//     says so, and says it differently from bytes that can never be valid. A
//     streaming reader needs that distinction; conflating them either rejects
//     good mail or waits forever for bad.
//
//   * REJECT, NEVER REPAIR. A header carrying a bare CR or LF, an address that
//     does not parse, a line past the length the standard allows: all are
//     refused. Quietly "fixing" an identity-bearing field is how a message
//     comes to claim a sender it never had.

/// Longest line RFC 5322 §2.1.1 permits, excluding the CRLF.
pub const MAX_LINE_LEN: usize = 998;

/// The column serialisation folds at, per the same section's recommendation.
pub const FOLD_COLUMN: usize = 78;

/// A field of the header block: its name and its value, as spans.
///
/// `value_len` covers the folded continuation lines as they appear on the
/// wire. [`unfold_value`] turns that into the logical value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeaderSpan {
    pub name_at: usize,
    pub name_len: usize,
    pub value_at: usize,
    pub value_len: usize,
}

/// The outcome of scanning for one header field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderScan {
    /// A field, and the offset just past it.
    Field(HeaderSpan, usize),
    /// The empty line that ends the header block, and the offset of the body.
    End(usize),
    /// The bytes so far end mid-field. More may complete it.
    Incomplete,
    /// These bytes are not a header block and no continuation fixes that.
    Malformed,
}

/// Whether a byte may appear in a field name (RFC 5322 `ftext`).
fn is_ftext(b: u8) -> bool {
    (33..=126).contains(&b) && b != b':'
}

/// Whether a byte is the folding whitespace a continuation line begins with.
fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Find the CRLF at or after `at`. `None` while no complete line is present.
fn line_end(buf: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Scan one header field starting at `at`.
///
/// A field is `name ":" value CRLF`, with continuation lines beginning with
/// folding whitespace. A bare CR or a bare LF anywhere in the block is
/// malformed: those are the bytes a header-injection attempt is made of, and
/// accepting them would let a value carry a field the author never wrote.
pub fn scan_header(buf: &[u8], at: usize) -> HeaderScan {
    if at >= buf.len() {
        return HeaderScan::Incomplete;
    }
    // The empty line that ends the block.
    if buf[at] == b'\r' {
        return match buf.get(at + 1) {
            None => HeaderScan::Incomplete,
            Some(&b'\n') => HeaderScan::End(at + 2),
            Some(_) => HeaderScan::Malformed,
        };
    }
    if buf[at] == b'\n' {
        // A bare LF where the block should end.
        return HeaderScan::Malformed;
    }
    // A field may not begin with folding whitespace: that would be a
    // continuation of a field that does not exist.
    if is_wsp(buf[at]) {
        return HeaderScan::Malformed;
    }

    // Name, up to the colon.
    let mut i = at;
    while i < buf.len() && buf[i] != b':' {
        if !is_ftext(buf[i]) {
            return HeaderScan::Malformed;
        }
        i += 1;
    }
    if i >= buf.len() {
        return HeaderScan::Incomplete;
    }
    let name_len = i - at;
    if name_len == 0 {
        return HeaderScan::Malformed;
    }
    let value_at = i + 1;

    // Value, across any folded continuation lines.
    let mut cursor = value_at;
    loop {
        let Some(crlf) = line_end(buf, cursor) else {
            // No complete line yet. A bare LF before it would be malformed
            // rather than merely unfinished.
            let mut k = cursor;
            while k < buf.len() {
                if buf[k] == b'\n' {
                    return HeaderScan::Malformed;
                }
                k += 1;
            }
            return HeaderScan::Incomplete;
        };
        // Bytes between here and the CRLF must not contain a bare CR or LF.
        let mut k = cursor;
        while k < crlf {
            if buf[k] == b'\r' || buf[k] == b'\n' {
                return HeaderScan::Malformed;
            }
            k += 1;
        }
        if crlf.saturating_sub(cursor) > MAX_LINE_LEN {
            return HeaderScan::Malformed;
        }
        match buf.get(crlf + 2) {
            // The field may continue on a folded line.
            Some(&b) if is_wsp(b) => {
                cursor = crlf + 2;
            }
            // Field ends here.
            Some(_) => {
                return HeaderScan::Field(
                    HeaderSpan {
                        name_at: at,
                        name_len,
                        value_at,
                        value_len: crlf - value_at,
                    },
                    crlf + 2,
                );
            }
            // The CRLF is the last thing present; whether the field continues
            // depends on a byte that has not arrived.
            None => return HeaderScan::Incomplete,
        }
    }
}

/// Offset of the body, i.e. just past the empty line ending the header block.
///
/// `None` while the block is incomplete or malformed; the caller that needs to
/// tell those apart scans field by field.
pub fn body_offset(buf: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    loop {
        match scan_header(buf, at) {
            HeaderScan::Field(_, next) => at = next,
            HeaderScan::End(body) => return Some(body),
            HeaderScan::Incomplete | HeaderScan::Malformed => return None,
        }
    }
}

/// ASCII-case-insensitive comparison of a scanned field name against `name`.
pub fn header_name_is(buf: &[u8], span: HeaderSpan, name: &[u8]) -> bool {
    if span.name_len != name.len() {
        return false;
    }
    let mut i = 0usize;
    while i < name.len() {
        if !buf[span.name_at + i].eq_ignore_ascii_case(&name[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// The first field with this name, if the block holds one.
pub fn find_header(buf: &[u8], name: &[u8]) -> Option<HeaderSpan> {
    let mut at = 0usize;
    loop {
        match scan_header(buf, at) {
            HeaderScan::Field(span, next) => {
                if header_name_is(buf, span, name) {
                    return Some(span);
                }
                at = next;
            }
            HeaderScan::End(_) | HeaderScan::Incomplete | HeaderScan::Malformed => return None,
        }
    }
}

/// Write a field's logical value into `out`: leading whitespace trimmed, each
/// fold replaced by the single space it stands for.
///
/// Returns the length written, or `None` if `out` is too small — never a
/// truncated value, which would silently change what the field says.
pub fn unfold_value(buf: &[u8], span: HeaderSpan, out: &mut [u8]) -> Option<usize> {
    let mut p = 0usize;
    let mut i = span.value_at;
    let end = span.value_at + span.value_len;
    let mut at_start = true;
    while i < end {
        let b = buf[i];
        if b == b'\r' && i + 1 < end && buf[i + 1] == b'\n' {
            // A fold: the CRLF and the whitespace that follows stand for one
            // space, and only if something has already been written.
            i += 2;
            while i < end && is_wsp(buf[i]) {
                i += 1;
            }
            if !at_start {
                *out.get_mut(p)? = b' ';
                p += 1;
            }
            continue;
        }
        if at_start && is_wsp(b) {
            i += 1;
            continue;
        }
        *out.get_mut(p)? = b;
        p += 1;
        at_start = false;
        i += 1;
    }
    // Trim the trailing space a fold may have left.
    while p > 0 && is_wsp(out[p - 1]) {
        p -= 1;
    }
    Some(p)
}

// ---- addresses --------------------------------------------------------------

/// One address: its optional display name and its `local@domain` part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrSpan {
    pub display_at: usize,
    pub display_len: usize,
    pub addr_at: usize,
    pub addr_len: usize,
}

/// The outcome of scanning for one address in an address field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddrScan {
    /// An address, and the offset just past its separator.
    Addr(AddrSpan, usize),
    /// No further address in this field.
    End,
    /// The field does not parse as an address list.
    ///
    /// Refused rather than half-read: an address list read past a construct
    /// this does not implement would drop or invent a recipient.
    Malformed,
}

/// Skip whitespace and comments, honouring nesting and quoted pairs.
fn skip_cfws(buf: &[u8], mut at: usize, end: usize) -> Option<usize> {
    loop {
        while at < end && (is_wsp(buf[at]) || buf[at] == b'\r' || buf[at] == b'\n') {
            at += 1;
        }
        if at < end && buf[at] == b'(' {
            let mut depth = 1usize;
            at += 1;
            while at < end && depth > 0 {
                match buf[at] {
                    b'\\' => at += 1,
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                at += 1;
            }
            if depth > 0 {
                return None;
            }
            continue;
        }
        return Some(at);
    }
}

/// Whether `local@domain` is shaped like an address at all.
///
/// Deliberately structural, not a deliverability check: exactly one `@`, both
/// sides non-empty, no whitespace or angle brackets, and no control bytes.
fn addr_spec_is_wellformed(buf: &[u8], at: usize, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    let mut ats = 0usize;
    let mut at_pos = 0usize;
    let mut i = 0usize;
    while i < len {
        let b = buf[at + i];
        if b == b'@' {
            ats += 1;
            at_pos = i;
        }
        if b.is_ascii_control() || is_wsp(b) || b == b'<' || b == b'>' || b == b',' {
            return false;
        }
        i += 1;
    }
    ats == 1 && at_pos > 0 && at_pos + 1 < len
}

/// Scan one address of an address field, starting at `at`.
///
/// Handles `local@domain`, `Display Name <local@domain>` and a quoted display
/// name. Group syntax (`name: a@b, c@d;`) is refused rather than guessed at:
/// misreading a group changes who a message was addressed to.
pub fn scan_address(buf: &[u8], at: usize, end: usize) -> AddrScan {
    let Some(mut i) = skip_cfws(buf, at, end) else {
        return AddrScan::Malformed;
    };
    if i >= end {
        return AddrScan::End;
    }
    let display_start = i;
    let mut display_end = i;
    let mut angle_at = None;

    // Walk to the separator, remembering an angle-addr if one appears.
    while i < end {
        match buf[i] {
            b'"' => {
                // A quoted string may contain a comma or an angle bracket.
                i += 1;
                let mut closed = false;
                while i < end {
                    if buf[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if buf[i] == b'"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    return AddrScan::Malformed;
                }
            }
            b'<' => {
                display_end = i;
                let start = i + 1;
                let mut j = start;
                while j < end && buf[j] != b'>' {
                    j += 1;
                }
                if j >= end {
                    return AddrScan::Malformed;
                }
                angle_at = Some((start, j - start));
                i = j + 1;
            }
            b':' => return AddrScan::Malformed, // group syntax
            b',' => break,
            _ => i += 1,
        }
    }
    let separator = i;
    let next = if separator < end { separator + 1 } else { end };

    let (addr_at, addr_len) = match angle_at {
        Some(span) => span,
        None => {
            // No angle brackets: the whole token is the address.
            let mut s = display_start;
            let mut e = separator;
            while s < e && (is_wsp(buf[s]) || buf[s] == b'\r' || buf[s] == b'\n') {
                s += 1;
            }
            while e > s && (is_wsp(buf[e - 1]) || buf[e - 1] == b'\r' || buf[e - 1] == b'\n') {
                e -= 1;
            }
            display_end = s;
            (s, e - s)
        }
    };
    if !addr_spec_is_wellformed(buf, addr_at, addr_len) {
        return AddrScan::Malformed;
    }

    // Trim the display name.
    let mut d_start = display_start;
    let mut d_end = display_end;
    while d_start < d_end
        && (is_wsp(buf[d_start]) || buf[d_start] == b'\r' || buf[d_start] == b'\n')
    {
        d_start += 1;
    }
    while d_end > d_start
        && (is_wsp(buf[d_end - 1]) || buf[d_end - 1] == b'\r' || buf[d_end - 1] == b'\n')
    {
        d_end -= 1;
    }
    // A display name of only an address is not a display name.
    if d_start >= d_end || angle_at.is_none() {
        d_start = 0;
        d_end = 0;
    }

    AddrScan::Addr(
        AddrSpan {
            display_at: d_start,
            display_len: d_end.saturating_sub(d_start),
            addr_at,
            addr_len,
        },
        next,
    )
}

// ---- identifier fields ------------------------------------------------------

/// The outcome of scanning for one message identifier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsgIdScan {
    /// An identifier's span, WITHOUT its angle brackets, and the offset past it.
    Id(usize, usize, usize),
    /// No further identifier.
    End,
    /// The field does not parse as identifiers.
    Malformed,
}

/// Scan one `<id>` of a `Message-ID`, `In-Reply-To` or `References` field.
///
/// The angle brackets are structure, not identity: the value between them is
/// what relates one message to another, and it is returned unaltered. An
/// identifier is never normalised, because two identifiers that differ by a
/// byte are different identifiers.
pub fn scan_msg_id(buf: &[u8], at: usize, end: usize) -> MsgIdScan {
    let Some(mut i) = skip_cfws(buf, at, end) else {
        return MsgIdScan::Malformed;
    };
    if i >= end {
        return MsgIdScan::End;
    }
    if buf[i] != b'<' {
        return MsgIdScan::Malformed;
    }
    i += 1;
    let start = i;
    while i < end && buf[i] != b'>' {
        if buf[i].is_ascii_control() || is_wsp(buf[i]) {
            return MsgIdScan::Malformed;
        }
        i += 1;
    }
    if i >= end {
        return MsgIdScan::Malformed;
    }
    let len = i - start;
    if len == 0 {
        return MsgIdScan::Malformed;
    }
    MsgIdScan::Id(start, len, i + 1)
}

// ---- serialisation ----------------------------------------------------------

/// Whether a field name is one that may be written.
pub fn header_name_is_valid(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&b| is_ftext(b))
}

/// Whether a field value may be written as-is.
///
/// A value carrying CR or LF is refused. Folding is this module's to insert;
/// a caller-supplied line break is indistinguishable from an attempt to append
/// a header the author never wrote.
pub fn header_value_is_valid(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b != b'\r' && b != b'\n' && (b == b'\t' || !b.is_ascii_control()))
}

/// Write `name: value` into `out`, folding long values at whitespace.
///
/// Returns the length written, or `None` if the name or value is invalid or
/// `out` is too small. A folded line always begins with a space, so unfolding
/// recovers the value exactly.
pub fn write_header(name: &[u8], value: &[u8], out: &mut [u8]) -> Option<usize> {
    if !header_name_is_valid(name) || !header_value_is_valid(value) {
        return None;
    }
    let mut p = 0usize;
    let mut put = |bytes: &[u8], p: &mut usize| -> Option<()> {
        let end = p.checked_add(bytes.len())?;
        if end > out.len() {
            return None;
        }
        out[*p..end].copy_from_slice(bytes);
        *p = end;
        Some(())
    };
    put(name, &mut p)?;
    put(b":", &mut p)?;

    let mut column = name.len() + 1;
    let mut i = 0usize;
    while i < value.len() {
        // The next token, and the whitespace before it.
        let mut ws_end = i;
        while ws_end < value.len() && is_wsp(value[ws_end]) {
            ws_end += 1;
        }
        let mut tok_end = ws_end;
        while tok_end < value.len() && !is_wsp(value[tok_end]) {
            tok_end += 1;
        }
        if ws_end == tok_end {
            break;
        }
        let token = &value[ws_end..tok_end];
        // Fold when the line would otherwise pass the column, but never
        // before the first token: a header whose value starts on a folded
        // line is legal and needlessly surprising.
        if column > name.len() + 1 && column + 1 + token.len() > FOLD_COLUMN {
            put(b"\r\n ", &mut p)?;
            column = 1;
        } else {
            put(b" ", &mut p)?;
            column += 1;
        }
        put(token, &mut p)?;
        column += token.len();
        i = tok_end;
    }
    put(b"\r\n", &mut p)?;
    Some(p)
}

/// Write the empty line that ends a header block.
pub fn write_header_end(out: &mut [u8]) -> Option<usize> {
    if out.len() < 2 {
        return None;
    }
    out[0] = b'\r';
    out[1] = b'\n';
    Some(2)
}
