// Bounded, no_std, no-alloc MIME mechanics: media types and their parameters,
// content dispositions, transfer encodings, multipart boundaries, and the two
// decoders those encodings name. `include!`d by the host crate (tests) and by
// any module that reads or writes mail bodies.
//
// The same three rules as `rfc5322.rs`: spans rather than copies, incomplete
// distinguished from malformed, and no repair of a value that does not parse.
//
// What a part IS remains the reader's decision. This file will tell a caller
// that a part declares `text/html`, that it is base64 encoded, and that its
// disposition names a filename — never that the filename is safe to use, that
// the type is what the bytes actually are, or that an attachment should be
// retained.

/// Longest boundary RFC 2046 §5.1.1 permits.
pub const MAX_BOUNDARY_LEN: usize = 70;

// ---- media types and parameters ---------------------------------------------

/// A parsed media type: `type/subtype` and the span its parameters occupy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MediaType {
    pub type_at: usize,
    pub type_len: usize,
    pub sub_at: usize,
    pub sub_len: usize,
    pub params_at: usize,
    pub params_len: usize,
}

/// Whether a byte may appear in a token (RFC 2045 §5.1).
fn is_token(b: u8) -> bool {
    b > 32
        && b < 127
        && !matches!(
            b,
            b'(' | b')'
                | b'<'
                | b'>'
                | b'@'
                | b','
                | b';'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'='
        )
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn skip_wsp(value: &[u8], mut at: usize) -> usize {
    while at < value.len() && is_wsp(value[at]) {
        at += 1;
    }
    at
}

/// Parse an unfolded `Content-Type` value.
///
/// `None` when it is not `type/subtype`: a value this cannot read is reported
/// as unparsed rather than defaulted, because guessing a type decides how a
/// body is rendered.
pub fn parse_content_type(value: &[u8]) -> Option<MediaType> {
    let mut i = skip_wsp(value, 0);
    let type_at = i;
    while i < value.len() && is_token(value[i]) {
        i += 1;
    }
    let type_len = i - type_at;
    if type_len == 0 || i >= value.len() || value[i] != b'/' {
        return None;
    }
    i += 1;
    let sub_at = i;
    while i < value.len() && is_token(value[i]) {
        i += 1;
    }
    let sub_len = i - sub_at;
    if sub_len == 0 {
        return None;
    }
    Some(MediaType {
        type_at,
        type_len,
        sub_at,
        sub_len,
        params_at: i,
        params_len: value.len() - i,
    })
}

/// ASCII-case-insensitive comparison of two byte strings.
pub fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Whether a parsed media type is `type/subtype`.
pub fn media_type_is(value: &[u8], mt: &MediaType, ty: &[u8], sub: &[u8]) -> bool {
    ascii_eq_ignore_case(&value[mt.type_at..mt.type_at + mt.type_len], ty)
        && ascii_eq_ignore_case(&value[mt.sub_at..mt.sub_at + mt.sub_len], sub)
}

/// Whether a parsed media type's top-level type is `ty`.
pub fn media_top_type_is(value: &[u8], mt: &MediaType, ty: &[u8]) -> bool {
    ascii_eq_ignore_case(&value[mt.type_at..mt.type_at + mt.type_len], ty)
}

/// One `;name=value` parameter: the spans of its name and its raw value, and
/// whether that value was quoted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParamSpan {
    pub name_at: usize,
    pub name_len: usize,
    pub value_at: usize,
    pub value_len: usize,
    pub quoted: bool,
}

/// Scan one parameter starting at `at`, returning it and the offset past it.
///
/// `None` at the end of the parameter list, or on a parameter that does not
/// parse — the caller that needs those apart checks whether `at` reached the
/// end.
pub fn next_param(value: &[u8], at: usize) -> Option<(ParamSpan, usize)> {
    let mut i = skip_wsp(value, at);
    if i >= value.len() || value[i] != b';' {
        return None;
    }
    i = skip_wsp(value, i + 1);
    let name_at = i;
    while i < value.len() && is_token(value[i]) {
        i += 1;
    }
    let name_len = i - name_at;
    if name_len == 0 {
        return None;
    }
    i = skip_wsp(value, i);
    if i >= value.len() || value[i] != b'=' {
        return None;
    }
    i = skip_wsp(value, i + 1);
    if i >= value.len() {
        return None;
    }
    if value[i] == b'"' {
        let start = i + 1;
        let mut j = start;
        while j < value.len() {
            if value[j] == b'\\' {
                j += 2;
                continue;
            }
            if value[j] == b'"' {
                break;
            }
            j += 1;
        }
        if j >= value.len() {
            // An unterminated quoted value: refused rather than read to the
            // end of the field, which would swallow the parameters after it.
            return None;
        }
        Some((
            ParamSpan {
                name_at,
                name_len,
                value_at: start,
                value_len: j - start,
                quoted: true,
            },
            j + 1,
        ))
    } else {
        let start = i;
        while i < value.len() && is_token(value[i]) {
            i += 1;
        }
        if i == start {
            return None;
        }
        Some((
            ParamSpan {
                name_at,
                name_len,
                value_at: start,
                value_len: i - start,
                quoted: false,
            },
            i,
        ))
    }
}

/// The first parameter with this name, searched from `params_at`.
pub fn find_param(value: &[u8], from: usize, name: &[u8]) -> Option<ParamSpan> {
    let mut at = from;
    while let Some((param, next)) = next_param(value, at) {
        if ascii_eq_ignore_case(&value[param.name_at..param.name_at + param.name_len], name) {
            return Some(param);
        }
        at = next;
    }
    None
}

/// Copy a parameter's value into `out`, removing the quoted-pair escapes a
/// quoted value may carry. Returns the length written.
pub fn unquote_param(value: &[u8], param: ParamSpan, out: &mut [u8]) -> Option<usize> {
    let mut p = 0usize;
    let mut i = param.value_at;
    let end = param.value_at + param.value_len;
    while i < end {
        let b = if param.quoted && value[i] == b'\\' && i + 1 < end {
            i += 1;
            value[i]
        } else {
            value[i]
        };
        *out.get_mut(p)? = b;
        p += 1;
        i += 1;
    }
    Some(p)
}

// ---- transfer encodings -----------------------------------------------------

/// How a part's bytes were encoded for transport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    SevenBit,
    EightBit,
    Binary,
    QuotedPrintable,
    Base64,
    /// A value this does not implement.
    ///
    /// Reported rather than treated as `7bit`, because handing a caller bytes
    /// that are still encoded, labelled as if they were not, is worse than
    /// saying so.
    Unknown,
}

impl Encoding {
    /// Whether the bytes need decoding before they are the part's content.
    pub fn needs_decoding(self) -> bool {
        matches!(self, Self::QuotedPrintable | Self::Base64)
    }

    /// The stable byte this encoding is reported as.
    ///
    /// Wire positions: append, never renumber.
    pub fn code(self) -> u8 {
        match self {
            Self::SevenBit => 0,
            Self::EightBit => 1,
            Self::Binary => 2,
            Self::QuotedPrintable => 3,
            Self::Base64 => 4,
            Self::Unknown => 255,
        }
    }
}

/// Parse an unfolded `Content-Transfer-Encoding` value.
pub fn parse_encoding(value: &[u8]) -> Encoding {
    let start = skip_wsp(value, 0);
    let mut end = start;
    while end < value.len() && is_token(value[end]) {
        end += 1;
    }
    let token = &value[start..end];
    if ascii_eq_ignore_case(token, b"7bit") {
        Encoding::SevenBit
    } else if ascii_eq_ignore_case(token, b"8bit") {
        Encoding::EightBit
    } else if ascii_eq_ignore_case(token, b"binary") {
        Encoding::Binary
    } else if ascii_eq_ignore_case(token, b"quoted-printable") {
        Encoding::QuotedPrintable
    } else if ascii_eq_ignore_case(token, b"base64") {
        Encoding::Base64
    } else {
        Encoding::Unknown
    }
}

// ---- multipart --------------------------------------------------------------

/// The outcome of scanning for the next multipart delimiter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoundaryScan {
    /// A delimiter: the preceding part ends at `part_end`, the next part
    /// begins at `next`, and `last` marks the closing delimiter.
    Found {
        part_end: usize,
        next: usize,
        last: bool,
    },
    /// No delimiter in these bytes yet.
    Incomplete,
}

/// Find the next `--boundary` delimiter line at or after `at`.
///
/// A delimiter is a line consisting of `--` and the boundary, optionally
/// followed by `--` for the closing one. The CRLF that precedes a delimiter
/// belongs to the delimiter, not to the part before it, which is why
/// `part_end` excludes it.
pub fn scan_boundary(buf: &[u8], at: usize, boundary: &[u8]) -> BoundaryScan {
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_LEN {
        return BoundaryScan::Incomplete;
    }
    let mut i = at;
    while i < buf.len() {
        // A delimiter sits at the start of a line: either the very start of
        // the scanned region, or just after a CRLF.
        let line_start = i == at && at == 0;
        let after_crlf = i >= 2 && buf[i - 2] == b'\r' && buf[i - 1] == b'\n';
        let at_line_start = line_start || after_crlf;
        let room = buf.len() >= i + 2 + boundary.len();
        if at_line_start
            && room
            && &buf[i..i + 2] == b"--"
            && &buf[i + 2..i + 2 + boundary.len()] == boundary
        {
            {
                let after = i + 2 + boundary.len();
                let last = buf.len() >= after + 2 && &buf[after..after + 2] == b"--";
                let tail = if last { after + 2 } else { after };
                // The delimiter line must end.
                let mut j = tail;
                while j < buf.len() && is_wsp(buf[j]) {
                    j += 1;
                }
                if j + 1 < buf.len() && buf[j] == b'\r' && buf[j + 1] == b'\n' {
                    let part_end = if after_crlf { i - 2 } else { i };
                    return BoundaryScan::Found {
                        part_end,
                        next: j + 2,
                        last,
                    };
                }
                if last && j >= buf.len() {
                    // A closing delimiter at the very end, with no trailing
                    // CRLF, is still a closing delimiter.
                    let part_end = if after_crlf { i - 2 } else { i };
                    return BoundaryScan::Found {
                        part_end,
                        next: buf.len(),
                        last: true,
                    };
                }
            }
        }
        i += 1;
    }
    BoundaryScan::Incomplete
}

// ---- decoders ---------------------------------------------------------------

/// Decode quoted-printable into `out`, returning the length written.
///
/// Soft line breaks (`=` at end of line) vanish, `=XX` becomes its byte, and
/// everything else passes through. `None` when `out` is too small or the input
/// carries an `=` that is neither a soft break nor two hex digits — a malformed
/// escape is refused rather than passed through as literal text, since the two
/// readings differ in exactly the bytes an attachment is made of.
pub fn qp_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut p = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        if b != b'=' {
            *out.get_mut(p)? = b;
            p += 1;
            i += 1;
            continue;
        }
        // Soft line break.
        if i + 2 < input.len() && input[i + 1] == b'\r' && input[i + 2] == b'\n' {
            i += 3;
            continue;
        }
        if i + 1 < input.len() && input[i + 1] == b'\n' {
            i += 2;
            continue;
        }
        let hi = hex_value(*input.get(i + 1)?)?;
        let lo = hex_value(*input.get(i + 2)?)?;
        *out.get_mut(p)? = (hi << 4) | lo;
        p += 1;
        i += 3;
    }
    Some(p)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Decode base64 into `out`, returning the length written.
///
/// Line breaks and whitespace are skipped, as a transported body carries them.
/// `None` on a character outside the alphabet, on padding in the wrong place,
/// or when `out` is too small.
pub fn b64_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut p = 0usize;
    let mut quad = [0u8; 4];
    let mut have = 0usize;
    let mut padding = 0usize;
    for &b in input {
        if b == b'\r' || b == b'\n' || is_wsp(b) {
            continue;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                if padding > 2 || have < 2 {
                    return None;
                }
                quad[have] = 0;
                have += 1;
                if have == 4 {
                    let written = emit_quad(&quad, padding, out, p)?;
                    p += written;
                    have = 0;
                }
                continue;
            }
            _ => return None,
        };
        if padding > 0 {
            // Data after padding: the encoding ended and then did not.
            return None;
        }
        quad[have] = v;
        have += 1;
        if have == 4 {
            let written = emit_quad(&quad, 0, out, p)?;
            p += written;
            have = 0;
        }
    }
    if have != 0 {
        // A trailing group of one character cannot encode anything; two or
        // three without padding still encode bytes, which lenient encoders
        // emit.
        if have == 1 {
            return None;
        }
        let missing = 4 - have;
        let mut tail = quad;
        for slot in tail.iter_mut().skip(have) {
            *slot = 0;
        }
        let written = emit_quad(&tail, missing, out, p)?;
        p += written;
    }
    Some(p)
}

/// Write the one to three bytes a base64 quad stands for.
fn emit_quad(quad: &[u8; 4], padding: usize, out: &mut [u8], at: usize) -> Option<usize> {
    let triple = (u32::from(quad[0]) << 18)
        | (u32::from(quad[1]) << 12)
        | (u32::from(quad[2]) << 6)
        | u32::from(quad[3]);
    let count = 3usize.checked_sub(padding)?;
    let bytes = [
        ((triple >> 16) & 0xFF) as u8,
        ((triple >> 8) & 0xFF) as u8,
        (triple & 0xFF) as u8,
    ];
    for (k, byte) in bytes.iter().enumerate().take(count) {
        *out.get_mut(at + k)? = *byte;
    }
    Some(count)
}
