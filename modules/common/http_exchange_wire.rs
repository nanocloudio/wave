// Wire format for the HTTP client's exchange ports.
//
// These records are the seam a caller asks THROUGH: one request, and the
// answer to it. They are the client-side mirror of wave's HTTP application
// fan-out (`HttpRequest`/`HttpResponse` on `req_out` / `resp_in`) -- there a
// graph node ANSWERS requests a gateway hands it; here a graph node ISSUES a
// request a connector performs, over Fluxor's `stream.ordered_ack.exchange`.
//
// The exchange contract is deliberately payload-agnostic: it carries records
// and never learns what they mean. What they mean is here, and here only --
// both the client that parses them and the producer that composes them mount
// this file, so neither restates an offset and the two cannot drift.
//
// Layouts (multi-byte ints LE):
//
//   Request, plain -- answered with the response BODY alone:
//     [method:u8][path_len:u16][body_len:u16][path…][body…]
//
//   Request, extended -- the verb's high bit asks for the whole response and
//   says the record carries a header block of its own. Verb codes are small,
//   so the bit is free, and a producer that leaves it clear composes the
//   plain record above:
//     [method|0x80][path_len:u16][body_len:u16][hdr_len:u16]
//     [path…][headers…][body…]
//
//   Reply to an extended request -- the response's head. Its BODY streams
//   separately, because a reply is one record on a surface whose ceiling
//   every provider sizes its buffers from, and a response of any length
//   cannot be one:
//     [status:u16][hdr_len:u16][headers…]
//
//   One streamed body chunk. A zero-length chunk ends the body: without it a
//   reader cannot tell a pause from an ending.
//     [len:u16][bytes…]
//
// `headers` in both directions is a block as it goes on the wire, each line
// ending CRLF.

/// The verb's high bit: this record is extended.
pub const EXTENDED: u8 = 0x80;
/// Bytes before the fields of a plain request.
pub const REQ_HEAD: usize = 1 + 2 + 2;
/// Bytes before the fields of an extended request.
pub const REQ_HEAD_EXTENDED: usize = REQ_HEAD + 2;
/// Bytes before the header block of a reply.
pub const RESP_HEAD: usize = 2 + 2;
/// The length that precedes each chunk of a streamed body.
///
/// The reply to an extended request carries the head and goes before the
/// body, so nothing else says where that body ends. A zero-length chunk does,
/// and a length on every chunk is what makes the zero one readable rather
/// than an empty record a channel might not carry at all.
pub const CHUNK_HEAD: usize = 2;

/// What a request record says, with the fields still inside the caller's
/// buffer. Nothing is copied: a parser hands back where things are, and a
/// module that wants them elsewhere copies them itself.
pub struct Request<'a> {
    pub method: u8,
    pub extended: bool,
    pub path: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

/// The ceilings a request is held to. They belong to the module rather than
/// to the layout -- a consumer with more room is not reading a different
/// record -- so they are passed in rather than written here.
pub struct Limits {
    pub path: usize,
    pub headers: usize,
    pub body: usize,
}

/// Why a request record was not accepted. The two are answered differently:
/// a malformed record is unroutable, an oversize one is a record this
/// consumer cannot hold, and a caller can act on the difference.
pub enum RequestParse<'a> {
    Ok(Request<'a>),
    Malformed,
    Oversize,
}

fn u16_at(bytes: &[u8], at: usize) -> usize {
    match bytes.get(at..at + 2) {
        Some(pair) => usize::from(u16::from_le_bytes([pair[0], pair[1]])),
        None => 0,
    }
}

/// Read a request record.
///
/// Every length is checked against the record's own length before any field
/// is named, so a record whose fields do not add up is refused rather than
/// read past. `path_len == 0` is malformed: a request names a resource.
pub fn parse_request<'a>(payload: &'a [u8], limits: &Limits) -> RequestParse<'a> {
    if payload.len() < REQ_HEAD {
        return RequestParse::Malformed;
    }
    let raw = payload[0];
    let extended = raw & EXTENDED != 0;
    let method = raw & !EXTENDED;
    let path_len = u16_at(payload, 1);
    let body_len = u16_at(payload, 3);
    let head = if extended {
        REQ_HEAD_EXTENDED
    } else {
        REQ_HEAD
    };
    if payload.len() < head {
        return RequestParse::Malformed;
    }
    let headers_len = if extended {
        u16_at(payload, REQ_HEAD)
    } else {
        0
    };
    let path_at = head;
    let headers_at = path_at + path_len;
    let body_at = headers_at + headers_len;
    if path_len == 0 || body_at + body_len != payload.len() {
        return RequestParse::Malformed;
    }
    let Some(headers) = payload.get(headers_at..body_at) else {
        return RequestParse::Malformed;
    };
    if !header_block_ok(headers) {
        return RequestParse::Malformed;
    }
    // Shape first, size second: a record that does not parse is malformed
    // whatever its lengths claim, and answering "too big" to a record that
    // was never well formed tells a caller to retry smaller for no reason.
    if path_len > limits.path || headers_len > limits.headers || body_len > limits.body {
        return RequestParse::Oversize;
    }
    let (Some(path), Some(body)) = (
        payload.get(path_at..headers_at),
        payload.get(body_at..body_at + body_len),
    ) else {
        return RequestParse::Malformed;
    };
    RequestParse::Ok(Request {
        method,
        extended,
        path,
        headers,
        body,
    })
}

/// Compose a request record into `out`, answering its length.
///
/// `None` when `out` cannot hold it, which is the only way this can fail:
/// every field is already bounded by the lengths it writes.
pub fn write_request(
    method: u8,
    extended: bool,
    path: &[u8],
    headers: &[u8],
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let head = if extended {
        REQ_HEAD_EXTENDED
    } else {
        REQ_HEAD
    };
    let total = head + path.len() + if extended { headers.len() } else { 0 } + body.len();
    if total > out.len()
        || path.len() > u16::MAX as usize
        || headers.len() > u16::MAX as usize
        || body.len() > u16::MAX as usize
    {
        return None;
    }
    out[0] = if extended {
        method | EXTENDED
    } else {
        method & !EXTENDED
    };
    let path_len = (path.len() as u16).to_le_bytes();
    out[1] = path_len[0];
    out[2] = path_len[1];
    let body_len = (body.len() as u16).to_le_bytes();
    out[3] = body_len[0];
    out[4] = body_len[1];
    if extended {
        let headers_len = (headers.len() as u16).to_le_bytes();
        out[REQ_HEAD] = headers_len[0];
        out[REQ_HEAD + 1] = headers_len[1];
    }
    let mut at = head;
    for field in [path, if extended { headers } else { &[] }, body] {
        let end = at + field.len();
        match out.get_mut(at..end) {
            Some(slot) => slot.copy_from_slice(field),
            None => return None,
        }
        at = end;
    }
    Some(at)
}

/// Compose a reply head into `out`, answering its length.
pub fn write_reply_head(status: u16, headers: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = RESP_HEAD + headers.len();
    if total > out.len() || headers.len() > u16::MAX as usize {
        return None;
    }
    let code = status.to_le_bytes();
    out[0] = code[0];
    out[1] = code[1];
    let head_len = (headers.len() as u16).to_le_bytes();
    out[2] = head_len[0];
    out[3] = head_len[1];
    out.get_mut(RESP_HEAD..total)?.copy_from_slice(headers);
    Some(total)
}

/// Read a reply head, answering the status and the block behind it.
pub fn parse_reply_head(payload: &[u8]) -> Option<(u16, &[u8])> {
    if payload.len() < RESP_HEAD {
        return None;
    }
    let status = u16::from_le_bytes([payload[0], payload[1]]);
    let head_len = u16_at(payload, 2);
    let headers = payload.get(RESP_HEAD..RESP_HEAD + head_len)?;
    Some((status, headers))
}

/// Frame one body chunk into `out`, answering its length. A zero-length
/// `bytes` composes the chunk that ends the body.
pub fn write_chunk(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = CHUNK_HEAD + bytes.len();
    if total > out.len() || bytes.len() > u16::MAX as usize {
        return None;
    }
    let length = (bytes.len() as u16).to_le_bytes();
    out[0] = length[0];
    out[1] = length[1];
    out.get_mut(CHUNK_HEAD..total)?.copy_from_slice(bytes);
    Some(total)
}

/// Read one body chunk, answering its bytes and how much of `buffer` it
/// took. `None` while the chunk is still arriving -- a reader keeps what it
/// has and asks again, rather than reading a length that is not all there.
pub fn parse_chunk(buffer: &[u8]) -> Option<(&[u8], usize)> {
    if buffer.len() < CHUNK_HEAD {
        return None;
    }
    let length = u16_at(buffer, 0);
    let bytes = buffer.get(CHUNK_HEAD..CHUNK_HEAD + length)?;
    Some((bytes, CHUNK_HEAD + length))
}

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
/// Four names are the connector's own: it sets the length or the encoding
/// from what it is actually sending, and the host and connection from the
/// endpoint it was wired to. A caller that could set them could describe a
/// body it did not send, which is a request smuggled past whatever read the
/// record.
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
pub fn header_block_ok(b: &[u8]) -> bool {
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
