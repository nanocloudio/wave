// Wire format for the `s3_client` PIC's request/response ports.
//
// These two records are the seam a caller asks THROUGH: one object operation
// and its answer. They are the client-side mirror of wave's HTTP application
// fan-out (`HttpRequest`/`HttpResponse` on `req_out` / `resp_in`) — there a
// graph node ANSWERS requests a gateway hands it; here a graph node ISSUES
// requests a connector performs. A pipeline that terminates HTTP on one side
// and stores blobs on the other needs both halves.
//
// Layouts (multi-byte ints LE):
//
//   S3Request   [op:u8][cid:u32][bucket_len:u16][key_len:u16][body_len:u32]
//               [bucket:bucket_len][key:key_len][body:body_len]
//
//   S3Response  [op:u8][cid:u32][status:u16][body_len:u32][body:body_len]
//
// `cid` is a caller-chosen correlation id echoed on the response, so a caller
// may have several requests outstanding without keeping per-call state. It is
// opaque here: this module never interprets it, it only returns it.
//
// The ports are `OctetStream` rather than a registered content type. That is
// deliberate: a new entry in Fluxor's `CONTENT_TYPES` moves the ABI surface
// digest, which re-stamps every `.fmod` in every workspace member and forces a
// coordinated rebuild. A request/response pair between two modules that already
// agree on a layout does not earn that cost — the same call loam's storage
// ports make.
//
// The boundary this sits on: S3 framing and SigV4 are HTTP mechanics and
// belong here; mapping a bucket and key onto whatever the application calls an
// object stays with the consumer.

/// Retrieve an object. `body_len` must be 0.
pub const S3_OP_GET: u8 = 0x50;
/// Store an object; `body` is the payload, hashed into the SigV4 signature.
pub const S3_OP_PUT: u8 = 0x51;
/// Existence and metadata only — the response carries a status and no body.
pub const S3_OP_HEAD: u8 = 0x52;
/// Remove an object.
pub const S3_OP_DELETE: u8 = 0x53;

/// Fixed prefix of an `S3Request`: `[op][cid][bucket_len][key_len][body_len]`.
pub const S3_REQ_HDR: usize = 1 + 4 + 2 + 2 + 4;
/// Fixed prefix of an `S3Response`: `[op][cid][status][body_len]`.
pub const S3_RESP_HDR: usize = 1 + 4 + 2 + 4;

/// A parsed `S3Request`, as offsets into the caller's buffer.
///
/// Offsets rather than slices because the module reads into a fixed state-owned
/// array and then signs out of that same array; handing back borrows would pin
/// it for the whole request lifetime.
#[derive(Clone, Copy)]
pub struct S3ReqView {
    pub op: u8,
    pub cid: u32,
    pub bucket_at: usize,
    pub bucket_len: usize,
    pub key_at: usize,
    pub key_len: usize,
    pub body_at: usize,
    pub body_len: usize,
}

/// Parse an `S3Request`. `None` when the buffer is shorter than the header, or
/// shorter than the lengths that header declares — a truncated record is
/// dropped rather than read past, exactly as the HTTP fan-out drops one.
pub fn parse_s3_request(buf: &[u8]) -> Option<S3ReqView> {
    if buf.len() < S3_REQ_HDR {
        return None;
    }
    let op = buf[0];
    let cid = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let bucket_len = u16::from_le_bytes([buf[5], buf[6]]) as usize;
    let key_len = u16::from_le_bytes([buf[7], buf[8]]) as usize;
    let body_len = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]) as usize;

    let need = S3_REQ_HDR
        .checked_add(bucket_len)?
        .checked_add(key_len)?
        .checked_add(body_len)?;
    if buf.len() < need {
        return None;
    }
    let bucket_at = S3_REQ_HDR;
    let key_at = bucket_at + bucket_len;
    let body_at = key_at + key_len;
    Some(S3ReqView {
        op,
        cid,
        bucket_at,
        bucket_len,
        key_at,
        key_len,
        body_at,
        body_len,
    })
}

/// Whether an op is one this connector performs. An unknown op is answered with
/// a status rather than dropped, so a caller learns its request was refused
/// instead of waiting out a timeout.
pub fn s3_op_is_known(op: u8) -> bool {
    matches!(op, S3_OP_GET | S3_OP_PUT | S3_OP_HEAD | S3_OP_DELETE)
}

/// The HTTP method an op maps to.
pub fn s3_op_method(op: u8) -> &'static [u8] {
    match op {
        S3_OP_PUT => b"PUT",
        S3_OP_HEAD => b"HEAD",
        S3_OP_DELETE => b"DELETE",
        _ => b"GET",
    }
}

/// Whether a response to this op may carry a body. HEAD never does — a body
/// after a HEAD desynchronises the caller exactly as it would on the server
/// side.
pub fn s3_op_expects_body(op: u8) -> bool {
    op == S3_OP_GET
}

/// Write `/bucket/key` into `out`, returning its length.
///
/// The gateway maps a bucket to a namespace root and the key to a path beneath
/// it, so this is the whole of the addressing. Returns `None` if the path would
/// not fit — a truncated path would address a DIFFERENT object, which is worse
/// than failing.
///
/// A key that ALREADY begins with `/` has that separator absorbed rather than
/// doubled. The same reasoning: `//v2/x` and `/v2/x` are different keys to a
/// gateway (an S3 key is opaque bytes), so emitting `/bucket//v2/x` for the key
/// `/v2/x` addresses an object that is not the one asked for — silently, with a
/// 404 rather than an error. Callers that pass a URL path straight through as a
/// key hit this immediately, which is how it was found.
pub fn s3_object_path(bucket: &[u8], key: &[u8], out: &mut [u8]) -> Option<usize> {
    let key = if key.first() == Some(&b'/') {
        &key[1..]
    } else {
        key
    };
    let need = 1 + bucket.len() + 1 + key.len();
    if need > out.len() {
        return None;
    }
    let mut p = 0;
    out[p] = b'/';
    p += 1;
    out[p..p + bucket.len()].copy_from_slice(bucket);
    p += bucket.len();
    out[p] = b'/';
    p += 1;
    out[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    Some(p)
}

/// Stamp an `S3Response` header into `out`. The body, if any, follows at
/// `S3_RESP_HDR`; the caller writes it there and passes its length here.
pub fn write_s3_response(
    op: u8,
    cid: u32,
    status: u16,
    body_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < S3_RESP_HDR {
        return None;
    }
    out[0] = op;
    out[1..5].copy_from_slice(&cid.to_le_bytes());
    out[5..7].copy_from_slice(&status.to_le_bytes());
    out[7..11].copy_from_slice(&(body_len as u32).to_le_bytes());
    Some(S3_RESP_HDR + body_len)
}

/// Offset of the response body within an `S3Response` — where a caller writes
/// it, and where a reader finds it.
pub const S3_RESP_BODY_AT: usize = S3_RESP_HDR;

/// The body span of a response, given the whole record. `None` if the record is
/// shorter than the length it declares.
pub fn s3_response_body(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < S3_RESP_HDR {
        return None;
    }
    let body_len = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]) as usize;
    if buf.len() < S3_RESP_HDR + body_len {
        return None;
    }
    Some((S3_RESP_HDR, body_len))
}

/// Status of a response record, for a caller that only needs the outcome.
pub fn s3_response_status(buf: &[u8]) -> Option<u16> {
    if buf.len() < S3_RESP_HDR {
        return None;
    }
    Some(u16::from_le_bytes([buf[5], buf[6]]))
}

/// Correlation id of a response record.
pub fn s3_response_cid(buf: &[u8]) -> Option<u32> {
    if buf.len() < S3_RESP_HDR {
        return None;
    }
    Some(u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]))
}

/// Find the end of an HTTP response head (`\r\n\r\n`), i.e. where the body
/// starts. `None` while the head is still incomplete.
pub fn http_body_offset(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 3 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}
