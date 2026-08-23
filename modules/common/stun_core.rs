// Bounded, no_std, no-alloc STUN message mechanics (RFC 8489): the header, the
// attribute list, XOR-mapped addresses, and the two computed attributes —
// MESSAGE-INTEGRITY and FINGERPRINT. `include!`d by the host crate (tests) and
// by any module that reads or writes STUN.
//
// This file tells a caller what a STUN message SAYS. It decides nothing. Which
// messages to send, to whom, in what order, and what their answers mean for
// reachability is an ICE agent's work, and an agent's decisions are
// NAT-traversal policy rather than protocol mechanics — a different concern in
// a different repository. The same split the family already uses: the codec
// lives with the other codecs, the policy lives with the concern that owns the
// outcome.
//
// The rules are `rfc5322.rs`'s, for the same reasons: spans rather than
// copies, incomplete distinguished from malformed, and no repair. A half-read
// attribute list names attributes the peer did not send, which for a
// connectivity check means believing a path was verified when it was not.
//
// Requires `sha1` to be in scope at the mount site, as `ws_frame_core.rs`
// requires it: MESSAGE-INTEGRITY is HMAC-SHA-1 and the standard fixes that.

/// Fixed STUN header length.
pub const STUN_HEADER_LEN: usize = 20;
/// The magic cookie every STUN message after RFC 3489 carries.
pub const STUN_MAGIC: u32 = 0x2112_A442;
/// Transaction id length.
pub const STUN_TXN_LEN: usize = 12;
/// Length of a MESSAGE-INTEGRITY attribute's value (an HMAC-SHA-1).
pub const STUN_INTEGRITY_LEN: usize = 20;
/// Length of a FINGERPRINT attribute's value.
pub const STUN_FINGERPRINT_LEN: usize = 4;

// ---- classes and methods ----------------------------------------------------

/// A request, which expects a response.
pub const STUN_CLASS_REQUEST: u8 = 0b00;
/// An indication, which does not.
pub const STUN_CLASS_INDICATION: u8 = 0b01;
/// A success response.
pub const STUN_CLASS_SUCCESS: u8 = 0b10;
/// An error response.
pub const STUN_CLASS_ERROR: u8 = 0b11;

/// The Binding method — the only one STUN itself defines.
pub const STUN_METHOD_BINDING: u16 = 0x001;

// ---- attribute types --------------------------------------------------------

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// ICE: the priority of the candidate that sent the check.
pub const ATTR_PRIORITY: u16 = 0x0024;
/// ICE: this check nominates its pair.
pub const ATTR_USE_CANDIDATE: u16 = 0x0025;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_ALTERNATE_SERVER: u16 = 0x8023;
pub const ATTR_FINGERPRINT: u16 = 0x8028;
/// ICE: the sender believes it is controlled.
pub const ATTR_ICE_CONTROLLED: u16 = 0x8029;
/// ICE: the sender believes it is controlling.
pub const ATTR_ICE_CONTROLLING: u16 = 0x802A;

/// Address family in a MAPPED-ADDRESS-shaped attribute.
pub const STUN_FAMILY_IPV4: u8 = 0x01;
pub const STUN_FAMILY_IPV6: u8 = 0x02;

/// Whether an attribute type is in the comprehension-required range.
///
/// A responder that does not understand one of these must reject the message
/// rather than answer it, which is the difference between "I ignored something
/// you asked for" and "we agree".
pub fn attr_is_comprehension_required(typ: u16) -> bool {
    typ < 0x8000
}

// ---- header -----------------------------------------------------------------

/// A parsed STUN header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StunHeader {
    pub class: u8,
    pub method: u16,
    /// Length of the attribute section, as the header declares it.
    pub length: usize,
    pub txn: [u8; STUN_TXN_LEN],
}

/// Whether these bytes could be a STUN message at all.
///
/// The two leading bits are zero and the magic cookie is present. Used to
/// demultiplex STUN from RTP and DTLS on one socket, which is what an ICE
/// agent needs it for.
pub fn stun_is_plausible(buf: &[u8]) -> bool {
    buf.len() >= STUN_HEADER_LEN
        && buf[0] & 0xC0 == 0
        && u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) == STUN_MAGIC
}

/// Parse a STUN header.
///
/// `None` when the buffer is shorter than a header, the cookie is absent, or
/// the declared length is not a multiple of four or overruns the buffer. A
/// message whose length field disagrees with what arrived is refused rather
/// than read to whatever is present.
pub fn parse_stun_header(buf: &[u8]) -> Option<StunHeader> {
    if !stun_is_plausible(buf) {
        return None;
    }
    let typ = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if !length.is_multiple_of(4) || STUN_HEADER_LEN + length > buf.len() {
        return None;
    }
    // Class bits are scattered through the type field: bit 4 and bit 8.
    let class = (((typ >> 7) & 0x02) | ((typ >> 4) & 0x01)) as u8;
    let method = (typ & 0x000F) | ((typ >> 1) & 0x0070) | ((typ >> 2) & 0x0F80);
    let mut txn = [0u8; STUN_TXN_LEN];
    txn.copy_from_slice(&buf[8..20]);
    Some(StunHeader {
        class,
        method,
        length,
        txn,
    })
}

/// Compose the 16-bit type field from a class and a method.
pub fn stun_message_type(class: u8, method: u16) -> u16 {
    let c = u16::from(class);
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((c & 0x01) << 4)
        | ((c & 0x02) << 7)
}

// ---- attributes -------------------------------------------------------------

/// The outcome of scanning for one attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttrScan {
    /// An attribute: its type, the span of its value, and the offset of the
    /// next attribute.
    Attr {
        typ: u16,
        at: usize,
        len: usize,
        next: usize,
    },
    /// The end of the attribute section.
    End,
    /// The section does not parse.
    Malformed,
}

/// Scan one attribute starting at `at`, within a message of `total` bytes.
pub fn next_attribute(buf: &[u8], at: usize, total: usize) -> AttrScan {
    if at >= total {
        return AttrScan::End;
    }
    if at + 4 > total {
        return AttrScan::Malformed;
    }
    let typ = u16::from_be_bytes([buf[at], buf[at + 1]]);
    let len = u16::from_be_bytes([buf[at + 2], buf[at + 3]]) as usize;
    let value_at = at + 4;
    let Some(end) = value_at.checked_add(len) else {
        return AttrScan::Malformed;
    };
    if end > total {
        return AttrScan::Malformed;
    }
    // Attributes are padded to a four-byte boundary; the padding is not part
    // of the value.
    let padded = (len + 3) & !3;
    let next = value_at + padded;
    if next > total {
        // The final attribute may be unpadded at the very end of a message
        // some implementations emit; anything else is malformed.
        if end == total {
            return AttrScan::Attr {
                typ,
                at: value_at,
                len,
                next: total,
            };
        }
        return AttrScan::Malformed;
    }
    AttrScan::Attr {
        typ,
        at: value_at,
        len,
        next,
    }
}

/// The span of the first attribute of this type, if the message carries one.
pub fn find_attribute(buf: &[u8], header: &StunHeader, typ: u16) -> Option<(usize, usize)> {
    let total = STUN_HEADER_LEN + header.length;
    let mut at = STUN_HEADER_LEN;
    loop {
        match next_attribute(buf, at, total) {
            AttrScan::Attr {
                typ: found,
                at: value_at,
                len,
                next,
            } => {
                if found == typ {
                    return Some((value_at, len));
                }
                at = next;
            }
            AttrScan::End | AttrScan::Malformed => return None,
        }
    }
}

/// Whether every comprehension-required attribute is one of `known`.
///
/// Returns the first unknown one, so a responder can name it in the error it
/// sends rather than refusing without saying why.
pub fn first_unknown_required(buf: &[u8], header: &StunHeader, known: &[u16]) -> Option<u16> {
    let total = STUN_HEADER_LEN + header.length;
    let mut at = STUN_HEADER_LEN;
    loop {
        match next_attribute(buf, at, total) {
            AttrScan::Attr { typ, next, .. } => {
                if attr_is_comprehension_required(typ) && !known.contains(&typ) {
                    return Some(typ);
                }
                at = next;
            }
            AttrScan::End | AttrScan::Malformed => return None,
        }
    }
}

// ---- addresses --------------------------------------------------------------

/// A transport address carried in a STUN attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StunAddress {
    pub family: u8,
    /// The address, big-endian, as the datagram surface carries it. Only the
    /// first four bytes are meaningful for IPv4.
    pub addr: [u8; 16],
    pub port: u16,
}

/// Parse an XOR-MAPPED-ADDRESS value.
///
/// The port and address are obfuscated with the magic cookie and, for IPv6,
/// the transaction id. Un-XORing is not decryption and adds no secrecy; it
/// exists so that NATs rewriting a payload that happens to contain their own
/// address do not corrupt it.
pub fn parse_xor_mapped_address(
    buf: &[u8],
    at: usize,
    len: usize,
    txn: &[u8; STUN_TXN_LEN],
) -> Option<StunAddress> {
    if len < 4 {
        return None;
    }
    let family = buf[at + 1];
    let port = u16::from_be_bytes([buf[at + 2], buf[at + 3]]) ^ ((STUN_MAGIC >> 16) as u16);
    let magic = STUN_MAGIC.to_be_bytes();
    let mut addr = [0u8; 16];
    match family {
        STUN_FAMILY_IPV4 => {
            if len < 8 {
                return None;
            }
            for i in 0..4 {
                addr[i] = buf[at + 4 + i] ^ magic[i];
            }
        }
        STUN_FAMILY_IPV6 => {
            if len < 20 {
                return None;
            }
            for i in 0..16 {
                let mask = if i < 4 { magic[i] } else { txn[i - 4] };
                addr[i] = buf[at + 4 + i] ^ mask;
            }
        }
        _ => return None,
    }
    Some(StunAddress { family, addr, port })
}

/// Parse a plain MAPPED-ADDRESS value.
pub fn parse_mapped_address(buf: &[u8], at: usize, len: usize) -> Option<StunAddress> {
    if len < 8 {
        return None;
    }
    let family = buf[at + 1];
    let port = u16::from_be_bytes([buf[at + 2], buf[at + 3]]);
    let mut addr = [0u8; 16];
    let take = if family == STUN_FAMILY_IPV6 { 16 } else { 4 };
    if len < 4 + take {
        return None;
    }
    addr[..take].copy_from_slice(&buf[at + 4..at + 4 + take]);
    Some(StunAddress { family, addr, port })
}

// ---- building ---------------------------------------------------------------

/// Write a STUN header with an empty attribute section.
///
/// The length field is fixed up by [`stun_set_length`] as attributes are
/// appended, so a caller never computes it twice.
pub fn write_stun_header(
    class: u8,
    method: u16,
    txn: &[u8; STUN_TXN_LEN],
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < STUN_HEADER_LEN {
        return None;
    }
    let typ = stun_message_type(class, method);
    out[0..2].copy_from_slice(&typ.to_be_bytes());
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    out[8..20].copy_from_slice(txn);
    Some(STUN_HEADER_LEN)
}

/// Set the header's length field to cover `total - STUN_HEADER_LEN` bytes.
pub fn stun_set_length(out: &mut [u8], total: usize) -> Option<()> {
    let body = total.checked_sub(STUN_HEADER_LEN)?;
    if body > u16::MAX as usize || out.len() < STUN_HEADER_LEN {
        return None;
    }
    out[2..4].copy_from_slice(&(body as u16).to_be_bytes());
    Some(())
}

/// Append an attribute, padding its value to a four-byte boundary.
pub fn append_attribute(typ: u16, value: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    let padded = (value.len() + 3) & !3;
    let end = at.checked_add(4)?.checked_add(padded)?;
    if end > out.len() || value.len() > u16::MAX as usize {
        return None;
    }
    out[at..at + 2].copy_from_slice(&typ.to_be_bytes());
    out[at + 2..at + 4].copy_from_slice(&(value.len() as u16).to_be_bytes());
    out[at + 4..at + 4 + value.len()].copy_from_slice(value);
    for slot in out.iter_mut().take(end).skip(at + 4 + value.len()) {
        *slot = 0;
    }
    Some(end)
}

/// Append an XOR-MAPPED-ADDRESS for an IPv4 peer.
pub fn append_xor_mapped_address_v4(
    addr: [u8; 4],
    port: u16,
    out: &mut [u8],
    at: usize,
) -> Option<usize> {
    let magic = STUN_MAGIC.to_be_bytes();
    let mut value = [0u8; 8];
    value[0] = 0;
    value[1] = STUN_FAMILY_IPV4;
    let xport = port ^ ((STUN_MAGIC >> 16) as u16);
    value[2..4].copy_from_slice(&xport.to_be_bytes());
    for i in 0..4 {
        value[4 + i] = addr[i] ^ magic[i];
    }
    append_attribute(ATTR_XOR_MAPPED_ADDRESS, &value, out, at)
}

/// Append an ERROR-CODE attribute.
pub fn append_error_code(code: u16, reason: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    if !(300..700).contains(&code) {
        return None;
    }
    let mut value = [0u8; 4 + 64];
    value[2] = (code / 100) as u8;
    value[3] = (code % 100) as u8;
    let take = reason.len().min(64);
    value[4..4 + take].copy_from_slice(&reason[..take]);
    append_attribute(ATTR_ERROR_CODE, &value[..4 + take], out, at)
}

/// The status code an ERROR-CODE value states.
pub fn parse_error_code(buf: &[u8], at: usize, len: usize) -> Option<u16> {
    if len < 4 {
        return None;
    }
    let class = u16::from(buf[at + 2] & 0x07);
    let number = u16::from(buf[at + 3]);
    if !(3..7).contains(&class) || number > 99 {
        return None;
    }
    Some(class * 100 + number)
}

// ---- MESSAGE-INTEGRITY ------------------------------------------------------

/// HMAC-SHA-1 over `data` with `key`, as MESSAGE-INTEGRITY requires.
///
/// SHA-1 is not a choice here: RFC 8489 fixes it for this attribute, and the
/// security of the check rests on the key rather than on collision resistance.
pub fn stun_hmac_sha1(key: &[u8], data: &[u8], out: &mut [u8; 20]) {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = sha1(key);
        k[..20].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5Cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    // Inner: H(ipad || data). Bounded by the caller's message size, which is
    // one datagram.
    let mut inner_in = [0u8; BLOCK + 1500];
    let take = data.len().min(inner_in.len() - BLOCK);
    inner_in[..BLOCK].copy_from_slice(&ipad);
    inner_in[BLOCK..BLOCK + take].copy_from_slice(&data[..take]);
    let inner = sha1(&inner_in[..BLOCK + take]);

    let mut outer_in = [0u8; BLOCK + 20];
    outer_in[..BLOCK].copy_from_slice(&opad);
    outer_in[BLOCK..].copy_from_slice(&inner);
    *out = sha1(&outer_in);
}

/// Append MESSAGE-INTEGRITY over the message built so far.
///
/// The header length must already cover the attribute being added, which is
/// what the standard means by computing the HMAC over the message "as if" the
/// attribute were present. Getting that wrong produces an integrity value both
/// ends compute differently and neither can explain.
pub fn append_message_integrity(key: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    let end = at.checked_add(4)?.checked_add(STUN_INTEGRITY_LEN)?;
    if end > out.len() {
        return None;
    }
    stun_set_length(out, end)?;
    let mut mac = [0u8; 20];
    stun_hmac_sha1(key, &out[..at], &mut mac);
    append_attribute(ATTR_MESSAGE_INTEGRITY, &mac, out, at)
}

/// Whether the message's MESSAGE-INTEGRITY verifies under `key`.
///
/// False when the attribute is absent: a message that did not claim integrity
/// has not passed a check, and treating "no claim" as "verified" is how an
/// unauthenticated check gets accepted.
pub fn verify_message_integrity(buf: &[u8], header: &StunHeader, key: &[u8]) -> bool {
    let Some((at, len)) = find_attribute(buf, header, ATTR_MESSAGE_INTEGRITY) else {
        return false;
    };
    if len != STUN_INTEGRITY_LEN {
        return false;
    }
    let attr_start = at - 4;
    // The HMAC covers the message up to the attribute, with the length field
    // as it was when the sender computed it: covering through this attribute
    // and no further.
    let mut scratch = [0u8; 1500];
    if attr_start > scratch.len() {
        return false;
    }
    scratch[..attr_start].copy_from_slice(&buf[..attr_start]);
    let covered = attr_start + 4 + STUN_INTEGRITY_LEN;
    let Some(body) = covered.checked_sub(STUN_HEADER_LEN) else {
        return false;
    };
    if body > u16::MAX as usize {
        return false;
    }
    scratch[2..4].copy_from_slice(&(body as u16).to_be_bytes());
    let mut expected = [0u8; 20];
    stun_hmac_sha1(key, &scratch[..attr_start], &mut expected);
    let mut diff = 0u8;
    for i in 0..STUN_INTEGRITY_LEN {
        diff |= expected[i] ^ buf[at + i];
    }
    diff == 0
}

// ---- FINGERPRINT ------------------------------------------------------------

/// CRC-32 (IEEE) over `data`.
///
/// Computed bitwise rather than from a table: a 1 KiB table is a poor trade
/// against flash on the smallest target, and a fingerprint is computed once
/// per message rather than per byte of media.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Append FINGERPRINT over the message built so far.
pub fn append_fingerprint(out: &mut [u8], at: usize) -> Option<usize> {
    let end = at.checked_add(4)?.checked_add(STUN_FINGERPRINT_LEN)?;
    if end > out.len() {
        return None;
    }
    stun_set_length(out, end)?;
    let value = (crc32(&out[..at]) ^ 0x5354_554E).to_be_bytes();
    append_attribute(ATTR_FINGERPRINT, &value, out, at)
}

/// Whether the message's FINGERPRINT matches.
///
/// A fingerprint proves the message is STUN rather than something else that
/// happened to look like it. It proves nothing about who sent it.
pub fn verify_fingerprint(buf: &[u8], header: &StunHeader) -> bool {
    let Some((at, len)) = find_attribute(buf, header, ATTR_FINGERPRINT) else {
        return false;
    };
    if len != STUN_FINGERPRINT_LEN {
        return false;
    }
    let attr_start = at - 4;
    let claimed = u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    (crc32(&buf[..attr_start]) ^ 0x5354_554E) == claimed
}
