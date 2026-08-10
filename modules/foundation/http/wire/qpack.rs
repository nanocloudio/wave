//! QPACK header compression — RFC 9204.
//!
//! QPACK is HPACK's QUIC-friendly cousin. It splits the dynamic table
//! across a dedicated QPACK encoder/decoder unidirectional stream pair
//! so header decompression is independent of stream-data ordering.
//!
//! Like our HPACK implementation (`hpack.rs`), this module stores the
//! QPACK static table (RFC 9204 Appendix A — 99 entries) inline as a
//! `match` statement to avoid PIC relocation issues with const arrays.
//! The dynamic table is intentionally not implemented; we plan to
//! advertise `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` so the peer must
//! not send dynamic-table references.
//!
//! Status: static table, integer codec, block prefix, and field-line
//! encode/decode — including Huffman-coded names and values, which
//! RFC 9204 §4.1.2 takes unchanged from RFC 7541 Appendix B (shared with
//! HPACK via `super::huffman`). `h3.rs` consumes all of it for its request
//! decoder and response encoder; what is still missing above them is the
//! pump loop and the QUIC transport binding, not header coding.

#[path = "../../../../target/fluxor/fluxor-abi/sdk/wire/varint.rs"]
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod varint;

/// Lookup a static-table entry by 0-based index (RFC 9204 Appendix A).
/// Returns (name, value) byte slices on hit, None on out-of-range.
/// Implemented as a `match` — the same PIC-safety pattern as
/// `hpack.rs::static_lookup`.
pub fn qpack_static_lookup(idx: u32) -> Option<(&'static [u8], &'static [u8])> {
    Some(match idx {
        0 => (b":authority", b""),
        1 => (b":path", b"/"),
        2 => (b"age", b"0"),
        3 => (b"content-disposition", b""),
        4 => (b"content-length", b"0"),
        5 => (b"cookie", b""),
        6 => (b"date", b""),
        7 => (b"etag", b""),
        8 => (b"if-modified-since", b""),
        9 => (b"if-none-match", b""),
        10 => (b"last-modified", b""),
        11 => (b"link", b""),
        12 => (b"location", b""),
        13 => (b"referer", b""),
        14 => (b"set-cookie", b""),
        15 => (b":method", b"CONNECT"),
        16 => (b":method", b"DELETE"),
        17 => (b":method", b"GET"),
        18 => (b":method", b"HEAD"),
        19 => (b":method", b"OPTIONS"),
        20 => (b":method", b"POST"),
        21 => (b":method", b"PUT"),
        22 => (b":scheme", b"http"),
        23 => (b":scheme", b"https"),
        24 => (b":status", b"103"),
        25 => (b":status", b"200"),
        26 => (b":status", b"304"),
        27 => (b":status", b"404"),
        28 => (b":status", b"503"),
        29 => (b"accept", b"*/*"),
        30 => (b"accept", b"application/dns-message"),
        31 => (b"accept-encoding", b"gzip, deflate, br"),
        32 => (b"accept-ranges", b"bytes"),
        33 => (b"access-control-allow-headers", b"cache-control"),
        34 => (b"access-control-allow-headers", b"content-type"),
        35 => (b"access-control-allow-origin", b"*"),
        36 => (b"cache-control", b"max-age=0"),
        37 => (b"cache-control", b"max-age=2592000"),
        38 => (b"cache-control", b"max-age=604800"),
        39 => (b"cache-control", b"no-cache"),
        40 => (b"cache-control", b"no-store"),
        41 => (b"cache-control", b"public, max-age=31536000"),
        42 => (b"content-encoding", b"br"),
        43 => (b"content-encoding", b"gzip"),
        44 => (b"content-type", b"application/dns-message"),
        45 => (b"content-type", b"application/javascript"),
        46 => (b"content-type", b"application/json"),
        47 => (b"content-type", b"application/x-www-form-urlencoded"),
        48 => (b"content-type", b"image/gif"),
        49 => (b"content-type", b"image/jpeg"),
        50 => (b"content-type", b"image/png"),
        51 => (b"content-type", b"text/css"),
        52 => (b"content-type", b"text/html; charset=utf-8"),
        53 => (b"content-type", b"text/plain"),
        54 => (b"content-type", b"text/plain;charset=utf-8"),
        55 => (b"range", b"bytes=0-"),
        56 => (b"strict-transport-security", b"max-age=31536000"),
        57 => (
            b"strict-transport-security",
            b"max-age=31536000; includesubdomains",
        ),
        58 => (
            b"strict-transport-security",
            b"max-age=31536000; includesubdomains; preload",
        ),
        59 => (b"vary", b"accept-encoding"),
        60 => (b"vary", b"origin"),
        61 => (b"x-content-type-options", b"nosniff"),
        62 => (b"x-xss-protection", b"1; mode=block"),
        63 => (b":status", b"100"),
        64 => (b":status", b"204"),
        65 => (b":status", b"206"),
        66 => (b":status", b"302"),
        67 => (b":status", b"400"),
        68 => (b":status", b"403"),
        69 => (b":status", b"421"),
        70 => (b":status", b"425"),
        71 => (b":status", b"500"),
        72 => (b"accept-language", b""),
        73 => (b"access-control-allow-credentials", b"FALSE"),
        74 => (b"access-control-allow-credentials", b"TRUE"),
        75 => (b"access-control-allow-headers", b"*"),
        76 => (b"access-control-allow-methods", b"get"),
        77 => (b"access-control-allow-methods", b"get, post, options"),
        78 => (b"access-control-allow-methods", b"options"),
        79 => (b"access-control-expose-headers", b"content-length"),
        80 => (b"access-control-request-headers", b"content-type"),
        81 => (b"access-control-request-method", b"get"),
        82 => (b"access-control-request-method", b"post"),
        83 => (b"alt-svc", b"clear"),
        84 => (b"authorization", b""),
        85 => (
            b"content-security-policy",
            b"script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
        86 => (b"early-data", b"1"),
        87 => (b"expect-ct", b""),
        88 => (b"forwarded", b""),
        89 => (b"if-range", b""),
        90 => (b"origin", b""),
        91 => (b"purpose", b"prefetch"),
        92 => (b"server", b""),
        93 => (b"timing-allow-origin", b"*"),
        94 => (b"upgrade-insecure-requests", b"1"),
        95 => (b"user-agent", b""),
        96 => (b"x-forwarded-for", b""),
        97 => (b"x-frame-options", b"deny"),
        98 => (b"x-frame-options", b"sameorigin"),
        _ => return None,
    })
}

pub const QPACK_STATIC_COUNT: u32 = 99;

// ----------------------------------------------------------------------
// QPACK integer encoding (RFC 9204 §4.1.1) — same N-bit prefix scheme
// as HPACK §5.1, just with different prefix lengths per representation.
// ----------------------------------------------------------------------

/// Encode `value` with `prefix_bits` bits in the first byte. The high
/// `8 - prefix_bits` bits of `out[0]` are passed through as `flags`.
/// Returns bytes written, or 0 on overflow.
pub fn qpack_encode_int(value: u64, prefix_bits: u8, flags: u8, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out[0] = (flags & !mask_low(prefix_bits)) | (value as u8);
        return 1;
    }
    out[0] = (flags & !mask_low(prefix_bits)) | (max as u8);
    let mut remainder = value - max;
    let mut cursor = 1;
    while remainder >= 128 {
        if cursor >= out.len() {
            return 0;
        }
        out[cursor] = ((remainder & 0x7F) as u8) | 0x80;
        cursor += 1;
        remainder >>= 7;
    }
    if cursor >= out.len() {
        return 0;
    }
    out[cursor] = remainder as u8;
    cursor + 1
}

/// Decode an integer with `prefix_bits` prefix from `buf`. Returns
/// `(value, bytes_consumed)` on success, or None on truncation.
pub fn qpack_decode_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let mask = mask_low(prefix_bits) as u64;
    let mut value = (buf[0] as u64) & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut shift = 0u32;
    let mut cursor = 1;
    loop {
        if cursor >= buf.len() {
            return None;
        }
        let b = buf[cursor];
        cursor += 1;
        // RFC 7541 §5.1: reject encodings that don't fit in u64 instead
        // of wrapping. `shift >= 64` would shift the contribution off
        // the end; at shift == 63 only the low bit of (b & 0x7F) is
        // representable, the other 6 bits would silently truncate.
        if shift >= 64 {
            return None;
        }
        let chunk = (b as u64) & 0x7F;
        let max_chunk = (u64::MAX >> shift) & 0x7F;
        if chunk > max_chunk {
            return None;
        }
        value = value.checked_add(chunk << shift)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((value, cursor))
}

fn mask_low(bits: u8) -> u8 {
    if bits >= 8 {
        0xFF
    } else {
        ((1u16 << bits) - 1) as u8
    }
}

// ----------------------------------------------------------------------
// QPACK literal-only encoder (RFC 9204 §4.5)
// ----------------------------------------------------------------------
//
// We never emit dynamic-table references so every header pair is one
// of:
//   - Indexed Field Line (static)         §4.5.2 — name+value both in
//                                          the static table
//   - Literal Field Line With Name Ref    §4.5.4 — name in static
//                                          table; value literal
//   - Literal Field Line Without Name Ref §4.5.6 — both literal
//
// The encoded block is preceded by a 2-varint header (RFC 9204 §4.5.1)
// containing Required Insert Count + Delta Base. Since we don't use
// the dynamic table, both are zero.

/// Static-table entries that pair `name: value` exactly. Used for
/// `qpack_emit_indexed` lookups.
fn qpack_static_index_for_pair(name: &[u8], value: &[u8]) -> Option<u32> {
    // Walk the same set as qpack_static_lookup. Linear scan is fine —
    // there are 99 entries and we only consult a handful per response.
    let mut i = 0u32;
    while i < QPACK_STATIC_COUNT {
        if let Some((n, v)) = qpack_static_lookup(i) {
            if n == name && v == value {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn qpack_static_index_for_name(name: &[u8]) -> Option<u32> {
    let mut i = 0u32;
    while i < QPACK_STATIC_COUNT {
        if let Some((n, _)) = qpack_static_lookup(i) {
            if n == name {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Emit a QPACK header-block prefix for a header block with no
/// dynamic-table references. Required Insert Count = 0 (encoded as 0)
/// + Sign + Delta Base = 0. Returns bytes written.
pub fn qpack_emit_block_prefix(out: &mut [u8]) -> usize {
    if out.len() < 2 {
        return 0;
    }
    out[0] = 0x00; // Required Insert Count = 0 (8-bit prefix encoding)
    out[1] = 0x00; // Sign bit + 7-bit Delta Base = 0
    2
}

/// Encode one (name, value) pair into `out` using the smallest
/// QPACK representation that doesn't reference the dynamic table.
/// Returns bytes written, or 0 on overflow.
pub fn qpack_encode_field(name: &[u8], value: &[u8], out: &mut [u8]) -> usize {
    if let Some(idx) = qpack_static_index_for_pair(name, value) {
        // Indexed Field Line — pattern 1 1 T (T=1 for static), 6-bit prefix.
        let n = qpack_encode_int(idx as u64, 6, 0xC0, out);
        return n;
    }
    if let Some(idx) = qpack_static_index_for_name(name) {
        // Literal With Name Reference §4.5.4: pattern 0 1 N T (N=0,
        // T=1 static) 4-bit prefix on the index. Then a Huffman/raw
        // literal value with 7-bit prefix.
        let mut pos = qpack_encode_int(idx as u64, 4, 0x50, out);
        if pos == 0 {
            return 0;
        }
        // Value as raw literal (no Huffman): 7-bit length prefix.
        let n = qpack_encode_int(value.len() as u64, 7, 0x00, &mut out[pos..]);
        if n == 0 {
            return 0;
        }
        pos += n;
        if pos + value.len() > out.len() {
            return 0;
        }
        // SAFETY: `pos + value.len() <= out.len()` checked above; src/dst
        // are disjoint slices owned by different stack locals.
        unsafe {
            core::ptr::copy_nonoverlapping(value.as_ptr(), out.as_mut_ptr().add(pos), value.len());
        }
        pos += value.len();
        return pos;
    }
    // Literal Without Name Reference §4.5.6: pattern 0 0 1 N (N=0)
    // with 3-bit prefix on the name length. Name + value both raw.
    let mut pos = qpack_encode_int(name.len() as u64, 3, 0x20, out);
    if pos == 0 {
        return 0;
    }
    if pos + name.len() > out.len() {
        return 0;
    }
    // SAFETY: `pos + name.len() <= out.len()` checked above; disjoint slices.
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), out.as_mut_ptr().add(pos), name.len());
    }
    pos += name.len();
    let n = qpack_encode_int(value.len() as u64, 7, 0x00, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    if pos + value.len() > out.len() {
        return 0;
    }
    // SAFETY: `pos + value.len() <= out.len()` checked above; disjoint slices.
    unsafe {
        core::ptr::copy_nonoverlapping(value.as_ptr(), out.as_mut_ptr().add(pos), value.len());
    }
    pos + value.len()
}

// ----------------------------------------------------------------------
// QPACK decoder — static-table + literal forms only (no dynamic table).
// Returns (name_bytes, value_bytes, consumed) per call. Names + values
// either point into the static table (`'static` bytes) or into the
// caller's `block` buffer.
// ----------------------------------------------------------------------

pub enum QpackName<'a> {
    Static(&'static [u8]),
    Literal(&'a [u8]),
}

pub enum QpackValue<'a> {
    Static(&'static [u8]),
    Literal(&'a [u8]),
}

/// One decoded field line, as ranges into the caller's scratch buffer.
///
/// Ranges rather than slices because both the name and the value may need
/// DECODING (Huffman) rather than borrowing, and a static-table name is not in
/// the input block at all — so a uniform "everything lands in scratch" contract
/// is simpler than three lifetimes. `consumed` is the number of BLOCK bytes the
/// field occupied, which is what the caller advances by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QpackFieldRanges {
    pub name: (usize, usize),
    pub value: (usize, usize),
    pub consumed: usize,
}

/// Decode one field line, resolving Huffman-coded names and values.
///
/// The plain [`qpack_decode_field`] borrows from the block and therefore cannot
/// represent a Huffman string — it refuses one. Real HTTP/3 clients Huffman-
/// encode by default, so that refusal is not a niche gap.
///
/// RFC 9204 §4.1.2 specifies the SAME Huffman table as RFC 7541 Appendix B, so
/// this delegates to the shared `super::huffman` core rather than carrying a second
/// copy. That decoder is already pinned against the RFC 7541 Appendix C vectors
/// in `codec_conformance.rs`, which is what makes this verifiable without a
/// live HTTP/3 peer.
///
/// Returns `None` on a malformed field, a dynamic-table reference (this module
/// advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`), or a scratch buffer too
/// small to hold the decoded name and value.
pub fn qpack_decode_field_into(block: &[u8], scratch: &mut [u8]) -> Option<QpackFieldRanges> {
    let first = *block.first()?;
    let mut used = 0usize;

    // Copy `src` into scratch, Huffman-decoding it first when `huff` is set.
    // Returns the range it occupies.
    fn stash(
        scratch: &mut [u8],
        used: &mut usize,
        src: &[u8],
        huff: bool,
    ) -> Option<(usize, usize)> {
        let start = *used;
        let n = if huff {
            super::huffman::huffman_decode(src, scratch.get_mut(start..)?)?
        } else {
            let dst = scratch.get_mut(start..start.checked_add(src.len())?)?;
            dst.copy_from_slice(src);
            src.len()
        };
        *used = start.checked_add(n)?;
        Some((start, *used))
    }

    if first & 0x80 != 0 {
        // Indexed Field Line — 1 T I I I I I I. T=1 selects the static table.
        if first & 0x40 == 0 {
            return None; // dynamic table reference
        }
        let (idx, n) = qpack_decode_int(block, 6)?;
        let (name, value) = qpack_static_lookup(u32::try_from(idx).ok()?)?;
        let name_r = stash(scratch, &mut used, name, false)?;
        let value_r = stash(scratch, &mut used, value, false)?;
        return Some(QpackFieldRanges {
            name: name_r,
            value: value_r,
            consumed: n,
        });
    }

    if first & 0x40 != 0 {
        // Literal Field Line WITH Name Reference — 0 1 N T I I I I.
        if first & 0x10 == 0 {
            return None; // dynamic table name reference
        }
        let (idx, n_name) = qpack_decode_int(block, 4)?;
        let (name, _) = qpack_static_lookup(u32::try_from(idx).ok()?)?;
        let after = block.get(n_name..)?;
        let h_value = after.first()? & 0x80 != 0;
        let (vlen, n_vlen) = qpack_decode_int(after, 7)?;
        let vlen = usize::try_from(vlen).ok()?;
        let raw = after.get(n_vlen..n_vlen.checked_add(vlen)?)?;

        let name_r = stash(scratch, &mut used, name, false)?;
        let value_r = stash(scratch, &mut used, raw, h_value)?;
        return Some(QpackFieldRanges {
            name: name_r,
            value: value_r,
            consumed: n_name.checked_add(n_vlen)?.checked_add(vlen)?,
        });
    }

    if first & 0x20 != 0 {
        // Literal Field Line WITHOUT Name Reference — 0 0 1 N H (3-bit len).
        let h_name = first & 0x08 != 0;
        let (nlen, n_nlen) = qpack_decode_int(block, 3)?;
        let nlen = usize::try_from(nlen).ok()?;
        let raw_name = block.get(n_nlen..n_nlen.checked_add(nlen)?)?;

        let after = block.get(n_nlen.checked_add(nlen)?..)?;
        let h_value = after.first()? & 0x80 != 0;
        let (vlen, n_vlen) = qpack_decode_int(after, 7)?;
        let vlen = usize::try_from(vlen).ok()?;
        let raw_value = after.get(n_vlen..n_vlen.checked_add(vlen)?)?;

        let name_r = stash(scratch, &mut used, raw_name, h_name)?;
        let value_r = stash(scratch, &mut used, raw_value, h_value)?;
        return Some(QpackFieldRanges {
            name: name_r,
            value: value_r,
            consumed: n_nlen
                .checked_add(nlen)?
                .checked_add(n_vlen)?
                .checked_add(vlen)?,
        });
    }

    None
}

/// Decode the block prefix (Required Insert Count + Sign + Delta Base)
/// per RFC 9204 §4.5.1. Returns bytes consumed, or None on failure.
/// We expect both fields to be zero — anything else is rejected as
/// QPACK_DECOMPRESSION_FAILED.
pub fn qpack_decode_block_prefix(block: &[u8]) -> Option<usize> {
    let (ric, n1) = qpack_decode_int(block, 8)?;
    if ric != 0 {
        return None;
    }
    let after = &block[n1..];
    if after.is_empty() {
        return None;
    }
    let (db, n2) = qpack_decode_int(after, 7)?;
    if db != 0 {
        return None;
    }
    Some(n1 + n2)
}

/// Decode one field line. Returns (name, value, consumed). The
/// representations covered: Indexed (static), Literal With Name Ref
/// (static), Literal Without Name Ref. Anything dynamic-table-bound
/// returns None.
pub fn qpack_decode_field<'a>(block: &'a [u8]) -> Option<(QpackName<'a>, QpackValue<'a>, usize)> {
    if block.is_empty() {
        return None;
    }
    let first = block[0];
    if first & 0x80 != 0 {
        // Indexed Field Line — pattern 1 T iiiiii (6-bit index).
        let t = first & 0x40;
        if t == 0 {
            // Dynamic table — not supported.
            return None;
        }
        let (idx, n) = qpack_decode_int(block, 6)?;
        let (name, value) = qpack_static_lookup(idx as u32)?;
        return Some((QpackName::Static(name), QpackValue::Static(value), n));
    }
    if first & 0x40 != 0 {
        // Literal Field Line With Name Reference — pattern 0 1 N T iiii.
        let t = first & 0x10;
        if t == 0 {
            return None; // Dynamic-table name reference.
        }
        let (idx, n_name) = qpack_decode_int(block, 4)?;
        let (name, _) = qpack_static_lookup(idx as u32)?;
        let after = &block[n_name..];
        if after.is_empty() {
            return None;
        }
        // Value: 7-bit prefix + raw bytes (no Huffman this revision).
        let h_bit = after[0] & 0x80;
        if h_bit != 0 {
            return None; // Huffman-coded value — not implemented.
        }
        let (vlen, n_vlen) = qpack_decode_int(after, 7)?;
        let after2 = &after[n_vlen..];
        let vlen = vlen as usize;
        if after2.len() < vlen {
            return None;
        }
        let value = &after2[..vlen];
        return Some((
            QpackName::Static(name),
            QpackValue::Literal(value),
            n_name + n_vlen + vlen,
        ));
    }
    if first & 0x20 != 0 {
        // Literal Field Line Without Name Reference — pattern 0 0 1 N H.
        // Name length: 3-bit prefix. Then name bytes. Then value with 7-bit prefix.
        let h_name = first & 0x08;
        if h_name != 0 {
            return None;
        }
        let (nlen, n_nlen) = qpack_decode_int(block, 3)?;
        let after = &block[n_nlen..];
        let nlen = nlen as usize;
        if after.len() < nlen {
            return None;
        }
        let name = &after[..nlen];
        let after2 = &after[nlen..];
        if after2.is_empty() {
            return None;
        }
        let h_value = after2[0] & 0x80;
        if h_value != 0 {
            return None;
        }
        let (vlen, n_vlen) = qpack_decode_int(after2, 7)?;
        let after3 = &after2[n_vlen..];
        let vlen = vlen as usize;
        if after3.len() < vlen {
            return None;
        }
        let value = &after3[..vlen];
        return Some((
            QpackName::Literal(name),
            QpackValue::Literal(value),
            n_nlen + nlen + n_vlen + vlen,
        ));
    }
    // Other patterns (Indexed Field Line With Post-Base Index, etc.)
    // all reference the dynamic table — not supported.
    None
}
