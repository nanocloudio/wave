//! HPACK header compression — RFC 7541.
//!
//! This implementation supports the static table (61 entries), integer
//! and literal string primitives, and the four representation forms
//! (indexed, literal-with-incremental-indexing, literal-without-
//! indexing, literal-never-indexing), plus Huffman string decoding
//! (RFC 7541 Appendix B, `huffman_decode`) — real peers (e.g. gRPC
//! servers) Huffman-encode header/trailer names and values. The
//! encoder always emits literal-without-indexing form (§6.2.2, no
//! Huffman): no dynamic-table state to manage on the send side.
//!
//! Dynamic-table-on-decode is also not implemented; we advertise
//! `SETTINGS_HEADER_TABLE_SIZE = 0` so the peer must not attempt
//! incremental indexing. Some clients still send the indexing form
//! (the wire encoding works regardless of dynamic table size); we
//! treat those bytes as literal-without-indexing equivalents from a
//! semantic standpoint, ignoring the indexing instruction.

// ── Static table (RFC 7541 Appendix A) ────────────────────────────────────
//
// The 61-entry static table is *not* stored as a Rust constant array
// of tuples. PIC modules in this codebase don't carry runtime
// relocations, so a `const &[(&[u8], &[u8])]` would freeze each entry's
// pointer fields at compile-time link addresses that no longer hold
// after the module is loaded. Computing the slice references from byte
// literals at call time keeps every pointer PC-relative and correct
// regardless of load address.

/// Lookup a static-table entry by 1-based index. RFC 7541 Appendix A.
fn static_lookup(idx: u32) -> Option<(&'static [u8], &'static [u8])> {
    Some(match idx {
        1 => (b":authority", b""),
        2 => (b":method", b"GET"),
        3 => (b":method", b"POST"),
        4 => (b":path", b"/"),
        5 => (b":path", b"/index.html"),
        6 => (b":scheme", b"http"),
        7 => (b":scheme", b"https"),
        8 => (b":status", b"200"),
        9 => (b":status", b"204"),
        10 => (b":status", b"206"),
        11 => (b":status", b"304"),
        12 => (b":status", b"400"),
        13 => (b":status", b"404"),
        14 => (b":status", b"500"),
        15 => (b"accept-charset", b""),
        16 => (b"accept-encoding", b"gzip, deflate"),
        17 => (b"accept-language", b""),
        18 => (b"accept-ranges", b""),
        19 => (b"accept", b""),
        20 => (b"access-control-allow-origin", b""),
        21 => (b"age", b""),
        22 => (b"allow", b""),
        23 => (b"authorization", b""),
        24 => (b"cache-control", b""),
        25 => (b"content-disposition", b""),
        26 => (b"content-encoding", b""),
        27 => (b"content-language", b""),
        28 => (b"content-length", b""),
        29 => (b"content-location", b""),
        30 => (b"content-range", b""),
        31 => (b"content-type", b""),
        32 => (b"cookie", b""),
        33 => (b"date", b""),
        34 => (b"etag", b""),
        35 => (b"expect", b""),
        36 => (b"expires", b""),
        37 => (b"from", b""),
        38 => (b"host", b""),
        39 => (b"if-match", b""),
        40 => (b"if-modified-since", b""),
        41 => (b"if-none-match", b""),
        42 => (b"if-range", b""),
        43 => (b"if-unmodified-since", b""),
        44 => (b"last-modified", b""),
        45 => (b"link", b""),
        46 => (b"location", b""),
        47 => (b"max-forwards", b""),
        48 => (b"proxy-authenticate", b""),
        49 => (b"proxy-authorization", b""),
        50 => (b"range", b""),
        51 => (b"referer", b""),
        52 => (b"refresh", b""),
        53 => (b"retry-after", b""),
        54 => (b"server", b""),
        55 => (b"set-cookie", b""),
        56 => (b"strict-transport-security", b""),
        57 => (b"transfer-encoding", b""),
        58 => (b"user-agent", b""),
        59 => (b"vary", b""),
        60 => (b"via", b""),
        61 => (b"www-authenticate", b""),
        _ => return None,
    })
}

// ── Integer codec (§5.1) ──────────────────────────────────────────────────

/// Decode an HPACK integer with `prefix_bits` significant bits in the
/// first byte. Returns `(value, bytes_consumed)` or `Err(())` if
/// truncated or overflow.
pub(crate) unsafe fn decode_integer(
    buf: *const u8,
    len: usize,
    prefix_bits: u8,
) -> Result<(u32, usize), ()> {
    if len == 0 {
        return Err(());
    }
    let max_prefix: u32 = (1u32 << prefix_bits) - 1;
    let first = (*buf as u32) & max_prefix;
    if first < max_prefix {
        return Ok((first, 1));
    }
    // Multi-byte form: continue reading while the high bit is set,
    // accumulating 7 bits per byte (§5.1).
    let mut value: u32 = max_prefix;
    let mut shift: u32 = 0;
    let mut i: usize = 1;
    loop {
        if i >= len {
            return Err(());
        }
        let b = *buf.add(i);
        i += 1;
        let chunk = (b as u32) & 0x7F;
        if shift >= 32 {
            return Err(()); // overflow guard
        }
        let add = chunk.checked_shl(shift).ok_or(())?;
        value = value.checked_add(add).ok_or(())?;
        shift += 7;
        if (b & 0x80) == 0 {
            return Ok((value, i));
        }
        if i > 5 {
            // 5 bytes of continuation = 35 bits, more than enough for u32.
            return Err(());
        }
    }
}

/// Encode an HPACK integer with `prefix_bits` significant bits. The
/// `prefix` byte's high `8-prefix_bits` bits carry the representation
/// type and must already be set by the caller; this function ORs the
/// integer prefix in and writes any continuation bytes.
pub(crate) unsafe fn encode_integer(
    dst: *mut u8,
    dst_cap: usize,
    prefix: u8,
    prefix_bits: u8,
    value: u32,
) -> usize {
    if dst_cap == 0 {
        return 0;
    }
    let max_prefix: u32 = (1u32 << prefix_bits) - 1;
    if value < max_prefix {
        *dst = prefix | (value as u8);
        return 1;
    }
    *dst = prefix | (max_prefix as u8);
    let mut o = 1usize;
    let mut rem = value - max_prefix;
    while rem >= 128 {
        if o >= dst_cap {
            return 0;
        }
        *dst.add(o) = ((rem & 0x7F) as u8) | 0x80;
        o += 1;
        rem >>= 7;
    }
    if o >= dst_cap {
        return 0;
    }
    *dst.add(o) = rem as u8;
    o + 1
}

// ── String codec (§5.2) ───────────────────────────────────────────────────

/// Decode an HPACK string literal. Returns `(value_offset,
/// value_length, bytes_consumed_including_length_prefix, huffman)` or
/// `Err(())` if truncated or malformed.
///
/// The payload is not Huffman-decoded here — when the returned flag is
/// set the caller runs `huffman_decode` over the raw bytes.
pub(crate) unsafe fn decode_string(
    buf: *const u8,
    len: usize,
) -> Result<(usize, usize, usize, bool), ()> {
    if len == 0 {
        return Err(());
    }
    let h_flag = (*buf & 0x80) != 0;
    let (slen, hdr) = decode_integer(buf, len, 7)?;
    let total = hdr + slen as usize;
    if total > len {
        return Err(());
    }
    Ok((hdr, slen as usize, total, h_flag))
}

/// Encode an HPACK string literal (no Huffman). Writes the 7-bit
/// length prefix (with H=0) followed by the raw bytes. Returns total
/// bytes written, or 0 if `dst_cap` is insufficient.
pub(crate) unsafe fn encode_string(
    dst: *mut u8,
    dst_cap: usize,
    s: *const u8,
    s_len: usize,
) -> usize {
    let n = encode_integer(dst, dst_cap, 0x00, 7, s_len as u32);
    if n == 0 {
        return 0;
    }
    if n + s_len > dst_cap {
        return 0;
    }
    if s_len > 0 {
        core::ptr::copy_nonoverlapping(s, dst.add(n), s_len);
    }
    n + s_len
}

// ── Header decoding ──────────────────────────────────────────────────────

/// Decode an HPACK header block fragment. The `sink` closure is called
/// once per decoded header with `(name, value)` byte slices. Generic
/// over the closure type so we never construct a `&mut dyn FnMut` —
/// PIC modules can't reliably relocate the vtable that a trait-object
/// closure call would dispatch through.
///
/// Returns `Err(())` on any malformed input; callers respond with a
/// connection-level COMPRESSION_ERROR GOAWAY. We don't maintain a
/// dynamic table — `SETTINGS_HEADER_TABLE_SIZE = 0` is advertised at
/// connection setup. Dynamic-table-size-update directives (§6.3) are
/// still parsed and discarded so non-conforming peers see a clean
/// accept.
pub(crate) unsafe fn decode_block<F>(buf: *const u8, len: usize, mut sink: F) -> Result<(), ()>
where
    F: FnMut(&[u8], &[u8]),
{
    let mut i = 0usize;
    while i < len {
        let b = *buf.add(i);
        if (b & 0x80) != 0 {
            // §6.1 Indexed Header Field
            let (idx, n) = decode_integer(buf.add(i), len - i, 7)?;
            i += n;
            let (name, value) = static_lookup(idx).ok_or(())?;
            sink(name, value);
        } else if (b & 0xC0) == 0x40 {
            // §6.2.1 Literal Header Field with Incremental Indexing
            i += decode_literal(buf, len, i, 6, &mut sink)?;
        } else if (b & 0xE0) == 0x20 {
            // §6.3 Dynamic Table Size Update — parse and discard
            let (_sz, n) = decode_integer(buf.add(i), len - i, 5)?;
            i += n;
        } else if (b & 0xF0) == 0x10 {
            // §6.2.3 Literal Header Field Never Indexed
            i += decode_literal(buf, len, i, 4, &mut sink)?;
        } else {
            // §6.2.2 Literal Header Field without Indexing
            i += decode_literal(buf, len, i, 4, &mut sink)?;
        }
    }
    Ok(())
}

// RFC 7541 Appendix B Huffman table + decoder, shared with QPACK (h3). See
// modules/common/huffman_core.rs for why it is one file rather than two
// transcriptions.
// The table now lives in `super::huffman` so QPACK (h3) can reach it without
// pulling in h2. Re-exported here because `hpack::huffman_decode` is the name
// the conformance vectors and bounds sweep already pin.
pub(crate) use super::huffman::HUFF_SCRATCH;
pub use super::huffman::{huffman_decode, huffman_table_valid};

/// Decode a literal-form header (§6.2.x). `prefix_bits` is the integer
/// prefix used to encode the indexed name (6 for incremental, 4 for
/// never/without). Returns the total number of bytes consumed.
unsafe fn decode_literal<F>(
    buf: *const u8,
    len: usize,
    start: usize,
    prefix_bits: u8,
    sink: &mut F,
) -> Result<usize, ()>
where
    F: FnMut(&[u8], &[u8]),
{
    let (name_idx, n) = decode_integer(buf.add(start), len - start, prefix_bits)?;
    let mut consumed = n;

    let mut name_huffman = false;
    let (name_buf, name_off, name_len): (*const u8, usize, usize) = if name_idx == 0 {
        let (off, sl, total, h) = decode_string(buf.add(start + consumed), len - start - consumed)?;
        let raw = buf.add(start + consumed);
        consumed += total;
        name_huffman = h;
        (raw, off, sl)
    } else {
        let (nm, _v) = static_lookup(name_idx).ok_or(())?;
        (nm.as_ptr(), 0, nm.len())
    };

    let (val_off, val_len, val_total, val_huffman) =
        decode_string(buf.add(start + consumed), len - start - consumed)?;
    let val_raw = buf.add(start + consumed);
    consumed += val_total;

    // Huffman-decode name and/or value into stack scratch when flagged.
    // A decode failure or an entry longer than the scratch is dropped
    // (callsites ignore headers they don't consume), never surfaced as
    // raw Huffman bytes.
    let mut name_scratch = [0u8; HUFF_SCRATCH];
    let mut val_scratch = [0u8; HUFF_SCRATCH];

    let name_slice: &[u8] = if name_huffman {
        let raw = core::slice::from_raw_parts(name_buf.add(name_off), name_len);
        match huffman_decode(raw, &mut name_scratch) {
            Some(n) => &name_scratch[..n],
            None => return Ok(consumed),
        }
    } else {
        core::slice::from_raw_parts(name_buf.add(name_off), name_len)
    };

    let value_slice: &[u8] = if val_huffman {
        let raw = core::slice::from_raw_parts(val_raw.add(val_off), val_len);
        match huffman_decode(raw, &mut val_scratch) {
            Some(n) => &val_scratch[..n],
            None => return Ok(consumed),
        }
    } else {
        core::slice::from_raw_parts(val_raw.add(val_off), val_len)
    };
    sink(name_slice, value_slice);
    Ok(consumed)
}

// ── Header encoding ──────────────────────────────────────────────────────

/// Encode one header as literal-without-indexing (§6.2.2). If `name`
/// matches a static-table entry, its index is used; otherwise the name
/// is emitted as a literal string. The value is always literal.
///
/// Returns the number of bytes written, or 0 on insufficient capacity.
pub(crate) unsafe fn encode_header(
    dst: *mut u8,
    dst_cap: usize,
    name: &[u8],
    value: &[u8],
) -> usize {
    let idx = static_name_index(name);
    let o = if idx > 0 {
        let n = encode_integer(dst, dst_cap, 0x00, 4, idx);
        if n == 0 {
            return 0;
        }
        n
    } else {
        if dst_cap < 1 {
            return 0;
        }
        *dst = 0x00;
        let n = encode_string(dst.add(1), dst_cap - 1, name.as_ptr(), name.len());
        if n == 0 {
            return 0;
        }
        1 + n
    };
    let n = encode_string(dst.add(o), dst_cap - o, value.as_ptr(), value.len());
    if n == 0 {
        return 0;
    }
    o + n
}

/// Look up a name's static-table index. Driven off `static_lookup`
/// rather than a parallel const table so all byte literals are
/// PC-relative.
fn static_name_index(name: &[u8]) -> u32 {
    let mut i: u32 = 1;
    while i <= 61 {
        if let Some((nm, _)) = static_lookup(i) {
            if names_eq(nm, name) {
                return i;
            }
        }
        i += 1;
    }
    0
}

/// Byte-by-byte slice equality without `memcmp`. Used by
/// `static_name_index` so we don't pull in an external symbol the PIC
/// loader can't satisfy.
fn names_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    let ap = a.as_ptr();
    let bp = b.as_ptr();
    let mut i = 0usize;
    while i < n {
        // SAFETY: `n = a.len().min(b.len())` (computed above); `i < n`
        // is the loop invariant so both `add(i)` reads stay in-bounds.
        unsafe {
            if *ap.add(i) != *bp.add(i) {
                return false;
            }
        }
        i += 1;
    }
    true
}
