// Shared RFC 6455 frame-header decoder — the single implementation of §5.2's
// header layout and the validation rules in §5.2/§5.5.
//
// `include!`d by BOTH sides:
//   * `modules/foundation/websocket/mod.rs` — the client, alongside `ws_core.rs`
//   * `modules/foundation/http/wire/ws.rs`     — the codec http drives, on any
//     generation: an h1 upgrade, an RFC 8441 h2 CONNECT, an RFC 9220 h3 CONNECT
//
// WHY ONLY THE HEADER AND THE MASK ARE SHARED. Both sides require a whole frame
// before acting on it — the server bounds against its slot receive buffer and
// closes 1009 (Message Too Big) when a frame will not fit, the client returns
// `Incomplete` until its accumulator holds one. What differs is where the bytes
// live, and that is what keeps the two completeness checks apart:
//
//   * the SERVER unmasks in place through a raw pointer into the connection's
//     receive buffer, and reports through `Result<Option<Frame>>`.
//   * the CLIENT works on a slice of its accumulator, and reports through a
//     three-state enum.
//
// Shared here is what is genuinely one thing: how a header decodes, which
// frames are illegal, and the §5.3 mask transform. Those rules existed twice
// before, and only the server had them — the client accepted RSV bits, unknown
// opcodes, and fragmented 200-byte control frames that RFC 6455 §5.5 forbids.

/// RFC 6455 §5.2 opcodes.
pub const WS_OP_CONTINUATION: u8 = 0x0;
pub const WS_OP_TEXT: u8 = 0x1;
pub const WS_OP_BINARY: u8 = 0x2;
pub const WS_OP_CLOSE: u8 = 0x8;
pub const WS_OP_PING: u8 = 0x9;
pub const WS_OP_PONG: u8 = 0xA;

/// §5.5: opcodes 0x8..0xF are control frames.
#[inline]
#[must_use]
pub fn ws_is_control_opcode(op: u8) -> bool {
    op >= 0x8
}

/// Apply RFC 6455 §5.3 masking to `buf` in place.
///
/// XOR is its own inverse, so this both masks a client frame and unmasks a
/// received one — there is one transform, and it had three byte-at-a-time
/// copies before this (the server's unmask, the server's masked writer, and the
/// client's frame builder), which is three chances for the key index to drift.
///
/// `buf` must start at the payload's first byte: the key phase is `i % 4` from
/// there. Both sides of this codebase require a whole frame before unmasking, so
/// no caller needs to resume mid-payload; one that did would have to carry the
/// key phase itself rather than call this twice.
///
/// Four bytes at a time, because this runs over every byte of every WebSocket
/// payload and the per-byte form spent an index mask and a bounds-checked table
/// read on each one.
pub fn ws_mask_apply(buf: &mut [u8], mask_key: [u8; 4]) {
    // Native byte order on both sides of the XOR cancels out, leaving
    // `buf[i] ^ mask_key[i % 4]` on every target.
    let word = u32::from_ne_bytes(mask_key);
    let mut chunks = buf.chunks_exact_mut(4);
    for c in &mut chunks {
        let v = u32::from_ne_bytes([c[0], c[1], c[2], c[3]]) ^ word;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= mask_key[i];
    }
}

/// §5.2: every other opcode is reserved and must be rejected.
#[inline]
#[must_use]
pub fn ws_is_valid_opcode(op: u8) -> bool {
    matches!(
        op,
        WS_OP_CONTINUATION | WS_OP_TEXT | WS_OP_BINARY | WS_OP_CLOSE | WS_OP_PING | WS_OP_PONG
    )
}

/// A decoded RFC 6455 frame header.
///
/// `header_len` is the offset at which the payload begins — after the
/// 2-byte prefix, any extended length, and the 4-byte mask key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsHeader {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    pub mask_key: [u8; 4],
    pub header_len: usize,
    pub payload_len: u64,
}

/// Outcome of decoding a frame header.
///
/// The three states are kept distinct on purpose. Collapsing `Invalid` into
/// `Incomplete` — which is what an `Option` forces — makes a receiver buffer
/// forever on a frame that can never become valid, so a single malformed byte
/// becomes a stalled connection rather than a closed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsHeaderParse {
    /// A complete, legal header.
    Header(WsHeader),
    /// Not enough bytes yet; buffer more and retry.
    Incomplete,
    /// A protocol violation. The connection must be failed, never retried.
    Invalid,
}

/// Decode and validate one frame header from the front of `buf`.
///
/// Enforces, in order:
/// * §5.2 — RSV1..3 must be zero without a negotiated extension.
/// * §5.2 — the opcode must be one of the six defined values.
/// * §5.5 — a control frame must be FIN and carry at most 125 bytes.
/// * §5.2 — a 64-bit length must not have its high bit set, and must not
///   overflow the offset arithmetic that follows.
///
/// Does **not** look at the payload, so it is safe to call on a buffer holding
/// only a header.
#[must_use]
pub fn ws_decode_header(buf: &[u8]) -> WsHeaderParse {
    if buf.len() < 2 {
        return WsHeaderParse::Incomplete;
    }
    let b0 = buf[0];
    let b1 = buf[1];

    let fin = (b0 & 0x80) != 0;
    let rsv = b0 & 0x70;
    let opcode = b0 & 0x0F;
    let masked = (b1 & 0x80) != 0;
    let len7 = b1 & 0x7F;

    if rsv != 0 {
        return WsHeaderParse::Invalid;
    }
    if !ws_is_valid_opcode(opcode) {
        return WsHeaderParse::Invalid;
    }
    if ws_is_control_opcode(opcode) && (!fin || len7 > 125) {
        return WsHeaderParse::Invalid;
    }

    let (mut header_len, payload_len): (usize, u64) = match len7 {
        126 => {
            if buf.len() < 4 {
                return WsHeaderParse::Incomplete;
            }
            (4, u64::from(u16::from_be_bytes([buf[2], buf[3]])))
        }
        127 => {
            if buf.len() < 10 {
                return WsHeaderParse::Incomplete;
            }
            let v = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            // §5.2: "the most significant bit MUST be 0".
            if v & (1 << 63) != 0 {
                return WsHeaderParse::Invalid;
            }
            (10, v)
        }
        n => (2, u64::from(n)),
    };

    let mut mask_key = [0u8; 4];
    if masked {
        let need = header_len + 4;
        if buf.len() < need {
            return WsHeaderParse::Incomplete;
        }
        mask_key.copy_from_slice(&buf[header_len..need]);
        header_len = need;
    }

    // The caller will add `header_len` to `payload_len` to find the frame end.
    // Reject here rather than let that overflow: unchecked it wraps to a total
    // BELOW the header length, and every downstream range becomes inverted.
    if u64::try_from(header_len)
        .ok()
        .and_then(|h| h.checked_add(payload_len))
        .is_none()
    {
        return WsHeaderParse::Invalid;
    }

    WsHeaderParse::Header(WsHeader {
        fin,
        opcode,
        masked,
        mask_key,
        header_len,
        payload_len,
    })
}
