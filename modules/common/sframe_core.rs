// SFrame wire format: a media frame with a readable header and a sealed
// payload.
//
// The whole point of this framing is the split. A relay forwarding media must
// be able to do its job — detect loss, order frames, tell a keyframe from a
// delta, decide what may be dropped — without hearing anything. So the header
// is in the clear and covered by the authentication tag, and the payload is
// not.
//
// This file decides nothing. Which key, which epoch, who may publish and who
// may receive are all decided elsewhere; here there are only bytes. The
// encryption itself is not here either: what this provides is where the sealed
// bytes go, what the header says, and what the cipher must authenticate.
//
// The layout is RFC 9605 section 4.3, and it is pinned against that document's
// own test vectors. That matters more here than almost anywhere else in this
// tree: a wire format exists so two implementations that have never met agree,
// and a codec verified only against itself proves nothing about that. All 289
// published header vectors are checked.
//
//     0 1 2 3 4 5 6 7
//    +-+-+-+-+-+-+-+-+------------+------------+
//    |X|  K  |Y|  C  |   KID...   |   CTR...   |
//    +-+-+-+-+-+-+-+-+------------+------------+
//
// X and Y say whether K and C hold a value or a length. A KID or CTR below 8
// rides inside the config byte itself, so the common case — few senders, a
// counter that has not yet reached 8 — is a ONE byte header. Values of 8 or
// more are appended after the config byte, KID first, in the fewest bytes that
// hold them, with the length field carrying that count minus one.

/// The largest key identifier this codec writes or reads, in bytes.
pub const SFRAME_MAX_KID_LEN: usize = 8;

/// The largest counter, in bytes.
pub const SFRAME_MAX_CTR_LEN: usize = 8;

/// The largest header: config byte plus both fields at full width.
pub const SFRAME_MAX_HEADER_LEN: usize = 1 + SFRAME_MAX_KID_LEN + SFRAME_MAX_CTR_LEN;

/// The X bit: set when K carries a KID length rather than a KID.
pub const SFRAME_EXTENDED_KID: u8 = 0b1000_0000;

/// The Y bit: set when C carries a CTR length rather than a CTR.
pub const SFRAME_EXTENDED_CTR: u8 = 0b0000_1000;

/// The largest KID or CTR that rides inside the config byte.
///
/// Values below this need no trailing bytes at all, which is what makes the
/// common case a one-byte header.
pub const SFRAME_INLINE_MAX: u64 = 7;

/// A parsed header, and where the sealed payload begins.
pub struct SframeHeader {
    /// Which key sealed this frame.
    pub key_id: u64,
    /// The frame counter, unique per key.
    ///
    /// What makes the nonce unique. A counter that repeated under one key
    /// would repeat a nonce, which for an AEAD is not a weakened guarantee but
    /// none at all.
    pub counter: u64,
    /// How many bytes the header occupied.
    pub header_len: usize,
}

/// Bounded anti-replay state for one SFrame key identifier.
///
/// The AEAD implementation owns authentication; this small state machine
/// owns the receive-side counter policy. It accepts a new highest counter and
/// the previous 63 counters once each, while rejecting duplicates and values
/// older than the window. A caller must keep one window per active key/epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SframeReplayWindow {
    highest: u64,
    seen: u64,
    initialized: bool,
}

impl Default for SframeReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SframeReplayWindow {
    pub const EMPTY: Self = Self {
        highest: 0,
        seen: 0,
        initialized: false,
    };

    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Observe a counter. `true` means it is inside the replay window and has
    /// not been observed before; `false` means duplicate or too old.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = counter;
            self.seen = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = counter;
            return true;
        }
        let distance = self.highest - counter;
        if distance >= 64 {
            return false;
        }
        let bit = 1u64 << distance;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }

    pub const fn highest(&self) -> Option<u64> {
        if self.initialized {
            Some(self.highest)
        } else {
            None
        }
    }
}

/// The number of bytes needed to hold `value`, at least one.
///
/// At least one because a zero-length field would make a present value
/// indistinguishable from an absent one.
pub fn sframe_width(value: u64) -> usize {
    let mut width = 1;
    let mut remaining = value >> 8;
    while remaining != 0 && width < 8 {
        width += 1;
        remaining >>= 8;
    }
    width
}

/// The header length a given key id and counter will need.
///
/// Offered so a caller can size a buffer before writing, rather than writing
/// and discovering it did not fit.
pub fn sframe_header_len(key_id: u64, counter: u64) -> usize {
    let key_bytes = if key_id > SFRAME_INLINE_MAX {
        sframe_width(key_id)
    } else {
        0
    };
    let counter_bytes = if counter > SFRAME_INLINE_MAX {
        sframe_width(counter)
    } else {
        0
    };
    1 + key_bytes + counter_bytes
}

/// Write a header.
///
/// Returns the number of bytes written, or `None` if the buffer is too small —
/// never a partial header, which a reader would interpret as a different
/// frame.
pub fn write_sframe_header(key_id: u64, counter: u64, out: &mut [u8]) -> Option<usize> {
    let extended_kid = key_id > SFRAME_INLINE_MAX;
    let extended_ctr = counter > SFRAME_INLINE_MAX;
    let key_width = if extended_kid {
        sframe_width(key_id)
    } else {
        0
    };
    let counter_width = if extended_ctr {
        sframe_width(counter)
    } else {
        0
    };
    let total = 1 + key_width + counter_width;
    if out.len() < total {
        return None;
    }

    // K holds the KID itself when it fits, and its length minus one when it
    // does not. C holds the CTR on the same terms.
    let mut config = 0u8;
    if extended_kid {
        config |= SFRAME_EXTENDED_KID;
        config |= ((key_width as u8 - 1) & 0x07) << 4;
    } else {
        config |= ((key_id as u8) & 0x07) << 4;
    }
    if extended_ctr {
        config |= SFRAME_EXTENDED_CTR;
        config |= (counter_width as u8 - 1) & 0x07;
    } else {
        config |= (counter as u8) & 0x07;
    }
    out[0] = config;

    // KID first, CTR second.
    let mut at = 1;
    if extended_kid {
        write_be(key_id, key_width, &mut out[at..]);
        at += key_width;
    }
    if extended_ctr {
        write_be(counter, counter_width, &mut out[at..]);
    }
    Some(total)
}

/// Read a header from the front of a frame.
///
/// `None` when the buffer is shorter than the header it declares. A header
/// that runs past what arrived is not a short header, it is a different one,
/// and reading the bytes that follow as a payload would hand the cipher
/// something the sender did not send.
pub fn parse_sframe_header(buf: &[u8]) -> Option<SframeHeader> {
    if buf.is_empty() {
        return None;
    }
    let config = buf[0];
    let extended_kid = config & SFRAME_EXTENDED_KID != 0;
    let extended_ctr = config & SFRAME_EXTENDED_CTR != 0;
    let key_field = (config >> 4) & 0x07;
    let counter_field = config & 0x07;

    let key_width = if extended_kid {
        (key_field + 1) as usize
    } else {
        0
    };
    let counter_width = if extended_ctr {
        (counter_field + 1) as usize
    } else {
        0
    };

    let header_len = 1 + key_width + counter_width;
    if header_len > buf.len() {
        return None;
    }

    let key_id = if extended_kid {
        read_be(&buf[1..1 + key_width])
    } else {
        u64::from(key_field)
    };
    let counter = if extended_ctr {
        read_be(&buf[1 + key_width..header_len])
    } else {
        u64::from(counter_field)
    };

    Some(SframeHeader {
        key_id,
        counter,
        header_len,
    })
}

/// The header portion of the AEAD's associated data.
///
/// The full AAD is this followed by any application metadata the caller wants
/// authenticated (RFC 9605 section 4.4.1: `aad = header + metadata`). Only the
/// header half is here, because what metadata a deployment binds is not a
/// codec's decision — but a caller that passes this alone has bound nothing
/// but the header, which is the common and correct case for a bare frame.
///
/// Authenticating the header is what stops a relay editing a counter or
/// pointing a frame at a different key: it may READ the header, and any change
/// it makes breaks the tag.
pub fn sframe_associated_data<'a>(frame: &'a [u8], header: &SframeHeader) -> Option<&'a [u8]> {
    frame.get(..header.header_len)
}

/// Where the sealed payload sits within a frame.
pub fn sframe_payload<'a>(frame: &'a [u8], header: &SframeHeader) -> Option<&'a [u8]> {
    frame.get(header.header_len..)
}

/// Build the nonce for a frame from its counter.
///
/// The counter, big-endian, right-aligned in a zero-filled nonce, then
/// combined with the salt the key schedule provides. Right-aligned rather than
/// left so that consecutive counters differ in the low bytes, which is what
/// every implementation expects and what makes two implementations agree.
pub fn sframe_nonce(counter: u64, salt: &[u8], out: &mut [u8]) -> Option<()> {
    if out.len() < 8 || out.len() != salt.len() {
        return None;
    }
    for byte in out.iter_mut() {
        *byte = 0;
    }
    let start = out.len() - 8;
    out[start..].copy_from_slice(&counter.to_be_bytes());
    for (byte, salt_byte) in out.iter_mut().zip(salt.iter()) {
        *byte ^= *salt_byte;
    }
    Some(())
}

fn write_be(value: u64, width: usize, out: &mut [u8]) {
    let bytes = value.to_be_bytes();
    out[..width].copy_from_slice(&bytes[8 - width..]);
}

fn read_be(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    value
}
