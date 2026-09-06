// TURN wire format: the relay extension to STUN.
//
// TURN is STUN with more methods, so everything structural — the header, the
// attribute walk, MESSAGE-INTEGRITY, FINGERPRINT, the long-term credential
// attributes — comes from `stun_core.rs` and is not repeated here. What this
// file adds is the parts that only mean something when a relay is involved:
// the allocate/refresh/permission/channel methods, the attributes that carry a
// relayed address and a lifetime, and ChannelData framing.
//
// This file decides nothing. It reads and writes bytes. Whether to allocate,
// when to refresh, which peer to permit and which candidate to prefer are
// reachability policy and belong to the agent that holds the allocation, not
// to the codec that spells it.
//
// ChannelData is the one thing here that is not STUN at all. It is a four-byte
// framing carrying relayed payload, and it shares a socket with STUN messages,
// so telling the two apart from the first byte is a job this file must do
// correctly or a relayed media packet gets parsed as a malformed STUN message.

// ── methods ───────────────────────────────────────────────────────────────

/// Allocate: ask a relay for a transport address of its own.
pub const TURN_METHOD_ALLOCATE: u16 = 0x003;

/// Refresh: extend an allocation, or with a zero lifetime, end it.
pub const TURN_METHOD_REFRESH: u16 = 0x004;

/// Send: an indication carrying payload out through the relay.
pub const TURN_METHOD_SEND: u16 = 0x006;

/// Data: an indication carrying payload in from the relay.
pub const TURN_METHOD_DATA: u16 = 0x007;

/// `CreatePermission`: allow one peer address to reach the allocation.
pub const TURN_METHOD_CREATE_PERMISSION: u16 = 0x008;

/// `ChannelBind`: bind a peer to a channel number, so its traffic can use the
/// four-byte framing instead of a Send/Data indication per packet.
pub const TURN_METHOD_CHANNEL_BIND: u16 = 0x009;

// ── attributes ────────────────────────────────────────────────────────────

/// CHANNEL-NUMBER: the channel a bind request is asking for.
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;

/// LIFETIME: how long an allocation should last, in seconds.
pub const ATTR_LIFETIME: u16 = 0x000D;

/// XOR-PEER-ADDRESS: the peer an operation concerns.
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;

/// DATA: the payload a Send or Data indication carries.
pub const ATTR_DATA: u16 = 0x0013;

/// XOR-RELAYED-ADDRESS: the address the relay allocated. This is what becomes
/// a relay candidate.
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;

/// REQUESTED-ADDRESS-FAMILY: which family the allocation should be for.
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;

/// EVEN-PORT: ask for an even-numbered port.
pub const ATTR_EVEN_PORT: u16 = 0x0018;

/// REQUESTED-TRANSPORT: which transport the relay should use to the peer.
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

/// DONT-FRAGMENT: ask the relay to set DF on relayed datagrams.
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;

/// RESERVATION-TOKEN: claim a port reserved by an earlier allocation.
pub const ATTR_RESERVATION_TOKEN: u16 = 0x0022;

/// The REQUESTED-TRANSPORT value for UDP. The only transport this codec
/// spells: a relay allocation for anything else is not something the agents
/// above ask for.
pub const TURN_TRANSPORT_UDP: u8 = 17;

// ── errors a relay answers with ───────────────────────────────────────────

/// 401: the request carried no credentials, or stale ones. Expected on the
/// first Allocate: the realm and nonce to use arrive in this answer.
pub const TURN_ERR_UNAUTHORIZED: u16 = 401;

/// 403: the credentials were good and the request is still refused.
pub const TURN_ERR_FORBIDDEN: u16 = 403;

/// 437: the allocation this refers to is gone.
pub const TURN_ERR_ALLOCATION_MISMATCH: u16 = 437;

/// 438: the nonce has expired. Retry once with the new one; a client that
/// retries repeatedly on 438 is in a loop, not making progress.
pub const TURN_ERR_STALE_NONCE: u16 = 438;

/// 486: this address is in use.
pub const TURN_ERR_ALLOCATION_QUOTA: u16 = 486;

/// 508: the relay cannot satisfy what was asked for.
pub const TURN_ERR_INSUFFICIENT_CAPACITY: u16 = 508;

// ── ChannelData framing ───────────────────────────────────────────────────

/// The fixed size of a ChannelData header: channel number, then length.
pub const CHANNEL_DATA_HEADER_LEN: usize = 4;

/// The lowest channel number a peer may be bound to.
pub const CHANNEL_NUMBER_MIN: u16 = 0x4000;

/// The highest. Above this the range is reserved, and a number outside
/// `CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX` is not a channel at all.
pub const CHANNEL_NUMBER_MAX: u16 = 0x7FFF;

/// Whether a channel number is one a peer may actually be bound to.
pub fn channel_number_is_valid(channel: u16) -> bool {
    (CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel)
}

/// What a datagram arriving on a shared relayed socket is.
///
/// The first two bits separate them: a STUN message begins with `00`, and a
/// ChannelData frame begins with `01` because its channel number starts at
/// 0x4000. Getting this wrong means relayed media parsed as a malformed STUN
/// message, so it is decided once, here.
pub enum RelayedDatagram {
    /// A STUN or TURN message. Parse it with `parse_stun_header`.
    Stun,
    /// A ChannelData frame: a bound channel, and where its payload sits.
    Channel {
        channel: u16,
        offset: usize,
        len: usize,
    },
    /// Neither, or a frame whose length runs past what arrived.
    Unrecognised,
}

/// Classify a datagram that arrived on a socket carrying both.
pub fn classify_relayed(buf: &[u8]) -> RelayedDatagram {
    if buf.len() < CHANNEL_DATA_HEADER_LEN {
        return RelayedDatagram::Unrecognised;
    }
    // Bits 0-1 of the first byte. STUN's first two bits are zero; a channel
    // number's are 01.
    let leading = buf[0] >> 6;
    if leading == 0b00 {
        return RelayedDatagram::Stun;
    }
    if leading != 0b01 {
        return RelayedDatagram::Unrecognised;
    }
    let channel = u16::from_be_bytes([buf[0], buf[1]]);
    if !channel_number_is_valid(channel) {
        return RelayedDatagram::Unrecognised;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    // A length that runs past what arrived is a truncated or lying frame. It is
    // not repaired by clamping: a shortened payload is different bytes.
    if CHANNEL_DATA_HEADER_LEN + len > buf.len() {
        return RelayedDatagram::Unrecognised;
    }
    RelayedDatagram::Channel {
        channel,
        offset: CHANNEL_DATA_HEADER_LEN,
        len,
    }
}

/// Write a ChannelData frame around `payload`.
///
/// Returns the total length written. `None` if the buffer is too small or the
/// channel is not one a peer may be bound to — never a truncated frame, which
/// would deliver bytes the sender did not send.
pub fn write_channel_data(channel: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if !channel_number_is_valid(channel) {
        return None;
    }
    if payload.len() > u16::MAX as usize {
        return None;
    }
    let total = CHANNEL_DATA_HEADER_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    out[0..2].copy_from_slice(&channel.to_be_bytes());
    // The length field is the payload's, not the frame's: a reader that
    // included the header would skip four bytes of every packet.
    out[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[CHANNEL_DATA_HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

/// The length a ChannelData frame occupies when padded to a four-byte
/// boundary.
///
/// Over a stream transport, frames are padded so the next one starts aligned.
/// Over a datagram transport the padding is not required, which is why this is
/// a separate function rather than something `write_channel_data` does: the
/// caller knows which transport it is on and this file does not.
pub fn channel_data_padded_len(payload_len: usize) -> usize {
    let total = CHANNEL_DATA_HEADER_LEN + payload_len;
    (total + 3) & !3
}

// ── attribute readers and writers ─────────────────────────────────────────

/// Read a LIFETIME value, in seconds.
pub fn parse_lifetime(buf: &[u8], at: usize, len: usize) -> Option<u32> {
    if len != 4 || at + 4 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
    ]))
}

/// Write a LIFETIME attribute.
pub fn append_lifetime(seconds: u32, out: &mut [u8], at: usize) -> Option<usize> {
    append_attribute(ATTR_LIFETIME, &seconds.to_be_bytes(), out, at)
}

/// Write REQUESTED-TRANSPORT.
///
/// The three trailing bytes are reserved and must be zero: a relay that
/// compared them would refuse a request that set them to anything else.
pub fn append_requested_transport(transport: u8, out: &mut [u8], at: usize) -> Option<usize> {
    append_attribute(ATTR_REQUESTED_TRANSPORT, &[transport, 0, 0, 0], out, at)
}

/// Write CHANNEL-NUMBER.
pub fn append_channel_number(channel: u16, out: &mut [u8], at: usize) -> Option<usize> {
    if !channel_number_is_valid(channel) {
        return None;
    }
    let value = [(channel >> 8) as u8, (channel & 0xFF) as u8, 0, 0];
    append_attribute(ATTR_CHANNEL_NUMBER, &value, out, at)
}

/// Write DONT-FRAGMENT, which carries no value.
pub fn append_dont_fragment(out: &mut [u8], at: usize) -> Option<usize> {
    append_attribute(ATTR_DONT_FRAGMENT, &[], out, at)
}

/// Write an XOR-PEER-ADDRESS for an IPv4 peer.
///
/// The same XOR encoding as XOR-MAPPED-ADDRESS, under a different attribute
/// type: the relay obscures a peer address for the same reason it obscures a
/// mapped one, so that a middlebox rewriting addresses does not silently
/// rewrite this one too.
pub fn append_xor_peer_address_v4(
    addr: [u8; 4],
    port: u16,
    out: &mut [u8],
    at: usize,
) -> Option<usize> {
    let magic = STUN_MAGIC.to_be_bytes();
    let mut value = [0u8; 8];
    value[1] = STUN_FAMILY_IPV4;
    let xport = port ^ ((STUN_MAGIC >> 16) as u16);
    value[2..4].copy_from_slice(&xport.to_be_bytes());
    for i in 0..4 {
        value[4 + i] = addr[i] ^ magic[i];
    }
    append_attribute(ATTR_XOR_PEER_ADDRESS, &value, out, at)
}

/// Write the DATA attribute carrying a payload to relay.
pub fn append_data(payload: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    append_attribute(ATTR_DATA, payload, out, at)
}

/// Build a TURN Send Indication carrying one UDP datagram to a permitted peer.
/// Indications are deliberately unauthenticated per RFC 5766: permission
/// state on the relay is the authorization boundary. The fingerprint remains
/// present so demultiplexers can reject corruption before dispatch.
pub fn write_send_indication(
    txn: &[u8; STUN_TXN_LEN],
    peer_addr: [u8; 4],
    peer_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut at = write_stun_header(STUN_CLASS_INDICATION, TURN_METHOD_SEND, txn, out)?;
    at = append_xor_peer_address_v4(peer_addr, peer_port, out, at)?;
    at = append_data(payload, out, at)?;
    at = append_fingerprint(out, at)?;
    stun_set_length(out, at)?;
    Some(at)
}

/// Read an XOR-RELAYED-ADDRESS. This is the address that becomes a relay
/// candidate.
pub fn parse_xor_relayed_address(
    buf: &[u8],
    at: usize,
    len: usize,
    txn: &[u8; STUN_TXN_LEN],
) -> Option<StunAddress> {
    parse_xor_mapped_address(buf, at, len, txn)
}

/// The attribute types this codec understands, for the unknown-attribute check
/// a receiver owes a sender.
///
/// Stated as a list rather than a range: an attribute silently accepted
/// because it fell inside a range is one whose meaning was never checked.
pub const TURN_KNOWN_ATTRIBUTES: &[u16] = &[
    ATTR_MAPPED_ADDRESS,
    ATTR_USERNAME,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_ERROR_CODE,
    ATTR_UNKNOWN_ATTRIBUTES,
    ATTR_REALM,
    ATTR_NONCE,
    ATTR_XOR_MAPPED_ADDRESS,
    ATTR_CHANNEL_NUMBER,
    ATTR_LIFETIME,
    ATTR_XOR_PEER_ADDRESS,
    ATTR_DATA,
    ATTR_XOR_RELAYED_ADDRESS,
    ATTR_REQUESTED_ADDRESS_FAMILY,
    ATTR_EVEN_PORT,
    ATTR_REQUESTED_TRANSPORT,
    ATTR_DONT_FRAGMENT,
    ATTR_RESERVATION_TOKEN,
    ATTR_SOFTWARE,
    ATTR_FINGERPRINT,
];

/// The key a long-term credential produces: MD5 is required by the protocol
/// here, and this is the one place it is used.
///
/// It is not a password hash and is not treated as one. It exists because
/// TURN's long-term credential mechanism specifies it, and the security of the
/// exchange rests on the integrity attribute it keys, not on this digest being
/// hard to invert. Stated plainly so nobody reads its presence as an
/// endorsement.
pub fn long_term_key(username: &[u8], realm: &[u8], password: &[u8], out: &mut [u8; 16]) {
    let mut input = [0u8; 256];
    let total = username.len() + 1 + realm.len() + 1 + password.len();
    if total > input.len() {
        // A credential this long is a configuration error, and a truncated key
        // would fail integrity checks in a way that looks like a network fault.
        *out = [0u8; 16];
        return;
    }
    let mut at = 0;
    input[at..at + username.len()].copy_from_slice(username);
    at += username.len();
    input[at] = b':';
    at += 1;
    input[at..at + realm.len()].copy_from_slice(realm);
    at += realm.len();
    input[at] = b':';
    at += 1;
    input[at..at + password.len()].copy_from_slice(password);
    at += password.len();
    md5(&input[..at], out);
}

/// MD5, for the long-term credential key above and nothing else.
///
/// Written out here rather than pulled from the SDK because the SDK offers no
/// MD5 and should not gain one: a hash this weak in a general-purpose crypto
/// surface invites use somewhere it matters. It is visible only so its
/// published vectors can be pinned — a transcription error in the constant
/// tables below would otherwise surface as an integrity check that fails like
/// a network fault. `long_term_key` is its only caller in this codec, and
/// nothing above should acquire a second one.
pub fn md5(data: &[u8], out: &mut [u8; 16]) {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    // One padded copy, bounded: the only caller passes a short credential.
    let mut block = [0u8; 320];
    let len = data.len();
    if len + 9 > block.len() {
        *out = [0u8; 16];
        return;
    }
    block[..len].copy_from_slice(data);
    block[len] = 0x80;
    let padded = ((len + 8) / 64 + 1) * 64;
    let bits = (len as u64).wrapping_mul(8);
    block[padded - 8..padded].copy_from_slice(&bits.to_le_bytes());

    let mut offset = 0;
    while offset < padded {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let at = offset + i * 4;
            *word = u32::from_le_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }

        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        offset += 64;
    }

    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}
