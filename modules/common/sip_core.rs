// Bounded, no_std, no-alloc SIP (RFC 3261 subset) message core — the request
// and response line/header formatters and the response/SDP parsers used by a
// two-party PCMU voice dialog. `include!`d by the host crate (tests) and the
// SIP `.fmod`, so the device build and the host conformance harness compile
// identical bytes.
//
// SIP is the "session signalling" class: text request/response messages that
// establish, modify, and tear down a media dialog. This core owns only the
// wire vocabulary — how an INVITE/ACK/BYE and a 200 OK are spelled, and how the
// facts a UAC needs (status code, remote SDP endpoint, Call-ID, dialog tags)
// are read back out. Dialog policy — who may call, when to ring, how a call
// maps to a conversation — is the caller's, never this file's.
//
// The single implementation of the RFC 3261 message formatters and parsers.
// (`Complete Wave voice protocol ownership`). The relocation proved a byte-parity
// move; a follow-up semantic commit then **corrected one origin fault**:
// [`sdp_content_length`] now equals the body [`write_sdp`] actually emits. The
// origin's fixed-chunk constants (`20+17+17+35`) overcounted the real chunks
// (`20+16+17+34`) by 2, so it advertised a `Content-Length` two larger than the
// SDP that followed. This core diverges from the origin there by design; every
// other formatted byte is identical. Golden transcripts live in
// `tests/harness/tests/sip_vectors.rs`.
//
// Dialog tags and the Via branch are formatted as exactly four lowercase hex
// digits ([`put_hex16`]) — the origin's fixed width, correct for the `u16`
// counters that feed them.

/// Policy-free dialog facts needed to format a request or response. Every field
/// is a protocol value; none carries call policy or conversation identity.
/// `*_ip` are host-order `u32` (wire form is `to_be_bytes`, dotted-decimal).
pub struct SipDialog<'a> {
    /// Local signalling address.
    pub local_ip: u32,
    /// Remote signalling address.
    pub peer_ip: u32,
    /// Local SIP UDP port.
    pub local_port: u16,
    /// Remote SIP UDP port.
    pub peer_port: u16,
    /// Local RTP port advertised in the SDP `m=audio` line.
    pub rtp_port: u16,
    /// Command sequence number for the `CSeq` header.
    pub cseq: u32,
    /// Local dialog tag (`From` on a UAC request, `To` on our answer).
    pub from_tag: u16,
    /// Remote dialog tag; `0` means absent and the tag parameter is omitted.
    pub to_tag: u16,
    /// Via branch identifier (transaction id), formatted after `z9hG4bK`.
    pub branch: u16,
    /// Call-ID token (without the `@host` suffix the requests append).
    pub call_id: &'a [u8],
}

/// A parsed remote media endpoint from an SDP answer: the `m=audio` port and,
/// when present, the `c=IN IP4` address. A missing address is `None`, which the
/// caller resolves to the signalling peer per the origin behaviour.
pub struct SdpEndpoint {
    /// Remote RTP address, host-order, if the SDP carried a `c=` line.
    pub ip: Option<u32>,
    /// Remote RTP port from the `m=audio` line.
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Bounded writer — bounds-checked, returns None rather than truncating.
// ---------------------------------------------------------------------------

struct SipWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl SipWriter<'_> {
    fn put(&mut self, b: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(b.len())?;
        if end > self.out.len() {
            return None;
        }
        self.out[self.pos..end].copy_from_slice(b);
        self.pos = end;
        Some(())
    }

    fn put_byte(&mut self, b: u8) -> Option<()> {
        self.put(&[b])
    }

    /// Dotted-decimal IPv4, no leading zeros — e.g. `192.168.1.10`.
    fn put_ip(&mut self, ip: u32) -> Option<()> {
        let o = ip.to_be_bytes();
        self.put_u8_decimal(o[0])?;
        self.put_byte(b'.')?;
        self.put_u8_decimal(o[1])?;
        self.put_byte(b'.')?;
        self.put_u8_decimal(o[2])?;
        self.put_byte(b'.')?;
        self.put_u8_decimal(o[3])
    }

    fn put_u8_decimal(&mut self, v: u8) -> Option<()> {
        if v >= 100 {
            self.put_byte(b'0' + v / 100)?;
            self.put_byte(b'0' + (v / 10) % 10)?;
            self.put_byte(b'0' + v % 10)
        } else if v >= 10 {
            self.put_byte(b'0' + v / 10)?;
            self.put_byte(b'0' + v % 10)
        } else {
            self.put_byte(b'0' + v)
        }
    }

    fn put_u32_decimal(&mut self, mut v: u32) -> Option<()> {
        let mut buf = [0u8; 10];
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&buf[i..])
    }

    fn put_u16_decimal(&mut self, v: u16) -> Option<()> {
        self.put_u32_decimal(v as u32)
    }

    /// Exactly four lowercase hex digits (see the fault note in the module doc).
    fn put_hex16(&mut self, v: u16) -> Option<()> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.put(&[
            HEX[((v >> 12) & 0xF) as usize],
            HEX[((v >> 8) & 0xF) as usize],
            HEX[((v >> 4) & 0xF) as usize],
            HEX[(v & 0xF) as usize],
        ])
    }
}

// ---------------------------------------------------------------------------
// SDP
// ---------------------------------------------------------------------------

/// Write the offer/answer SDP body (single PCMU audio stream) and return the
/// number of bytes emitted. This is the *actual* body length.
pub fn write_sdp(ip: u32, port: u16, out: &mut [u8]) -> Option<usize> {
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"v=0\r\no=- 0 0 IN IP4 ")?;
    w.put_ip(ip)?;
    w.put(b"\r\ns=-\r\nc=IN IP4 ")?;
    w.put_ip(ip)?;
    w.put(b"\r\nt=0 0\r\nm=audio ")?;
    w.put_u16_decimal(port)?;
    w.put(b" RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")?;
    Some(w.pos)
}

/// The `Content-Length` for the [`write_sdp`] body — the sum of its fixed text
/// chunks plus the two dotted-decimal IPs and the port. Equals the bytes
/// `write_sdp` emits (the origin overcounted this by 2; corrected here).
#[must_use]
pub fn sdp_content_length(ip: u32, port: u16) -> usize {
    // Fixed chunks around the two IPs and the port: 20 + 16 + 17 + 34 = 87.
    let fixed = 20 + 16 + 17 + 34;
    fixed + ip_decimal_len(ip) * 2 + u16_decimal_len(port)
}

fn ip_decimal_len(ip: u32) -> usize {
    let b = ip.to_be_bytes();
    u8_decimal_len(b[0])
        + 1
        + u8_decimal_len(b[1])
        + 1
        + u8_decimal_len(b[2])
        + 1
        + u8_decimal_len(b[3])
}

fn u8_decimal_len(v: u8) -> usize {
    if v >= 100 {
        3
    } else if v >= 10 {
        2
    } else {
        1
    }
}

fn u16_decimal_len(v: u16) -> usize {
    if v >= 10000 {
        5
    } else if v >= 1000 {
        4
    } else if v >= 100 {
        3
    } else if v >= 10 {
        2
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// Request / response builders — each returns the total message length.
// ---------------------------------------------------------------------------

fn put_via_branch(w: &mut SipWriter<'_>, ip: u32, port: u16, branch: u16) -> Option<()> {
    w.put(b"Via: SIP/2.0/UDP ")?;
    w.put_ip(ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(port)?;
    w.put(b";branch=z9hG4bK")?;
    w.put_hex16(branch)?;
    w.put(b"\r\n")
}

fn put_call_id_at_host(w: &mut SipWriter<'_>, call_id: &[u8], host_ip: u32) -> Option<()> {
    w.put(b"Call-ID: ")?;
    w.put(call_id)?;
    w.put_byte(b'@')?;
    w.put_ip(host_ip)?;
    w.put(b"\r\n")
}

fn put_to_with_optional_tag(w: &mut SipWriter<'_>, ip: u32, to_tag: u16) -> Option<()> {
    w.put(b"To: <sip:")?;
    w.put_ip(ip)?;
    if to_tag != 0 {
        w.put(b">;tag=")?;
        w.put_hex16(to_tag)?;
        w.put(b"\r\n")
    } else {
        w.put(b">\r\n")
    }
}

fn put_sdp_body(w: &mut SipWriter<'_>, ip: u32, port: u16) -> Option<()> {
    w.put(b"Content-Type: application/sdp\r\n")?;
    w.put(b"Content-Length: ")?;
    w.put_u16_decimal(sdp_content_length(ip, port) as u16)?;
    w.put(b"\r\n\r\n")?;
    // Reborrow the tail of the buffer for the SDP body.
    let n = write_sdp(ip, port, &mut w.out[w.pos..])?;
    w.pos += n;
    Some(())
}

/// UAC `INVITE` with a PCMU offer.
pub fn build_invite(d: &SipDialog<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"INVITE sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.peer_port)?;
    w.put(b" SIP/2.0\r\n")?;
    put_via_branch(&mut w, d.local_ip, d.local_port, d.branch)?;
    w.put(b"Max-Forwards: 70\r\n")?;
    w.put(b"From: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.from_tag)?;
    w.put(b"\r\n")?;
    w.put(b"To: <sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put(b">\r\n")?;
    put_call_id_at_host(&mut w, d.call_id, d.local_ip)?;
    w.put(b"CSeq: ")?;
    w.put_u32_decimal(d.cseq)?;
    w.put(b" INVITE\r\n")?;
    w.put(b"Contact: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.local_port)?;
    w.put(b">\r\n")?;
    put_sdp_body(&mut w, d.local_ip, d.rtp_port)?;
    Some(w.pos)
}

/// UAS `200 OK` answering an `INVITE`, carrying the PCMU answer. Role fields are
/// mirrored: `From` names the caller (peer) with the remote tag, `To` names us
/// (local) with our tag.
pub fn build_invite_ok(d: &SipDialog<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"SIP/2.0 200 OK\r\n")?;
    w.put(b"Via: SIP/2.0/UDP ")?;
    w.put_ip(d.peer_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.peer_port)?;
    w.put(b"\r\n")?;
    w.put(b"From: <sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.to_tag)?;
    w.put(b"\r\n")?;
    w.put(b"To: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.from_tag)?;
    w.put(b"\r\n")?;
    w.put(b"Call-ID: ")?;
    w.put(d.call_id)?;
    w.put(b"\r\n")?;
    w.put(b"CSeq: ")?;
    w.put_u32_decimal(d.cseq)?;
    w.put(b" INVITE\r\n")?;
    w.put(b"Contact: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.local_port)?;
    w.put(b">\r\n")?;
    put_sdp_body(&mut w, d.local_ip, d.rtp_port)?;
    Some(w.pos)
}

/// UAC `ACK` confirming a final response.
pub fn build_ack(d: &SipDialog<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"ACK sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.peer_port)?;
    w.put(b" SIP/2.0\r\n")?;
    put_via_branch(&mut w, d.local_ip, d.local_port, d.branch)?;
    w.put(b"Max-Forwards: 70\r\n")?;
    w.put(b"From: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.from_tag)?;
    w.put(b"\r\n")?;
    put_to_with_optional_tag(&mut w, d.peer_ip, d.to_tag)?;
    put_call_id_at_host(&mut w, d.call_id, d.local_ip)?;
    w.put(b"CSeq: ")?;
    w.put_u32_decimal(d.cseq)?;
    w.put(b" ACK\r\n")?;
    w.put(b"Content-Length: 0\r\n\r\n")?;
    Some(w.pos)
}

/// UAC `BYE`. The caller advances `cseq`/`branch` before formatting; this core
/// only serialises the dialog it is given.
pub fn build_bye(d: &SipDialog<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"BYE sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.peer_port)?;
    w.put(b" SIP/2.0\r\n")?;
    put_via_branch(&mut w, d.local_ip, d.local_port, d.branch)?;
    w.put(b"Max-Forwards: 70\r\n")?;
    w.put(b"From: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.from_tag)?;
    w.put(b"\r\n")?;
    put_to_with_optional_tag(&mut w, d.peer_ip, d.to_tag)?;
    put_call_id_at_host(&mut w, d.call_id, d.local_ip)?;
    w.put(b"CSeq: ")?;
    w.put_u32_decimal(d.cseq)?;
    w.put(b" BYE\r\n")?;
    w.put(b"Content-Length: 0\r\n\r\n")?;
    Some(w.pos)
}

/// UAS `200 OK` acknowledging a received `BYE`.
pub fn build_bye_ok(d: &SipDialog<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"SIP/2.0 200 OK\r\n")?;
    w.put(b"Via: SIP/2.0/UDP ")?;
    w.put_ip(d.peer_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.peer_port)?;
    w.put(b"\r\n")?;
    w.put(b"From: <sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put(b">\r\n")?;
    w.put(b"To: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.from_tag)?;
    w.put(b"\r\n")?;
    w.put(b"Call-ID: ")?;
    w.put(d.call_id)?;
    w.put(b"\r\n")?;
    w.put(b"CSeq: ")?;
    w.put_u32_decimal(d.cseq)?;
    w.put(b" BYE\r\n")?;
    w.put(b"Content-Length: 0\r\n\r\n")?;
    Some(w.pos)
}

/// UAS final response refusing an `INVITE`, with the status the caller chose.
///
/// The reason phrase is derived from the code rather than taken from the
/// caller: a phrase and a code that disagree describe two different refusals,
/// and the code is the one the peer acts on.
pub fn build_invite_status(d: &SipDialog<'_>, code: u16, out: &mut [u8]) -> Option<usize> {
    let phrase: &[u8] = match code {
        400 => b"Bad Request",
        403 => b"Forbidden",
        404 => b"Not Found",
        486 => b"Busy Here",
        487 => b"Request Terminated",
        488 => b"Not Acceptable Here",
        603 => b"Decline",
        _ => b"Declined",
    };
    let mut w = SipWriter { out, pos: 0 };
    w.put(b"SIP/2.0 ")?;
    w.put_u16_decimal(code)?;
    w.put_byte(b' ')?;
    w.put(phrase)?;
    w.put(b"\r\n")?;
    w.put(b"Via: SIP/2.0/UDP ")?;
    w.put_ip(d.peer_ip)?;
    w.put_byte(b':')?;
    w.put_u16_decimal(d.peer_port)?;
    w.put(b"\r\n")?;
    w.put(b"From: <sip:")?;
    w.put_ip(d.peer_ip)?;
    w.put(b">\r\n")?;
    w.put(b"To: <sip:")?;
    w.put_ip(d.local_ip)?;
    w.put(b">;tag=")?;
    w.put_hex16(d.to_tag)?;
    w.put(b"\r\n")?;
    w.put(b"Call-ID: ")?;
    w.put(d.call_id)?;
    w.put(b"\r\n")?;
    w.put(b"CSeq: ")?;
    w.put_u32_decimal(d.cseq)?;
    w.put(b" INVITE\r\n")?;
    w.put(b"Content-Length: 0\r\n\r\n")?;
    Some(w.pos)
}

// ---------------------------------------------------------------------------
// Parsers — read protocol facts out of a received message.
// ---------------------------------------------------------------------------

/// The 3-digit status code of a `SIP/2.0 NNN ...` response, or `0` if the
/// message is not a well-formed status line.
#[must_use]
pub fn parse_status_code(msg: &[u8]) -> u16 {
    if msg.len() < 12 || !msg.starts_with(b"SIP/2.0 ") {
        return 0;
    }
    let d = &msg[8..11];
    if d.iter().any(|c| !c.is_ascii_digit()) {
        return 0;
    }
    (d[0] - b'0') as u16 * 100 + (d[1] - b'0') as u16 * 10 + (d[2] - b'0') as u16
}

/// The remote RTP endpoint from an SDP answer: the `m=audio` port (required)
/// and the `c=IN IP4` address (optional; `None` when absent).
#[must_use]
pub fn parse_sdp_endpoint(msg: &[u8]) -> Option<SdpEndpoint> {
    let mpos = find_bytes(msg, b"m=audio ")?;
    let port = parse_decimal_u16(&msg[mpos + 8..]);
    if port == 0 {
        return None;
    }
    let ip = find_bytes(msg, b"c=IN IP4 ").and_then(|cpos| {
        let v = parse_ip4(&msg[cpos + 9..]);
        (v != 0).then_some(v)
    });
    Some(SdpEndpoint { ip, port })
}

/// The `Call-ID` header value (bytes up to the line terminator), if present.
#[must_use]
pub fn find_call_id(msg: &[u8]) -> Option<&[u8]> {
    let start = find_bytes(msg, b"Call-ID: ")? + 9;
    let mut end = start;
    while end < msg.len() && msg[end] != b'\r' && msg[end] != b'\n' {
        end += 1;
    }
    Some(&msg[start..end])
}

/// The `tag=` parameter on the `From` header, as the origin's `u16` hex tag.
/// Returns `0` when absent — the origin's "no tag" sentinel.
#[must_use]
pub fn parse_from_tag(msg: &[u8]) -> u16 {
    tag_on_line(msg, find_bytes(msg, b"From:"))
}

/// The `tag=` parameter on the `To` header (matched at a line start to avoid
/// the request's own `To:` on the first line — the origin keys on `\nTo:`).
#[must_use]
pub fn parse_to_tag(msg: &[u8]) -> u16 {
    tag_on_line(msg, find_bytes(msg, b"\nTo:").map(|p| p + 1))
}

fn tag_on_line(msg: &[u8], line_start: Option<usize>) -> u16 {
    let Some(start) = line_start else {
        return 0;
    };
    let mut end = start;
    while end < msg.len() && msg[end] != b'\r' {
        end += 1;
    }
    match find_bytes(&msg[start..end], b";tag=") {
        Some(rel) => parse_hex16(&msg[start + rel + 5..]),
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Byte primitives (safe slice forms of the origin helpers).
// ---------------------------------------------------------------------------

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_decimal_u16(buf: &[u8]) -> u16 {
    let mut val: u16 = 0;
    for &c in buf {
        if !c.is_ascii_digit() {
            break;
        }
        val = val.wrapping_mul(10).wrapping_add((c - b'0') as u16);
    }
    val
}

fn parse_ip4(buf: &[u8]) -> u32 {
    let mut octets = [0u8; 4];
    let mut idx = 0;
    let mut val: u16 = 0;
    for &c in buf {
        if idx >= 4 {
            break;
        }
        if c.is_ascii_digit() {
            val = val * 10 + (c - b'0') as u16;
        } else if c == b'.' {
            if val > 255 {
                return 0;
            }
            octets[idx] = val as u8;
            idx += 1;
            val = 0;
        } else {
            break;
        }
    }
    if idx < 4 && val <= 255 {
        octets[idx] = val as u8;
        idx += 1;
    }
    if idx != 4 {
        return 0;
    }
    u32::from_be_bytes(octets)
}

fn parse_hex16(buf: &[u8]) -> u16 {
    let mut val: u16 = 0;
    for &c in buf.iter().take(4) {
        let digit = match c {
            b'0'..=b'9' => (c - b'0') as u16,
            b'a'..=b'f' => (c - b'a' + 10) as u16,
            b'A'..=b'F' => (c - b'A' + 10) as u16,
            _ => break,
        };
        val = (val << 4) | digit;
    }
    val
}
