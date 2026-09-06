// The SDP attributes a WebRTC session description carries, and nothing else.
//
// `sip_core.rs` writes an SDP body for a single PCMU audio stream between two
// fixed endpoints. That is the right shape for a SIP call to a telephone and
// the wrong shape for a browser: a WebRTC description carries the ICE
// credentials a peer authenticates checks with, the candidates it should try,
// and the DTLS fingerprint that binds the media path to the signalling one.
// None of those exist in a SIP-to-PSTN body, and adding them there would put
// browser concerns in the middle of a telephony codec.
//
// So this is a separate reader and writer for the attributes that make a
// description a WebRTC one. It shares the line-level conventions with SDP
// generally, because SDP is SDP.
//
// This file decides nothing. It does not gather candidates, choose a role,
// verify a fingerprint, or decide whether a description is acceptable. Those
// are reachability and security policy and belong to an agent.

/// The longest ICE username fragment this codec carries.
///
/// A ufrag is chosen by the peer and travels in every connectivity check, so
/// it is bounded here rather than wherever it is first copied.
pub const MAX_UFRAG_LEN: usize = 256;

/// The longest ICE password.
pub const MAX_PWD_LEN: usize = 256;

/// The longest fingerprint value, which is a hex digest with separators.
pub const MAX_FINGERPRINT_LEN: usize = 256;

/// The most candidates one description carries.
///
/// Bounded because the list arrives from a peer, and an unbounded one would
/// let a peer decide how much work reading a description costs.
pub const MAX_SDP_CANDIDATES: usize = 32;

/// Which side of the DTLS handshake a description offers to take.
///
/// This is what stops both peers waiting for the other to start. `Actpass` is
/// what an offer says; an answer must resolve it to one or the other, and an
/// answer that echoed `actpass` would leave the role undecided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SetupRole {
    /// Will start the handshake.
    Active,
    /// Will wait for it.
    Passive,
    /// Either; only valid in an offer.
    Actpass,
}

impl SetupRole {
    /// The token as it appears on an `a=setup:` line.
    pub fn as_token(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::Actpass => "actpass",
        }
    }

    /// The role a token names.
    pub fn from_token(token: &[u8]) -> Option<Self> {
        match token {
            b"active" => Some(Self::Active),
            b"passive" => Some(Self::Passive),
            b"actpass" => Some(Self::Actpass),
            _ => None,
        }
    }

    /// The role that answers this one.
    ///
    /// `None` for an offer of `active` or `passive` answered by the same
    /// value: both sides active means neither is listening, and both passive
    /// means neither ever starts.
    pub fn answering(self) -> Option<Self> {
        match self {
            // An offer of actpass is answered by taking a definite role.
            // Active is chosen so the answerer starts the handshake, which is
            // what lets it begin the moment it has a candidate pair.
            Self::Actpass => Some(Self::Active),
            Self::Passive => Some(Self::Active),
            Self::Active => Some(Self::Passive),
        }
    }
}

/// A candidate as an SDP line carries it.
///
/// Byte ranges into the description rather than copies: a description arrives
/// in one buffer and a parser that copied every field would need somewhere to
/// put them.
pub struct SdpCandidate {
    /// Where the `a=candidate:` value starts.
    pub offset: usize,
    /// How long it is.
    pub len: usize,
    /// The component this candidate is for. 1 is RTP, 2 is RTCP.
    pub component: u8,
    /// The candidate's priority.
    pub priority: u32,
}

/// What a description said.
///
/// Every field is optional because a description that is missing one is a real
/// thing that arrives, and refusing to parse it would leave a caller unable to
/// say which part was absent.
pub struct WebrtcDescription {
    /// `a=ice-ufrag:` — offset and length into the description.
    pub ufrag: Option<(usize, usize)>,
    /// `a=ice-pwd:`.
    pub pwd: Option<(usize, usize)>,
    /// `a=fingerprint:` — the whole value, algorithm and digest.
    pub fingerprint: Option<(usize, usize)>,
    /// `a=setup:`.
    pub setup: Option<SetupRole>,
    /// Whether the description declared `a=ice-lite`.
    ///
    /// A lite implementation never takes the controlling role. Reading it
    /// wrongly means both peers acting as controlled and nothing being
    /// nominated.
    pub ice_lite: bool,
    /// How many candidates were found.
    pub candidate_count: usize,
}

impl WebrtcDescription {
    /// Whether this description carries everything a check needs.
    ///
    /// Both credentials and a fingerprint. A description missing any of them
    /// cannot produce an authenticated connectivity check or a bound media
    /// path, and starting ICE on it would fail later in a way that looks like
    /// a network problem.
    pub fn is_complete(&self) -> bool {
        self.ufrag.is_some() && self.pwd.is_some() && self.fingerprint.is_some()
    }
}

/// Read the WebRTC attributes from a session description.
///
/// `candidates` is filled with as many candidates as fit; the count in the
/// returned description says how many were found, which may be more. A caller
/// that needs to know it lost some compares the two.
pub fn parse_webrtc_sdp(body: &[u8], candidates: &mut [SdpCandidate]) -> Option<WebrtcDescription> {
    let mut out = WebrtcDescription {
        ufrag: None,
        pwd: None,
        fingerprint: None,
        setup: None,
        ice_lite: false,
        candidate_count: 0,
    };

    let mut at = 0;
    let mut stored = 0;
    while at < body.len() {
        let end = line_end(body, at);
        let line = &body[at..end];

        if let Some(value) = after(line, b"a=ice-ufrag:") {
            if value.1 <= MAX_UFRAG_LEN && out.ufrag.is_none() {
                out.ufrag = Some((at + value.0, value.1));
            }
        } else if let Some(value) = after(line, b"a=ice-pwd:") {
            if value.1 <= MAX_PWD_LEN && out.pwd.is_none() {
                out.pwd = Some((at + value.0, value.1));
            }
        } else if let Some(value) = after(line, b"a=fingerprint:") {
            if value.1 <= MAX_FINGERPRINT_LEN && out.fingerprint.is_none() {
                out.fingerprint = Some((at + value.0, value.1));
            }
        } else if let Some(value) = after(line, b"a=setup:") {
            if out.setup.is_none() {
                out.setup = SetupRole::from_token(&line[value.0..value.0 + value.1]);
            }
        } else if line == b"a=ice-lite" {
            out.ice_lite = true;
        } else if let Some(value) = after(line, b"a=candidate:") {
            // Counted even when there is nowhere to put it, so a caller can
            // tell "no candidates" from "more candidates than I made room
            // for".
            if out.candidate_count < MAX_SDP_CANDIDATES {
                out.candidate_count += 1;
                if stored < candidates.len() {
                    let value_bytes = &line[value.0..value.0 + value.1];
                    let (component, priority) = candidate_fields(value_bytes);
                    candidates[stored] = SdpCandidate {
                        offset: at + value.0,
                        len: value.1,
                        component,
                        priority,
                    };
                    stored += 1;
                }
            }
        }

        at = next_line(body, end);
    }

    Some(out)
}

/// The component and priority from a candidate value.
///
/// `foundation component transport priority ...`. Zero for either when the
/// field is absent or unreadable — a candidate whose priority did not parse
/// still exists, and dropping it because one field was malformed would lose a
/// path that might have been the only working one.
fn candidate_fields(value: &[u8]) -> (u8, u32) {
    let mut component = 0u8;
    let mut priority = 0u32;
    let mut field = 0;
    let mut at = 0;
    while at < value.len() && field < 4 {
        let start = at;
        while at < value.len() && value[at] != b' ' {
            at += 1;
        }
        match field {
            1 => component = parse_u32(&value[start..at]) as u8,
            3 => priority = parse_u32(&value[start..at]),
            _ => {}
        }
        field += 1;
        at += 1;
    }
    (component, priority)
}

fn parse_u32(bytes: &[u8]) -> u32 {
    let mut value = 0u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return 0;
        }
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'));
    }
    value
}

/// The value after `prefix`, as (offset within the line, length).
fn after(line: &[u8], prefix: &[u8]) -> Option<(usize, usize)> {
    if line.len() <= prefix.len() || &line[..prefix.len()] != prefix {
        return None;
    }
    Some((prefix.len(), line.len() - prefix.len()))
}

fn line_end(body: &[u8], from: usize) -> usize {
    let mut at = from;
    while at < body.len() && body[at] != b'\r' && body[at] != b'\n' {
        at += 1;
    }
    at
}

fn next_line(body: &[u8], end: usize) -> usize {
    let mut at = end;
    if at < body.len() && body[at] == b'\r' {
        at += 1;
    }
    if at < body.len() && body[at] == b'\n' {
        at += 1;
    }
    at
}

/// Write the ICE and DTLS attribute lines for a media section.
///
/// Only the attributes this file owns. The session and media lines around them
/// belong to whatever is assembling the description, because what codecs are
/// offered and how many streams there are is not a WebRTC question.
pub fn write_webrtc_attributes(
    ufrag: &[u8],
    pwd: &[u8],
    fingerprint: &[u8],
    setup: SetupRole,
    out: &mut [u8],
    at: usize,
) -> Option<usize> {
    if ufrag.len() > MAX_UFRAG_LEN
        || pwd.len() > MAX_PWD_LEN
        || fingerprint.len() > MAX_FINGERPRINT_LEN
    {
        return None;
    }
    // A credential carrying a line break would end its own line and let the
    // rest be read as another attribute. Refused rather than escaped: a
    // credential that was quietly rewritten no longer matches the one the
    // peer checks against.
    if contains_break(ufrag) || contains_break(pwd) || contains_break(fingerprint) {
        return None;
    }

    let mut at = write_line(b"a=ice-ufrag:", ufrag, out, at)?;
    at = write_line(b"a=ice-pwd:", pwd, out, at)?;
    at = write_line(b"a=fingerprint:", fingerprint, out, at)?;
    at = write_line(b"a=setup:", setup.as_token().as_bytes(), out, at)?;
    Some(at)
}

/// Write one `a=candidate:` line.
pub fn write_candidate_line(value: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    if contains_break(value) {
        return None;
    }
    write_line(b"a=candidate:", value, out, at)
}

fn write_line(prefix: &[u8], value: &[u8], out: &mut [u8], at: usize) -> Option<usize> {
    let total = prefix.len() + value.len() + 2;
    if at + total > out.len() {
        return None;
    }
    out[at..at + prefix.len()].copy_from_slice(prefix);
    let mut end = at + prefix.len();
    out[end..end + value.len()].copy_from_slice(value);
    end += value.len();
    out[end] = b'\r';
    out[end + 1] = b'\n';
    Some(end + 2)
}

fn contains_break(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte == b'\r' || *byte == b'\n')
}

/// Bounds for the browser profile; storage is supplied by the caller.
pub const MAX_SDP_MEDIA: usize = 16;
pub const MAX_SDP_BYTES: usize = 65536;
pub const MAX_SDP_LINE: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdpError {
    Malformed,
    Duplicate,
    Oversize,
    Unsupported,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MediaDirection {
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct TransportAttributes<'a> {
    pub ufrag: Option<&'a [u8]>,
    pub pwd: Option<&'a [u8]>,
    pub fingerprint: Option<&'a [u8]>,
    pub setup: Option<SetupRole>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct MediaDescription<'a> {
    pub kind: &'a [u8],
    pub port: u16,
    pub protocol: &'a [u8],
    pub formats: &'a [u8],
    pub mid: Option<&'a [u8]>,
    pub msid: Option<&'a [u8]>,
    pub transport: TransportAttributes<'a>,
    pub direction: MediaDirection,
    pub rtcp_mux: bool,
    pub bundle_only: bool,
    pub end_of_candidates: bool,
    /// Raw section, for bounded iteration over extension attributes.
    pub raw: &'a [u8],
    seen: u16,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ScopedCandidate<'a> {
    pub media_index: usize,
    pub value: &'a [u8],
}
#[derive(Debug)]
pub struct ScopedDescription<'a> {
    pub transport: TransportAttributes<'a>,
    pub direction: MediaDirection,
    pub bundle: &'a [u8],
    pub ice_lite: bool,
    pub media_count: usize,
    pub candidate_count: usize,
}

fn sdp_decimal(bytes: &[u8]) -> Result<u32, SdpError> {
    if bytes.is_empty() {
        return Err(SdpError::Malformed);
    }
    let mut n = 0u32;
    for b in bytes {
        if !b.is_ascii_digit() {
            return Err(SdpError::Malformed);
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u32::from(b - b'0')))
            .ok_or(SdpError::Malformed)?;
    }
    Ok(n)
}
fn sdp_once(seen: &mut u16, bit: u16) -> Result<(), SdpError> {
    if *seen & bit != 0 {
        return Err(SdpError::Duplicate);
    }
    *seen |= bit;
    Ok(())
}
fn sdp_token(value: &[u8], max: usize) -> Result<(), SdpError> {
    if value.is_empty() || value.iter().any(|b| *b <= 32 || *b >= 127) {
        return Err(SdpError::Malformed);
    }
    if value.len() > max {
        return Err(SdpError::Oversize);
    }
    Ok(())
}

/// Parse session/media facts without copying attacker-controlled text.
///
/// Every attribute is scoped to the m-line it appears under, so two media
/// sections offering different ICE credentials or setup roles are never
/// collapsed into one transport. Returned references borrow `body`; the caller
/// supplies both arrays, so there is no hidden allocation.
pub fn parse_scoped_webrtc_sdp<'a>(
    body: &'a [u8],
    media: &mut [MediaDescription<'a>],
    candidates: &mut [ScopedCandidate<'a>],
) -> Result<ScopedDescription<'a>, SdpError> {
    if body.len() > MAX_SDP_BYTES {
        return Err(SdpError::Oversize);
    }
    let mut out = ScopedDescription {
        transport: TransportAttributes::default(),
        direction: MediaDirection::SendRecv,
        bundle: &[],
        ice_lite: false,
        media_count: 0,
        candidate_count: 0,
    };
    let mut session_seen = 0u16;
    let mut at = 0;
    let mut section_start = 0;
    while at < body.len() {
        let end = line_end(body, at);
        let line = &body[at..end];
        if line.len() > MAX_SDP_LINE {
            return Err(SdpError::Oversize);
        }
        if line.len() < 2 || line[1] != b'=' || line.iter().any(|b| *b == 0 || (*b < 32 && *b != 9))
        {
            return Err(SdpError::Malformed);
        }
        if let Some(value) = line.strip_prefix(b"m=") {
            if out.media_count >= media.len() || out.media_count >= MAX_SDP_MEDIA {
                return Err(SdpError::Oversize);
            }
            if out.media_count > 0 {
                media[out.media_count - 1].raw = &body[section_start..at];
            }
            let mut parts = value.splitn(4, |b| *b == b' ');
            let kind = parts.next().ok_or(SdpError::Malformed)?;
            let port = parts.next().ok_or(SdpError::Malformed)?;
            let protocol = parts.next().ok_or(SdpError::Malformed)?;
            let formats = parts.next().ok_or(SdpError::Malformed)?;
            sdp_token(kind, 32)?;
            sdp_token(protocol, 64)?;
            let port = u16::try_from(sdp_decimal(port)?).map_err(|_| SdpError::Malformed)?;
            if formats.is_empty() {
                return Err(SdpError::Malformed);
            }
            media[out.media_count] = MediaDescription {
                kind,
                port,
                protocol,
                formats,
                transport: out.transport,
                direction: out.direction,
                ..MediaDescription::default()
            };
            out.media_count += 1;
            section_start = at;
        } else if let Some(value) = line.strip_prefix(b"a=") {
            let current = out.media_count.checked_sub(1);
            let (transport, direction, seen) = if let Some(i) = current {
                let m = &mut media[i];
                (&mut m.transport, &mut m.direction, &mut m.seen)
            } else {
                (&mut out.transport, &mut out.direction, &mut session_seen)
            };
            if let Some(v) = value.strip_prefix(b"ice-ufrag:") {
                sdp_once(seen, 1)?;
                sdp_token(v, MAX_UFRAG_LEN)?;
                transport.ufrag = Some(v);
            } else if let Some(v) = value.strip_prefix(b"ice-pwd:") {
                sdp_once(seen, 2)?;
                sdp_token(v, MAX_PWD_LEN)?;
                transport.pwd = Some(v);
            } else if let Some(v) = value.strip_prefix(b"fingerprint:") {
                sdp_once(seen, 4)?;
                if v.is_empty() || v.len() > MAX_FINGERPRINT_LEN {
                    return Err(SdpError::Malformed);
                }
                transport.fingerprint = Some(v);
            } else if let Some(v) = value.strip_prefix(b"setup:") {
                sdp_once(seen, 8)?;
                transport.setup = Some(SetupRole::from_token(v).ok_or(SdpError::Malformed)?);
            } else if matches!(value, b"sendrecv" | b"sendonly" | b"recvonly" | b"inactive") {
                sdp_once(seen, 16)?;
                *direction = match value {
                    b"sendonly" => MediaDirection::SendOnly,
                    b"recvonly" => MediaDirection::RecvOnly,
                    b"inactive" => MediaDirection::Inactive,
                    _ => MediaDirection::SendRecv,
                };
            } else if value == b"ice-lite" {
                if current.is_some() {
                    return Err(SdpError::Malformed);
                }
                sdp_once(seen, 32)?;
                out.ice_lite = true;
            } else if let Some(v) = value.strip_prefix(b"group:BUNDLE ") {
                if current.is_some() {
                    return Err(SdpError::Malformed);
                }
                sdp_once(seen, 64)?;
                if v.is_empty() {
                    return Err(SdpError::Malformed);
                }
                out.bundle = v;
            } else if let Some(v) = value.strip_prefix(b"mid:") {
                let i = current.ok_or(SdpError::Malformed)?;
                sdp_once(seen, 32)?;
                sdp_token(v, 64)?;
                media[i].mid = Some(v);
            } else if let Some(v) = value.strip_prefix(b"msid:") {
                let i = current.ok_or(SdpError::Malformed)?;
                sdp_once(seen, 64)?;
                if v.is_empty() {
                    return Err(SdpError::Malformed);
                }
                media[i].msid = Some(v);
            } else if value == b"rtcp-mux" {
                let i = current.ok_or(SdpError::Malformed)?;
                sdp_once(seen, 128)?;
                media[i].rtcp_mux = true;
            } else if value == b"bundle-only" {
                let i = current.ok_or(SdpError::Malformed)?;
                sdp_once(seen, 256)?;
                media[i].bundle_only = true;
            } else if value == b"end-of-candidates" {
                let i = current.ok_or(SdpError::Malformed)?;
                sdp_once(seen, 512)?;
                media[i].end_of_candidates = true;
            } else if let Some(v) = value.strip_prefix(b"candidate:") {
                let i = current.ok_or(SdpError::Malformed)?;
                if out.candidate_count >= candidates.len()
                    || out.candidate_count >= MAX_SDP_CANDIDATES
                {
                    return Err(SdpError::Oversize);
                }
                if v.is_empty() {
                    return Err(SdpError::Malformed);
                }
                candidates[out.candidate_count] = ScopedCandidate {
                    media_index: i,
                    value: v,
                };
                out.candidate_count += 1;
            }
        }
        at = next_line(body, end);
    }
    if out.media_count > 0 {
        media[out.media_count - 1].raw = &body[section_start..];
    }
    for i in 0..out.media_count {
        if let Some(mid) = media[i].mid {
            if media[..i].iter().any(|m| m.mid == Some(mid)) {
                return Err(SdpError::Duplicate);
            }
        }
    }
    if !out.bundle.is_empty() {
        let mut consumed = 0;
        for mid in out.bundle.split(|b| *b == b' ') {
            sdp_token(mid, 64)?;
            if !media[..out.media_count].iter().any(|m| m.mid == Some(mid)) {
                return Err(SdpError::Malformed);
            }
            if out.bundle[..consumed]
                .split(|b| *b == b' ')
                .any(|v| v == mid)
            {
                return Err(SdpError::Duplicate);
            }
            consumed += mid.len() + 1;
        }
    }
    Ok(out)
}

pub const MAX_SDP_PAYLOADS: usize = 32;
#[derive(Clone, Copy, Debug, Default)]
pub struct PayloadDescription<'a> {
    pub payload_type: u8,
    pub encoding: Option<&'a [u8]>,
    pub clock_rate: u32,
    pub channels: u16,
    pub fmtp: Option<&'a [u8]>,
}
fn attribute_pair(value: &[u8]) -> Result<(&[u8], &[u8]), SdpError> {
    let split = value
        .iter()
        .position(|b| *b == b' ')
        .ok_or(SdpError::Malformed)?;
    let (key, rest) = value.split_at(split);
    if key.is_empty() || rest.len() < 2 {
        return Err(SdpError::Malformed);
    }
    Ok((key, &rest[1..]))
}
/// Read the negotiated RTP payload facts for this media section only. The
/// m-line defines the set; attributes for an unlisted payload are rejected.
pub fn media_payloads<'a>(
    media: &MediaDescription<'a>,
    out: &mut [PayloadDescription<'a>],
) -> Result<usize, SdpError> {
    if !matches!(media.kind, b"audio" | b"video") {
        return Err(SdpError::Unsupported);
    }
    let mut count = 0;
    for token in media.formats.split(|b| *b == b' ') {
        if count >= out.len() || count >= MAX_SDP_PAYLOADS {
            return Err(SdpError::Oversize);
        }
        let pt = u8::try_from(sdp_decimal(token)?).map_err(|_| SdpError::Malformed)?;
        if pt > 127 {
            return Err(SdpError::Malformed);
        }
        if out[..count].iter().any(|p| p.payload_type == pt) {
            return Err(SdpError::Duplicate);
        }
        out[count] = PayloadDescription {
            payload_type: pt,
            channels: 1,
            ..PayloadDescription::default()
        };
        count += 1;
    }
    let mut at = 0;
    while at < media.raw.len() {
        let end = line_end(media.raw, at);
        let line = &media.raw[at..end];
        if let Some(value) = line.strip_prefix(b"a=rtpmap:") {
            let (pt, mapping) = attribute_pair(value)?;
            let pt = sdp_decimal(pt)?;
            let p = out[..count]
                .iter_mut()
                .find(|p| u32::from(p.payload_type) == pt)
                .ok_or(SdpError::Malformed)?;
            if p.encoding.is_some() {
                return Err(SdpError::Duplicate);
            }
            let mut parts = mapping.split(|b| *b == b'/');
            let name = parts.next().ok_or(SdpError::Malformed)?;
            sdp_token(name, 64)?;
            let rate = sdp_decimal(parts.next().ok_or(SdpError::Malformed)?)?;
            let channels = match parts.next() {
                Some(v) => u16::try_from(sdp_decimal(v)?).map_err(|_| SdpError::Malformed)?,
                None => 1,
            };
            if rate == 0 || channels == 0 || parts.next().is_some() {
                return Err(SdpError::Malformed);
            }
            p.encoding = Some(name);
            p.clock_rate = rate;
            p.channels = channels;
        } else if let Some(value) = line.strip_prefix(b"a=fmtp:") {
            let (pt, params) = attribute_pair(value)?;
            let pt = sdp_decimal(pt)?;
            let p = out[..count]
                .iter_mut()
                .find(|p| u32::from(p.payload_type) == pt)
                .ok_or(SdpError::Malformed)?;
            if p.fmtp.replace(params).is_some() {
                return Err(SdpError::Duplicate);
            }
        } else if let Some(value) = line.strip_prefix(b"a=rtcp-fb:") {
            let (pt, _) = attribute_pair(value)?;
            if pt != b"*" {
                let pt = sdp_decimal(pt)?;
                if !out[..count].iter().any(|p| u32::from(p.payload_type) == pt) {
                    return Err(SdpError::Malformed);
                }
            }
        }
        at = next_line(media.raw, end);
    }
    for p in &mut out[..count] {
        if p.encoding.is_none() {
            let name = match p.payload_type {
                0 => b"PCMU".as_slice(),
                8 => b"PCMA".as_slice(),
                9 => b"G722".as_slice(),
                _ => return Err(SdpError::Unsupported),
            };
            p.encoding = Some(name);
            p.clock_rate = 8000;
        }
    }
    Ok(count)
}

/// Iterator over this payload's RTCP feedback attributes, including wildcards.
/// Values retain complete feedback parameters (for example `nack pli`).
pub struct Feedback<'a> {
    body: &'a [u8],
    at: usize,
    payload_type: u8,
}
impl<'a> MediaDescription<'a> {
    pub fn feedback(&self, payload_type: u8) -> Feedback<'a> {
        Feedback {
            body: self.raw,
            at: 0,
            payload_type,
        }
    }
}
impl<'a> Iterator for Feedback<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        while self.at < self.body.len() {
            let end = line_end(self.body, self.at);
            let line = &self.body[self.at..end];
            self.at = next_line(self.body, end);
            if let Some(value) = line.strip_prefix(b"a=rtcp-fb:") {
                if let Ok((pt, params)) = attribute_pair(value) {
                    if pt == b"*" || sdp_decimal(pt).ok() == Some(u32::from(self.payload_type)) {
                        return Some(params);
                    }
                }
            }
        }
        None
    }
}
