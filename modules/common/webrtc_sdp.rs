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
