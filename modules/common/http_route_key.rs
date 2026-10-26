// Bounded, no_std, no-alloc HTTP route-key canonicalisation: the
// `(authority_host, authority_port, path)` triple a request names, in the one
// spelling every reader derives from it. `include!`d verbatim by the host
// crate (tests) and by any module that routes on an HTTP request — like the
// other `modules/common` cores it carries NO inner attributes and NO test
// module.
//
// This file says what a request's route key IS. It decides nothing about
// where the request goes: placement, hashing policy and backend choice belong
// to whoever consumes the key (the Wormhole load balancer, the http module's
// own route table). Wave owns the parsing because the parsing is
// HTTP. The rule the file is built around: refuse what does not
// canonicalise rather than hash a guess at it. Two readers that hash
// different bytes for one request place it twice, and a key truncated to fit
// is a different key that happens to share a prefix.
//
// Canonical form:
//
//   host  lowercased (ASCII only), one trailing dot stripped, an explicit
//         default port removed (`:443` or `:80` per the scheme the caller
//         names), an IPv6 literal kept in its brackets and validated as one.
//         Non-ASCII and percent-encoded hosts are REFUSED (`NonAscii`): IDNA
//         is a separate contract, and a guess at it is a second key.
//   port  the explicit port when it is not the scheme default, else the
//         scheme default the caller passed.
//   path  RFC 3986 §5.2.4 remove-dot-segments after §6.2.2 case and
//         percent-encoding normalisation: unreserved characters decoded,
//         everything else left encoded with uppercase hex, so `%2F` stays a
//         `%2F` and never becomes a segment boundary. The query is not part
//         of the key; it is handed back separately.
//
// What is refused rather than resolved: an absolute-form target whose
// authority does not agree with the `Host` header, an `:authority` that does
// not agree with a literal `host` field, a `Host` line that appears twice
// (`Ambiguous`); a host or path past `MAX_ROUTE_HOST` / `MAX_ROUTE_PATH`
// (`Oversize`); an authority-form target on anything but CONNECT and `*` on
// anything but OPTIONS (`BadTarget`); an empty host (`EmptyHost`). Agreement
// is judged on the canonical forms — `Example.COM:443` and `example.com`
// under https are one authority, not two — so case and a default port are
// never a reason to refuse.

/// Longest canonical host, including an IPv6 literal's brackets. 255 is the
/// DNS name ceiling (RFC 1035 §2.3.4); anything longer is not a name this key
/// could ever resolve, so it is refused rather than clipped.
pub const MAX_ROUTE_HOST: usize = 255;
/// Longest path (as received, before normalisation — the canonical form is
/// never longer than the wire form). Refused past it, never truncated.
pub const MAX_ROUTE_PATH: usize = 2048;
/// Widest `:port` suffix a wire authority may carry past its host.
const PORT_SUFFIX_MAX: usize = 6;
/// Domain separator the digest input starts with, NUL-terminated so no
/// host can continue it.
pub const ROUTE_KEY_DOMAIN: &[u8] = b"wave-http-route-key\0";
/// Size of the canonical digest input at its widest:
/// `domain | host | 0 | port BE | 0 | path`.
pub const ROUTE_KEY_CANON_BYTES: usize =
    ROUTE_KEY_DOMAIN.len() + MAX_ROUTE_HOST + 4 + MAX_ROUTE_PATH;

/// Why a request yields no route key. Every variant is a refusal: the request
/// is answered as malformed, not routed on a best guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteKeyError {
    /// Two sources of the authority (absolute-form target, `:authority`,
    /// `Host`) disagree after canonicalisation, or `Host` appears twice with
    /// different values.
    Ambiguous,
    /// Host longer than `MAX_ROUTE_HOST` or path longer than `MAX_ROUTE_PATH`.
    Oversize,
    /// A host byte outside ASCII, or a percent-encoded host. IDNA is out of
    /// scope and is refused, not guessed.
    NonAscii,
    /// No authority at all, or one that canonicalises to nothing.
    EmptyHost,
    /// An authority that is not `host[:port]` / `[v6][:port]`: userinfo, a
    /// character outside the host alphabet, an empty label, a bare IPv6.
    BadHost,
    /// A port that is not 1..=65535 in decimal.
    BadPort,
    /// A path byte outside the `pchar` alphabet, a broken percent-escape, or
    /// a raw non-ASCII byte.
    BadPath,
    /// A target form the method does not admit (`*` off OPTIONS,
    /// authority-form off CONNECT, origin/absolute-form on CONNECT), a
    /// fragment, a protocol-relative `//` origin-form, or an empty target.
    BadTarget,
}

/// Caller-owned storage the canonical key is written into.
pub struct RouteKeyBuf {
    host: [u8; MAX_ROUTE_HOST],
    path: [u8; MAX_ROUTE_PATH],
}

impl RouteKeyBuf {
    pub const fn new() -> Self {
        Self {
            host: [0; MAX_ROUTE_HOST],
            path: [0; MAX_ROUTE_PATH],
        }
    }
}

impl Default for RouteKeyBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// A canonical route key. `host`/`path` borrow the caller's `RouteKeyBuf`;
/// `query` borrows the target it was cut from and is NOT part of the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouteKey<'a> {
    pub host: &'a [u8],
    pub port: u16,
    pub path: &'a [u8],
    pub query: &'a [u8],
}

enum TargetForm<'a> {
    Origin {
        path: &'a [u8],
        query: &'a [u8],
    },
    Absolute {
        authority: &'a [u8],
        path: &'a [u8],
        query: &'a [u8],
    },
    Authority(&'a [u8]),
    Asterisk,
}

/// Derive the canonical route key of one request.
///
/// `target` is the request-target as received (origin-, absolute-,
/// authority- or asterisk-form); `host_header` the trimmed `Host` value when
/// one was present (`Some(b"")` for a present-but-empty one, which is how h1
/// sends it); `authority_pseudo` the h2/h3 `:authority`; `scheme_default_port`
/// 443 for https, 80 for http. Every source present must agree.
pub fn route_key<'a>(
    method: &[u8],
    target: &'a [u8],
    host_header: Option<&[u8]>,
    authority_pseudo: Option<&[u8]>,
    scheme_default_port: u16,
    out: &'a mut RouteKeyBuf,
) -> Result<RouteKey<'a>, RouteKeyError> {
    let form = classify_target(target)?;
    let is_connect = method == b"CONNECT";
    let is_options = method == b"OPTIONS";
    match form {
        TargetForm::Asterisk if !is_options => return Err(RouteKeyError::BadTarget),
        TargetForm::Authority(_) if !is_connect => return Err(RouteKeyError::BadTarget),
        TargetForm::Origin { .. } | TargetForm::Absolute { .. } if is_connect => {
            return Err(RouteKeyError::BadTarget)
        }
        _ => {}
    }

    let target_authority = match form {
        TargetForm::Absolute { authority, .. } | TargetForm::Authority(authority) => {
            Some(authority)
        }
        _ => None,
    };

    // The first source present fills the key; every later one must
    // canonicalise to the same bytes, or the request names two authorities.
    let mut have = false;
    let mut host_len = 0usize;
    let mut port = scheme_default_port;
    let mut tmp = [0u8; MAX_ROUTE_HOST];
    let sources = [target_authority, authority_pseudo, host_header];
    let mut si = 0;
    while si < sources.len() {
        if let Some(src) = sources[si] {
            if !have {
                let (l, p, explicit) = norm_host(src, scheme_default_port, &mut out.host)?;
                if is_connect && !explicit {
                    // RFC 9112 §3.2.3: authority-form carries a port.
                    return Err(RouteKeyError::BadTarget);
                }
                host_len = l;
                port = p;
                have = true;
            } else {
                match norm_host(src, scheme_default_port, &mut tmp) {
                    Ok((l, p, _)) => {
                        if l != host_len || p != port || tmp[..l] != out.host[..host_len] {
                            return Err(RouteKeyError::Ambiguous);
                        }
                    }
                    Err(RouteKeyError::EmptyHost) => return Err(RouteKeyError::Ambiguous),
                    Err(e) => return Err(e),
                }
            }
        }
        si += 1;
    }
    if !have {
        return Err(RouteKeyError::EmptyHost);
    }

    let (path_len, query): (usize, &'a [u8]) = match form {
        TargetForm::Asterisk => {
            out.path[0] = b'*';
            (1, &[])
        }
        TargetForm::Authority(_) => (0, &[]),
        TargetForm::Origin { path, query } | TargetForm::Absolute { path, query, .. } => {
            (norm_path(path, &mut out.path)?, query)
        }
    };

    Ok(RouteKey {
        host: &out.host[..host_len],
        port,
        path: &out.path[..path_len],
        query,
    })
}

/// The single `Host` value of an HTTP/1 head (request line + header lines,
/// through the blank line or the end of `head`), trimmed. `Ok(None)` when no
/// `Host` line is present; `Err(Ambiguous)` when more than one is.
///
/// A second `Host` line is refused however it reads: RFC 9112 §3.2 makes any
/// request carrying more than one a 400. Collapsing a byte-identical pair
/// would read as one fact what an intermediary in front of this server may
/// have joined from two different values, so the count decides and not the
/// bytes.
pub fn h1_host(head: &[u8]) -> Result<Option<&[u8]>, RouteKeyError> {
    let mut found: Option<&[u8]> = None;
    let mut cursor = 0usize;
    let mut first_line = true;
    while cursor < head.len() {
        let line_start = cursor;
        let mut nl = line_start;
        while nl < head.len() && head[nl] != b'\n' {
            nl += 1;
        }
        let mut line_end = nl;
        if line_end > line_start && head[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        cursor = nl + 1;
        if first_line {
            first_line = false;
            continue;
        }
        if line_end == line_start {
            break;
        }
        let line = &head[line_start..line_end];
        let mut colon = 0usize;
        while colon < line.len() && line[colon] != b':' {
            colon += 1;
        }
        if colon == line.len() || !line[..colon].eq_ignore_ascii_case(b"host") {
            continue;
        }
        let value = trim_ows(&line[colon + 1..]);
        if found.is_some() {
            return Err(RouteKeyError::Ambiguous);
        }
        found = Some(value);
    }
    Ok(found)
}

/// Whether two authorities name one host and port: byte-identical, or
/// identical once canonicalised. An authority that does not canonicalise
/// agrees with nothing, including a second copy of itself — a pair this
/// cannot read is a pair it cannot vouch for.
pub fn authority_agrees(a: &[u8], b: &[u8], scheme_default_port: u16) -> bool {
    if a == b {
        return true;
    }
    let mut ca = [0u8; MAX_ROUTE_HOST];
    let mut cb = [0u8; MAX_ROUTE_HOST];
    match (
        norm_host(a, scheme_default_port, &mut ca),
        norm_host(b, scheme_default_port, &mut cb),
    ) {
        (Ok((la, pa, _)), Ok((lb, pb, _))) => la == lb && pa == pb && ca[..la] == cb[..lb],
        _ => false,
    }
}

/// Canonicalise one authority into `dst` as `host` or `host:port` — the port
/// kept only when explicit and not the scheme default. Returns the length
/// written. This is the form a route table stores and matches on, so a
/// request `Host` and a programmed route meet as the same bytes.
pub fn canonical_authority(
    src: &[u8],
    scheme_default_port: u16,
    dst: &mut [u8],
) -> Result<usize, RouteKeyError> {
    let mut host = [0u8; MAX_ROUTE_HOST];
    let (len, port, _) = norm_host(src, scheme_default_port, &mut host)?;
    let mut need = len;
    let mut digits = [0u8; 5];
    let mut nd = 0usize;
    if port != scheme_default_port {
        let mut p = port;
        while p > 0 {
            digits[nd] = b'0' + (p % 10) as u8;
            p /= 10;
            nd += 1;
        }
        need += 1 + nd;
    }
    if need > dst.len() {
        return Err(RouteKeyError::Oversize);
    }
    dst[..len].copy_from_slice(&host[..len]);
    if nd > 0 {
        dst[len] = b':';
        let mut i = 0;
        while i < nd {
            dst[len + 1 + i] = digits[nd - 1 - i];
            i += 1;
        }
    }
    Ok(need)
}

/// Write the domain-separated canonical byte string of `key` into `out`:
/// `ROUTE_KEY_DOMAIN | host | 0 | port BE | 0 | path`. Returns the length,
/// or `None` if `out` cannot hold it.
pub fn route_key_canonical(key: &RouteKey<'_>, out: &mut [u8]) -> Option<usize> {
    let need = ROUTE_KEY_DOMAIN.len() + key.host.len() + 4 + key.path.len();
    if need > out.len() {
        return None;
    }
    let mut o = 0usize;
    out[o..o + ROUTE_KEY_DOMAIN.len()].copy_from_slice(ROUTE_KEY_DOMAIN);
    o += ROUTE_KEY_DOMAIN.len();
    out[o..o + key.host.len()].copy_from_slice(key.host);
    o += key.host.len();
    out[o] = 0;
    out[o + 1] = (key.port >> 8) as u8;
    out[o + 2] = key.port as u8;
    out[o + 3] = 0;
    o += 4;
    out[o..o + key.path.len()].copy_from_slice(key.path);
    o += key.path.len();
    Some(o)
}

/// SHA-256 of [`route_key_canonical`], with the hash injected rather than
/// mounted: a consumer hashes a key it already holds without re-parsing the
/// request, and this file stays free of crypto.
///
/// `None` for a key whose canonical form does not fit `ROUTE_KEY_CANON_BYTES`.
/// Derivation never yields one, but the fields are public, so a caller can
/// assemble a key no parse would produce; answering that with the digest of a
/// shorter string would place two origins together.
pub fn route_key_digest(key: &RouteKey<'_>, sha256: fn(&[u8]) -> [u8; 32]) -> Option<[u8; 32]> {
    let mut buf = [0u8; ROUTE_KEY_CANON_BYTES];
    let n = route_key_canonical(key, &mut buf)?;
    Some(sha256(&buf[..n]))
}

// ── Target forms ──────────────────────────────────────────────────────────

fn classify_target(target: &[u8]) -> Result<TargetForm<'_>, RouteKeyError> {
    if target.is_empty() {
        return Err(RouteKeyError::BadTarget);
    }
    let mut i = 0;
    while i < target.len() {
        if target[i] == b'#' {
            // RFC 9112 §3.2: a request-target never carries a fragment.
            return Err(RouteKeyError::BadTarget);
        }
        i += 1;
    }
    if target == b"*" {
        return Ok(TargetForm::Asterisk);
    }
    if target[0] == b'/' {
        if target.len() > 1 && target[1] == b'/' {
            // `//host/x` reads as a network-path reference to one party and
            // as a path to another.
            return Err(RouteKeyError::BadTarget);
        }
        let (path, query) = split_query(target);
        return Ok(TargetForm::Origin { path, query });
    }
    if let Some(at) = scheme_end(target) {
        let rest = &target[at + 3..];
        let mut e = 0;
        while e < rest.len() && rest[e] != b'/' && rest[e] != b'?' {
            e += 1;
        }
        let authority = &rest[..e];
        let (path, query) = split_query(&rest[e..]);
        return Ok(TargetForm::Absolute {
            authority,
            path,
            query,
        });
    }
    Ok(TargetForm::Authority(target))
}

/// Offset of `://` when `target` opens with an RFC 3986 scheme, else `None`.
fn scheme_end(target: &[u8]) -> Option<usize> {
    if target.is_empty() || !target[0].is_ascii_alphabetic() {
        return None;
    }
    let mut i = 1;
    while i < target.len() {
        let b = target[i];
        if b == b':' {
            break;
        }
        if !(b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.') {
            return None;
        }
        i += 1;
    }
    if i + 2 < target.len() && target[i] == b':' && target[i + 1] == b'/' && target[i + 2] == b'/' {
        Some(i)
    } else {
        None
    }
}

fn split_query(s: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'?' {
            return (&s[..i], &s[i + 1..]);
        }
        i += 1;
    }
    (s, &[])
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = v.len();
    while s < e && (v[s] == b' ' || v[s] == b'\t') {
        s += 1;
    }
    while e > s && (v[e - 1] == b' ' || v[e - 1] == b'\t') {
        e -= 1;
    }
    &v[s..e]
}

// ── Host ──────────────────────────────────────────────────────────────────

/// Canonicalise `src` (`host[:port]` or `[v6][:port]`) into `dst`. Returns
/// `(host_len, port, port_was_explicit)`.
fn norm_host(
    src: &[u8],
    default_port: u16,
    dst: &mut [u8; MAX_ROUTE_HOST],
) -> Result<(usize, u16, bool), RouteKeyError> {
    if src.is_empty() {
        return Err(RouteKeyError::EmptyHost);
    }
    if src.len() > MAX_ROUTE_HOST + PORT_SUFFIX_MAX {
        return Err(RouteKeyError::Oversize);
    }
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        if b >= 0x80 || b == b'%' {
            return Err(RouteKeyError::NonAscii);
        }
        if b == b'@' {
            return Err(RouteKeyError::BadHost);
        }
        i += 1;
    }

    let (host_end, rest_at) = if src[0] == b'[' {
        let mut j = 1;
        while j < src.len() && src[j] != b']' {
            j += 1;
        }
        if j == src.len() || !ipv6_ok(&src[1..j]) {
            return Err(RouteKeyError::BadHost);
        }
        (j + 1, j + 1)
    } else {
        let mut c = 0;
        while c < src.len() && src[c] != b':' {
            c += 1;
        }
        let mut k = c + 1;
        while k < src.len() {
            if src[k] == b':' {
                // A second colon is an unbracketed IPv6 literal.
                return Err(RouteKeyError::BadHost);
            }
            k += 1;
        }
        if !reg_name_ok(&src[..c]) {
            return Err(RouteKeyError::BadHost);
        }
        (c, c)
    };

    let mut len = host_end;
    // One trailing dot: `example.com.` is the same name, fully qualified.
    if src[0] != b'[' && len > 1 && src[len - 1] == b'.' {
        len -= 1;
    }
    if len == 0 {
        return Err(RouteKeyError::EmptyHost);
    }
    if len > MAX_ROUTE_HOST {
        return Err(RouteKeyError::Oversize);
    }
    let mut k = 0;
    while k < len {
        dst[k] = src[k].to_ascii_lowercase();
        k += 1;
    }

    let rest = &src[rest_at..];
    if rest.is_empty() {
        return Ok((len, default_port, false));
    }
    if rest[0] != b':' {
        return Err(RouteKeyError::BadHost);
    }
    let digits = &rest[1..];
    if digits.is_empty() {
        // RFC 3986 §6.2.3: an empty port is the default port.
        return Ok((len, default_port, false));
    }
    if digits.len() > 5 {
        return Err(RouteKeyError::BadPort);
    }
    let mut port: u32 = 0;
    let mut d = 0;
    while d < digits.len() {
        if !digits[d].is_ascii_digit() {
            return Err(RouteKeyError::BadPort);
        }
        port = port * 10 + (digits[d] - b'0') as u32;
        d += 1;
    }
    if !(1..=65535).contains(&port) {
        return Err(RouteKeyError::BadPort);
    }
    Ok((len, port as u16, true))
}

/// A registered name: labels of `ALPHA / DIGIT / "-" / "_" / "~"`, dot
/// separated, no empty label. A single trailing dot is admitted here and
/// stripped by the caller afterwards, so `example.com.` passes as the name
/// it is. Sub-delims are RFC 3986-legal in a reg-name and refused here: no
/// name a resolver answers contains one, and a key that admits them has two
/// spellings for `a;b`.
fn reg_name_ok(h: &[u8]) -> bool {
    if h.is_empty() {
        // The caller reports EmptyHost.
        return true;
    }
    if h[0] == b'.' {
        return false;
    }
    let mut i = 0;
    while i < h.len() {
        let b = h[i];
        let ok = b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'~' || b == b'.';
        if !ok {
            return false;
        }
        if b == b'.' && i + 1 < h.len() && h[i + 1] == b'.' {
            return false;
        }
        i += 1;
    }
    true
}

fn ipv6_ok(s: &[u8]) -> bool {
    if s.len() < 2 || s.len() > 45 {
        return false;
    }
    let mut groups = 0usize;
    let mut compressed = false;
    let mut i = 0;
    if s[0] == b':' {
        if s[1] != b':' {
            return false;
        }
        compressed = true;
        i = 2;
        if i == s.len() {
            return true;
        }
    }
    loop {
        let start = i;
        while i < s.len() && s[i] != b':' {
            i += 1;
        }
        let g = &s[start..i];
        if g.is_empty() {
            return false;
        }
        let mut dotted = false;
        let mut k = 0;
        while k < g.len() {
            if g[k] == b'.' {
                dotted = true;
            }
            k += 1;
        }
        if dotted {
            if !ipv4_ok(g) || i != s.len() {
                return false;
            }
            groups += 2;
        } else {
            if g.len() > 4 {
                return false;
            }
            let mut k = 0;
            while k < g.len() {
                if !g[k].is_ascii_hexdigit() {
                    return false;
                }
                k += 1;
            }
            groups += 1;
        }
        if groups > 8 {
            return false;
        }
        if i == s.len() {
            break;
        }
        i += 1;
        if i == s.len() {
            return false;
        }
        if s[i] == b':' {
            if compressed {
                return false;
            }
            compressed = true;
            i += 1;
            if i == s.len() {
                break;
            }
        }
    }
    if compressed {
        groups < 8
    } else {
        groups == 8
    }
}

fn ipv4_ok(s: &[u8]) -> bool {
    let mut parts = 0usize;
    let mut i = 0;
    while i <= s.len() {
        let start = i;
        let mut v: u32 = 0;
        while i < s.len() && s[i] != b'.' {
            if !s[i].is_ascii_digit() || i - start >= 3 {
                return false;
            }
            v = v * 10 + (s[i] - b'0') as u32;
            i += 1;
        }
        if i == start || v > 255 {
            return false;
        }
        parts += 1;
        i += 1;
    }
    parts == 4
}

// ── Path ──────────────────────────────────────────────────────────────────

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
}

fn pchar_ok(b: u8) -> bool {
    unreserved(b)
        || matches!(
            b,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encoding normalisation then remove-dot-segments, into `dst`.
/// Returns the canonical length. An empty `src` is the root.
fn norm_path(src: &[u8], dst: &mut [u8; MAX_ROUTE_PATH]) -> Result<usize, RouteKeyError> {
    if src.len() > MAX_ROUTE_PATH {
        return Err(RouteKeyError::Oversize);
    }
    if src.is_empty() {
        dst[0] = b'/';
        return Ok(1);
    }
    let mut i = 0;
    let mut o = 0;
    while i < src.len() {
        let b = src[i];
        if b == b'%' {
            if i + 2 >= src.len() {
                return Err(RouteKeyError::BadPath);
            }
            let (h, l) = match (hex_val(src[i + 1]), hex_val(src[i + 2])) {
                (Some(h), Some(l)) => (h, l),
                _ => return Err(RouteKeyError::BadPath),
            };
            let v = (h << 4) | l;
            if unreserved(v) {
                dst[o] = v;
                o += 1;
            } else {
                dst[o] = b'%';
                dst[o + 1] = src[i + 1].to_ascii_uppercase();
                dst[o + 2] = src[i + 2].to_ascii_uppercase();
                o += 3;
            }
            i += 3;
        } else if b >= 0x80 {
            return Err(RouteKeyError::NonAscii);
        } else if pchar_ok(b) {
            dst[o] = b;
            o += 1;
            i += 1;
        } else {
            return Err(RouteKeyError::BadPath);
        }
    }
    let n = remove_dot_segments(dst, o);
    if n == 0 {
        dst[0] = b'/';
        return Ok(1);
    }
    Ok(n)
}

fn starts_with(s: &[u8], p: &[u8]) -> bool {
    s.len() >= p.len() && s[..p.len()] == *p
}

/// RFC 3986 §5.2.4, in place: the output never outruns the input cursor
/// because every step consumes at least as many bytes as it writes.
fn remove_dot_segments(buf: &mut [u8], n: usize) -> usize {
    let mut r = 0usize;
    let mut w = 0usize;
    while r < n {
        let rest = &buf[r..n];
        if starts_with(rest, b"../") {
            r += 3;
        } else if starts_with(rest, b"./") || starts_with(rest, b"/./") {
            r += 2;
        } else if rest == b"/." {
            buf[r + 1] = b'/';
            r += 1;
        } else if starts_with(rest, b"/../") {
            r += 3;
            w = pop_segment(buf, w);
        } else if rest == b"/.." {
            buf[r + 2] = b'/';
            r += 2;
            w = pop_segment(buf, w);
        } else if rest == b"." || rest == b".." {
            r = n;
        } else {
            let mut e = r;
            if buf[e] == b'/' {
                e += 1;
            }
            while e < n && buf[e] != b'/' {
                e += 1;
            }
            buf.copy_within(r..e, w);
            w += e - r;
            r = e;
        }
    }
    w
}

fn pop_segment(buf: &[u8], mut w: usize) -> usize {
    while w > 0 {
        w -= 1;
        if buf[w] == b'/' {
            break;
        }
    }
    w
}
