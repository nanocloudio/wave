//! Where a datagram connector sends, named once as `host[:port]`.
//!
//! The text is kept as configured and parsed when the module is
//! constructed, so an authority that is not one refuses construction with
//! a reason rather than sending packets nowhere. A literal is sent to as
//! an address; a name travels as a name on `CMD_DG_SEND_TO` for the
//! network provider to resolve, and the first datagram after the answer
//! lands is the one that goes out.
//!
//! The datagram surface here is IPv4: a v6 literal is refused by `adopt`.

// The single mount of the SDK contract for this file: the authority
// grammar lives with the wire record that carries it, so a connector
// never writes its own parser.
#[path = "../../target/fluxor/fluxor-abi/sdk/contracts/net/net_proto.rs"]
pub mod net_proto;

use net_proto::{name_ok, parse_v4};

/// Longest authority a connector keeps: a 63-byte label with a port fits,
/// and a longer name is refused rather than truncated into a different
/// host.
pub const DG_AUTHORITY_MAX: usize = 64;

/// One `host[:port]` as configured, resolved into the form a send takes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DgAuthority {
    text: [u8; DG_AUTHORITY_MAX],
    len: u8,
    /// The text offered was longer than the buffer; `adopt` refuses it.
    overflow: u8,
    /// Host-order IPv4 of a literal authority, 0 for a name.
    ip: u32,
    /// The address a named authority has been seen at: the source of the
    /// first datagram accepted for it. 0 until then.
    learned: u32,
    /// Length of the host when it is a name (a prefix of `text`), else 0.
    host_len: u8,
    _pad: u8,
    /// The authority's port, or the protocol default; 0 until `adopt`.
    port: u16,
}

impl DgAuthority {
    pub const fn empty() -> Self {
        DgAuthority {
            text: [0; DG_AUTHORITY_MAX],
            len: 0,
            overflow: 0,
            ip: 0,
            learned: 0,
            host_len: 0,
            _pad: 0,
            port: 0,
        }
    }

    pub fn clear(&mut self) {
        *self = DgAuthority::empty();
    }

    /// Keep `text` as written. Longer than `DG_AUTHORITY_MAX` is recorded
    /// as an overflow, so `adopt` refuses it by name.
    pub fn set(&mut self, text: &[u8]) {
        self.clear();
        if text.len() > DG_AUTHORITY_MAX {
            self.overflow = 1;
            return;
        }
        self.text[..text.len()].copy_from_slice(text);
        self.len = text.len() as u8;
    }

    /// Parse the kept text as `host[:port]`, `default_port` applying when
    /// it names none. `false` when nothing was set, the text overflowed,
    /// it is not an authority, or it is a v6 literal.
    pub fn adopt(&mut self, default_port: u16) -> bool {
        if self.overflow != 0 || self.len == 0 {
            return false;
        }
        let text = self.text;
        let len = self.len as usize;
        let Some((host, port)) = split_host_port(&text[..len], default_port) else {
            return false;
        };
        // v4-or-name, which is what this surface carries: a bracketed v6
        // literal is not one, and the grammar for it is not compiled in.
        if let Some(a) = parse_v4(host) {
            self.ip = u32::from_be_bytes(a);
            self.host_len = 0;
        } else if name_ok(host) {
            self.ip = 0;
            self.host_len = host.len() as u8;
        } else {
            return false;
        }
        self.port = port;
        true
    }

    /// Some text was offered, whether or not it fit: an optional
    /// authority that was given must still parse.
    pub fn offered(&self) -> bool {
        self.len > 0 || self.overflow != 0
    }

    /// Text was set and `adopt` accepted it.
    pub fn is_set(&self) -> bool {
        self.len > 0 && self.port != 0
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn text(&self) -> &[u8] {
        &self.text[..self.len as usize]
    }

    /// Host-order IPv4 of a literal authority; `None` for a name, which
    /// the provider resolves.
    pub fn ip(&self) -> Option<u32> {
        if self.host_len == 0 && self.ip != 0 {
            Some(self.ip)
        } else {
            None
        }
    }

    /// The host when the authority is a name.
    pub fn name(&self) -> Option<&[u8]> {
        if self.host_len == 0 {
            None
        } else {
            Some(&self.text[..self.host_len as usize])
        }
    }

    /// Whether `ip` (host order) and `port` are the peer this authority
    /// names.
    ///
    /// A literal is compared as configured. A name has no address to
    /// compare until one answers, so the FIRST source on the port is taken
    /// as the peer and every later datagram is held to it — one stranger
    /// can win the race, where without the latch every stranger would be
    /// admitted for as long as the session lasts.
    pub fn matches(&self, ip: u32, port: u16) -> bool {
        if port != self.port {
            return false;
        }
        if self.host_len == 0 {
            return ip == self.ip;
        }
        self.learned == 0 || ip == self.learned
    }

    /// Take `ip` as the address of a named peer, if none has been taken.
    /// A caller records it once the datagram has been accepted.
    pub fn learn(&mut self, ip: u32) {
        if self.host_len != 0 && self.learned == 0 {
            self.learned = ip;
        }
    }
}

/// Split `host[:port]`, answering the host and the port it names or
/// `default_port`. `None` when the text is not that shape: an empty host, a
/// port that is not 1..=65535, or more than one `:` — which is what a
/// bracketless v6 literal looks like here, and this surface carries none.
fn split_host_port(text: &[u8], default_port: u16) -> Option<(&[u8], u16)> {
    let mut colons = 0usize;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < text.len() {
        if text[i] == b':' {
            colons += 1;
            last = i;
        }
        i += 1;
    }
    match colons {
        0 => {
            if text.is_empty() {
                None
            } else {
                Some((text, default_port))
            }
        }
        1 => {
            let host = &text[..last];
            let digits = &text[last + 1..];
            if host.is_empty() || digits.is_empty() || digits.len() > 5 {
                return None;
            }
            let mut port: u32 = 0;
            for &c in digits {
                if !c.is_ascii_digit() {
                    return None;
                }
                port = port * 10 + u32::from(c - b'0');
            }
            if port == 0 || port > u32::from(u16::MAX) {
                return None;
            }
            Some((host, port as u16))
        }
        _ => None,
    }
}
