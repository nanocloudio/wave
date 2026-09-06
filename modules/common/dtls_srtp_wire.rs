//! Fixed-size DTLS-SRTP exporter handoff between the DTLS owner and media.
//!
//! The DTLS implementation owns the handshake and private state.  It publishes
//! one generation-scoped record; RTP/RTCP consume it and never retain DTLS
//! secrets.  The fixed layout is suitable for Fluxor channels on tiny targets.

pub const DTLS_SRTP_CONTEXT_VERSION: u8 = 1;
pub const DTLS_SRTP_PROFILE_GCM: u8 = 0;
pub const DTLS_SRTP_PROFILE_AES_CM_SHA1_80: u8 = 1;
pub const DTLS_SRTP_CONTEXT_LEN: usize = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtlsSrtpWireContext {
    pub session: u32,
    pub generation: u32,
    pub role: u8,
    pub profile: u8,
    pub exporter: [u8; 60],
}

impl DtlsSrtpWireContext {
    pub const fn empty() -> Self {
        Self {
            session: 0,
            generation: 0,
            role: 0,
            profile: DTLS_SRTP_PROFILE_GCM,
            exporter: [0; 60],
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < DTLS_SRTP_CONTEXT_LEN || self.role > 1 || self.profile > 1 {
            return None;
        }
        out[0] = DTLS_SRTP_CONTEXT_VERSION;
        out[1] = self.role;
        out[2] = self.profile;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.session.to_le_bytes());
        out[8..12].copy_from_slice(&self.generation.to_le_bytes());
        out[12..].copy_from_slice(&self.exporter);
        Some(DTLS_SRTP_CONTEXT_LEN)
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != DTLS_SRTP_CONTEXT_LEN
            || buf[0] != DTLS_SRTP_CONTEXT_VERSION
            || buf[1] > 1
            || buf[2] > 1
            || buf[3] != 0
        {
            return None;
        }
        let mut exporter = [0; 60];
        exporter.copy_from_slice(&buf[12..]);
        Some(Self {
            session: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            generation: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            role: buf[1],
            profile: buf[2],
            exporter,
        })
    }
}
