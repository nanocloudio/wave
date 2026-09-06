//! SRTP packet-index and replay-window mechanics (RFC 3711 §3.3.1/§3.3.2).
//!
//! The packet-index state is portable across targets. The AEAD helpers below
//! use the repository's audited AES-GCM primitive so a provider can protect a
//! packet without allocating; platform hardware may replace that primitive
//! behind the same bounded call boundary.

// The SDK's AES-GCM primitive is include!'d whole; this file calls the 128-bit
// AEAD and the raw block function and nothing else. `allow` rather than
// `expect`: the PIC module build reaches every item through the public surface
// and reports nothing, so an expectation would go unfulfilled there while the
// host harness — which compiles this as an ordinary library — needs it.
#[allow(
    dead_code,
    reason = "SDK crypto primitive included whole; the callers here use one AEAD and one block function"
)]
mod aes_gcm {
    fn zeroize<T: AsMut<[u8]>>(value: &mut T) {
        for byte in value.as_mut() {
            *byte = 0;
        }
    }
    include!("../../target/fluxor/fluxor-abi/sdk/crypto/aes_gcm.rs");
}

mod sha1_core {
    include!("../../target/fluxor/fluxor-abi/sdk/crypto/sha1.rs");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrtpReplay {
    highest: u64,
    bitmap: u64,
    initialized: bool,
}

impl Default for SrtpReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl SrtpReplay {
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    pub fn accept(&mut self, index: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = index;
            self.bitmap = 1;
            return true;
        }
        if index > self.highest {
            let shift = index - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = index;
            return true;
        }
        let back = self.highest - index;
        if back >= 64 || (self.bitmap & (1u64 << back)) != 0 {
            return false;
        }
        self.bitmap |= 1u64 << back;
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

/// Estimate the 32-bit rollover counter for a sequence near the last packet.
pub fn estimate_roc(last_index: u64, sequence: u16) -> u64 {
    let last_seq = last_index as u16;
    let last_roc = last_index >> 16;
    if sequence < 0x8000 && last_seq > 0x8000 && last_roc > 0 {
        last_roc - 1
    } else if sequence > 0x8000 && last_seq < 0x8000 {
        last_roc + 1
    } else {
        last_roc
    }
}

/// Minimum authenticated packet shape for an SRTP profile. The crypto
/// provider performs AEAD; this validator keeps unauthenticated/truncated
/// packets out of that provider and gives SRTCP the same replay semantics.
pub const SRTP_AUTH_TAG_LEN: usize = 16;
pub const SRTCP_INDEX_LEN: usize = 4;

/// SRTP protection profile parameters used by browser/WebRTC deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrtpAeadProfile {
    pub master_key_len: usize,
    pub master_salt_len: usize,
    pub auth_tag_len: usize,
    pub nonce_len: usize,
}

pub const SRTP_AES128_CM_SHA1_80: SrtpAeadProfile = SrtpAeadProfile {
    master_key_len: 16,
    master_salt_len: 14,
    auth_tag_len: 10,
    nonce_len: 16,
};
pub const SRTP_AEAD_AES_128_GCM: SrtpAeadProfile = SrtpAeadProfile {
    master_key_len: 16,
    master_salt_len: 12,
    auth_tag_len: 16,
    nonce_len: 12,
};
pub const SRTP_AES_CM_KEY_LEN: usize = 16;
pub const SRTP_AES_CM_SALT_LEN: usize = 14;
pub const SRTP_AES_CM_AUTH_KEY_LEN: usize = 20;
pub const SRTP_AES_CM_TAG_LEN: usize = 10;
/// RFC 5764 §4.2 DTLS-SRTP exporter label.
pub const DTLS_SRTP_EXPORTER_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// Derive the AES-CM/HMAC-SHA1 session keys from one DTLS-SRTP master key and
/// salt (RFC 3711 §4.3). The exporter supplies only master material; the
/// encryption, authentication, and session-salt keys are separate KDF labels.
pub fn derive_aes_cm_session_keys(
    master_key: &[u8; 16],
    master_salt: &[u8; 14],
    enc_key: &mut [u8; 16],
    auth_key: &mut [u8; 20],
    session_salt: &mut [u8; 14],
) {
    fn derive(master_key: &[u8; 16], salt: &[u8; 14], label: u8, out: &mut [u8]) {
        let mut counter = [0u8; 16];
        counter[..14].copy_from_slice(salt);
        counter[7] ^= label;
        let mut written = 0usize;
        while written < out.len() {
            let mut block = counter;
            aes_gcm::aes128_ecb_encrypt_block(master_key, &mut block);
            let take = core::cmp::min(16, out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            let ctr = u16::from_be_bytes([counter[14], counter[15]])
                .wrapping_add(1)
                .to_be_bytes();
            counter[14] = ctr[0];
            counter[15] = ctr[1];
        }
    }
    derive(master_key, master_salt, 0x00, enc_key);
    derive(master_key, master_salt, 0x01, auth_key);
    derive(master_key, master_salt, 0x02, session_salt);
}

/// Derive one AES-GCM SRTP/SRTCP session context from DTLS master material.
/// Labels follow the SRTP KDF allocation: encryption and salting material are
/// distinct for SRTP (0/2) and SRTCP (3/5).
pub fn derive_aead_key_salt(
    master_key: &[u8; 16],
    master_salt: &[u8; 12],
    key_label: u8,
    salt_label: u8,
    key: &mut [u8; 16],
    salt: &mut [u8; 12],
) {
    let mut kdf_salt = [0u8; 14];
    kdf_salt[..12].copy_from_slice(master_salt);
    fn derive(master_key: &[u8; 16], salt: &[u8; 14], label: u8, out: &mut [u8]) {
        let mut counter = [0u8; 16];
        counter[..14].copy_from_slice(salt);
        counter[7] ^= label;
        let mut written = 0;
        while written < out.len() {
            let mut block = counter;
            aes_gcm::aes128_ecb_encrypt_block(master_key, &mut block);
            let take = core::cmp::min(16, out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            let n = u16::from_be_bytes([counter[14], counter[15]])
                .wrapping_add(1)
                .to_be_bytes();
            counter[14] = n[0];
            counter[15] = n[1];
        }
    }
    derive(master_key, &kdf_salt, key_label, key);
    derive(master_key, &kdf_salt, salt_label, salt);
}

/// Keying material yielded by a DTLS-SRTP exporter for the AES-GCM profile.
/// DTLS orders client write key, server write key, client salt, server salt;
/// keeping that ordering explicit prevents the common endpoint-direction swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtlsSrtpContext {
    pub client_key: [u8; 16],
    pub server_key: [u8; 16],
    pub client_salt: [u8; 12],
    pub server_salt: [u8; 12],
}

pub fn dtls_srtp_context(exported: &[u8]) -> Option<DtlsSrtpContext> {
    if exported.len() < 56 {
        return None;
    }
    let mut context = DtlsSrtpContext {
        client_key: [0; 16],
        server_key: [0; 16],
        client_salt: [0; 12],
        server_salt: [0; 12],
    };
    context.client_key.copy_from_slice(&exported[..16]);
    context.server_key.copy_from_slice(&exported[16..32]);
    context.client_salt.copy_from_slice(&exported[32..44]);
    context.server_salt.copy_from_slice(&exported[44..56]);
    Some(context)
}

/// Build the AES-GCM nonce for SRTP AEAD_AES_128_GCM (RFC 7714 §8.1).
/// The 12-byte master salt is XORed with the SSRC and packet index; the
/// explicit construction keeps nonce uniqueness tied to the replay index.
pub fn gcm_nonce(master_salt: &[u8; 12], ssrc: u32, index: u64) -> [u8; 12] {
    let mut nonce = *master_salt;
    let mut input = [0u8; 12];
    input[2..6].copy_from_slice(&ssrc.to_be_bytes());
    input[6..10].copy_from_slice(&((index >> 16) as u32).to_be_bytes());
    input[10..12].copy_from_slice(&(index as u16).to_be_bytes());
    let mut n = 0;
    while n < 12 {
        nonce[n] ^= input[n];
        n += 1;
    }
    nonce
}

/// RFC 7714 §9.1 SRTCP IV: `00 00 || SSRC || 00 00 || E|index`, XOR salt.
pub fn srtcp_gcm_nonce(master_salt: &[u8; 12], ssrc: u32, index: u32) -> [u8; 12] {
    let mut nonce = *master_salt;
    let mut input = [0u8; 12];
    input[2..6].copy_from_slice(&ssrc.to_be_bytes());
    input[8..12].copy_from_slice(&(index & 0x7fff_ffff).to_be_bytes());
    let mut n = 0;
    while n < 12 {
        nonce[n] ^= input[n];
        n += 1;
    }
    nonce
}

fn hmac_sha1(key: &[u8], data: &[u8], out: &mut [u8; 20]) {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..20].copy_from_slice(&sha1_core::sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0u8; 1600];
    let mut n = 0;
    while n < 64 {
        inner[n] = block[n] ^ 0x36;
        n += 1;
    }
    if 64 + data.len() > inner.len() {
        return;
    }
    inner[64..64 + data.len()].copy_from_slice(data);
    let inner_hash = sha1_core::sha1(&inner[..64 + data.len()]);
    let mut outer = [0u8; 84];
    n = 0;
    while n < 64 {
        outer[n] = block[n] ^ 0x5c;
        n += 1;
    }
    outer[64..].copy_from_slice(&inner_hash);
    *out = sha1_core::sha1(&outer);
}

fn aes_cm_xor(key: &[u8; 16], salt: &[u8; 14], ssrc: u32, index: u64, data: &mut [u8]) {
    let mut counter = [0u8; 16];
    counter[..14].copy_from_slice(salt);
    let s = ssrc.to_be_bytes();
    let i = index.to_be_bytes();
    let mut n = 0;
    while n < 4 {
        counter[4 + n] ^= s[n];
        n += 1;
    }
    while n < 8 {
        counter[8 + n - 4] ^= i[n];
        n += 1;
    }
    let mut block_no = 0u32;
    let mut at = 0;
    while at < data.len() {
        counter[12..].copy_from_slice(&block_no.to_be_bytes());
        let mut stream = counter;
        aes_gcm::aes128_ecb_encrypt_block(key, &mut stream);
        let take = core::cmp::min(16, data.len() - at);
        for j in 0..take {
            data[at + j] ^= stream[j];
        }
        at += take;
        block_no = block_no.wrapping_add(1);
    }
}

/// Protect an SRTP AES_CM_128_HMAC_SHA1_80 packet. The packet contains the
/// RTP header and plaintext payload; the 4-byte ROC is authenticated after the
/// RTP bytes and the ten-byte truncated HMAC is appended.
#[expect(
    clippy::too_many_arguments,
    reason = "profile keys, packet identity, and bounded in-place buffer are all required by the SRTP ABI"
)]
pub fn protect_aes_cm_sha1_80(
    enc_key: &[u8; 16],
    auth_key: &[u8; 20],
    salt: &[u8; 14],
    ssrc: u32,
    index: u64,
    packet: &mut [u8],
    header_len: usize,
    plain_len: usize,
) -> Option<usize> {
    if header_len > plain_len || plain_len > packet.len().saturating_sub(SRTP_AES_CM_TAG_LEN) {
        return None;
    }
    aes_cm_xor(
        enc_key,
        salt,
        ssrc,
        index,
        &mut packet[header_len..plain_len],
    );
    let mut auth = [0u8; 20];
    let mut input = [0u8; 1600];
    if plain_len + 4 > input.len() {
        return None;
    }
    input[..plain_len].copy_from_slice(&packet[..plain_len]);
    input[plain_len..plain_len + 4].copy_from_slice(&((index >> 16) as u32).to_be_bytes());
    hmac_sha1(auth_key, &input[..plain_len + 4], &mut auth);
    packet[plain_len..plain_len + SRTP_AES_CM_TAG_LEN]
        .copy_from_slice(&auth[..SRTP_AES_CM_TAG_LEN]);
    Some(plain_len + SRTP_AES_CM_TAG_LEN)
}

/// Authenticate and decrypt an AES-CM/SHA1-80 packet in place.
pub fn unprotect_aes_cm_sha1_80(
    enc_key: &[u8; 16],
    auth_key: &[u8; 20],
    salt: &[u8; 14],
    ssrc: u32,
    index: u64,
    packet: &mut [u8],
    header_len: usize,
) -> Option<usize> {
    if packet.len() <= SRTP_AES_CM_TAG_LEN {
        return None;
    }
    let plain_len = packet.len() - SRTP_AES_CM_TAG_LEN;
    if header_len > plain_len {
        return None;
    }
    let mut input = [0u8; 1600];
    if plain_len + 4 > input.len() {
        return None;
    }
    input[..plain_len].copy_from_slice(&packet[..plain_len]);
    input[plain_len..plain_len + 4].copy_from_slice(&((index >> 16) as u32).to_be_bytes());
    let mut auth = [0u8; 20];
    hmac_sha1(auth_key, &input[..plain_len + 4], &mut auth);
    let mut diff = 0u8;
    for i in 0..SRTP_AES_CM_TAG_LEN {
        diff |= auth[i] ^ packet[plain_len + i];
    }
    if diff != 0 {
        return None;
    }
    aes_cm_xor(
        enc_key,
        salt,
        ssrc,
        index,
        &mut packet[header_len..plain_len],
    );
    Some(plain_len)
}

/// Protect an RTP packet in place and append its 16-byte AEAD tag.
/// `packet` must contain the RTP header and plaintext payload, with capacity
/// for `SRTP_AUTH_TAG_LEN` additional bytes. The RTP bytes are authenticated
/// as AAD, as required by RFC 7714.
pub fn protect_aes128_gcm(
    master_key: &[u8; 16],
    master_salt: &[u8; 12],
    ssrc: u32,
    index: u64,
    packet: &mut [u8],
    header_len: usize,
    plain_len: usize,
) -> Option<usize> {
    if header_len > plain_len || plain_len > packet.len().saturating_sub(SRTP_AUTH_TAG_LEN) {
        return None;
    }
    let nonce = gcm_nonce(master_salt, ssrc, index);
    let aead = aes_gcm::AesGcm::new_128(master_key);
    let mut aad = [0u8; 256];
    if header_len > aad.len() {
        return None;
    }
    aad[..header_len].copy_from_slice(&packet[..header_len]);
    let tag = aead.encrypt(
        &nonce,
        &aad[..header_len],
        &mut packet[header_len..plain_len],
    );
    packet[plain_len..plain_len + SRTP_AUTH_TAG_LEN].copy_from_slice(&tag);
    Some(plain_len + SRTP_AUTH_TAG_LEN)
}

/// Authenticate and decrypt an SRTP AES-GCM packet in place. The tag is
/// checked before plaintext is exposed; on failure the ciphertext is left
/// untouched and `None` is returned.
pub fn unprotect_aes128_gcm(
    master_key: &[u8; 16],
    master_salt: &[u8; 12],
    ssrc: u32,
    index: u64,
    packet: &mut [u8],
    header_len: usize,
) -> Option<usize> {
    if packet.len() <= SRTP_AUTH_TAG_LEN {
        return None;
    }
    let plain_len = packet.len() - SRTP_AUTH_TAG_LEN;
    let mut tag = [0u8; SRTP_AUTH_TAG_LEN];
    tag.copy_from_slice(&packet[plain_len..]);
    if header_len > plain_len {
        return None;
    }
    let nonce = gcm_nonce(master_salt, ssrc, index);
    let mut aad = [0u8; 256];
    if header_len > aad.len() {
        return None;
    }
    aad[..header_len].copy_from_slice(&packet[..header_len]);
    let aead = aes_gcm::AesGcm::new_128(master_key);
    if !aead.decrypt(
        &nonce,
        &aad[..header_len],
        &mut packet[header_len..plain_len],
        &tag,
    ) {
        return None;
    }
    Some(plain_len)
}

/// Protect an SRTCP compound packet with AEAD_AES_128_GCM. The caller passes
/// an RTCP packet including its fixed header and SSRC; the 32-bit SRTCP index
/// is appended before the authentication tag and is authenticated as AAD.
pub fn protect_srtcp_aes128_gcm(
    master_key: &[u8; 16],
    master_salt: &[u8; 12],
    packet: &mut [u8],
    plain_len: usize,
    index: u32,
) -> Option<usize> {
    if plain_len < 8 || plain_len > packet.len().saturating_sub(SRTP_AUTH_TAG_LEN + 4) {
        return None;
    }
    let ssrc = u32::from_be_bytes(packet[4..8].try_into().ok()?);
    let index_at = plain_len;
    let index_word = (index & 0x7fff_ffff) | 0x8000_0000;
    packet[index_at..index_at + 4].copy_from_slice(&index_word.to_be_bytes());
    let nonce = srtcp_gcm_nonce(master_salt, ssrc, index);
    let mut aad = [0u8; 12];
    aad[..8].copy_from_slice(&packet[..8]);
    aad[8..12].copy_from_slice(&packet[index_at..index_at + 4]);
    let aead = aes_gcm::AesGcm::new_128(master_key);
    let tag = aead.encrypt(&nonce, &aad, &mut packet[8..plain_len]);
    packet[plain_len + 4..plain_len + 4 + SRTP_AUTH_TAG_LEN].copy_from_slice(&tag);
    Some(plain_len + 4 + SRTP_AUTH_TAG_LEN)
}

/// Authenticate and decrypt an SRTCP AES-GCM packet in place. The index is
/// retained in the packet until the caller applies replay-window admission.
pub fn unprotect_srtcp_aes128_gcm(
    master_key: &[u8; 16],
    master_salt: &[u8; 12],
    packet: &mut [u8],
) -> Option<(usize, u32)> {
    if packet.len() < 8 + 4 + SRTP_AUTH_TAG_LEN {
        return None;
    }
    let tag_at = packet.len() - SRTP_AUTH_TAG_LEN;
    let index_at = tag_at - 4;
    let index_word = u32::from_be_bytes(packet[index_at..tag_at].try_into().ok()?);
    if index_word & 0x8000_0000 == 0 {
        return None;
    }
    let index = index_word & 0x7fff_ffff;
    let ssrc = u32::from_be_bytes(packet[4..8].try_into().ok()?);
    let nonce = srtcp_gcm_nonce(master_salt, ssrc, index);
    let mut aad = [0u8; 12];
    aad[..8].copy_from_slice(&packet[..8]);
    aad[8..12].copy_from_slice(&packet[index_at..tag_at]);
    let mut tag = [0u8; SRTP_AUTH_TAG_LEN];
    tag.copy_from_slice(&packet[tag_at..]);
    let aead = aes_gcm::AesGcm::new_128(master_key);
    if !aead.decrypt(&nonce, &aad, &mut packet[8..index_at], &tag) {
        return None;
    }
    Some((index_at, index))
}

/// Construct the RFC 3711 packet index used by key derivation and replay
/// protection. The caller supplies the rollover counter selected by the
/// packet-index estimator and the RTP sequence from the header.
pub const fn packet_index(roc: u32, sequence: u16) -> u64 {
    ((roc as u64) << 16) | sequence as u64
}

pub fn validate_srtp_packet(packet: &[u8], tag_len: usize) -> Option<(&[u8], &[u8])> {
    if tag_len == 0 || packet.len() <= tag_len {
        return None;
    }
    let split = packet.len() - tag_len;
    Some((&packet[..split], &packet[split..]))
}

pub fn validate_srtcp_packet(packet: &[u8], tag_len: usize) -> Option<(&[u8], u32, &[u8])> {
    if packet.len() < SRTCP_INDEX_LEN + tag_len {
        return None;
    }
    let tag_at = packet.len() - tag_len;
    let index_at = tag_at - SRTCP_INDEX_LEN;
    let index = u32::from_be_bytes(packet[index_at..tag_at].try_into().ok()?);
    Some((&packet[..index_at], index, &packet[tag_at..]))
}
