// Scalar UTF-8 validation for PIC modules, without an external libcore call.
// Reject overlong encodings, surrogate code points, and values above U+10FFFF.
pub fn valid_utf8(mut bytes: &[u8]) -> bool {
    while let Some(&first) = bytes.first() {
        let (n, low, high) = match first {
            0..=0x7f => {
                bytes = &bytes[1..];
                continue;
            }
            0xc2..=0xdf => (2, 0x80, 0xbf),
            0xe0 => (3, 0xa0, 0xbf),
            0xe1..=0xec | 0xee..=0xef => (3, 0x80, 0xbf),
            0xed => (3, 0x80, 0x9f),
            0xf0 => (4, 0x90, 0xbf),
            0xf1..=0xf3 => (4, 0x80, 0xbf),
            0xf4 => (4, 0x80, 0x8f),
            _ => return false,
        };
        if bytes.len() < n || bytes[1] < low || bytes[1] > high {
            return false;
        }
        for &b in &bytes[2..n] {
            if !(0x80..=0xbf).contains(&b) {
                return false;
            }
        }
        bytes = &bytes[n..];
    }
    true
}
