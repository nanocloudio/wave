//! Bounded Annex-B access-unit scanner for RTP video adapters.
//!
//! Spectra emits H.264 elementary streams as Annex-B NAL units. This scanner
//! identifies one complete NAL in a borrowed chunk without allocating or
//! copying; the caller can pass it directly to the RFC 6184 FU-A packetizer.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnexBNal<'a> {
    pub bytes: &'a [u8],
    pub keyframe: bool,
}

pub struct AnnexB<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> AnnexB<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn start_at(&self, from: usize) -> Option<(usize, usize)> {
        let b = self.input;
        let mut i = from;
        while i + 3 <= b.len() {
            if b[i] == 0 && b[i + 1] == 0 {
                if b[i + 2] == 1 {
                    return Some((i, 3));
                }
                if i + 4 <= b.len() && b[i + 2] == 0 && b[i + 3] == 1 {
                    return Some((i, 4));
                }
            }
            i += 1;
        }
        None
    }

    fn next_nal(&mut self) -> Option<AnnexBNal<'a>> {
        let (start, prefix) = self.start_at(self.cursor)?;
        let body = start + prefix;
        let end = self
            .start_at(body)
            .map(|(next, _)| next)
            .unwrap_or(self.input.len());
        self.cursor = end;
        if body >= end {
            return self.next();
        }
        let bytes = &self.input[body..end];
        let nal_type = bytes[0] & 0x1f;
        Some(AnnexBNal {
            bytes,
            keyframe: nal_type == 5,
        })
    }
}

impl<'a> Iterator for AnnexB<'a> {
    type Item = AnnexBNal<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_nal()
    }
}
