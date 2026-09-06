//! Incremental HTTP/1 response framing with bounded metadata and streamed bodies.
//! An EOF completes only a valid close-delimited response, never a partial head,
//! fixed-length body or chunked body. No allocation and no transport ownership.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Head,
    Fixed,
    UntilClose,
    ChunkSize,
    ChunkData,
    ChunkCr,
    ChunkLf,
    Trailer,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    Malformed,
    Oversize,
    Incomplete,
    Unsupported,
}

pub struct ResponseDecoder {
    phase: Phase,
    scratch: [u8; 2048],
    len: usize,
    metadata: usize,
    remaining: u64,
    informationals: u8,
    head_request: bool,
    connect_request: bool,
    pub status: u16,
    pub reusable: bool,
}

impl Default for ResponseDecoder {
    fn default() -> Self {
        Self::new(false, false)
    }
}

impl ResponseDecoder {
    pub const fn new(head_request: bool, connect_request: bool) -> Self {
        Self {
            phase: Phase::Head,
            scratch: [0; 2048],
            len: 0,
            metadata: 0,
            remaining: 0,
            informationals: 0,
            head_request,
            connect_request,
            status: 0,
            reusable: false,
        }
    }
    pub fn done(&self) -> bool {
        self.phase == Phase::Done
    }
    pub fn has_head(&self) -> bool {
        self.status != 0
    }
    pub fn eof(&mut self) -> Result<(), ResponseError> {
        if self.phase == Phase::UntilClose {
            self.phase = Phase::Done;
        }
        if self.done() {
            Ok(())
        } else {
            Err(ResponseError::Incomplete)
        }
    }
    /// Returns input consumed and decoded body bytes produced. Once output is
    /// full, the caller retains the unconsumed input until downstream accepts it.
    pub fn consume(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), ResponseError> {
        let (mut at, mut written) = (0, 0);
        while at < input.len() && !self.done() {
            match self.phase {
                Phase::Head | Phase::ChunkSize | Phase::Trailer => {
                    if self.len == self.scratch.len() || self.metadata >= 16384 {
                        return Err(ResponseError::Oversize);
                    }
                    self.scratch[self.len] = input[at];
                    self.len += 1;
                    at += 1;
                    self.metadata += 1;
                    if self.phase == Phase::Head {
                        if self.len >= 4 && &self.scratch[self.len - 4..self.len] == b"\r\n\r\n" {
                            self.head()?;
                        }
                    } else if self.len >= 2 && &self.scratch[self.len - 2..self.len] == b"\r\n" {
                        if self.phase == Phase::ChunkSize {
                            let line = &self.scratch[..self.len - 2];
                            let digits = line.split(|b| *b == b';').next().unwrap_or(&[]);
                            if digits.is_empty()
                                || digits.len() > 16
                                || line.iter().any(|b| *b < 32 || *b == 127)
                            {
                                return Err(ResponseError::Malformed);
                            }
                            let mut size = 0u64;
                            for b in digits {
                                let d = match b {
                                    b'0'..=b'9' => b - b'0',
                                    b'a'..=b'f' => b - b'a' + 10,
                                    b'A'..=b'F' => b - b'A' + 10,
                                    _ => return Err(ResponseError::Malformed),
                                };
                                size = size
                                    .checked_mul(16)
                                    .and_then(|v| v.checked_add(d as u64))
                                    .ok_or(ResponseError::Malformed)?;
                            }
                            // Bound each size line and the final trailer section,
                            // not the number of chunks in an arbitrarily long body.
                            self.metadata = 0;
                            self.remaining = size;
                            self.phase = if size == 0 {
                                Phase::Trailer
                            } else {
                                Phase::ChunkData
                            };
                        } else if self.len == 2 {
                            self.phase = Phase::Done;
                        } else {
                            let (name, _) = field(&self.scratch[..self.len - 2])?;
                            if name.eq_ignore_ascii_case(b"content-length")
                                || name.eq_ignore_ascii_case(b"transfer-encoding")
                            {
                                return Err(ResponseError::Malformed);
                            }
                        }
                        self.len = 0;
                    }
                }
                Phase::Fixed | Phase::UntilClose | Phase::ChunkData => {
                    let limit = if self.phase == Phase::UntilClose {
                        usize::MAX
                    } else {
                        usize::try_from(self.remaining).unwrap_or(usize::MAX)
                    };
                    let n = (input.len() - at).min(output.len() - written).min(limit);
                    if n == 0 {
                        break;
                    }
                    output[written..written + n].copy_from_slice(&input[at..at + n]);
                    written += n;
                    at += n;
                    if self.phase != Phase::UntilClose {
                        self.remaining -= n as u64;
                        if self.remaining == 0 {
                            self.phase = if self.phase == Phase::Fixed {
                                Phase::Done
                            } else {
                                Phase::ChunkCr
                            };
                        }
                    }
                }
                Phase::ChunkCr => {
                    if input[at] != b'\r' {
                        return Err(ResponseError::Malformed);
                    }
                    at += 1;
                    self.phase = Phase::ChunkLf;
                }
                Phase::ChunkLf => {
                    if input[at] != b'\n' {
                        return Err(ResponseError::Malformed);
                    }
                    at += 1;
                    self.phase = Phase::ChunkSize;
                }
                Phase::Done => break,
            }
        }
        Ok((at, written))
    }
    fn head(&mut self) -> Result<(), ResponseError> {
        let end = self.scratch[..self.len]
            .windows(2)
            .position(|p| p == b"\r\n")
            .ok_or(ResponseError::Malformed)?;
        let status_line = &self.scratch[..end];
        if status_line.len() < 13
            || !(status_line.starts_with(b"HTTP/1.1 ") || status_line.starts_with(b"HTTP/1.0 "))
            || status_line[12] != b' '
            || !status_line[9..12].iter().all(u8::is_ascii_digit)
        {
            return Err(ResponseError::Malformed);
        }
        let status = (status_line[9] - b'0') as u16 * 100
            + (status_line[10] - b'0') as u16 * 10
            + (status_line[11] - b'0') as u16;
        if !(100..=599).contains(&status) {
            return Err(ResponseError::Malformed);
        }
        let mut length = None;
        let mut chunked = false;
        let mut close = false;
        let mut keep = false;
        let mut at = end + 2;
        while at + 2 < self.len {
            let n = self.scratch[at..self.len]
                .windows(2)
                .position(|p| p == b"\r\n")
                .ok_or(ResponseError::Malformed)?;
            if n == 0 {
                break;
            }
            let (name, value) = field(&self.scratch[at..at + n])?;
            if name.eq_ignore_ascii_case(b"content-length") {
                if length.is_some() || value.is_empty() {
                    return Err(ResponseError::Malformed);
                }
                let mut size = 0u64;
                for b in value {
                    if !b.is_ascii_digit() {
                        return Err(ResponseError::Malformed);
                    }
                    size = size
                        .checked_mul(10)
                        .and_then(|v| v.checked_add((b - b'0') as u64))
                        .ok_or(ResponseError::Malformed)?;
                }
                length = Some(size);
            } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                if chunked
                    || !value.eq_ignore_ascii_case(b"chunked")
                    || status_line.starts_with(b"HTTP/1.0")
                {
                    return Err(ResponseError::Unsupported);
                }
                chunked = true;
            } else if name.eq_ignore_ascii_case(b"connection") {
                for token in value.split(|b| *b == b',') {
                    close |= trim(token).eq_ignore_ascii_case(b"close");
                    keep |= trim(token).eq_ignore_ascii_case(b"keep-alive");
                }
            }
            at += n + 2;
        }
        if chunked && length.is_some() {
            return Err(ResponseError::Malformed);
        }
        if status < 200 {
            if status == 101 || length.is_some() || chunked {
                return Err(ResponseError::Unsupported);
            }
            self.informationals += 1;
            if self.informationals > 16 {
                return Err(ResponseError::Oversize);
            }
            self.len = 0;
            return Ok(());
        }
        if self.connect_request && (200..300).contains(&status) {
            return Err(ResponseError::Unsupported);
        }
        self.status = status;
        self.reusable = !close && (status_line.starts_with(b"HTTP/1.1") || keep);
        self.len = 0;
        if self.head_request || status == 304 || status == 204 {
            if status == 204 && (length.is_some() || chunked) {
                return Err(ResponseError::Malformed);
            }
            self.phase = Phase::Done;
        } else if chunked {
            self.phase = Phase::ChunkSize;
        } else if let Some(n) = length {
            self.remaining = n;
            self.phase = if n == 0 { Phase::Done } else { Phase::Fixed };
        } else {
            self.phase = Phase::UntilClose;
            self.reusable = false;
        }
        Ok(())
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while s.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        s = &s[1..];
    }
    while s.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        s = &s[..s.len() - 1];
    }
    s
}
fn field(line: &[u8]) -> Result<(&[u8], &[u8]), ResponseError> {
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or(ResponseError::Malformed)?;
    if colon == 0
        || !line[..colon].iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    *b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(ResponseError::Malformed);
    }
    let value = trim(&line[colon + 1..]);
    if value.iter().any(|b| (*b < 32 && *b != b'\t') || *b == 127) {
        return Err(ResponseError::Malformed);
    }
    Ok((&line[..colon], value))
}
