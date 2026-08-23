// Bounded, no_std, no-alloc SMTP protocol core — reply-line parsing, the client
// command builders (with dot-stuffing), and the delivery phase machine. `include!`d
// by the host crate (tests) and the `smtp` .fmod.
//
// SMTP is a LOCKSTEP command/reply session, not a single-shot req/reply: the
// client sends one command, waits for a multi-line reply whose FINAL line's
// 3-digit code decides the next command, and walks a fixed sequence
//   220 greeting -> EHLO/250 -> MAIL FROM/250 -> RCPT TO/250 -> DATA/354
//   -> <message>.CRLF/250 -> QUIT/221
// with the message body dot-stuffed and terminated by `\r\n.\r\n`. A reply-code
// -dependent, multi-round-trip conversation over a server-chosen greeting is not
// expressible in a stateless codec, so it is a compiled module.
//
// Wire form is text, CRLF-terminated lines. A reply line is
//   `NNN<sep>text\r\n`  where sep = '-' (more lines follow) or ' ' (final line).

/// Bounded write into `out` at `*p`; advances `*p`. `None` on overflow.
fn smtp_put(out: &mut [u8], p: &mut usize, b: &[u8]) -> Option<()> {
    let end = p.checked_add(b.len())?;
    if end > out.len() {
        return None;
    }
    out[*p..end].copy_from_slice(b);
    *p = end;
    Some(())
}

/// Parse ONE reply line at `buf[0..]`. Returns `(code, is_final, line_len)` where
/// `line_len` includes the trailing CRLF, or `None` if there is no complete
/// CRLF-terminated line yet or the line is malformed (no 3-digit code). A line
/// whose 4th char is `-` is non-final (more lines of a multi-line reply follow);
/// a space or an exactly-3-digit line is final.
pub fn smtp_reply_line(buf: &[u8]) -> Option<(u16, bool, usize)> {
    let mut i = 0usize;
    let crlf = loop {
        if i + 1 >= buf.len() {
            return None;
        }
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            break i;
        }
        i += 1;
    };
    if crlf < 3 {
        return None;
    }
    let (d0, d1, d2) = (buf[0], buf[1], buf[2]);
    if !d0.is_ascii_digit() || !d1.is_ascii_digit() || !d2.is_ascii_digit() {
        return None;
    }
    let code = (d0 - b'0') as u16 * 100 + (d1 - b'0') as u16 * 10 + (d2 - b'0') as u16;
    // 4th char decides continuation; a bare 3-digit line (crlf == 3) is final.
    let is_final = crlf == 3 || buf[3] != b'-';
    Some((code, is_final, crlf + 2))
}

// ---- client command builders ------------------------------------------------

/// `EHLO <domain>\r\n`.
pub fn smtp_ehlo(domain: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut p = 0;
    smtp_put(out, &mut p, b"EHLO ")?;
    smtp_put(out, &mut p, domain)?;
    smtp_put(out, &mut p, b"\r\n")?;
    Some(p)
}

/// `MAIL FROM:<addr>\r\n`.
pub fn smtp_mail_from(addr: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut p = 0;
    smtp_put(out, &mut p, b"MAIL FROM:<")?;
    smtp_put(out, &mut p, addr)?;
    smtp_put(out, &mut p, b">\r\n")?;
    Some(p)
}

/// `RCPT TO:<addr>\r\n`.
pub fn smtp_rcpt_to(addr: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut p = 0;
    smtp_put(out, &mut p, b"RCPT TO:<")?;
    smtp_put(out, &mut p, addr)?;
    smtp_put(out, &mut p, b">\r\n")?;
    Some(p)
}

/// `DATA\r\n`.
pub fn smtp_data(out: &mut [u8]) -> Option<usize> {
    let mut p = 0;
    smtp_put(out, &mut p, b"DATA\r\n")?;
    Some(p)
}

/// `QUIT\r\n`.
pub fn smtp_quit(out: &mut [u8]) -> Option<usize> {
    let mut p = 0;
    smtp_put(out, &mut p, b"QUIT\r\n")?;
    Some(p)
}

/// The DATA payload: the message `body` transparency-encoded (RFC 5321 §4.5.2 —
/// any line beginning with `.` gets an extra leading `.`), guaranteed to end in
/// CRLF, then the end-of-data marker `.\r\n`. Bare LFs in `body` are treated as
/// line boundaries for dot-stuffing but copied verbatim (the caller supplies
/// CRLF-terminated text).
pub fn smtp_body(body: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut p = 0usize;
    let mut at_line_start = true;
    for &b in body {
        if at_line_start && b == b'.' {
            smtp_put(out, &mut p, b".")?; // transparency dot
        }
        smtp_put(out, &mut p, &[b])?;
        at_line_start = b == b'\n';
    }
    // Ensure the message ends with CRLF before the terminator.
    if p < 2 || out[p - 2] != b'\r' || out[p - 1] != b'\n' {
        smtp_put(out, &mut p, b"\r\n")?;
    }
    smtp_put(out, &mut p, b".\r\n")?;
    Some(p)
}

/// Dot-stuff one span of a message that is being streamed.
///
/// `at_line_start` carries the line state across a span boundary: transparency
/// applies to a `.` that begins a LINE, and a span that ends mid-line must not
/// re-arm it for the next span's first byte. Returns the bytes written and the
/// line state to carry forward.
///
/// Unlike [`smtp_body`] this writes no terminator: the message is not known to
/// be complete until the caller says so, and a terminator emitted early would
/// end the message at a span boundary.
pub fn smtp_body_chunk(chunk: &[u8], at_line_start: bool, out: &mut [u8]) -> Option<(usize, bool)> {
    let mut p = 0usize;
    let mut line_start = at_line_start;
    for &b in chunk {
        if line_start && b == b'.' {
            smtp_put(out, &mut p, b".")?; // transparency dot
        }
        smtp_put(out, &mut p, &[b])?;
        line_start = b == b'\n';
    }
    Some((p, line_start))
}

/// The end-of-data marker, preceded by CRLF when the message did not end with
/// one. RFC 5321 requires the terminator to sit on a line of its own.
pub fn smtp_body_end(ends_with_crlf: bool, out: &mut [u8]) -> Option<usize> {
    let mut p = 0usize;
    if !ends_with_crlf {
        smtp_put(out, &mut p, b"\r\n")?;
    }
    smtp_put(out, &mut p, b".\r\n")?;
    Some(p)
}

// ---- delivery phase machine -------------------------------------------------

/// Where the delivery conversation currently stands. `Disconnected`/`Connecting`
/// are driven by the transport; `Greet`..`Quit` each await a reply code; `Done`
/// and `Failed` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpPhase {
    Disconnected,
    Connecting,
    Greet,
    Ehlo,
    MailFrom,
    RcptTo,
    Data,
    Body,
    Quit,
    Done,
    Failed,
}

/// The command the pump should emit next (or a terminal signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpCmd {
    SendEhlo,
    SendMailFrom,
    SendRcptTo,
    SendData,
    SendBody,
    SendQuit,
    /// The 221 to QUIT arrived — the message is delivered.
    Complete,
    /// An unexpected reply code for this phase — abort.
    Fail,
}

/// Whether this reply is the server taking responsibility for the message.
///
/// Exactly one reply means that: the 250 answering end-of-data. From that
/// moment the message is the server's, and the QUIT that follows is graceful
/// cleanup — a failed QUIT does not un-accept a message, and resubmitting on
/// the strength of one would deliver it twice.
pub fn smtp_reply_accepts(phase: SmtpPhase, code: u16) -> bool {
    matches!(phase, SmtpPhase::Body) && code == 250
}

/// The stable byte a phase is reported as on the result port.
///
/// Wire positions: append new phases, never renumber an existing one.
pub fn smtp_phase_code(phase: SmtpPhase) -> u8 {
    match phase {
        SmtpPhase::Disconnected => 0,
        SmtpPhase::Connecting => 1,
        SmtpPhase::Greet => 2,
        SmtpPhase::Ehlo => 3,
        SmtpPhase::MailFrom => 4,
        SmtpPhase::RcptTo => 5,
        SmtpPhase::Data => 6,
        SmtpPhase::Body => 7,
        SmtpPhase::Quit => 8,
        SmtpPhase::Done => 9,
        SmtpPhase::Failed => 10,
    }
}

/// The reply text of one reply line, without its code, separator or CRLF.
///
/// Returns the span within `buf`, so a caller can copy the bounded text it
/// wants to keep. `None` for a line too short to carry any.
pub fn smtp_reply_text(buf: &[u8], line_len: usize) -> Option<(usize, usize)> {
    // The span must lie inside the buffer it is measured against: a caller
    // passing a length from a different line would otherwise name bytes that
    // are not part of this reply.
    if line_len > buf.len() {
        return None;
    }
    // `line_len` includes the trailing CRLF; the text starts after the
    // 3-digit code and its separator, when there is one.
    let end = line_len.checked_sub(2)?;
    if end <= 4 {
        return None;
    }
    Some((4, end - 4))
}

/// Decide the next command from the current phase and a FINAL reply code. Every
/// step demands its specific success code (220/250/250/250/354/250/221); any
/// other code aborts (`Fail`). Pure and total.
pub fn smtp_on_reply(phase: SmtpPhase, code: u16) -> (SmtpCmd, SmtpPhase) {
    match phase {
        SmtpPhase::Greet if code == 220 => (SmtpCmd::SendEhlo, SmtpPhase::Ehlo),
        SmtpPhase::Ehlo if code == 250 => (SmtpCmd::SendMailFrom, SmtpPhase::MailFrom),
        SmtpPhase::MailFrom if code == 250 => (SmtpCmd::SendRcptTo, SmtpPhase::RcptTo),
        SmtpPhase::RcptTo if code == 250 => (SmtpCmd::SendData, SmtpPhase::Data),
        SmtpPhase::Data if code == 354 => (SmtpCmd::SendBody, SmtpPhase::Body),
        SmtpPhase::Body if code == 250 => (SmtpCmd::SendQuit, SmtpPhase::Quit),
        SmtpPhase::Quit if code == 221 => (SmtpCmd::Complete, SmtpPhase::Done),
        _ => (SmtpCmd::Fail, SmtpPhase::Failed),
    }
}
