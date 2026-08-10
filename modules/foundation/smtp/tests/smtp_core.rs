//! SMTP connector core: reply-line parsing, command builders with RFC 5321
//! dot-stuffing, and the lockstep delivery phase machine. The exact logic the
//! `smtp` `.fmod` runs, driven here host-side.

use super::smtp::smtp_core::{
    smtp_body, smtp_data, smtp_ehlo, smtp_mail_from, smtp_on_reply, smtp_quit, smtp_rcpt_to,
    smtp_reply_line, SmtpCmd, SmtpPhase,
};

#[test]
fn reply_line_parses_code_and_finality() {
    // Final single line.
    assert_eq!(
        smtp_reply_line(b"220 mail.example\r\n"),
        Some((220, true, 18))
    );
    // Non-final line of a multi-line 250 reply (4th char '-').
    let (code, fin, len) = smtp_reply_line(b"250-SIZE 1000\r\nrest").unwrap();
    assert_eq!((code, fin), (250, false));
    assert_eq!(len, 15);
    // The final line of that reply.
    assert_eq!(smtp_reply_line(b"250 HELP\r\n"), Some((250, true, 10)));
    // Bare 3-digit line is final.
    assert_eq!(smtp_reply_line(b"354\r\n"), Some((354, true, 5)));
    // No complete line yet.
    assert_eq!(smtp_reply_line(b"250 HEL"), None);
    // Non-numeric → not a reply line.
    assert_eq!(smtp_reply_line(b"oops\r\n"), None);
}

#[test]
fn command_builders_emit_the_wire_lines() {
    let mut b = [0u8; 64];
    let n = smtp_ehlo(b"chronicle.local", &mut b).unwrap();
    assert_eq!(&b[..n], b"EHLO chronicle.local\r\n");
    let n = smtp_mail_from(b"ops@chronicle.local", &mut b).unwrap();
    assert_eq!(&b[..n], b"MAIL FROM:<ops@chronicle.local>\r\n");
    let n = smtp_rcpt_to(b"you@example.com", &mut b).unwrap();
    assert_eq!(&b[..n], b"RCPT TO:<you@example.com>\r\n");
    let n = smtp_data(&mut b).unwrap();
    assert_eq!(&b[..n], b"DATA\r\n");
    let n = smtp_quit(&mut b).unwrap();
    assert_eq!(&b[..n], b"QUIT\r\n");
}

#[test]
fn body_is_dot_stuffed_and_terminated() {
    // A body whose second line begins with a dot must be transparency-encoded,
    // and the whole thing terminated by CRLF + ".\r\n".
    let mut out = [0u8; 128];
    let n = smtp_body(b"Subject: hi\r\n.hidden leading dot\r\n", &mut out).unwrap();
    assert_eq!(&out[..n], b"Subject: hi\r\n..hidden leading dot\r\n.\r\n");
    // A body not ending in CRLF gets one before the terminator.
    let n = smtp_body(b"no crlf", &mut out).unwrap();
    assert_eq!(&out[..n], b"no crlf\r\n.\r\n");
    // A lone "." line becomes ".." so it can't be read as end-of-data.
    let n = smtp_body(b".\r\n", &mut out).unwrap();
    assert_eq!(&out[..n], b"..\r\n.\r\n");
}

#[test]
fn phase_machine_walks_the_happy_path() {
    // Greet(220) -> EHLO -> 250 -> MAIL -> 250 -> RCPT -> 250 -> DATA -> 354 ->
    // BODY -> 250 -> QUIT -> 221 -> Complete.
    let (c, p) = smtp_on_reply(SmtpPhase::Greet, 220);
    assert_eq!((c, p), (SmtpCmd::SendEhlo, SmtpPhase::Ehlo));
    let (c, p) = smtp_on_reply(p, 250);
    assert_eq!((c, p), (SmtpCmd::SendMailFrom, SmtpPhase::MailFrom));
    let (c, p) = smtp_on_reply(p, 250);
    assert_eq!((c, p), (SmtpCmd::SendRcptTo, SmtpPhase::RcptTo));
    let (c, p) = smtp_on_reply(p, 250);
    assert_eq!((c, p), (SmtpCmd::SendData, SmtpPhase::Data));
    let (c, p) = smtp_on_reply(p, 354);
    assert_eq!((c, p), (SmtpCmd::SendBody, SmtpPhase::Body));
    let (c, p) = smtp_on_reply(p, 250);
    assert_eq!((c, p), (SmtpCmd::SendQuit, SmtpPhase::Quit));
    let (c, p) = smtp_on_reply(p, 221);
    assert_eq!((c, p), (SmtpCmd::Complete, SmtpPhase::Done));
}

#[test]
fn phase_machine_aborts_on_an_unexpected_code() {
    // A 550 mailbox-unavailable at RCPT aborts.
    assert_eq!(
        smtp_on_reply(SmtpPhase::RcptTo, 550),
        (SmtpCmd::Fail, SmtpPhase::Failed)
    );
    // A 421 greeting (service not available) at Greet aborts.
    assert_eq!(
        smtp_on_reply(SmtpPhase::Greet, 421),
        (SmtpCmd::Fail, SmtpPhase::Failed)
    );
    // The right code but the wrong phase aborts (e.g. 250 while awaiting DATA's 354).
    assert_eq!(
        smtp_on_reply(SmtpPhase::Data, 250),
        (SmtpCmd::Fail, SmtpPhase::Failed)
    );
}

/// Never-panic fuzzing: the reply parser and the dot-stuffer must return values
/// (or `None`) for ANY bytes and must respect the caller's buffer — a panic
/// inside a `.fmod` takes the module down. Relocated with the core from
/// Chronicle, whose `robustness.rs` holds the same bar for its VMs.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn upto(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

#[test]
fn smtp_reply_and_body_never_panic_on_arbitrary_bytes() {
    let mut rng = Rng(0x5117_0DEC);
    for _ in 0..80_000 {
        let n = rng.upto(40);
        // Bias toward digits, CRLF, dots, and the reply separators.
        let bytes: Vec<u8> = (0..n)
            .map(|_| match rng.upto(7) {
                0 => b'\r',
                1 => b'\n',
                2 => b'.',
                3 => b'-',
                4 => b' ',
                5 => b'0' + (rng.upto(10) as u8),
                _ => rng.byte(),
            })
            .collect();
        if let Some((_code, _final, len)) = smtp_reply_line(&bytes) {
            assert!(len <= bytes.len());
        }
        // Dot-stuffing into a bounded buffer must never panic and must respect it.
        let mut out = [0u8; 96];
        if let Some(m) = smtp_body(&bytes, &mut out) {
            assert!(m <= out.len());
        }
    }
}
