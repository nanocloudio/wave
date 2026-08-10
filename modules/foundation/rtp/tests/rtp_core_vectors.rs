// RFC 3550 §5.1 header vectors for `modules/common/rtp_core.rs`.
//
// The point of these is the payload BOUNDARY. Every field decode is easy to get
// right and easy to test; what determines whether a call sounds correct is
// which bytes the receiver treats as audio. The CSRC list, the §5.3.1
// extension and §5.1 padding each move that boundary, and a receiver that
// ignores one plays protocol bytes as µ-law.

use super::rtp::rtp_core::{rtp_parse, RTP_HEADER_SIZE};

/// Minimal V2 header: no CSRC, no extension, no padding, no marker.
fn header(payload: &[u8]) -> Vec<u8> {
    let mut p = vec![
        0x80, // V=2, P=0, X=0, CC=0
        0x00, // M=0, PT=0 (PCMU)
        0x12, 0x34, // sequence
        0x00, 0x00, 0x27, 0x10, // timestamp 10000
        0x46, 0x58, 0x52, 0x54, // SSRC "FXRT"
    ];
    p.extend_from_slice(payload);
    p
}

#[test]
fn plain_packet_decodes_its_fields_and_payload() {
    let pkt = header(b"\xff\xfe\xfd\xfc");
    let h = rtp_parse(&pkt).expect("a minimal V2 packet must parse");
    assert_eq!(h.seq, 0x1234);
    assert_eq!(h.timestamp, 10_000);
    assert_eq!(h.ssrc, 0x4658_5254);
    assert_eq!(h.payload_type, 0);
    assert!(!h.marker);
    assert_eq!(h.payload_start, RTP_HEADER_SIZE);
    assert_eq!(&pkt[h.payload_start..h.payload_end], b"\xff\xfe\xfd\xfc");
}

#[test]
fn marker_and_payload_type_come_from_the_second_octet() {
    let mut pkt = header(b"aa");
    pkt[1] = 0x80 | 8; // M=1, PT=8 (PCMA)
    let h = rtp_parse(&pkt).expect("parse");
    assert!(h.marker);
    assert_eq!(h.payload_type, 8);
}

#[test]
fn csrc_list_shifts_the_payload() {
    let mut pkt = header(b"");
    pkt[0] = 0x80 | 2; // CC=2 → 8 bytes of CSRC
    pkt.extend_from_slice(&[0xAA; 8]);
    pkt.extend_from_slice(b"audio");
    let h = rtp_parse(&pkt).expect("parse");
    assert_eq!(h.payload_start, RTP_HEADER_SIZE + 8);
    assert_eq!(&pkt[h.payload_start..h.payload_end], b"audio");
}

/// X=1: `[profile:2][length:2]` then `length` 32-bit words, all of it skipped.
///
/// Before `rtp_core` existed both `rtp` and `sip` ignored X and played the
/// extension header as audio — 8 bytes of it, here, at the head of every packet.
#[test]
fn extension_header_is_skipped_not_played() {
    let mut pkt = header(b"");
    pkt[0] = 0x80 | 0x10; // X=1
    pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01]); // profile, length = 1 word
    pkt.extend_from_slice(&[0x99; 4]); // the one word
    pkt.extend_from_slice(b"audio");
    let h = rtp_parse(&pkt).expect("parse");
    assert_eq!(h.payload_start, RTP_HEADER_SIZE + 8);
    assert_eq!(&pkt[h.payload_start..h.payload_end], b"audio");
}

#[test]
fn extension_and_csrc_stack() {
    let mut pkt = header(b"");
    pkt[0] = 0x80 | 0x10 | 1; // X=1, CC=1
    pkt.extend_from_slice(&[0xAA; 4]); // CSRC
    pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x02]); // length = 2 words
    pkt.extend_from_slice(&[0x99; 8]);
    pkt.extend_from_slice(b"x");
    let h = rtp_parse(&pkt).expect("parse");
    assert_eq!(h.payload_start, RTP_HEADER_SIZE + 4 + 12);
    assert_eq!(&pkt[h.payload_start..h.payload_end], b"x");
}

/// P=1: the final octet counts the padding octets, itself included.
#[test]
fn padding_is_stripped_from_the_tail() {
    let mut pkt = header(b"audio");
    pkt[0] = 0x80 | 0x20; // P=1
    pkt.extend_from_slice(&[0x00, 0x00, 0x03]); // 3 padding octets incl. count
    let h = rtp_parse(&pkt).expect("parse");
    assert_eq!(&pkt[h.payload_start..h.payload_end], b"audio");
}

#[test]
fn padding_of_exactly_one_octet_is_the_count_itself() {
    let mut pkt = header(b"audio");
    pkt[0] = 0x80 | 0x20;
    pkt.push(0x01);
    let h = rtp_parse(&pkt).expect("parse");
    assert_eq!(&pkt[h.payload_start..h.payload_end], b"audio");
}

// ── rejections ───────────────────────────────────────────────────────────────
//
// RTP rides datagrams, so there is no "incomplete": a packet that does not add
// up is dropped. Each of these would otherwise hand a caller an inverted or
// out-of-range payload window.

#[test]
fn short_and_wrong_version_packets_are_refused() {
    assert!(rtp_parse(&[]).is_none());
    assert!(
        rtp_parse(&[0x80; RTP_HEADER_SIZE - 1]).is_none(),
        "truncated"
    );
    let mut v1 = header(b"aa");
    v1[0] = 0x40; // V=1
    assert!(rtp_parse(&v1).is_none(), "version 1");
}

#[test]
fn header_with_no_payload_is_refused() {
    assert!(rtp_parse(&header(b"")).is_none(), "12 bytes, no payload");
}

#[test]
fn csrc_count_overrunning_the_packet_is_refused() {
    let mut pkt = header(b"aa");
    pkt[0] = 0x80 | 15; // CC=15 → 60 bytes that are not there
    assert!(rtp_parse(&pkt).is_none());
}

#[test]
fn extension_overrunning_the_packet_is_refused() {
    let mut short = header(b"");
    short[0] = 0x80 | 0x10;
    short.extend_from_slice(&[0xBE, 0xDE]); // truncated ext header
    assert!(rtp_parse(&short).is_none(), "ext header truncated");

    let mut long = header(b"");
    long[0] = 0x80 | 0x10;
    long.extend_from_slice(&[0xBE, 0xDE, 0xFF, 0xFF]); // 65535 words claimed
    long.extend_from_slice(b"audio");
    assert!(rtp_parse(&long).is_none(), "ext length overruns");
}

#[test]
fn padding_that_overruns_or_is_zero_is_refused() {
    let mut zero = header(b"audio");
    zero[0] = 0x80 | 0x20;
    zero.push(0x00);
    assert!(
        rtp_parse(&zero).is_none(),
        "a zero count cannot include itself"
    );

    let mut over = header(b"audio");
    over[0] = 0x80 | 0x20;
    over.push(0xFF);
    assert!(
        rtp_parse(&over).is_none(),
        "padding longer than the payload"
    );
}

#[test]
fn all_padding_and_no_audio_is_refused() {
    let mut pkt = header(b"");
    pkt[0] = 0x80 | 0x20;
    pkt.extend_from_slice(&[0x00, 0x00, 0x03]);
    assert!(
        rtp_parse(&pkt).is_none(),
        "a zero-length payload reads as a codec underrun downstream"
    );
}

/// Every truncation of a valid packet must be refused or bounded — never a
/// window that points past the buffer.
#[test]
fn every_prefix_of_a_valid_packet_stays_in_range() {
    let mut pkt = header(b"");
    pkt[0] = 0x80 | 0x10 | 0x20 | 1; // CC=1, X=1, P=1 — every boundary at once
    pkt.extend_from_slice(&[0xAA; 4]);
    pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01]);
    pkt.extend_from_slice(&[0x99; 4]);
    pkt.extend_from_slice(b"audio");
    pkt.extend_from_slice(&[0x00, 0x02]);

    for n in 0..=pkt.len() {
        if let Some(h) = rtp_parse(&pkt[..n]) {
            assert!(h.payload_start <= h.payload_end, "inverted window at {n}");
            assert!(h.payload_end <= n, "window past the buffer at {n}");
            assert!(h.payload_len() > 0, "empty payload reported at {n}");
        }
    }
}
