//! SIP message parity vectors (Conclave plan S4.3).
//!
//! Golden transcripts freeze `modules/common/sip_core.rs` to the byte-exact output of
//! the builders in `modules/common/sip_core.rs`, so the SIP `.fmod` can
//! be repointed at this core with wire parity. Any change to a transcript is a
//! semantic change and must be reviewed as such (see the preserved-fault note
//! in `sip_core.rs`).

use super::sip::sip_core::{
    build_ack, build_bye, build_bye_ok, build_invite, build_invite_ok, find_call_id,
    parse_from_tag, parse_sdp_endpoint, parse_status_code, parse_to_tag, sdp_content_length,
    write_sdp, SipDialog,
};

const LOCAL_IP: u32 = 0xC0A8_010A; // 192.168.1.10
const PEER_IP: u32 = 0xC0A8_0114; // 192.168.1.20

fn dialog(to_tag: u16) -> SipDialog<'static> {
    SipDialog {
        local_ip: LOCAL_IP,
        peer_ip: PEER_IP,
        local_port: 5060,
        peer_port: 5060,
        rtp_port: 5004,
        cseq: 1,
        from_tag: 0x1a2b,
        to_tag,
        branch: 1,
        call_id: b"abc123",
    }
}

fn built(f: fn(&SipDialog<'_>, &mut [u8]) -> Option<usize>, d: &SipDialog<'_>) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = f(d, &mut buf).expect("message fits");
    buf[..n].to_vec()
}

const INVITE: &[u8] = b"INVITE sip:192.168.1.20:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK0001\r\n\
Max-Forwards: 70\r\n\
From: <sip:192.168.1.10>;tag=1a2b\r\n\
To: <sip:192.168.1.20>\r\n\
Call-ID: abc123@192.168.1.10\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:192.168.1.10:5060>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 115\r\n\r\n\
v=0\r\no=- 0 0 IN IP4 192.168.1.10\r\ns=-\r\nc=IN IP4 192.168.1.10\r\n\
t=0 0\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

const INVITE_OK: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060\r\n\
From: <sip:192.168.1.20>;tag=0000\r\n\
To: <sip:192.168.1.10>;tag=1a2b\r\n\
Call-ID: abc123\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:192.168.1.10:5060>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 115\r\n\r\n\
v=0\r\no=- 0 0 IN IP4 192.168.1.10\r\ns=-\r\nc=IN IP4 192.168.1.10\r\n\
t=0 0\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

const ACK: &[u8] = b"ACK sip:192.168.1.20:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK0001\r\n\
Max-Forwards: 70\r\n\
From: <sip:192.168.1.10>;tag=1a2b\r\n\
To: <sip:192.168.1.20>\r\n\
Call-ID: abc123@192.168.1.10\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n";

const BYE: &[u8] = b"BYE sip:192.168.1.20:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK0001\r\n\
Max-Forwards: 70\r\n\
From: <sip:192.168.1.10>;tag=1a2b\r\n\
To: <sip:192.168.1.20>\r\n\
Call-ID: abc123@192.168.1.10\r\n\
CSeq: 1 BYE\r\n\
Content-Length: 0\r\n\r\n";

const BYE_OK: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.20:5060\r\n\
From: <sip:192.168.1.20>\r\n\
To: <sip:192.168.1.10>;tag=1a2b\r\n\
Call-ID: abc123\r\n\
CSeq: 1 BYE\r\n\
Content-Length: 0\r\n\r\n";

#[test]
fn builders_match_golden_transcripts() {
    let d = dialog(0);
    assert_eq!(built(build_invite, &d), INVITE, "INVITE");
    assert_eq!(built(build_invite_ok, &d), INVITE_OK, "200 OK (INVITE)");
    assert_eq!(built(build_ack, &d), ACK, "ACK");
    assert_eq!(built(build_bye, &d), BYE, "BYE");
    assert_eq!(built(build_bye_ok, &d), BYE_OK, "200 OK (BYE)");
}

#[test]
fn ack_includes_to_tag_when_present() {
    let got = built(build_ack, &dialog(0x9f01));
    assert!(
        find_bytes(&got, b"To: <sip:192.168.1.20>;tag=9f01\r\n"),
        "ACK with a dialog to-tag must carry it",
    );
}

/// The corrected SDP length: the advertised `Content-Length` equals the body
/// `write_sdp` produces (the origin overcounted by 2). See `sip_core.rs`.
#[test]
fn sdp_content_length_matches_body() {
    let mut body = [0u8; 256];
    let actual = write_sdp(LOCAL_IP, 5004, &mut body).unwrap();
    assert_eq!(actual, 115, "real SDP body length");
    assert_eq!(
        sdp_content_length(LOCAL_IP, 5004),
        actual,
        "advertised length must equal the body",
    );
}

#[test]
fn parsers_read_response_facts() {
    // Status line.
    assert_eq!(parse_status_code(INVITE_OK), 200);
    assert_eq!(parse_status_code(b"SIP/2.0 486 Busy Here\r\n"), 486);
    assert_eq!(parse_status_code(INVITE), 0, "a request has no status code");

    // Call-ID (response form, no @host suffix).
    assert_eq!(find_call_id(INVITE_OK), Some(&b"abc123"[..]));

    // Dialog tags: our answer put from_tag on To and to_tag(0 -> "0000") on From.
    assert_eq!(parse_to_tag(INVITE_OK), 0x1a2b);
    assert_eq!(parse_from_tag(INVITE_OK), 0x0000);

    // Remote media endpoint from the SDP answer.
    let ep = parse_sdp_endpoint(INVITE_OK).expect("SDP endpoint");
    assert_eq!(ep.port, 5004);
    assert_eq!(ep.ip, Some(LOCAL_IP));
}

#[test]
fn parse_sdp_endpoint_without_connection_line_yields_no_ip() {
    let sdp = b"SIP/2.0 200 OK\r\n\r\nv=0\r\nm=audio 6000 RTP/AVP 0\r\n";
    let ep = parse_sdp_endpoint(sdp).expect("port present");
    assert_eq!(ep.port, 6000);
    assert_eq!(ep.ip, None, "caller resolves a missing c= line to the peer");
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Malformed or non-audio SDP must be rejected, not guessed at — the dialog
/// treats an unusable answer as a call-failure path.
#[test]
fn unusable_sdp_is_rejected() {
    assert!(parse_sdp_endpoint(b"").is_none(), "empty");
    assert!(
        parse_sdp_endpoint(b"v=0\r\ns=-\r\n").is_none(),
        "no m=audio"
    );
    assert!(
        parse_sdp_endpoint(b"m=video 5000 RTP/AVP 96\r\n").is_none(),
        "video-only must not be taken as audio"
    );
}

/// A request is not a response: `parse_status_code` must not read a code out of
/// an INVITE line, or a retransmitted request would be taken for an answer.
#[test]
fn status_code_parsing_rejects_requests_and_empty_input() {
    assert_eq!(parse_status_code(b"SIP/2.0 486 Busy Here\r\n"), 486);
    assert_eq!(parse_status_code(b"INVITE sip:x@y SIP/2.0\r\n"), 0);
    assert_eq!(parse_status_code(b""), 0);
}

/// ACK and the BYE pair carry no SDP; only the INVITE/200 pair negotiates media.
#[test]
fn only_the_invite_pair_carries_sdp() {
    let d = dialog(0);
    for (name, msg) in [
        ("ACK", built(build_ack, &d)),
        ("BYE", built(build_bye, &d)),
        ("BYE 200", built(build_bye_ok, &d)),
    ] {
        let s = String::from_utf8_lossy(&msg);
        assert!(!s.contains("m=audio"), "{name} must not carry SDP:\n{s}");
        assert!(s.contains("Content-Length:"), "{name} needs Content-Length");
    }
    assert!(String::from_utf8_lossy(&built(build_invite_ok, &d)).contains("m=audio"));
}

/// The writer is bounds-checked: too small a buffer fails rather than emitting
/// a truncated message a peer would misparse.
#[test]
fn undersized_buffers_fail_instead_of_truncating() {
    let d = dialog(0);
    let mut full = [0u8; 1024];
    let n = build_invite(&d, &mut full).expect("baseline fits");
    let mut tight = vec![0u8; n - 1];
    assert!(build_invite(&d, &mut tight).is_none(), "one byte short");
    assert!(
        write_sdp(d.local_ip, d.rtp_port, &mut [0u8; 4]).is_none(),
        "tiny sdp"
    );
}
