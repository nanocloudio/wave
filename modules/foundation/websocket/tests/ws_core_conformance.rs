//! RFC 6455 conformance vectors for the shared WebSocket core.
//!
//! These pin the byte semantics that the `websocket` client `.fmod`, the `http`
//! server's upgrade path, and `ws_stream`'s adapter all have to agree on. The
//! core is `include!`d verbatim by the PIC modules, so a vector that passes here
//! is the same code that runs on device.

use super::websocket::{
    b64_encode, hex_decode, hex_encode, sha1, ws_accept, ws_frame, ws_mask_apply, ws_op,
    ws_parse_frame, ws_transition, ws_upgrade_request, ws_verify_upgrade, WsAct, WsEv, WsPhase,
};

/// RFC 6455 §5.7, "a single-frame masked text message": the exact eleven bytes a
/// conforming client puts on the wire for `Hello` with key `37 fa 21 3d`.
///
/// This is the one masking assertion that is not self-referential. A round-trip
/// test — mask, then unmask, then compare — passes just as happily on a wrong
/// key phase, because the same wrong phase undoes it. The transform is four
/// bytes at a time, so getting the phase wrong is exactly the plausible defect,
/// and only an external vector catches it.
const RFC_5_7_MASKED_HELLO: [u8; 11] = [
    0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
];

#[test]
fn masking_matches_the_rfc_6455_wire_bytes() {
    let mut wire = [0u8; 32];
    let n =
        ws_frame(ws_op::TEXT, b"Hello", [0x37, 0xfa, 0x21, 0x3d], &mut wire).expect("frame fits");
    assert_eq!(
        &wire[..n],
        &RFC_5_7_MASKED_HELLO,
        "RFC 6455 §5.7 wire bytes"
    );
}

#[test]
fn unmasking_the_rfc_wire_bytes_recovers_the_payload() {
    let mut buf = RFC_5_7_MASKED_HELLO;
    let f = ws_parse_frame(&buf).expect("parses");
    let (start, end) = (f.payload_start, f.payload_end);
    ws_mask_apply(&mut buf[start..end], [0x37, 0xfa, 0x21, 0x3d]);
    assert_eq!(&buf[start..end], b"Hello");
}

/// The transform runs four bytes at a time with a byte-wise remainder, so both
/// paths need a length that reaches them: 8 is two whole words, 11 is two words
/// plus three, 3 is remainder only.
#[test]
fn masking_is_its_own_inverse_at_every_length_class() {
    let mask = [0xA1, 0xB2, 0xC3, 0xD4];
    for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 11, 16, 17] {
        let original: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
        let mut buf = original.clone();
        ws_mask_apply(&mut buf, mask);
        if len >= 4 {
            assert_ne!(
                buf, original,
                "len {len} should not survive masking unchanged"
            );
        }
        // Byte-for-byte against the definition in §5.3, not against itself.
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, original[i] ^ mask[i % 4], "len {len}, byte {i}");
        }
        ws_mask_apply(&mut buf, mask);
        assert_eq!(buf, original, "len {len} must round-trip");
    }
}

/// RFC 6455 §1.3 worked example: key `dGhlIHNhbXBsZSBub25jZQ==` must yield accept
/// `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.
#[test]
fn accept_matches_the_rfc_6455_example() {
    let mut out = [0u8; 32];
    let n = ws_accept(b"dGhlIHNhbXBsZSBub25jZQ==", &mut out).expect("accept fits");
    assert_eq!(&out[..n], b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

/// RFC 3174 vector — `ws_accept` is only as correct as its SHA-1.
#[test]
fn sha1_matches_the_abc_vector() {
    let mut hex = [0u8; 40];
    let n = hex_encode(&sha1(b"abc"), &mut hex).expect("hex fits");
    assert_eq!(&hex[..n], b"a9993e364706816aba3e25717850c26c9cd0d89d");
}

/// RFC 4648 §10 Base64 vectors, covering both pad lengths.
#[test]
fn base64_matches_the_rfc_4648_vectors() {
    for (input, expected) in [
        (&b""[..], &b""[..]),
        (b"f", b"Zg=="),
        (b"fo", b"Zm8="),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg=="),
        (b"fooba", b"Zm9vYmE="),
        (b"foobar", b"Zm9vYmFy"),
    ] {
        let mut out = [0u8; 16];
        let n = b64_encode(input, &mut out).expect("encode fits");
        assert_eq!(&out[..n], expected, "encoding {input:?}");
    }
}

/// §5.3: a client frame is masked, and the payload must not appear in the clear.
#[test]
fn masked_client_frame_round_trips() {
    let payload = b"Hello, Wave";
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut wire = [0u8; 64];
    let n = ws_frame(ws_op::TEXT, payload, mask, &mut wire).expect("frame fits");

    assert_eq!(wire[0], 0x80 | ws_op::TEXT, "FIN + TEXT");
    assert_eq!(wire[1], 0x80 | payload.len() as u8, "MASK + 7-bit length");
    assert!(
        !wire[..n].windows(payload.len()).any(|w| w == payload),
        "payload leaked unmasked onto the wire"
    );

    let parsed = ws_parse_frame(&wire[..n]).expect("parses");
    assert!(parsed.fin);
    assert!(parsed.masked);
    assert_eq!(parsed.opcode, ws_op::TEXT);
    assert_eq!(parsed.total, n);

    let masked_payload = &wire[parsed.payload_start..parsed.payload_end];
    let plain: Vec<u8> = masked_payload
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    assert_eq!(plain, payload);
}

/// The 16-bit extended length path (126 ≤ len < 65536) frames and reparses.
#[test]
fn extended_length_frame_round_trips() {
    let payload = [0xa5u8; 300];
    let mut wire = [0u8; 512];
    let n = ws_frame(ws_op::BINARY, &payload, [9, 8, 7, 6], &mut wire).expect("frame fits");
    assert_eq!(wire[1] & 0x7f, 126, "16-bit length marker");
    let parsed = ws_parse_frame(&wire[..n]).expect("parses");
    assert_eq!(parsed.payload_end - parsed.payload_start, payload.len());
    assert_eq!(parsed.total, n);
}

/// Every truncation is an incomplete read, never a panic or an overrun.
#[test]
fn truncated_frame_is_refused_not_overrun() {
    let mut wire = [0u8; 64];
    let n = ws_frame(ws_op::BINARY, b"0123456789", [1, 2, 3, 4], &mut wire).expect("frame fits");
    for cut in 0..n {
        assert!(
            ws_parse_frame(&wire[..cut]).is_none(),
            "a {cut}-byte prefix of a {n}-byte frame must not parse"
        );
    }
    assert!(ws_parse_frame(&wire[..n]).is_some());
}

/// An output buffer too small for the frame is refused, never truncated.
#[test]
fn frame_refuses_an_undersized_buffer() {
    let mut tiny = [0u8; 4];
    assert!(ws_frame(ws_op::TEXT, b"too long for four bytes", [0; 4], &mut tiny).is_none());
    let mut empty: [u8; 0] = [];
    assert!(ws_frame(ws_op::PING, b"", [0; 4], &mut empty).is_none());
}

/// The upgrade is verified cryptographically: only a server that proves
/// `base64(SHA1(key ++ magic))` switches the connection.
#[test]
fn upgrade_verification_rejects_a_forged_accept() {
    let key = b"dGhlIHNhbXBsZSBub25jZQ==";
    let mut buf = [0u8; 256];
    let n = ws_upgrade_request(b"example.com", b"/chat", key, &mut buf).expect("request fits");
    let request = &buf[..n];

    assert!(request.starts_with(b"GET /chat HTTP/1.1\r\n"));
    assert!(request.ends_with(b"\r\n\r\n"));
    for header in [
        &b"Host: example.com"[..],
        b"Upgrade: websocket",
        b"Connection: Upgrade",
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        b"Sec-WebSocket-Version: 13",
    ] {
        assert!(
            request.windows(header.len()).any(|w| w == header),
            "request is missing {:?}",
            core::str::from_utf8(header).unwrap()
        );
    }

    let mut accept = [0u8; 32];
    let a = ws_accept(key, &mut accept).expect("accept fits");
    let accept = &accept[..a];

    let good = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(ws_verify_upgrade(good, accept), Some(true));

    let forged = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
    assert_eq!(ws_verify_upgrade(forged, accept), Some(false));

    let not_101 = b"HTTP/1.1 200 OK\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(ws_verify_upgrade(not_101, accept), Some(false));

    // A partial header block is "keep reading", not "accepted".
    assert_eq!(ws_verify_upgrade(&good[..20], accept), None);
}

/// `Ready` is reachable only through a verified upgrade; every failure path
/// lands back in `Disconnected` rather than half-open.
#[test]
fn client_state_machine_gates_ready_on_the_upgrade() {
    let (act, phase) = ws_transition(WsPhase::Disconnected, WsEv::Start);
    assert_eq!((act, phase), (WsAct::Connect, WsPhase::Connecting));

    let (act, phase) = ws_transition(phase, WsEv::Connected);
    assert_eq!((act, phase), (WsAct::SendUpgrade, WsPhase::AwaitUpgrade));

    let (act, ready) = ws_transition(phase, WsEv::Upgraded);
    assert_eq!((act, ready), (WsAct::None, WsPhase::Ready));

    assert_eq!(
        ws_transition(phase, WsEv::UpgradeFailed),
        (WsAct::Fail, WsPhase::Disconnected)
    );
    for ev in [WsEv::PeerClosed, WsEv::NetError] {
        assert_eq!(
            ws_transition(ready, ev),
            (WsAct::Fail, WsPhase::Disconnected),
            "{ev:?} must fully tear the session down"
        );
    }
    // A frame event before the upgrade cannot advance the phase.
    assert_eq!(
        ws_transition(WsPhase::Connecting, WsEv::Upgraded),
        (WsAct::None, WsPhase::Connecting)
    );
}

/// Endpoint parameters arrive hex-encoded because a config carries text, not raw
/// bytes; the decode must reject anything malformed.
#[test]
fn hex_round_trips_and_rejects_malformed_input() {
    let mut out = [0u8; 6];
    let n = hex_decode(b"7f000001235c", &mut out).expect("decodes");
    assert_eq!(&out[..n], &[0x7f, 0x00, 0x00, 0x01, 0x23, 0x5c]);

    assert!(hex_decode(b"abc", &mut out).is_none(), "odd length");
    assert!(hex_decode(b"zz", &mut out).is_none(), "non-hex digit");
    assert!(
        hex_decode(b"00112233445566", &mut out).is_none(),
        "output too small"
    );
}
