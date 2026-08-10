//! RTP jitter buffer parity vectors (Conclave plan S4.3, T4.3.7).
//!
//! Lock `modules/common/jitter_core.rs` to the reorder/playout behaviour of the origin
//! The ring: sequence-keyed insert within a
//! 16-packet forward window, in-order playout, and u-law-silence concealment for
//! missing sequences.

use super::sip::jitter_core::{
    JitterBuffer, Playout, JITTER_MAX_SLOTS, JITTER_SLOT_SIZE, ULAW_SILENCE,
};

/// A 160-byte payload whose bytes all equal `fill` — a stand-in for one 20 ms
/// G.711 frame, distinguishable per sequence.
fn frame(fill: u8) -> [u8; JITTER_SLOT_SIZE] {
    [fill; JITTER_SLOT_SIZE]
}

fn play(jb: &mut JitterBuffer) -> (Playout, [u8; JITTER_SLOT_SIZE]) {
    let mut out = [0u8; JITTER_SLOT_SIZE];
    let r = jb.playout(JITTER_SLOT_SIZE, &mut out).expect("out sized");
    (r, out)
}

#[test]
fn in_order_playout_returns_payloads() {
    let mut jb = JitterBuffer::new();
    for seq in 0u16..3 {
        assert!(jb.insert(seq, &frame(seq as u8 + 1)));
    }
    assert_eq!(jb.fill_count(), 3);
    for seq in 0u16..3 {
        let (r, out) = play(&mut jb);
        assert_eq!(r, Playout::Packet, "seq {seq}");
        assert_eq!(out, frame(seq as u8 + 1), "seq {seq} payload");
    }
    assert_eq!(jb.fill_count(), 0);
    assert_eq!(jb.packets_lost(), 0);
}

#[test]
fn missing_sequence_is_concealed_with_silence() {
    let mut jb = JitterBuffer::new();
    jb.insert(0, &frame(0xAA)); // establishes play base = 0
    jb.insert(2, &frame(0xCC)); // seq 1 never arrives

    let (r0, o0) = play(&mut jb);
    assert_eq!(r0, Playout::Packet);
    assert_eq!(o0, frame(0xAA));

    let (r1, o1) = play(&mut jb);
    assert_eq!(r1, Playout::Silence, "gap must conceal");
    assert_eq!(o1, [ULAW_SILENCE; JITTER_SLOT_SIZE]);

    let (r2, o2) = play(&mut jb);
    assert_eq!(r2, Playout::Packet);
    assert_eq!(o2, frame(0xCC));

    assert_eq!(jb.packets_lost(), 1);
}

#[test]
fn out_of_order_arrival_plays_in_sequence() {
    let mut jb = JitterBuffer::new();
    jb.insert(0, &frame(0x10)); // base = 0
    jb.insert(2, &frame(0x30)); // arrives before 1
    jb.insert(1, &frame(0x20)); // late but within window

    for (seq, fill) in [(0u16, 0x10u8), (1, 0x20), (2, 0x30)] {
        let (r, out) = play(&mut jb);
        assert_eq!(r, Playout::Packet, "seq {seq}");
        assert_eq!(out, frame(fill), "seq {seq}");
    }
}

#[test]
fn payloads_beyond_the_window_are_dropped() {
    let mut jb = JitterBuffer::new();
    jb.insert(0, &frame(1)); // base = 0
                             // Exactly at the window edge and beyond: dropped.
    assert!(
        !jb.insert(JITTER_MAX_SLOTS as u16, &frame(2)),
        "== window edge drops"
    );
    assert!(
        !jb.insert(JITTER_MAX_SLOTS as u16 + 5, &frame(3)),
        "far ahead drops"
    );
    // Last in-window sequence is accepted.
    assert!(
        jb.insert(JITTER_MAX_SLOTS as u16 - 1, &frame(4)),
        "window edge-1 stored"
    );
    assert_eq!(jb.fill_count(), 2);
}

#[test]
fn duplicate_sequence_is_not_overwritten() {
    let mut jb = JitterBuffer::new();
    assert!(jb.insert(0, &frame(0x11)));
    assert!(
        !jb.insert(0, &frame(0x22)),
        "same seq in a filled slot is ignored"
    );
    let (r, out) = play(&mut jb);
    assert_eq!(r, Playout::Packet);
    assert_eq!(out, frame(0x11), "first payload wins");
}

#[test]
fn playout_sequence_wraps_through_zero() {
    let mut jb = JitterBuffer::new();
    let base = 0xFFFEu16;
    jb.insert(base, &frame(0x01));
    jb.insert(base.wrapping_add(1), &frame(0x02)); // 0xFFFF
    jb.insert(base.wrapping_add(2), &frame(0x03)); // 0x0000 after wrap

    for fill in [0x01u8, 0x02, 0x03] {
        let (r, out) = play(&mut jb);
        assert_eq!(r, Playout::Packet, "fill {fill:#x}");
        assert_eq!(out, frame(fill));
    }
}

#[test]
fn short_payload_is_silence_padded_to_output_len() {
    let mut jb = JitterBuffer::new();
    let short = [0x7Fu8; 40]; // 5 ms, shorter than a 20 ms output frame
    jb.insert(0, &short);
    let (r, out) = play(&mut jb);
    assert_eq!(r, Playout::Packet);
    assert_eq!(&out[..40], &short, "payload copied");
    assert!(
        out[40..].iter().all(|&b| b == ULAW_SILENCE),
        "tail padded with silence"
    );
}

#[test]
fn reset_clears_state() {
    let mut jb = JitterBuffer::new();
    jb.insert(5, &frame(9));
    let _ = play(&mut jb);
    jb.reset();
    assert_eq!(jb.fill_count(), 0);
    assert_eq!(jb.packets_received(), 0);
    assert_eq!(jb.packets_lost(), 0);
    // A fresh base sequence is taken from the next insert.
    assert!(jb.insert(100, &frame(7)));
    let (r, out) = play(&mut jb);
    assert_eq!(r, Playout::Packet);
    assert_eq!(out, frame(7));
}

/// A sequence already behind the playout point is stale; accepting it would
/// alias onto a live slot via `seq % JITTER_MAX_SLOTS`.
#[test]
fn stale_payload_is_dropped() {
    let mut jb = JitterBuffer::default();
    jb.insert(100, &frame(1));
    let mut out = [0u8; JITTER_SLOT_SIZE];
    let _ = jb.playout(JITTER_SLOT_SIZE, &mut out); // base advances to 101
    assert!(
        !jb.insert(100, &frame(2)),
        "already-played sequence accepted"
    );
    assert!(!jb.insert(99, &frame(3)), "older sequence accepted");
}

/// An oversized payload is clamped to the slot rather than overflowing it.
#[test]
fn oversized_payload_is_clamped_to_the_slot() {
    let mut jb = JitterBuffer::default();
    assert!(jb.insert(1, &[0x7Eu8; JITTER_SLOT_SIZE * 2]));
    let mut out = [0u8; JITTER_SLOT_SIZE];
    assert_eq!(
        jb.playout(JITTER_SLOT_SIZE, &mut out),
        Some(Playout::Packet)
    );
    assert!(out.iter().all(|&b| b == 0x7E));
}

/// `playout` refuses a buffer shorter than the requested frame rather than
/// writing a partial frame.
#[test]
fn playout_refuses_a_short_output_buffer() {
    let mut jb = JitterBuffer::default();
    jb.insert(1, &frame(1));
    assert_eq!(jb.playout(JITTER_SLOT_SIZE, &mut [0u8; 8]), None);
}
