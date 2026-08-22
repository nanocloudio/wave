//! WebSocket: the server's half of RFC 6455, and the fan-out that rides it.
//!
//! Three layers, in order of how much they know.
//!
//! **Upgrade** — `begin_ws_upgrade` validates the request headers and computes
//! the accept proof. Until it succeeds, the connection is an HTTP request; after
//! it does, the slot is in a WS phase for the rest of its life.
//!
//! **Framing** — `ws_queue_frame` / `ws_begin_close` stage frames into
//! `send_buf`. The frame bytes themselves are `super::super::wire::ws`, which is
//! transport-agnostic: the same codec serves h1 upgrades, RFC 8441 h2 CONNECT
//! and RFC 9220 h3 CONNECT, so nothing here may assume an h1 connection.
//!
//! **Fan-out** — `HANDLER_WEBSOCKET_FANOUT` routes frames to and from the
//! module's `ws_out`/`ws_in` ports so a downstream module owns the application
//! protocol while this module keeps owning the envelope. Retention is the part
//! worth care: a late subscriber replays the last captured envelope, which is
//! correct for idempotent presentation state and WRONG for a session protocol —
//! hence `HANDLER_WEBSOCKET_SESSION`, which is identical wiring with replay
//! suppressed.

use super::super::connection::NET_CMD_SEND;
use super::super::wire::ws;
use super::response::build_error;
use super::routes::{HANDLER_WEBSOCKET_FANOUT, HANDLER_WEBSOCKET_SESSION};
use super::{
    cur_conn_id, cur_matched_route, cur_recv_buf_mut_ptr, cur_recv_buf_ptr, cur_recv_len,
    cur_send_buf_mut_ptr, cur_send_buf_ptr, cur_send_len, cur_slot, cur_slot_mut, cur_ws_fan_out,
    dev_channel_ioctl, dev_channel_port, dev_csprng_fill, dev_log, find_sentinel_ws_fanout_slot,
    find_slot_by_conn_id, heap_alloc, heap_free, log, msg_read, net_send, net_write_frame,
    set_cur_phase, HttpState, Phase, IOCTL_FLUSH, IOCTL_NOTIFY, MAX_CONCURRENT_CONNS, MSG_HDR_SIZE,
    NET_FRAME_HDR, POLL_IN, RECV_BUF_SIZE, SEND_BUF_SIZE,
};

// ── Retention buffer sizing ───────────────────────────────────────────────

/// Server-wide retention buffer capacity. Sized for one decoded
/// 800×480 RGB565 frame (~750 KiB) plus headroom for envelope
/// headers and a small margin; multi-MiB images won't fit and will
/// reset capture mid-stream — that's fine for the demo (single
/// fan-out producer + browser size cap), and the value can grow on
/// large-host profiles when a richer use case lands.
pub(crate) const RETAINED_BUF_CAP: usize = 2 * 1024 * 1024;
/// Per-envelope header in `retained_buf`:
/// `[opcode:u8][fin:u8][payload_len:u16 LE]`.
pub(crate) const RETAINED_ENVELOPE_HDR: usize = 4;
/// Ticks of `module_step` quiescence on `ws_in` before the next
/// captured envelope wipes the buffer and starts fresh. At a typical
/// 100µs tick the threshold is ~50 ms — much longer than the gap
/// between chunks of one decoded frame, much shorter than any
/// reasonable producer-side state change.
pub(crate) const RETAIN_RESET_TICKS: u16 = 500;

// ── Upgrade and framing ───────────────────────────────────────────────────

/// Try to upgrade the just-parsed HTTP request into a WebSocket
/// connection. Validates the required headers, computes the accept
/// value, and queues the 101 response into `send_buf`. Returns `true`
/// if the upgrade is in progress (caller should transition to
/// `WsHandshake`); `false` if the request is malformed (caller has
/// already populated `send_buf` with the appropriate error response and
/// transitioned to `DrainSend`).
pub(crate) unsafe fn begin_ws_upgrade(s: &mut HttpState) -> bool {
    let buf = cur_recv_buf_ptr(s);
    let len = cur_recv_len(s) as usize;

    let upgrade = ws::find_header_value(buf, len, b"Upgrade");
    let connection = ws::find_header_value(buf, len, b"Connection");
    let key = ws::find_header_value(buf, len, b"Sec-WebSocket-Key");
    let version = ws::find_header_value(buf, len, b"Sec-WebSocket-Version");

    let upgrade_ok = match upgrade {
        Some((off, n)) => ws::header_value_contains_token(buf, off, n, b"websocket"),
        None => false,
    };
    let connection_ok = match connection {
        Some((off, n)) => ws::header_value_contains_token(buf, off, n, b"upgrade"),
        None => false,
    };
    let version_ok = match version {
        Some((off, n)) => n == 2 && *buf.add(off) == b'1' && *buf.add(off + 1) == b'3',
        None => false,
    };

    let (key_off, key_len) = match key {
        Some(v) if upgrade_ok && connection_ok && version_ok => v,
        _ => {
            build_error(s, b"400 Bad Request", b"Bad Request\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return false;
        }
    };

    let mut accept = [0u8; 28];
    ws::compute_accept(buf.add(key_off), key_len, accept.as_mut_ptr());

    let written =
        ws::write_handshake_response(cur_send_buf_mut_ptr(s), SEND_BUF_SIZE, accept.as_ptr());
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = written as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_parsed = 0;
    }
    true
}

/// Build an unmasked server-to-client WebSocket frame in `send_buf`.
pub(crate) unsafe fn ws_queue_frame(
    s: &mut HttpState,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
) {
    ws_queue_frame_fin(s, opcode, true, payload, payload_len);
}

/// Variant that lets the caller control the FIN bit. Used by the fan-out
/// outbound path where a single application-level message may span multiple
/// WS frames (BINARY/fin=0, CONTINUATION/fin=0, ..., CONTINUATION/fin=1).
pub(crate) unsafe fn ws_queue_frame_fin(
    s: &mut HttpState,
    opcode: u8,
    fin: bool,
    payload: *const u8,
    payload_len: usize,
) {
    let written = ws::write_frame(
        cur_send_buf_mut_ptr(s),
        SEND_BUF_SIZE,
        fin,
        opcode,
        payload,
        payload_len,
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = written as u16;
    }
}

/// Build a CLOSE frame carrying `code` (network-byte-order u16) and
/// transition to the close-flush phase.
pub(crate) unsafe fn ws_begin_close(s: &mut HttpState, code: u16) {
    let payload = [(code >> 8) as u8, (code & 0xFF) as u8];
    ws_queue_frame(s, ws::OP_CLOSE, payload.as_ptr(), 2);
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = Phase::WsClose;
    }
}

//
// Wire format on the `ws_out` / `ws_in` ports (content type `WsFrame`):
//   [conn_id : u32 LE]   bytes 0..4
//   [opcode  : u8]       byte  4   (RFC 6455 opcode: text/binary/cont)
//   [fin     : u8]       byte  5   (1 = final frame in WS message)
//   [payload_len : u16 LE] bytes 6..8
//   [payload : payload_len bytes]
//
// One mailbox-style write per frame, capped at CHANNEL_BUFFER_SIZE.

pub(crate) const WS_FRAME_HDR: usize = 8;

/// Header bytes to reserve at the front of `send_buf` when sizing a
/// WS wire fragment. RFC 6455 §5.2 server-to-client frame headers
/// are 2 bytes for ≤125-byte payloads, 4 bytes for ≤65535-byte
/// payloads. We size each fragment so its header fits in 4 bytes
/// (i.e. payload ≤ 65535) and the total wire frame fits in
/// `SEND_BUF_SIZE`. Anything larger gets split into multiple
/// fragments via the continuation path.
pub(crate) const WS_FRAG_HDR_RESERVE: usize = 4;

/// Emit a single inbound WS data frame on the `ws_out` port.
///
/// Returns whether the caller may now consume the source frame. `false` means
/// only one thing — `ws_out` refused the write — and the caller must leave the
/// frame buffered so the identical bytes are offered again next step.
///
/// The two `true`-with-no-delivery cases are deliberate and different from
/// backpressure: an unwired port means nobody asked for the data, and an
/// envelope larger than the channel buffer can never be delivered however long
/// it is retried. Both are counted or structural; a full channel is neither,
/// and treating it like them loses a frame the peer successfully sent.
#[must_use]
pub(crate) unsafe fn ws_emit_fanout_frame(
    s: &mut HttpState,
    opcode: u8,
    fin: u8,
    payload: *const u8,
    payload_len: usize,
) -> bool {
    if s.server.ws_out_chan < 0 {
        return true;
    }
    if WS_FRAME_HDR + payload_len > super::super::abi::CHANNEL_BUFFER_SIZE {
        s.server.ws_envelopes_dropped = s.server.ws_envelopes_dropped.wrapping_add(1);
        return true;
    }
    let mut frame_buf = [0u8; super::super::abi::CHANNEL_BUFFER_SIZE];
    let conn_id = cur_conn_id(s) as u32;
    frame_buf[0..4].copy_from_slice(&conn_id.to_le_bytes());
    frame_buf[4] = opcode;
    frame_buf[5] = fin;
    let plen = payload_len as u16;
    frame_buf[6..8].copy_from_slice(&plen.to_le_bytes());
    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(
            payload,
            frame_buf.as_mut_ptr().add(WS_FRAME_HDR),
            payload_len,
        );
    }
    let total = WS_FRAME_HDR + payload_len;
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.server.ws_out_chan, super::super::POLL_OUT);
    if poll <= 0 || (poll as u32 & super::super::POLL_OUT) == 0 {
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        return false;
    }
    if (sys.channel_write)(s.server.ws_out_chan, frame_buf.as_ptr(), total) <= 0 {
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        return false;
    }
    true
}

/// Try to read one outbound WsFrame from `ws_in` and queue it as a WS
/// wire frame in `send_buf`. Returns true if a wire frame was queued,
/// false if no data was available or the frame couldn't fit.
///
/// Caller must guarantee `send_buf` is empty before calling — this
/// function unconditionally overwrites it.
///
/// **Fragmentation**: when the source envelope's payload exceeds
/// `SEND_BUF_SIZE - WS_FRAG_HDR_RESERVE`, the message is split across
/// multiple wire frames per RFC 6455 §5.4. The first fragment carries
/// the original opcode (BINARY/TEXT) with `fin=0`; subsequent
/// fragments carry `OP_CONTINUATION` with `fin=0`; the last carries
/// `fin=1` if the source envelope had `fin=1`. While a fragmentation
/// is in flight on the active slot (`ws_frag_buf` non-null) the
/// function emits the next continuation chunk instead of reading
/// from `ws_in` — preserving the message ordering guarantee that no
/// other frame interleaves with the fragmented one on the wire.
pub(crate) unsafe fn ws_drain_fanout_input(s: &mut HttpState) -> bool {
    if s.server.ws_in_chan < 0 {
        return false;
    }

    // If a fragmentation is in flight on the active slot, emit the
    // next continuation chunk — do not read a new frame from ws_in.
    let frag_in_flight = cur_slot(s)
        .map(|c| !c.ws_frag_buf.is_null())
        .unwrap_or(false);
    if frag_in_flight {
        return ws_emit_next_fragment(s);
    }

    let sys = &*s.syscalls;
    let chan = s.server.ws_in_chan;
    let poll = (sys.channel_poll)(chan, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return false;
    }

    let mut frame_buf = [0u8; super::super::abi::CHANNEL_BUFFER_SIZE];
    // mailbox-mode read pulls a complete WsFrame in one shot.
    let n = (sys.channel_read)(
        chan,
        frame_buf.as_mut_ptr(),
        super::super::abi::CHANNEL_BUFFER_SIZE,
    );
    if n < WS_FRAME_HDR as i32 {
        return false;
    }
    let payload_len = u16::from_le_bytes([frame_buf[6], frame_buf[7]]) as usize;
    let total = WS_FRAME_HDR + payload_len;
    if (n as usize) < total {
        // The envelope claims more than one channel read carries. It has
        // already been consumed, so it is lost — count it rather than let a
        // silently missing frame look like a producer that never sent one.
        s.server.ws_envelopes_dropped = s.server.ws_envelopes_dropped.wrapping_add(1);
        return false;
    }
    let opcode = frame_buf[4];
    let fin = frame_buf[5] != 0;

    // Route by envelope conn_id. ws_stream stamps the recipient
    // conn_id at bytes 0-3 of every envelope; the active slot
    // calling ws_drain may not be the target, so without explicit
    // routing one client's bytes could be delivered to another.
    //
    // Special case: until ws_stream observes an inbound frame
    // from the browser it stamps the `u32::MAX` "unclaimed"
    // sentinel — producer-first bundles (server pushes
    // immediately on connect) ride this path. Sentinel envelopes
    // go to the first ws-fan-out slot found; routing them by a
    // default id of 0 would alias slot 0, which is typically the
    // IP listener and never a fan-out target.
    //
    // Real conn_ids are u8 and originate from the IP module's TCP
    // slot index (`MAX_TCP_CONNS`, independent of HTTP's
    // `MAX_CONCURRENT_CONNS`). On the wire bytes 1..4 are
    // zero-padding for real ids; they're all `0xFF` for the
    // sentinel, which is how we distinguish "no real id yet" from
    // a valid id 255. `find_slot_by_conn_id` returns `None` when
    // no slot owns the requested id (the conn may have closed
    // between the producer's write and our read), so it doubles
    // as the validity check.
    let conn_u32 = u32::from_le_bytes([frame_buf[0], frame_buf[1], frame_buf[2], frame_buf[3]]);
    let target_idx = if conn_u32 == u32::MAX {
        match find_sentinel_ws_fanout_slot(s) {
            Some(i) => i,
            None => {
                // Either no fan-out slot is active, or several are and the
                // sentinel cannot say which one this envelope is for. Both are
                // a drop, and both are counted — the second case used to be a
                // silent delivery to the wrong client.
                s.server.ws_envelopes_dropped = s.server.ws_envelopes_dropped.wrapping_add(1);
                return false;
            }
        }
    } else {
        match find_slot_by_conn_id(s, conn_u32 as u16) {
            Some(i) => i,
            None => {
                // Unknown conn — the conn closed between the
                // producer's write and our read. Drop the envelope;
                // unavoidable loss for a closed recipient, but a rising
                // count distinguishes "the peer went away" from "the
                // producer is addressing connections that never existed".
                s.server.ws_envelopes_dropped = s.server.ws_envelopes_dropped.wrapping_add(1);
                return false;
            }
        }
    };

    // The target slot's send_buf must be empty before we overwrite
    // it. The active caller's own send_buf is empty by contract,
    // but the target's may not be. We've already consumed the
    // envelope from the mailbox (so ws_stream's tx_pending retry
    // can't replay it for us), so on contention we write it back:
    //
    //   * After `channel_read` the mailbox is STREAMING.
    //   * `channel_write` of the same envelope returns it to READY.
    //   * The cross-domain pump's POLL_OUT check observes
    //     non-STREAMING and holds — ws_stream stays in tx_pending
    //     until the mailbox is free again.
    //   * The next ws_drain on any slot reads the same envelope
    //     and re-attempts routing.
    //
    // The hold is bounded by the target's send_buf drain time —
    // typically a handful of ticks.
    let target_send_busy = {
        let slot = &*s.server.slots.as_ptr().add(target_idx);
        slot.send_len > slot.send_offset || !slot.ws_frag_buf.is_null()
    };
    if target_send_busy {
        let _ = (sys.channel_write)(chan, frame_buf.as_ptr(), total);
        return false;
    }

    // Switch cur_slot to target for the queue operation; the helpers
    // (ws_queue_frame_fin, cur_slot_mut, cur_send_buf_mut_ptr) all
    // key off cur_slot. Restore on the way out so the caller's
    // WsActive loop continues on its own slot.
    let saved_cur = s.server.cur_slot;
    s.server.cur_slot = target_idx as i32;

    let queued = ws_queue_envelope_on_active(
        s,
        opcode,
        fin,
        frame_buf.as_ptr().add(WS_FRAME_HDR),
        payload_len,
    );
    s.server.cur_slot = saved_cur;
    if !queued {
        return false;
    }

    // Capture: append this envelope to the retention buffer so a
    // future fan-out connect can replay the producer's snapshot
    // without the producer re-emitting. Idle-gap reset wipes the
    // buffer on the first envelope after a long quiet period so we
    // hold the *latest* state, not an unbounded history.
    retain_capture_envelope(
        s,
        opcode,
        fin,
        frame_buf.as_ptr().add(WS_FRAME_HDR),
        payload_len,
    );

    true
}

/// Queue one logical envelope on the currently-active slot. Single-
/// frame fast path if the payload fits within `SEND_BUF_SIZE -
/// WS_FRAG_HDR_RESERVE`; otherwise stamps the slot's `ws_frag_*`
/// fields and emits the first fragment, with subsequent
/// continuations driven by `ws_emit_next_fragment` on later ticks.
///
/// Caller guarantees:
///   * the active slot's `send_buf` is empty
///   * no fragmentation is currently in flight on the active slot
///
/// Returns `false` on heap-alloc failure (only possible for the
/// fragmentation path); the caller must treat that as "this envelope
/// is dropped and the producer must retry."
pub(crate) unsafe fn ws_queue_envelope_on_active(
    s: &mut HttpState,
    opcode: u8,
    fin: bool,
    payload: *const u8,
    payload_len: usize,
) -> bool {
    let max_chunk = SEND_BUF_SIZE.saturating_sub(WS_FRAG_HDR_RESERVE);
    if payload_len <= max_chunk {
        ws_queue_frame_fin(s, opcode, fin, payload, payload_len);
        return true;
    }
    let sys = &*s.syscalls;
    let frag_buf = heap_alloc(sys, payload_len as u32);
    if frag_buf.is_null() {
        return false;
    }
    core::ptr::copy_nonoverlapping(payload, frag_buf, payload_len);
    if let Some(cur) = cur_slot_mut(s) {
        cur.ws_frag_buf = frag_buf;
        cur.ws_frag_total = payload_len as u16;
        cur.ws_frag_offset = max_chunk as u16;
        cur.ws_frag_opcode = opcode;
        cur.ws_frag_orig_fin = if fin { 1 } else { 0 };
    }
    ws_queue_frame_fin(s, opcode, false, frag_buf, max_chunk);
    true
}

/// Append a captured envelope to the server-wide retention buffer.
/// Idle-gap reset: if `retained_idle_ticks > RETAIN_RESET_TICKS`,
/// wipe the buffer first so the captured snapshot reflects only the
/// *new* burst (avoids unbounded growth across producer state
/// changes). Envelopes that won't fit even after a reset are
/// dropped silently — retention is best-effort.
pub(crate) unsafe fn retain_capture_envelope(
    s: &mut HttpState,
    opcode: u8,
    fin: bool,
    payload: *const u8,
    payload_len: usize,
) {
    if s.server.retained_buf.is_null() || s.server.retained_cap == 0 {
        return;
    }
    if payload_len > u16::MAX as usize {
        return;
    }
    // Retention feeds ONLY `HANDLER_WEBSOCKET_FANOUT` replay. If no
    // configured route replays (session-mode fan-out or none at all),
    // capturing would retain one session's frames for no consumer —
    // and stale session data must not outlive its connection.
    let mut any_replay_route = false;
    for i in 0..s.server.route_count as usize {
        if s.server.routes[i].handler == HANDLER_WEBSOCKET_FANOUT {
            any_replay_route = true;
            break;
        }
    }
    if !any_replay_route {
        return;
    }
    let needed = RETAINED_ENVELOPE_HDR + payload_len;
    if s.server.retained_idle_ticks > RETAIN_RESET_TICKS {
        s.server.retained_used = 0;
        s.server.retained_envelope_count = 0;
    }
    if s.server.retained_used as usize + needed > s.server.retained_cap as usize {
        // No room — wipe and try once. If a single envelope still
        // can't fit, retention is misconfigured (cap too small for
        // this workload); drop and let the live path serve it.
        s.server.retained_used = 0;
        s.server.retained_envelope_count = 0;
        if needed > s.server.retained_cap as usize {
            return;
        }
    }
    let dst = s.server.retained_buf.add(s.server.retained_used as usize);
    *dst = opcode;
    *dst.add(1) = if fin { 1 } else { 0 };
    let len_bytes = (payload_len as u16).to_le_bytes();
    *dst.add(2) = len_bytes[0];
    *dst.add(3) = len_bytes[1];
    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(payload, dst.add(RETAINED_ENVELOPE_HDR), payload_len);
    }
    s.server.retained_used += needed as u32;
    s.server.retained_envelope_count = s.server.retained_envelope_count.saturating_add(1);
    s.server.retained_idle_ticks = 0;
}

/// Emit the next continuation fragment from the active slot's
/// in-flight fragmentation. Frees `ws_frag_buf` and clears state on
/// the final fragment (which carries the original `fin` bit).
pub(crate) unsafe fn ws_emit_next_fragment(s: &mut HttpState) -> bool {
    let max_chunk = SEND_BUF_SIZE.saturating_sub(WS_FRAG_HDR_RESERVE);
    let (buf, total, offset, orig_fin) = {
        let Some(cur) = cur_slot(s) else {
            return false;
        };
        (
            cur.ws_frag_buf,
            cur.ws_frag_total as usize,
            cur.ws_frag_offset as usize,
            cur.ws_frag_orig_fin,
        )
    };
    if buf.is_null() || offset >= total {
        return false;
    }

    let remaining = total - offset;
    let chunk = remaining.min(max_chunk);
    let is_last = chunk == remaining;
    let final_fin = is_last && orig_fin != 0;

    ws_queue_frame_fin(s, ws::OP_CONTINUATION, final_fin, buf.add(offset), chunk);

    if is_last {
        let sys = &*s.syscalls;
        heap_free(sys, buf);
        if let Some(cur) = cur_slot_mut(s) {
            cur.ws_frag_buf = core::ptr::null_mut();
            cur.ws_frag_total = 0;
            cur.ws_frag_offset = 0;
            cur.ws_frag_opcode = 0;
            cur.ws_frag_orig_fin = 0;
        }
    } else if let Some(cur) = cur_slot_mut(s) {
        cur.ws_frag_offset = (offset + chunk) as u16;
    }
    true
}

/// Process WebSocket frames buffered in `recv_buf`. Returns `true` if a
/// frame was processed (caller should re-enter the step loop), `false`
/// if more data is needed.
pub(crate) unsafe fn ws_process_inbound(s: &mut HttpState) -> bool {
    let buf_ptr = cur_recv_buf_mut_ptr(s);
    let len = cur_recv_len(s) as usize;

    let frame = match ws::parse_frame(buf_ptr, len) {
        Ok(Some(f)) => f,
        Ok(None) => return false,
        Err(()) => {
            // Drop everything buffered so the bad bytes don't get re-
            // parsed on every future tick — that would re-enter
            // `ws_begin_close` until the loop's progress signal flipped.
            if let Some(cur) = cur_slot_mut(s) {
                cur.recv_len = 0;
            }
            ws_begin_close(s, ws::CLOSE_PROTOCOL_ERROR);
            return true;
        }
    };

    let total = frame.header_len as usize + frame.payload_len as usize;
    if total > RECV_BUF_SIZE {
        // Frame won't fit in our receive buffer; close cleanly with
        // 1009 (Message Too Big) rather than reading partial data we
        // can't act on.
        ws_begin_close(s, ws::CLOSE_MESSAGE_TOO_BIG);
        return true;
    }
    if len < total {
        return false;
    }

    // Per RFC 6455 §5.3, every client→server frame must be masked.
    if !frame.masked {
        ws_begin_close(s, ws::CLOSE_PROTOCOL_ERROR);
        return true;
    }

    let payload_ptr = buf_ptr.add(frame.header_len as usize);
    ws::unmask(payload_ptr, frame.payload_len, &frame.mask_key);

    match frame.opcode {
        ws::OP_CLOSE => {
            // Echo the peer's close payload (or send a bare close if
            // they sent an empty body).
            let pl = frame.payload_len as usize;
            ws_queue_frame(s, ws::OP_CLOSE, payload_ptr, pl);
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::WsClose;
            }
        }
        ws::OP_PING => {
            ws_queue_frame(s, ws::OP_PONG, payload_ptr, frame.payload_len as usize);
        }
        ws::OP_PONG => {
            // Unsolicited pongs are valid keep-alives — drop silently.
        }
        ws::OP_TEXT | ws::OP_BINARY | ws::OP_CONTINUATION => {
            if cur_ws_fan_out(s) != 0 {
                // Fan out: emit a WsFrame record on `ws_out` and let the
                // downstream module decide what to do with the payload.
                //
                // A refusal leaves the frame in `recv_buf`, unconsumed, and
                // returns "need more data" so the same bytes are re-parsed and
                // re-offered next step. Consuming it here would drop a frame
                // the peer sent successfully, with nothing downstream aware one
                // was ever coming.
                if !ws_emit_fanout_frame(
                    s,
                    frame.opcode,
                    if frame.fin { 1 } else { 0 },
                    payload_ptr,
                    frame.payload_len as usize,
                ) {
                    return false;
                }
            } else {
                // Echo: send back as the same data opcode. Continuation
                // frames keep the original opcode the peer chose; the
                // echo pattern doesn't need to track fragmented messages
                // because we mirror them frame-for-frame.
                let echo_op = if frame.opcode == ws::OP_CONTINUATION {
                    ws::OP_CONTINUATION
                } else {
                    frame.opcode
                };
                ws_queue_frame(s, echo_op, payload_ptr, frame.payload_len as usize);
            }
        }
        _ => {
            ws_begin_close(s, ws::CLOSE_PROTOCOL_ERROR);
            return true;
        }
    }

    // Shift any bytes after this frame to the start of the buffer.
    let consumed = total;
    let leftover = len - consumed;
    if leftover > 0 {
        let mut i = 0;
        while i < leftover {
            *buf_ptr.add(i) = *buf_ptr.add(consumed + i);
            i += 1;
        }
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
    }
    true
}
