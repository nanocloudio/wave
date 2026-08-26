"""A minimal SIP user agent + RTP peer, for driving Wave's `sip` module.

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
This is a peer, not an oracle. Every other interop suite in this repository is
graded by an implementation with no shared lineage — curl, ffmpeg, Python
`websockets`, grpcio, Exim, aioquic — because a test written by the same author
as the code under test shares its blind spots.

No such SIP peer is available here: `sipp`, `pjsua` and `baresip` are not
installed, and `aiosip` (the only pip option) is dead on Python 3.13. So this
file is written deliberately and its limits are stated rather than implied:

  * It CANNOT tell you Wave's SIP bytes are right. That is what
    `modules/foundation/sip/tests/sip_vectors.rs` and `modules/foundation/sip/tests/sip_dialog_vectors.rs` are for — they pin
    the formatters and the dialog FSM against the origin implementation the
    module was extracted from, which IS independent.
  * It CAN tell you the media path works end to end on a real link: that a call
    is answered, that the answer's SDP names a port audio actually arrives on,
    and that audio sent to the DUT comes back out of it. That is a system
    property no codec vector reaches, and it is what the L4 and rig scenarios
    are asking about.

Replace it with `sipp` the moment one is installable; the assertions below are
written to survive that swap.

Usage:
    sip_ua.py call <dut_ip> <dut_sip_port> <local_ip> <local_sip_port>
                        <local_rtp_port> [--frames N]
"""

import socket
import struct
import sys
import time

# G.711 µ-law silence, the value `jitter_core` conceals with.
ULAW_SILENCE = 0xFF
PTIME_MS = 20
SAMPLES_PER_FRAME = 160  # 20 ms at 8 kHz


def sdp(local_ip, rtp_port):
    return (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {local_ip}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
    )


def invite(dut_ip, dut_port, local_ip, local_port, rtp_port, call_id, branch, tag):
    body = sdp(local_ip, rtp_port)
    return (
        f"INVITE sip:wave@{dut_ip}:{dut_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{branch}\r\n"
        f"From: <sip:test@{local_ip}>;tag={tag}\r\n"
        f"To: <sip:wave@{dut_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        f"Contact: <sip:test@{local_ip}:{local_port}>\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    ).encode()


def ack(dut_ip, dut_port, local_ip, local_port, call_id, branch, tag, to_tag):
    to = f"<sip:wave@{dut_ip}>" + (f";tag={to_tag}" if to_tag else "")
    return (
        f"ACK sip:wave@{dut_ip}:{dut_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{branch}\r\n"
        f"From: <sip:test@{local_ip}>;tag={tag}\r\n"
        f"To: {to}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 ACK\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


def bye(dut_ip, dut_port, local_ip, local_port, call_id, branch, tag, to_tag):
    to = f"<sip:wave@{dut_ip}>" + (f";tag={to_tag}" if to_tag else "")
    return (
        f"BYE sip:wave@{dut_ip}:{dut_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK{branch}\r\n"
        f"From: <sip:test@{local_ip}>;tag={tag}\r\n"
        f"To: {to}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 2 BYE\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


def parse_sdp_port(msg):
    """The audio port the peer's SDP answer names — where audio must be sent."""
    for line in msg.split(b"\r\n"):
        if line.startswith(b"m=audio "):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def parse_to_tag(msg):
    for line in msg.split(b"\r\n"):
        if line.lower().startswith(b"to:") and b"tag=" in line:
            return line.split(b"tag=", 1)[1].split(b";")[0].decode(errors="replace")
    return None


def rtp_packet(seq, ts, ssrc, payload):
    """RFC 3550 §5.1: V=2, no padding/extension/CSRC, PT=0 (PCMU)."""
    return struct.pack("!BBHII", 0x80, 0x00, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + payload


def one_call(dut_ip, dut_port, local_ip, local_port, rtp_port, frames, call_id, tag):
    """Run a whole dialog: (answered, media_port, rtp_in, bye_ok, rtp_tone)."""
    return _dialog(dut_ip, dut_port, local_ip, local_port, rtp_port, frames, call_id, tag)


def main(argv):
    if len(argv) >= 6 and argv[0] == "diag":
        # Two calls in one boot: the rig costs a power cycle per attempt, so a
        # diagnosis that needs "with media" vs "without media" gets both from
        # one run rather than two cycles and a comparison across reboots.
        dut_ip, dut_port = argv[1], int(argv[2])
        local_ip, local_port, rtp_port = argv[3], int(argv[4]), int(argv[5])
        a = _dialog(dut_ip, dut_port, local_ip, local_port, rtp_port, 50, "wave-diag-a", "8801")
        print(f"DIAG call-a-media answered={int(a[0])} rtp_in={a[2]} rtp_tone={a[4]} bye={int(a[3])}", flush=True)
        time.sleep(1)
        # Same local SIP port as call A, deliberately: the module answers to its
        # CONFIGURED peer_sip_port, so a second call on a different local port
        # is unanswerable by construction — that looked like a one-call-per-boot
        # defect until the port was the thing that changed.
        b = _dialog(dut_ip, dut_port, local_ip, local_port, rtp_port + 2, 0,
                    "wave-diag-b", "8802")
        print(f"DIAG call-b-nomedia answered={int(b[0])} rtp_in={b[2]} rtp_tone={b[4]} bye={int(b[3])}", flush=True)
        return 0
    if len(argv) < 6 or argv[0] != "call":
        print(__doc__)
        return 2
    dut_ip, dut_port = argv[1], int(argv[2])
    local_ip, local_port, rtp_port = argv[3], int(argv[4]), int(argv[5])
    frames = 50
    if "--frames" in argv:
        frames = int(argv[argv.index("--frames") + 1])
    answered, media_port, received, bye_ok, tone = _dialog(
        dut_ip, dut_port, local_ip, local_port, rtp_port, frames, "wave-l4-test", "9911")
    if not answered:
        print("RESULT fail=no-answer", flush=True)
        return 1
    if media_port is None:
        print("RESULT fail=no-sdp-media-port", flush=True)
        return 1
    # Tone, not merely packets: the jitter adapter conceals losses at cadence,
    # so a DUT that never heard a frame still returns a full run of silence.
    ok = received > 0 and tone > 0 and bye_ok
    print(f"RESULT {'pass' if ok else 'fail'} answered=1 media_port={media_port} "
          f"rtp_in={received} rtp_tone={tone} bye={int(bye_ok)}", flush=True)
    return 0 if ok else 1


def _dialog(dut_ip, dut_port, local_ip, local_port, rtp_port, frames, call_id, tag):
    sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # A previous run's socket can still be in the kernel's table; without this a
    # rig scenario fails on bind and reports it as "the DUT did not answer".
    sip.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sip.bind((local_ip, local_port))
    sip.settimeout(5.0)
    rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rtp.bind((local_ip, rtp_port))
    # Short timeout: the send loop must keep the ptime cadence, so it drains
    # opportunistically rather than blocking half a second per frame.
    rtp.settimeout(0.005)

    # ── INVITE ──────────────────────────────────────────────────────────
    sip.sendto(invite(dut_ip, dut_port, local_ip, local_port, rtp_port, call_id, "1", tag),
               (dut_ip, dut_port))
    answer, to_tag, media_port = None, None, None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            data, _ = sip.recvfrom(2048)
        except socket.timeout:
            break
        if data.startswith(b"SIP/2.0"):
            code = data.split(b" ", 2)[1].decode(errors="replace")
            print(f"SIP-RESPONSE {code}", flush=True)
            if code.startswith("2"):
                answer = data
                to_tag = parse_to_tag(data)
                media_port = parse_sdp_port(data)
                break
    if answer is None or media_port is None:
        sip.close(); rtp.close()
        return (answer is not None, media_port, 0, False)
    print(f"SDP-MEDIA-PORT {media_port}", flush=True)

    sip.sendto(ack(dut_ip, dut_port, local_ip, local_port, call_id, "1", tag, to_tag),
               (dut_ip, dut_port))

    # ── Media ───────────────────────────────────────────────────────────
    # Send a run of PCMU frames at ptime cadence to the port the ANSWER named,
    # and count what comes back. The DUT graph loops its playout into its
    # transmitter, so audio returning at all exercises receive -> jitter ->
    # playout -> packetise -> transmit.
    ssrc = 0x5AFE7357
    payload = bytes([0x55]) * SAMPLES_PER_FRAME  # a constant, non-silence tone
    received = 0
    got_payload_bytes = 0
    tone_frames = 0

    def _count(pkt):
        # Concealment is µ-law silence (0xFF): a frame carrying ANY tone byte
        # proves the DUT's RECEIVE path heard us. Counting packets alone is
        # blind to a dead receive path — the jitter adapter conceals losses at
        # cadence, so a DUT that never hears a single frame still transmits
        # a full run of silence (found by the §4.3 media-path mutation, which
        # a packet count did not detect).
        nonlocal received, got_payload_bytes, tone_frames
        if len(pkt) >= 12 and (pkt[0] >> 6) == 2:
            received += 1
            body = pkt[12:]
            got_payload_bytes += len(body)
            if any(b != ULAW_SILENCE for b in body):
                tone_frames += 1

    for i in range(frames):
        rtp.sendto(rtp_packet(i, i * SAMPLES_PER_FRAME, ssrc, payload), (dut_ip, media_port))
        # Hold the cadence while draining whatever has arrived.
        until = time.monotonic() + PTIME_MS / 1000.0
        while time.monotonic() < until:
            try:
                pkt, _ = rtp.recvfrom(2048)
            except socket.timeout:
                continue
            _count(pkt)
    # Drain anything still in flight.
    drain_until = time.monotonic() + 1.0
    while time.monotonic() < drain_until:
        try:
            pkt, _ = rtp.recvfrom(2048)
        except socket.timeout:
            continue
        _count(pkt)

    print(f"RTP-SENT {frames} RTP-RECEIVED {received} RTP-TONE {tone_frames} "
          f"PAYLOAD-BYTES {got_payload_bytes}", flush=True)

    # ── BYE ─────────────────────────────────────────────────────────────
    # Retransmit per RFC 3261 §17.1.2.1 (timer E): BYE is a non-INVITE request
    # over UDP, so a UA that sends it once and concludes the peer is dead is
    # reporting packet loss as a peer defect.
    byte_msg = bye(dut_ip, dut_port, local_ip, local_port, call_id, "2", tag, to_tag)
    sip.sendto(byte_msg, (dut_ip, dut_port))
    # Read until a 2xx arrives or the window closes, printing everything seen.
    # A single blocking read was not enough: the peer may still be retransmitting
    # its INVITE answer, and one read cannot tell "nothing came" from "something
    # else came first". Printing the traffic is what makes a failure diagnosable
    # from a rig capture, where there is no second chance to look.
    bye_ok = False
    bye_deadline = time.monotonic() + 5
    next_retry = time.monotonic() + 0.5
    retries = 0
    sip.settimeout(0.25)
    while time.monotonic() < bye_deadline:
        if time.monotonic() >= next_retry and retries < 3:
            retries += 1
            sip.sendto(byte_msg, (dut_ip, dut_port))
            print(f"BYE-RETRANSMIT {retries}", flush=True)
            next_retry = time.monotonic() + 0.5 * (2 ** retries)
        try:
            data, addr = sip.recvfrom(2048)
        except socket.timeout:
            continue
        first = data.split(b"\r\n", 1)[0].decode(errors="replace")
        print(f"AFTER-BYE from {addr[0]}:{addr[1]}: {first}", flush=True)
        if data.startswith(b"SIP/2.0 2") and b"BYE" in data:
            bye_ok = True
            print("BYE-ANSWERED", flush=True)
            break

    sip.close()
    rtp.close()
    return (True, media_port, received, bye_ok, tone_frames)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
