#!/usr/bin/env bash
# SIP + RTP media path end to end, on a real Fluxor graph.
#
# The L4 proxy for the voice path — rig.md §7 says a graph passes here before it
# is worth booting silicon, and this is the gate `pi5_wave_sip` sits behind.
#
# Driven by tools/peers/sip_ua.py, which is a PEER, NOT AN ORACLE: no independent
# SIP implementation is installable on this host (no sipp/pjsua/baresip; aiosip
# is dead on Python 3.13). Byte-level SIP correctness is pinned by
# tests/harness/tests/sip_vectors.rs and tests/harness/tests/sip_dialog_vectors.rs against the origin
# implementation. What this asserts is the system property those cannot reach:
# a call is answered, the answer's SDP names a port audio actually arrives on,
# audio comes back out, and BYE ends it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
# Prefer the runtime `fluxor sync` materialises into THIS checkout: it is pinned
# by fluxor.lock, so it is the one the modules were built against. A sibling
# checkout is the fallback, for a working-on-both-repos setup where a local
# debug build is the point.
SYNCED_RUNTIME="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
if [ -n "${WAVE_LINUX_RUNTIME:-}" ]; then
  RUNTIME="$WAVE_LINUX_RUNTIME"
elif [ -x "$SYNCED_RUNTIME" ]; then
  RUNTIME="$SYNCED_RUNTIME"
else
  RUNTIME="$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor-linux"
fi
DUT_SIP_PORT=5062
UA_SIP_PORT=5061
UA_RTP_PORT=5010
WORK=""
DUT=""
cleanup() { [ -n "$DUT" ] && kill "$DUT" 2>/dev/null || true; [ -n "$WORK" ] && rm -rf "$WORK" || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [ -n "$WORK" ] && tail -20 "$WORK/dut.log" 2>/dev/null; exit 1; }

[ -x "$RUNTIME" ] || fail "no fluxor-linux runtime at $RUNTIME"
WORK="$(mktemp -d /tmp/wave-sip-XXXXXX)"

echo "── building examples/linux/wave_sip.yaml ──"
( cd "$ROOT" && fluxor build examples/linux/wave_sip.yaml ) >/dev/null || fail "graph build"

echo "── booting the voice-echo graph ──"
( cd "$ROOT" && "$RUNTIME" --config target/linux/wave_sip/config.bin \
  --modules target/linux/wave_sip/modules.bin ) > "$WORK/dut.log" 2>&1 &
DUT=$!
sleep 4

echo "── placing a call ──"
set +e
timeout 40 python3 "$ROOT/tools/peers/sip_ua.py" call 127.0.0.1 "$DUT_SIP_PORT" \
  127.0.0.1 "$UA_SIP_PORT" "$UA_RTP_PORT" --frames 25 > "$WORK/ua.log" 2>&1
rc=$?
set -e
cat "$WORK/ua.log"

grep -q "^SIP-RESPONSE 200" "$WORK/ua.log" || fail "the call was not answered"
echo "   ok  INVITE answered with 200"

# The SDP answer must name the module's configured rtp_port (5006), not a
# default or an echo of ours — that is what proves the answer was built from
# this graph's configuration.
grep -q "^SDP-MEDIA-PORT 5006" "$WORK/ua.log" \
  || fail "the answer's SDP named the wrong media port: $(grep SDP-MEDIA "$WORK/ua.log")"
echo "   ok  the answer's SDP names the configured media port"

# Audio must come BACK. The graph loops playout into the transmitter, so this
# exercises receive -> jitter -> playout -> packetise -> transmit. More frames
# return than were sent: playout runs at a constant ptime cadence once the call
# is up, concealing gaps, which is the behaviour a voice path must have.
rtp_in="$(sed -n 's/.*RTP-RECEIVED \([0-9]*\).*/\1/p' "$WORK/ua.log")"
[ -n "$rtp_in" ] && [ "$rtp_in" -gt 0 ] || fail "no RTP came back from the DUT"
rtp_tone="$(sed -n 's/.*RTP-TONE \([0-9]*\).*/\1/p' "$WORK/ua.log")"
# Tone, not merely packets: the jitter adapter conceals losses at cadence, so
# a DUT that never heard a frame still returns a full run of silence.
[ -n "$rtp_tone" ] && [ "$rtp_tone" -gt 0 ] || fail "audio returned but ALL SILENCE — the receive path heard nothing"
echo "   ok  audio returned from the DUT ($rtp_in packets, $rtp_tone tone)"

grep -q "^BYE-ANSWERED" "$WORK/ua.log" || fail "BYE was not answered"
echo "   ok  BYE answered"

grep -q "\[rtp\] starting" "$WORK/dut.log" \
  || fail "sip never drove the transmitter (no rtp_ctrl START on the wire)"
echo "   ok  sip drove the separate rtp transmitter over rtp_ctrl"

[ "$rc" = "0" ] || fail "the UA reported failure (rc=$rc)"
echo
echo "PASS: SIP call + bidirectional RTP on a real graph."
