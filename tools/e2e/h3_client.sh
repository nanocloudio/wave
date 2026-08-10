#!/usr/bin/env bash
# HTTP/3 CLIENT end to end: Wave `http` -> Fluxor `quic` -> aioquic server.
#
# The mirror of h3_e2e.sh. There, aioquic drives Wave's server; here aioquic IS
# the server and grades what Wave sends — it prints the method, path, authority
# and scheme it decoded, so the verdict is an outside implementation's reading
# of our request rather than our own bytes read back.
#
# Two Fluxor QUIC defects had to be fixed before this could pass at all, both
# invisible to fluxor-to-fluxor testing:
#   * client Initial datagrams were 1198 bytes. RFC 9000 §14.1 requires >=1200
#     and requires a server to DISCARD anything smaller, so every conforming
#     peer ignored us silently. Our own server did not enforce it.
#   * quic's built-in `GET /` self-test request went out alongside the app's.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
RUNTIME="${WAVE_LINUX_RUNTIME:-$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor-linux}"
PORT="${WAVE_H3_SERVER_PORT:-18555}"
WORK=""
SRV=""
CLI=""
cleanup() {
  [ -n "$CLI" ] && kill "$CLI" 2>/dev/null || true
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  [ -n "$WORK" ] && rm -rf "$WORK" || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [ -n "$WORK" ] && tail -20 "$WORK/client.log" 2>/dev/null; exit 1; }

python3 -c "import aioquic" 2>/dev/null || {
  [ "${WAVE_REQUIRE_INTEROP:-0}" = "1" ] && fail "WAVE_REQUIRE_INTEROP=1 but aioquic is missing"
  echo "SKIP: aioquic not installed — h3 client interop not exercised"; exit 0; }
[ -x "$RUNTIME" ] || fail "no fluxor-linux runtime at $RUNTIME"
[ -s /tmp/server_cert.pem ] || fail "/tmp/server_cert.pem missing (PEM, for the aioquic server)"

WORK="$(mktemp -d /tmp/wave-h3cli-XXXXXX)"
echo "── building examples/linux/wave_h3_client.yaml ──"
( cd "$ROOT" && fluxor build examples/linux/wave_h3_client.yaml ) >/dev/null || fail "graph build"

echo "── starting the aioquic server on udp:$PORT ──"
python3 "$ROOT/tools/peers/h3_server.py" "$PORT" /tmp/server_cert.pem /tmp/server_key.pem \
  > "$WORK/server.log" 2>&1 &
SRV=$!
for _ in $(seq 1 40); do ss -ulnp 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
ss -ulnp 2>/dev/null | grep -q ":$PORT " || fail "aioquic server never bound"

echo "── booting Wave's h3 client ──"
( cd "$ROOT" && "$RUNTIME" --config target/linux/wave_h3_client/config.bin \
  --modules target/linux/wave_h3_client/modules.bin ) > "$WORK/client.log" 2>&1 &
CLI=$!
sleep 10

grep -q "handshake complete" "$WORK/client.log" || fail "no QUIC handshake"
echo "   ok  QUIC handshake with an independent server"

# The server's own reading of our request — not our bytes read back.
grep -q "path=b'/from-wave'" "$WORK/server.log" \
  || fail "the server did not see Wave's configured path: $(grep -a SERVER-SAW "$WORK/server.log" | head -1)"
grep -q "method=b'GET'" "$WORK/server.log" || fail "method not GET"
grep -q "scheme=b'https'" "$WORK/server.log" || fail "scheme missing"
echo "   ok  aioquic decoded Wave's request: GET /from-wave, scheme https"

# Exactly one request: quic's built-in self-test must not also fire.
n="$(grep -c SERVER-SAW "$WORK/server.log")"
[ "$n" = "1" ] || fail "expected exactly 1 request, saw $n (quic's self-test firing too?)"
echo "   ok  exactly one request on the wire"

grep -q "h3 client status=200 body=013" "$WORK/client.log" \
  || fail "client did not decode the 200 + 13-byte body: $(grep -a 'h3 client' "$WORK/client.log" | head -1)"
echo "   ok  Wave decoded the response: status 200, 13-byte body"

echo
echo "PASS: HTTP/3 client end to end — wave http -> fluxor quic -> aioquic."
