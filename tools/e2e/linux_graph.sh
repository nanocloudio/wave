#!/usr/bin/env bash
# Scripted Linux-graph runner (Conclave plan S3.4, T3.4.1).
#
# Boots Wave's `http` module inside a REAL Fluxor graph on the host — real
# scheduler, real `linux_net` transport, real TCP socket — and asserts it end to
# end with curl. The harness interop suites bridge a socket to a mocked runtime;
# this is the complement, and `../standards/rig.md` §7 names it as the proxy a rig
# graph should pass before it is worth booting silicon.
#
#   tools/e2e/linux_graph.sh              # plaintext
#   tools/e2e/linux_graph.sh --tls        # TLS-terminated (tls -> http)
#   tools/e2e/linux_graph.sh --all        # both, sequentially
#
# Exits non-zero on the first failure and prints the runtime log tail, so a
# green line means the graph actually served bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
RUNTIME="${WAVE_LINUX_RUNTIME:-$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor-linux}"

PLAIN_PORT=18081
TLS_PORT=18443
BODY_MARK="wave linux graph"

RUNTIME_PID=""
WORK=""

cleanup() {
  if [ -n "$RUNTIME_PID" ]; then
    kill "$RUNTIME_PID" 2>/dev/null || true
    wait "$RUNTIME_PID" 2>/dev/null || true
  fi
  [ -n "$WORK" ] && rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1" >&2
  if [ -n "$WORK" ] && [ -f "$WORK/runtime.log" ]; then
    echo "--- runtime.log (last 30) ---" >&2
    tail -30 "$WORK/runtime.log" >&2 || true
  fi
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is not on PATH"; }

# The runtime is built out of the Fluxor checkout. It is not a source change —
# just a build — but it is not produced by Wave's own build, so say exactly how
# to get it rather than failing with a bare path.
require_runtime() {
  [ -x "$RUNTIME" ] || fail "no fluxor-linux runtime at $RUNTIME
  Build it (a build, not a source change):
    cd $FLUXOR_ROOT
    cargo build --bin fluxor-linux --no-default-features --features host-linux \\
      --target aarch64-unknown-linux-gnu
  The --target is required: .cargo/config.toml pins a bare-metal ARM target, so
  without it the host crates compile no_std and the build fails inside \`log\`.
  Override the path with WAVE_LINUX_RUNTIME."
}

# Wait until $1 accepts a connection, or fail after ~10 s.
wait_for_port() {
  local port="$1" i=0
  while [ "$i" -lt 200 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3<&- 3>&-
      return 0
    fi
    sleep 0.05
    i=$((i + 1))
  done
  fail "nothing listening on 127.0.0.1:$port after 10 s — the graph never bound"
}

boot_graph() {
  local yaml="$1" name="$2" port="$3"
  echo "── building $name ──"
  ( cd "$ROOT" && fluxor build "$yaml" ) >/dev/null || fail "fluxor build $yaml"

  local out="$ROOT/target/linux/$name"
  [ -s "$out/config.bin" ] || fail "$out/config.bin missing or empty"
  [ -s "$out/modules.bin" ] || fail "$out/modules.bin missing or empty"

  echo "── booting $name on :$port ──"
  "$RUNTIME" --config "$out/config.bin" --modules "$out/modules.bin" \
    >"$WORK/runtime.log" 2>&1 &
  RUNTIME_PID=$!
  sleep 0.3
  kill -0 "$RUNTIME_PID" 2>/dev/null || fail "runtime exited immediately"
  wait_for_port "$port"
}

stop_graph() {
  if [ -n "$RUNTIME_PID" ]; then
    kill "$RUNTIME_PID" 2>/dev/null || true
    wait "$RUNTIME_PID" 2>/dev/null || true
    RUNTIME_PID=""
  fi
}

# curl is the oracle: it enforces the framing rules and only reports a body when
# the status line, header terminator and Content-Length all agree.
assert_serves() {
  local url="$1" want="$2" label="$3"
  shift 3
  local body
  body="$(curl --silent --show-error --max-time 10 "$@" "$url" 2>"$WORK/curl.err")" \
    || fail "$label: curl failed — $(cat "$WORK/curl.err")"
  case "$body" in
    *"$want"*) echo "  ok   $label" ;;
    *) fail "$label: expected to find '$want' in the response, got: ${body:0:200}" ;;
  esac
}

assert_status() {
  local url="$1" want="$2" label="$3"
  shift 3
  local code
  code="$(curl --silent --show-error --max-time 10 -o /dev/null -w '%{http_code}' "$@" "$url" 2>"$WORK/curl.err")" \
    || fail "$label: curl failed — $(cat "$WORK/curl.err")"
  [ "$code" = "$want" ] || fail "$label: expected HTTP $want, got $code"
  echo "  ok   $label"
}

# WebSocket echo through the graph, using an independent RFC 6455 client.
# Skipped (loudly) when no interpreter with `websockets` is available — the
# same policy as tests/harness/tests/ws_interop.rs.
assert_websocket_echo() {
  local port="$1" py="${WAVE_PYTHON:-python3}"
  if ! "$py" -c "import websockets" >/dev/null 2>&1; then
    echo "  SKIP websocket echo — \`$py\` has no websockets package (set WAVE_PYTHON)"
    return 0
  fi
  local got
  got="$("$py" -u -c '
import asyncio, sys, websockets
async def main():
    async with websockets.connect(sys.argv[1]) as ws:
        await ws.send("wave-linux-graph")
        print(await ws.recv())
asyncio.run(main())
' "ws://127.0.0.1:$port/ws" 2>"$WORK/ws.err")" \
    || fail "websocket echo: client failed — $(cat "$WORK/ws.err")"
  [ "$got" = "wave-linux-graph" ] \
    || fail "websocket echo: expected the payload back, got '$got'"
  echo "  ok   websocket echo round trips"
}

run_plaintext() {
  boot_graph "examples/linux/wave_http.yaml" "wave_http" "$PLAIN_PORT"
  local base="http://127.0.0.1:$PLAIN_PORT"
  # HTTP/1.1
  assert_serves "$base/" "$BODY_MARK" "h1: GET / serves the route body" --http1.1
  assert_serves "$base/healthz" "ok" "h1: GET /healthz serves the health body" --http1.1
  assert_status "$base/nope" "404" "h1: an unrouted path is 404" --http1.1
  # HTTP/2 cleartext, prior knowledge — no upgrade negotiation.
  assert_serves "$base/" "$BODY_MARK" "h2c: GET / serves the route body" --http2-prior-knowledge
  # WebSocket on the same listener.
  assert_websocket_echo "$PLAIN_PORT"
  stop_graph
  echo "PASS plaintext (h1, h2c, ws)"
}

run_tls() {
  local yaml="examples/linux/wave_https.yaml"
  [ -f "$ROOT/$yaml" ] || fail "no TLS graph at $yaml"
  need openssl

  # A throwaway P-256 cert; the graph reads DER, as the rig graph does.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 -subj "/CN=wave" \
    >/dev/null 2>&1 || fail "openssl could not mint a test certificate"
  openssl x509 -in "$WORK/cert.pem" -outform DER -out /tmp/wave_linux_cert.der 2>/dev/null
  openssl ec -in "$WORK/key.pem" -outform DER -out /tmp/wave_linux_key.der 2>/dev/null

  boot_graph "$yaml" "wave_https" "$TLS_PORT"
  local base="https://127.0.0.1:$TLS_PORT"
  # --insecure: the cert is self-signed and minted seconds ago. This asserts the
  # TLS handshake and record layer, not a PKI decision.
  assert_serves "$base/" "$BODY_MARK" "h1+tls: GET / serves the route body" --insecure --http1.1
  assert_status "$base/nope" "404" "h1+tls: an unrouted path is 404" --insecure --http1.1
  stop_graph
  echo "PASS tls"
}

main() {
  need curl
  need fluxor
  require_runtime
  WORK="$(mktemp -d /tmp/wave-linux-graph-XXXXXX)"

  case "${1:---plain}" in
    --plain) run_plaintext ;;
    --tls)   run_tls ;;
    --all)   run_plaintext; run_tls ;;
    *) echo "usage: $0 [--plain|--tls|--all]" >&2; exit 2 ;;
  esac
}

main "$@"
