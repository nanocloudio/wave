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
#   tools/e2e/linux_graph.sh --app        # HANDLER_APP fan-out to a real module
#   tools/e2e/linux_graph.sh --all        # all three, sequentially
#
# Exits non-zero on the first failure and prints the runtime log tail, so a
# green line means the graph actually served bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
# Prefer the runtime `fluxor sync` materialises into THIS checkout: it is pinned
# by fluxor.lock, so it is the one the modules were built against. A sibling
# checkout is the fallback, for a working-on-both-repos setup where a local
# debug build is the point. Looking only at the sibling meant a fresh clone that
# had run `fluxor sync` — which is the documented setup — still failed here with
# "no fluxor-linux runtime", pointing at a build command it did not need.
SYNCED_RUNTIME="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
if [ -n "${WAVE_LINUX_RUNTIME:-}" ]; then
  RUNTIME="$WAVE_LINUX_RUNTIME"
elif [ -x "$SYNCED_RUNTIME" ]; then
  RUNTIME="$SYNCED_RUNTIME"
else
  RUNTIME="$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor-linux"
fi

PLAIN_PORT=18081
APP_PORT=18082
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

# ── HANDLER_APP: the request/response fan-out to a real graph node ──────────
#
# Everything above proves the gateway can answer from its own configuration.
# This proves it can answer from a module that did not exist when the route was
# written — which is the difference between serving files and serving an API.
#
# The far side is `modules/fixtures/http_echo_app`, which reflects the method,
# path and body it was handed. Asserting on that reflection rather than on a
# status code is deliberate: a 200 alone would also be produced by a gateway
# that answered by itself and never consulted anyone.
run_app() {
  boot_graph "examples/linux/wave_http_app.yaml" "wave_http_app" "$APP_PORT"
  local base="http://127.0.0.1:$APP_PORT"

  # The gateway still answers its own routes, in the same graph, on the same
  # listener — so a failure below is about the fan-out and not about the graph.
  assert_serves "$base/static" "served by the gateway" \
    "app: a config route still answers alongside" --http1.1

  # GET: method and path cross the port pair intact, and the FULL path arrives,
  # not just the part after the matched prefix.
  assert_serves "$base/app/hello" "method=GET path=/app/hello" \
    "app: GET reaches the application with its whole path" --http1.1

  # PUT with a body: the request-body path, end to end.
  assert_serves "$base/app/blobs" "method=PUT path=/app/blobs body=hello-from-curl" \
    "app: a PUT body reaches the application" \
    --http1.1 -X PUT --data-binary "hello-from-curl"

  # Methods beyond GET, dispatched from the shared vocabulary.
  assert_serves "$base/app/x" "method=DELETE" \
    "app: DELETE is dispatched, not refused" --http1.1 -X DELETE
  assert_serves "$base/app/x" "method=PATCH" \
    "app: PATCH is dispatched, not refused" \
    --http1.1 -X PATCH --data-binary "p"

  # `Expect: 100-continue`. curl sends it for a large enough body and WAITS; a
  # server that ignored it would hang here rather than fail fast.
  local big
  big="$(head -c 2000 /dev/zero | tr '\0' 'z')"
  assert_serves "$base/app/expect" "method=POST" \
    "app: a 100-continue upload completes" \
    --http1.1 -H "Expect: 100-continue" -X POST --data-binary "$big"

  # The application's status is forwarded verbatim, including ones the gateway
  # would never choose for itself.
  assert_status "$base/app/status/404" "404" \
    "app: an application 404 is forwarded" --http1.1
  assert_status "$base/app/status/201" "201" \
    "app: an application 201 is forwarded" --http1.1
  assert_status "$base/app/status/503" "503" \
    "app: an application 503 is forwarded" --http1.1

  # A streamed body larger than the connection's send buffer. This is the
  # artefact case: 4 x 2 KiB across four envelopes, which no single response
  # could carry.
  assert_stream_size "$base/app/stream" 8192 "app: a streamed body exceeds send_buf"

  # HEAD: answered, with the headers a GET would carry and no body.
  assert_head_without_body "$base/app/hello" "app: HEAD is answered without a body"

  # h2c over the same listener, same application: an application module must
  # not be able to tell which generation carried the request.
  assert_serves "$base/app/hello" "method=GET path=/app/hello" \
    "app: h2c reaches the same application" --http2-prior-knowledge
  assert_serves "$base/app/blobs" "method=PUT path=/app/blobs body=h2-body" \
    "app: an h2 PUT body reaches the application" \
    --http2-prior-knowledge -X PUT --data-binary "h2-body"

  stop_graph
  echo "PASS app fan-out (h1, h2c, bodies, streaming, statuses)"
}

# Assert a response body is exactly `want` bytes. Size rather than content,
# because the point of a streamed body is that all of it arrives — a truncation
# that kept the first chunk would satisfy any substring check.
assert_stream_size() {
  local url="$1" want="$2" label="$3"
  local got
  got="$(curl --silent --show-error --max-time 20 --http1.1 "$url" 2>"$WORK/curl.err" | wc -c)" \
    || fail "$label: curl failed — $(cat "$WORK/curl.err")"
  [ "$got" = "$want" ] || fail "$label: expected $want bytes, got $got"
  echo "  ok   $label ($got bytes)"
}

# HEAD must return the headers a GET would — Content-Length included — and no
# body. curl --head reports only the head, so the body is checked by asking for
# the transferred size.
assert_head_without_body() {
  local url="$1" label="$2"
  local head size
  head="$(curl --silent --show-error --max-time 10 --http1.1 --head "$url" 2>"$WORK/curl.err")" \
    || fail "$label: curl failed — $(cat "$WORK/curl.err")"
  case "$head" in
    *"200"*) ;;
    *) fail "$label: expected 200, got: ${head%%$'\r'*}" ;;
  esac
  case "$head" in
    *"Content-Length:"*) ;;
    *) fail "$label: HEAD must report the Content-Length its GET would" ;;
  esac
  size="$(curl --silent --show-error --max-time 10 --http1.1 --head \
    -o /dev/null -w '%{size_download}' "$url" 2>"$WORK/curl.err")" \
    || fail "$label: curl failed — $(cat "$WORK/curl.err")"
  [ "$size" = "0" ] || fail "$label: HEAD carried $size body bytes"
  echo "  ok   $label"
}

main() {
  need curl
  need fluxor
  require_runtime
  WORK="$(mktemp -d /tmp/wave-linux-graph-XXXXXX)"

  case "${1:---plain}" in
    --plain) run_plaintext ;;
    --tls)   run_tls ;;
    --app)   run_app ;;
    --all)   run_plaintext; run_app; run_tls ;;
    *) echo "usage: $0 [--plain|--app|--tls|--all]" >&2; exit 2 ;;
  esac
}

main "$@"
