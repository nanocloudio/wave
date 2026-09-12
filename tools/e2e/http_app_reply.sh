#!/usr/bin/env bash
# THE APPLICATION FAN-OUT'S REPLY HALF, END TO END.
#
# `http` terminates the connection and hands the request to a module over
# `req_out`; that module answers on `resp_in` and the gateway composes the
# response. This is the shape every application graph is built on — an identity
# provider answering `POST /oauth/token` is this path with a different module
# behind it — and the half that matters is the REPLY: a request the gateway
# forwards but whose answer never gets composed leaves the connection open and
# silent, which a client can only report as a timeout.
#
# So each assertion here is about the answer arriving, not the request leaving:
#
#   * a POST body reaches the application and its answer reaches the client,
#     carrying the method, path and body the application saw — proving the
#     gateway consulted it rather than answering by itself;
#   * a status the application chose is forwarded verbatim, including one the
#     gateway would never mint on its own;
#   * two requests on ONE connection are each answered, and answered in order —
#     the correlation is per request, not per connection.
#
# `modules/fixtures/http_echo_app` is the far side: a conformance fixture that
# reflects what it was handed, which is the least an application can do while
# still proving the contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
SYNCED_RUNTIME="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
if [ -n "${WAVE_LINUX_RUNTIME:-}" ]; then
  RUNTIME="$WAVE_LINUX_RUNTIME"
elif [ -x "$SYNCED_RUNTIME" ]; then
  RUNTIME="$SYNCED_RUNTIME"
else
  RUNTIME="$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor-linux"
fi

# Fixed, because the graph names it: examples/linux/wave_http_app.yaml listens
# on this port.
PORT=18082
WORK=""
PID=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  [ -n "$WORK" ] && rm -rf "$WORK" || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [ -n "$WORK" ] && tail -20 "$WORK/runtime.log" 2>/dev/null; exit 1; }

command -v curl >/dev/null 2>&1 || { echo "SKIP: curl not available"; exit 0; }
[ -x "$RUNTIME" ] || fail "no fluxor-linux runtime at $RUNTIME"

WORK="$(mktemp -d /tmp/wave-appreply-XXXXXX)"

echo "── building examples/linux/wave_http_app.yaml ──"
( cd "$ROOT" && fluxor build examples/linux/wave_http_app.yaml ) >/dev/null || fail "fluxor build"
OUT="$ROOT/target/linux/wave_http_app"
[ -s "$OUT/config.bin" ] || fail "$OUT/config.bin missing or empty"

echo "── booting on :$PORT ──"
"$RUNTIME" --config "$OUT/config.bin" --modules "$OUT/modules.bin" >"$WORK/runtime.log" 2>&1 &
PID=$!
for _ in $(seq 1 80); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
ss -ltn 2>/dev/null | grep -q ":$PORT " || fail "never bound :$PORT"
kill -0 "$PID" 2>/dev/null || fail "runtime exited immediately"

base="http://127.0.0.1:$PORT"

# The identity-provider shape: a POST with a body, answered by the module.
got="$(curl -fsS --http1.1 --max-time 10 -X POST --data-binary 'grant=client_credentials' \
        -H 'Content-Type: text/plain' "$base/app/token" 2>&1)" \
  || fail "POST /app/token got no answer (the reply never reached the client)"
case "$got" in
  *"method=POST"*"path=/app/token"*"body=grant=client_credentials"*)
    echo "   ok  the application's answer carried the method, path and body it saw" ;;
  *) fail "POST /app/token answered '$got'" ;;
esac

# A status the application chose. 401 is one the gateway has no route to mint,
# so seeing it proves the application's choice was forwarded rather than
# replaced by whatever the gateway would have said.
code="$(curl -s -o /dev/null -w '%{http_code}' --http1.1 --max-time 10 "$base/app/status/401")" \
  || fail "GET /app/status/401 got no answer"
[ "$code" = "401" ] || fail "application status not forwarded: got $code, wanted 401"
echo "   ok  a status the application chose is forwarded verbatim (401)"

# Two requests down one connection. `--next` reuses the socket, so an answer
# composed against the wrong request would show up here as the wrong body or a
# hang, neither of which a single request can reveal.
both="$(curl -fsS --http1.1 --max-time 15 "$base/app/first" --next "$base/app/second" 2>&1)" \
  || fail "a keep-alive pair was not fully answered: $both"
case "$both" in
  *"path=/app/first"*"path=/app/second"*)
    echo "   ok  two requests on one connection are both answered, in order" ;;
  *) fail "keep-alive pair answered '$both'" ;;
esac

kill -0 "$PID" 2>/dev/null || fail "runtime died during the run"

echo
echo "PASS: application fan-out reply path — request forwarded, answer composed, correlated back."
