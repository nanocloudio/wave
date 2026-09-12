#!/usr/bin/env bash
# THE EXCHANGE CLIENT, END TO END: a request record in, a correlated reply out.
#
# `http`'s `exchange` variant takes its request from the graph rather than from
# params: a `Publish` on `publish_in` carries the record, the client performs
# it against a real origin, and the answer leaves on `reply_out` echoing the
# request's `msg_key`.
#
# Three assertions, because no two of them together are enough:
#
#   * the runtime is still alive at the end — this graph exercises the only
#     path that composes a request head from the shared method table, and the
#     table is the kind of constant a flat `.fmod` image cannot hold as
#     pointers (`tools/ci/fmod_pic_relocs.sh`). A fault there lands between
#     "connected" and the first byte on the wire, where no HTTP-level check
#     would see anything but silence;
#   * the ORIGIN saw the request line the graph built, path included — proving
#     the record was decoded and issued, not merely accepted;
#   * the REPLY carries the origin's body AND echoes `msg_key` — proving the
#     answer was correlated back, which is what lets a downstream stage rejoin
#     it without holding state.
#
# Two verbs, not one: the method token is a span of a shared literal indexed by
# the verb, so a single verb would leave every other span unread.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
# The runtime `fluxor sync` materialises into THIS checkout is pinned by
# fluxor.lock, so it is the one the modules were built against. A sibling
# checkout is the fallback, for a working-on-both-repos setup.
SYNCED_RUNTIME="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
if [ -n "${WAVE_LINUX_RUNTIME:-}" ]; then
  RUNTIME="$WAVE_LINUX_RUNTIME"
elif [ -x "$SYNCED_RUNTIME" ]; then
  RUNTIME="$SYNCED_RUNTIME"
else
  RUNTIME="$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor-linux"
fi

# Fixed, because the graph names it: `examples/linux/wave_http_exchange.yaml`
# dials 127.0.0.1 on this port.
PORT=18084
WORK=""
ORIGIN=""
cleanup() {
  [ -n "$ORIGIN" ] && kill "$ORIGIN" 2>/dev/null || true
  [ -n "$WORK" ] && rm -rf "$WORK" || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$RUNTIME" ] || fail "no fluxor-linux runtime at $RUNTIME"

WORK="$(mktemp -d /tmp/wave-exchange-XXXXXX)"

echo "── building examples/linux/wave_http_exchange.yaml ──"
( cd "$ROOT" && fluxor build examples/linux/wave_http_exchange.yaml ) >/dev/null \
  || fail "fluxor build"
OUT="$ROOT/target/linux/wave_http_exchange"
[ -s "$OUT/config.bin" ] || fail "$OUT/config.bin missing or empty"
[ -s "$OUT/modules.bin" ] || fail "$OUT/modules.bin missing or empty"

echo "── starting the origin on :$PORT ──"
python3 "$ROOT/tools/peers/http_origin.py" "$WORK/req.txt" "$PORT" >"$WORK/origin.log" 2>&1 &
ORIGIN=$!
for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
ss -ltn 2>/dev/null | grep -q ":$PORT " || fail "origin never bound :$PORT"

# One exchange: publish the record, read the reply frame back off stdout.
#   [0xED][len:u16][corr:u64][flags][klen:u16][plen:u16][key][record]
#   record = [method:u8][path_len:u16][body_len:u16][path…][body…]
exchange() {
  local verb="$1" path="$2" key="$3"
  local hex
  hex=$(VERB="$verb" REQ_PATH="$path" KEY="$key" python3 - <<'PY'
import os, struct
verb = int(os.environ["VERB"])
path = os.environ["REQ_PATH"].encode()
key  = os.environ["KEY"].encode()
rec  = bytes([verb]) + struct.pack('<HH', len(path), 0) + path
pub  = struct.pack('<QBHH', 7, 0, len(key), len(rec)) + key + rec
print((bytes([0xED]) + struct.pack('<H', len(pub)) + pub).hex())
PY
)
  rm -f "$WORK/req.txt"
  set +e
  printf '%s' "$hex" | xxd -r -p \
    | timeout -k 2 20 "$RUNTIME" --config "$OUT/config.bin" --modules "$OUT/modules.bin" \
      >"$WORK/reply.bin" 2>"$WORK/runtime.log"
  RC=$?
  set -e
}

# METHOD_GET = 1, METHOD_POST = 3 (modules/foundation/http/wire/method.rs).
for case in "1 GET /hello job-42" "3 POST /submit job-43"; do
  set -- $case
  verb="$1" name="$2" path="$3" key="$4"

  echo "── $name $path ──"
  exchange "$verb" "$path" "$key"

  # The graph has no end: `timeout` stops it, and 124 is what that looks like.
  # A signal is not. 139 is the segfault this test exists for, and naming it
  # keeps the failure legible when it is the one that happens.
  if [ "$RC" -eq 139 ]; then
    fail "$name: the module segfaulted composing the request head (SIGSEGV)"
  elif [ "$RC" -ge 128 ]; then
    fail "$name: the runtime died on signal $((RC - 128))"
  elif [ "$RC" -ne 124 ] && [ "$RC" -ne 0 ]; then
    fail "$name: runtime exited $RC: $(tail -3 "$WORK/runtime.log")"
  fi
  echo "   ok  the module composed and sent the request without faulting"

  saw="$(cat "$WORK/req.txt" 2>/dev/null || true)"
  case "$saw" in
    "$name $path HTTP/1.1") echo "   ok  origin saw: $saw" ;;
    "")  fail "$name: origin saw no request" ;;
    *)   fail "$name: origin saw '$saw', wanted '$name $path HTTP/1.1'" ;;
  esac

  got="$(xxd -p "$WORK/reply.bin" | tr -d '\n')"
  [ -n "$got" ] || fail "$name: no reply frame emitted"
  [ "${got:0:2}" = "ef" ] || fail "$name: reply is not MSG_REPLY (0xEF): ${got:0:2}"
  key_hex="$(printf '%s' "$key" | xxd -p | tr -d '\n')"
  body_hex="$(printf 'echo:%s' "$path" | xxd -p | tr -d '\n')"
  printf '%s' "$got" | grep -q "$key_hex" || fail "$name: reply did not echo msg_key"
  printf '%s' "$got" | grep -q "$body_hex" || fail "$name: reply body missing: $got"
  echo "   ok  reply echoes msg_key '$key' and carries the origin's body"
done

echo
echo "PASS: exchange client end to end — record in, request on the wire, correlated reply out."
