#!/usr/bin/env bash
# THE EXCHANGE CLIENT, END TO END: a request record in, a correlated reply out.
#
# `http`'s `exchange` variant takes its request from the graph rather than from
# params: a `Publish` on `publish_in` carries the record, the client performs
# it against a real origin, and the answer leaves on `reply_out` under the same
# `corr`, echoing the request's `msg_key`.
#
# What each block here is for:
#
#   * the plain record — the runtime survives composing a request head, the
#     ORIGIN sees the line the graph built, and the reply is the body alone
#     under the right correlation. The first of those is not ceremony: the
#     head is composed from the shared method table, which is the kind of
#     constant a flat `.fmod` image cannot hold as pointers
#     (`tools/ci/fmod_pic_relocs.sh`), and a fault there lands between the
#     connection opening and the first byte out, where every HTTP-level check
#     sees silence rather than an error. Two verbs, because the method token
#     is a span of one literal indexed by the verb;
#   * the extended record — the caller's headers reach the origin beside the
#     ones this client frames the request with, and the reply leads with the
#     status and the response's own headers;
#   * the blocks that are refused — a header block decides where the request
#     head ends and what the origin reads as framing, so one carrying a blank
#     line, a bare LF, or a field this client frames with is refused before a
#     connection is opened.
#
# Replies are decoded rather than searched. A substring match on the hex would
# accept a status, a key or a body landing anywhere in the frame, including in
# a length field, and would not notice a plain record answered in the extended
# shape.
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

# One publish frame:
#   [0xED][len:u16][corr:u64][flags][klen:u16][plen:u16][key][record]
# record = [method(|0x80)][path_len:u16][body_len:u16]([hdr_len:u16])
#          [path…][headers…][body…]
publish() {
  VERB="$1" REQ_PATH="$2" HDRS="$3" KEY="$4" CORR="$5" python3 - <<'INNER'
import os, struct
verb = int(os.environ["VERB"])
path = os.environ["REQ_PATH"].encode()
hdrs = os.environ["HDRS"].encode().decode("unicode_escape").encode("latin1")
key  = os.environ["KEY"].encode()
head = struct.pack('<HH', len(path), 0)
if verb & 0x80:
    head += struct.pack('<H', len(hdrs))
rec = bytes([verb]) + head + path + hdrs
pub = struct.pack('<QBHH', int(os.environ["CORR"]), 0, len(key), len(rec)) + key + rec
print((bytes([0xED]) + struct.pack('<H', len(pub)) + pub).hex())
INNER
}

# Drive one exchange. The graph has no end, so `timeout` stops it and 124 is
# what that looks like; a signal is not, and 139 is the fault the first block
# exists for, named so the failure stays legible when it is the one that
# happens.
run_one() {
  local hex="$1" label="$2"
  [ -n "$hex" ] || fail "$label: the record generator produced nothing"
  rm -f "$WORK/req.txt" "$WORK/reply.bin"
  set +e
  printf '%s' "$hex" | xxd -r -p \
    | timeout -k 2 20 "$RUNTIME" --config "$OUT/config.bin" --modules "$OUT/modules.bin" \
      >"$WORK/reply.bin" 2>"$WORK/runtime.log"
  local rc=$?
  set -e
  if [ "$rc" -eq 139 ]; then
    fail "$label: the module segfaulted composing the request (SIGSEGV)"
  elif [ "$rc" -ge 128 ]; then
    fail "$label: the runtime died on signal $((rc - 128))"
  elif [ "$rc" -ne 124 ] && [ "$rc" -ne 0 ]; then
    fail "$label: runtime exited $rc: $(tail -3 "$WORK/runtime.log")"
  fi
}

# Decode the reply frame and assert its envelope, then hand the payload to the
# caller's own checks on stdin.
#   decode_reply <corr> <status> <key> [python-assertions-on-`payload`]
decode_reply() {
  CORR="$1" STATUS="$2" KEY="$3" EXTRA="${4:-}" python3 - "$WORK/reply.bin" <<'INNER'
import os, struct, sys
raw = open(sys.argv[1], "rb").read()
assert raw[:1] == b"\xef", f"not MSG_REPLY: {raw[:1]!r}"
corr, status, klen, plen = struct.unpack_from('<QBHH', raw, 3)
assert corr == int(os.environ["CORR"]), f"corr {corr}"
assert status == int(os.environ["STATUS"]), f"reply status {status}"
key = raw[16:16 + klen]
assert key == os.environ["KEY"].encode(), f"msg_key {key!r}"
payload = raw[16 + klen:]
assert len(payload) == plen, f"plen {plen} but {len(payload)} bytes follow"
extra = os.environ["EXTRA"]
if extra:
    exec(extra)
INNER
}

# METHOD_GET = 1, METHOD_POST = 3 (modules/foundation/http/wire/method.rs).
i=0
for case in "1 GET /hello job-42" "3 POST /submit job-43"; do
  set -- $case
  verb="$1" name="$2" path="$3" key="$4"
  i=$((i + 1))

  echo "── $name $path ──"
  rec="$(publish "$verb" "$path" '' "$key" "$i")"
  run_one "$rec" "$name"
  echo "   ok  the module composed and sent the request without faulting"

  saw="$(head -1 "$WORK/req.txt" 2>/dev/null | tr -d '\r' || true)"
  case "$saw" in
    "$name $path HTTP/1.1") echo "   ok  origin saw: $saw" ;;
    "")  fail "$name: origin saw no request" ;;
    *)   fail "$name: origin saw '$saw', wanted '$name $path HTTP/1.1'" ;;
  esac

  # The payload is the body and nothing else: a plain record answered in the
  # extended shape would carry four bytes of head in front of it.
  decode_reply "$i" 0 "$key" \
    "assert payload == b'echo:$path', f'payload {payload!r}'" \
    || fail "$name: the reply was not the body alone"
  echo "   ok  reply is the body alone, under corr $i and msg_key '$key'"
done

echo "── GET /typed, asking for the whole response ──"
rec="$(publish $((1 | 0x80)) /typed 'X-Wave-Test: present\r\nAccept: text/plain\r\n' job-44 9)"
run_one "$rec" extended

# The caller's fields sit in a head that still carries the ones this client
# frames the request with, each exactly once.
python3 - "$WORK/req.txt" <<'INNER' || fail "extended: the request head is not what it should be"
import sys
head = open(sys.argv[1], "rb").read()
lines = head.split(b"\r\n")
assert lines[0] == b"GET /typed HTTP/1.1", f"request line {lines[0]!r}"
fields = [l for l in lines[1:] if l]
def count(name):
    return sum(1 for f in fields if f.lower().startswith(name + b":"))
assert count(b"x-wave-test") == 1, f"caller field not once: {fields}"
assert count(b"accept") == 1, f"caller field not once: {fields}"
assert count(b"host") == 1, f"host not once: {fields}"
assert count(b"connection") == 1, f"connection not once: {fields}"
assert b"X-Wave-Test: present" in fields, f"verbatim bytes not kept: {fields}"
INNER
echo "   ok  the caller's fields reached the origin, beside the client's own, each once"

decode_reply 9 0 job-44 "$(cat <<'INNER'
code, hdr_len = struct.unpack_from('<HH', payload, 0)
assert code == 200, f"status {code}"
headers = payload[4:4 + hdr_len]
body = payload[4 + hdr_len:]
assert headers.endswith(b"\r\n"), f"block does not end CRLF: {headers!r}"
assert b"X-Origin-Note: seen\r\n" in headers, f"headers {headers!r}"
assert body == b"echo:/typed", f"body {body!r}"
INNER
)" || fail "extended: the reply did not decode"
echo "   ok  reply leads with status 200 and the header block it describes, then the body"

# Every way a block can reach into the request head. Each is refused
# UNROUTABLE — the record is not one this provider will perform, as against
# OVERSIZE, which is one it cannot fit — and refused before a connection, so
# nothing of it reaches the origin.
refused() {
  local label="$1" hdrs="$2" corr="$3"
  echo "── $label ──"
  local rec
  rec="$(publish $((1 | 0x80)) /refused "$hdrs" job-45 "$corr")"
  run_one "$rec" "$label"
  [ ! -s "$WORK/req.txt" ] || fail "$label: a request reached the origin: $(cat "$WORK/req.txt")"
  # REFUSE_UNROUTABLE = 2 in fluxor's exchange contract.
  decode_reply "$corr" 2 job-45 "assert plen == 0, f'payload {payload!r}'" \
    || fail "$label: not refused UNROUTABLE"
  echo "   ok  refused UNROUTABLE, the producer answered, no request on the wire"
}

refused "a block whose blank line would end the head" \
        'X-A: 1\r\n\r\nGET /evil HTTP/1.1\r\nHost: x\r\n' 11
refused "a block naming a field the client frames with" \
        'Content-Length: 99\r\n' 12
refused "a block splitting a line on a bare LF" \
        'X-A: 1\nX-B: 2\r\n' 13

echo
echo "PASS: exchange client end to end — record in, request on the wire, correlated reply out."
