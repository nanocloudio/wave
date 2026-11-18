#!/usr/bin/env bash
# THE EXCHANGE CLIENT, END TO END: a request record in, its answer out.
#
# `http`'s `exchange` variant takes its request from the graph rather than from
# params: an exchange request HEAD on `request_in` carries the method, target,
# headers and body, the client performs it against a real origin, and the
# answer leaves on `response_out` under the requester's exchange id.
#
# What each block here is for:
#
#   * the plain request — the runtime survives composing a request head, the
#     ORIGIN sees the line the graph built, and the answer carries the origin's
#     status, content type, headers and body under the right id. The first of
#     those is not ceremony: the head is composed from the shared method table,
#     which is the kind of constant a flat `.fmod` image cannot hold as pointers
#     (`tools/ci/fmod_pic_relocs.sh`), and a fault there lands between the
#     connection opening and the first byte out, where every HTTP-level check
#     sees silence rather than an error. Two verbs, because the method token
#     is a span of one literal indexed by the verb;
#   * the requester's headers — they reach the origin beside the ones this
#     client frames the request with, each once;
#   * the header blocks that are refused — a header block decides where the
#     request head ends and what the origin reads as framing, so one carrying a
#     blank line, a bare LF, or a field this client frames with is answered 400
#     before a connection is opened.
#
# Answers are decoded rather than searched. A substring match on the hex would
# accept a status or a body landing anywhere in the record, including in a
# length field.
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

# One exchange request HEAD, its body inline, under the neutral head:
#   [kind=1][flags=0][id:14][op=CALL][verb][target_len:u16][meta_len:u16]
#   [peer_len:u16][resp_credit:u32][target…][meta…][body…]
# Each header the requester names is one meta field, `[key_len:u8][key]
# [val_len:u16][val]`, keyed by its name in lower case. HDRS is a list of
# `name: value` fields separated by `\r\n`; a field's value is taken
# verbatim, escapes and all, so a test can put a CR or LF in one.
request() {
  VERB="$1" REQ_PATH="$2" HDRS="$3" BODY="$4" XID="$5" python3 - <<'INNER'
import os, struct
verb = int(os.environ["VERB"])
path = os.environ["REQ_PATH"].encode()
raw = os.environ["HDRS"]
meta = b""
for field in [f for f in raw.split("\\r\\n") if f]:
    name, _, value = field.partition(":")
    key = name.strip().lower().encode()
    val = value.lstrip(" ").encode().decode("unicode_escape").encode("latin1")
    meta += bytes([len(key)]) + key + struct.pack('<H', len(val)) + val
body = os.environ["BODY"].encode()
xid = struct.pack('<Q', int(os.environ["XID"])) + bytes(6)
CALL = 1
head = bytes([1, 0]) + xid + bytes([CALL, verb]) + struct.pack('<HHHI', len(path), len(meta), 0, 65536)
print((head + path + meta + body).hex())
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

# Decode the answer — one response HEAD carrying the whole body — and assert
# its id and status, then hand it to the caller's own checks. `raised` says
# the client refused the request itself, so the HEAD must be marked RAISED;
# an origin's answer must not be.
#   decode_answer <id> <status> [python-assertions-on-`ct`,`headers`,`body`] [raised]
decode_answer() {
  XID="$1" STATUS="$2" EXTRA="${3:-}" RAISED="${4:-}" python3 - "$WORK/reply.bin" <<'INNER'
import os, struct, sys
raw = open(sys.argv[1], "rb").read()
assert raw[:1] == b"\x01", f"not a response HEAD: {raw[:16]!r}"
RAISED = 0x08
want = RAISED if os.environ["RAISED"] else 0
assert raw[1] & 0x01 == 0, f"the answer is not whole in one record: flags {raw[1]}"
assert raw[1] == want, f"flags {raw[1]:#x}, wanted {want:#x} (RAISED marks a refusal)"
xid = struct.unpack_from('<Q', raw, 2)[0]
assert xid == int(os.environ["XID"]) and raw[10:16] == bytes(6), f"id {raw[2:16]!r}"
outcome, detail, meta_len = struct.unpack_from('<BHH', raw, 16)
# The HTTP binding: the status is the detail, else the outcome's own.
CANONICAL = {1: 200, 2: 400, 3: 404, 4: 403, 5: 409, 6: 413, 7: 503}
status = detail if detail else CANONICAL.get(outcome, 0)
assert status == int(os.environ["STATUS"]), f"status {status} (outcome {outcome}, detail {detail})"
at = 21
meta = raw[at:at + meta_len]
body = raw[at + meta_len:]
fields = []
m = 0
while m < len(meta):
    kl = meta[m]; key = meta[m + 1:m + 1 + kl]; m += 1 + kl
    vl = struct.unpack_from('<H', meta, m)[0]; val = meta[m + 2:m + 2 + vl]; m += 2 + vl
    fields.append((key, val))
ct = next((v for k, v in fields if k == b"content-type"), b"")
headers = b"".join(k + b": " + v + b"\r\n" for k, v in fields if not k.startswith(b":"))
extra = os.environ["EXTRA"]
if extra:
    exec(extra)
INNER
}

# Verbs of the HTTP binding (`exchange_http::method`): GET = 1, POST = 3.
i=0
for case in "1 GET /hello" "3 POST /submit"; do
  set -- $case
  verb="$1" name="$2" path="$3"
  i=$((i + 1))

  echo "── $name $path ──"
  rec="$(request "$verb" "$path" 'Content-Type: text/plain\r\n' 'payload' "$i")"
  run_one "$rec" "$name"
  echo "   ok  the module composed and sent the request without faulting"

  saw="$(head -1 "$WORK/req.txt" 2>/dev/null | tr -d '\r' || true)"
  case "$saw" in
    "$name $path HTTP/1.1") echo "   ok  origin saw: $saw" ;;
    "")  fail "$name: origin saw no request" ;;
    *)   fail "$name: origin saw '$saw', wanted '$name $path HTTP/1.1'" ;;
  esac

  decode_answer "$i" 200 "$(cat <<INNER
assert ct == b'text/plain', f'content type {ct!r}'
assert b'x-origin-note: seen\r\n' in headers, f'headers {headers!r}'
assert b'connection' not in headers, f'a framing field was forwarded {headers!r}'
assert body == b'echo:$path', f'body {body!r}'
INNER
)" || fail "$name: the answer did not decode"
  echo "   ok  the answer is the origin's status, content type, headers and body, under id $i"
done

echo "── GET /typed, with the requester's own headers ──"
rec="$(request 1 /typed 'X-Wave-Test: present\r\nAccept: text/plain\r\n' '' 9)"
run_one "$rec" headers

# The requester's fields sit in a head that still carries the ones this client
# frames the request with, each exactly once.
python3 - "$WORK/req.txt" <<'INNER' || fail "headers: the request head is not what it should be"
import sys
head = open(sys.argv[1], "rb").read()
lines = head.split(b"\r\n")
assert lines[0] == b"GET /typed HTTP/1.1", f"request line {lines[0]!r}"
fields = [l for l in lines[1:] if l]
def count(name):
    return sum(1 for f in fields if f.lower().startswith(name + b":"))
assert count(b"x-wave-test") == 1, f"requester field not once: {fields}"
assert count(b"accept") == 1, f"requester field not once: {fields}"
assert count(b"host") == 1, f"host not once: {fields}"
assert count(b"connection") == 1, f"connection not once: {fields}"
assert any(f.lower() == b"x-wave-test: present" for f in fields), f"value not kept: {fields}"
INNER
echo "   ok  the requester's fields reached the origin, beside the client's own, each once"
decode_answer 9 200 "assert body == b'echo:/typed', f'body {body!r}'" \
  || fail "headers: the answer did not decode"
echo "   ok  answered"

# Every way a block can reach into the request head. Each is answered 400 —
# not a request this provider will perform — and before a connection, so
# nothing of it reaches the origin.
refused() {
  local label="$1" hdrs="$2" xid="$3"
  echo "── $label ──"
  local rec
  rec="$(request 1 /refused "$hdrs" '' "$xid")"
  run_one "$rec" "$label"
  [ ! -s "$WORK/req.txt" ] || fail "$label: a request reached the origin: $(cat "$WORK/req.txt")"
  decode_answer "$xid" 400 "assert body == b'', f'body {body!r}'" raised \
    || fail "$label: not answered 400"
  echo "   ok  answered 400, raised by the client, no request on the wire"
}

refused "a value whose CR LF would end the head" \
        'X-A: 1\x0d\x0a\x0d\x0aGET /evil HTTP/1.1' 11
refused "a field the client frames with" \
        'Transfer-Encoding: chunked' 12
refused "a value splitting a line on a bare LF" \
        'X-A: 1\x0aX-B: 2' 13
refused "a host other than the pinned authority" \
        'Host: elsewhere.example' 14

echo
echo "PASS: exchange client end to end — request in, request on the wire, answer out."
