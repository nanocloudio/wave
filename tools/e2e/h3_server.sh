#!/usr/bin/env bash
# HTTP/3 end to end: aioquic -> Fluxor `quic` -> Wave `http`.
#
# The complement to `linux_graph_run.sh` (which does h1/h2 over TCP). Boots
# examples/linux/wave_h3.yaml in a REAL Fluxor graph and drives it with
# **aioquic** — an independent HTTP/3 implementation, no shared lineage with
# either repository — so the verdict comes from an outside party rather than
# from Wave reading back its own bytes.
#
# Why aioquic and not curl: this host's curl is built against OpenSSL 3.5,
# whose QUIC client fails before sending a packet
# (`error:0A0003E7:SSL routines::invalid session id`). That is a curl/OpenSSL
# limitation, not a server one — the server never sees the connection.
#
# What it asserts, and why each one is here:
#   * a configured route serves ITS body, not a fixture (the whole point of
#     moving HTTP/3 out of the transport);
#   * a second route serves a different body (so the first was really routed);
#   * an unmatched path is a 404 rendered by Wave;
#   * a TEMPLATE route renders through the same renderer h1/h2 use;
#   * requests keep working across MANY connections (the connection pool is
#     reused, not one-shot);
#   * two requests in flight on ONE connection are both served (multiplexing —
#     the reason HTTP/3 exists);
#   * RFC 9220 extended CONNECT upgrades a stream to a WebSocket tunnel, and the
#     tunnel outlives the response that opened it.
#
# Usage: tools/e2e/h3_server.sh
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
PORT="${WAVE_H3_PORT:-18444}"
GRAPH="examples/linux/wave_h3.yaml"
NAME="wave_h3"

RUNTIME_PID=""
WORK=""
cleanup() {
  [ -n "$RUNTIME_PID" ] && kill "$RUNTIME_PID" 2>/dev/null || true
  [ -n "$WORK" ] && rm -rf "$WORK" || true
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; [ -n "$WORK" ] && tail -20 "$WORK/runtime.log" 2>/dev/null; exit 1; }

python3 -c "import aioquic" 2>/dev/null || {
  if [ "${WAVE_REQUIRE_INTEROP:-0}" = "1" ]; then
    fail "WAVE_REQUIRE_INTEROP=1 but aioquic is not installed"
  fi
  echo "SKIP: aioquic not installed — HTTP/3 end-to-end not exercised"
  exit 0
}
[ -x "$RUNTIME" ] || fail "no fluxor-linux runtime at $RUNTIME (build it: cd $FLUXOR_ROOT && cargo build --bin fluxor-linux --no-default-features --features host-linux --target aarch64-unknown-linux-gnu)"
[ -s /tmp/server_cert.der ] || fail "/tmp/server_cert.der missing — the graph needs a server certificate"

WORK="$(mktemp -d /tmp/wave-h3-XXXXXX)"
cat > "$WORK/client.py" <<'PY'
import asyncio, ssl, sys
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

class H3Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._http = H3Connection(self._quic)
        self.responses = {}
        self.finished = asyncio.Event()
        self.expect = 0

    def quic_event_received(self, event):
        for ev in self._http.handle_event(event):
            r = self.responses.setdefault(ev.stream_id, {"status": None, "body": b""})
            if isinstance(ev, HeadersReceived):
                r["status"] = dict(ev.headers).get(b":status")
            elif isinstance(ev, DataReceived):
                r["body"] += ev.data
            if getattr(ev, "stream_ended", False):
                r["done"] = True
            if sum(1 for v in self.responses.values() if v.get("done")) >= self.expect:
                self.finished.set()

    async def get_many(self, authority, paths):
        self.expect = len(paths)
        ids = {}
        for p in paths:
            sid = self._quic.get_next_available_stream_id(is_unidirectional=False)
            ids[sid] = p
            self._http.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", authority.encode()), (b":path", p.encode()),
            ], end_stream=True)
        self.transmit()
        try:
            await asyncio.wait_for(self.finished.wait(), timeout=8)
        except asyncio.TimeoutError:
            pass
        return [(ids.get(s, "?"), v["status"], v["body"]) for s, v in sorted(self.responses.items())]

async def main(host, port, paths):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=cfg, create_protocol=H3Client) as c:
        for path, status, body in await c.get_many(host, paths):
            print(f"{path}\t{(status or b'-').decode()}\t{body.decode(errors='replace').strip()}")

asyncio.run(main(sys.argv[1], int(sys.argv[2]), sys.argv[3:]))
PY

cat > "$WORK/ws.py" <<'PYWS'
import asyncio, ssl, sys
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

def mask_frame(opcode, payload):
    m = b"\x37\xfa\x21\x3d"
    return bytes([0x80 | opcode, 0x80 | len(payload)]) + m + bytes(
        b ^ m[i % 4] for i, b in enumerate(payload))

class WsClient(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._http = H3Connection(self._quic, enable_webtransport=True)
        self.status = None
        self.data = b""
        self.got_status = asyncio.Event()
        self.got_data = asyncio.Event()

    def quic_event_received(self, event):
        for ev in self._http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                self.status = dict(ev.headers).get(b":status")
                self.got_status.set()
            elif isinstance(ev, DataReceived):
                self.data += ev.data
                self.got_data.set()

    async def run(self, authority, path, message):
        sid = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._http.send_headers(sid, [
            (b":method", b"CONNECT"), (b":protocol", b"websocket"),
            (b":scheme", b"https"), (b":authority", authority.encode()),
            (b":path", path.encode()),
        ], end_stream=False)
        self.transmit()
        try:
            await asyncio.wait_for(self.got_status.wait(), timeout=6)
        except asyncio.TimeoutError:
            return
        print("status\t%s" % (self.status or b"-").decode())
        if self.status != b"200":
            return
        self._http.send_data(sid, mask_frame(0x1, message.encode()), end_stream=False)
        self.transmit()
        try:
            await asyncio.wait_for(self.got_data.wait(), timeout=6)
        except asyncio.TimeoutError:
            pass
        d = self.data
        if len(d) >= 2:
            op, ln = d[0] & 0x0F, d[1] & 0x7F
            print("frame\t%x\t%s\t%s" % (op, (d[1] & 0x80) != 0, d[2:2+ln].decode(errors="replace")))

async def main(host, port, path, message):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=cfg, create_protocol=WsClient) as c:
        await c.run(host, path, message)

asyncio.run(main(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]))
PYWS

echo "── building $GRAPH ──"
( cd "$ROOT" && fluxor build "$GRAPH" ) >/dev/null || fail "fluxor build $GRAPH"
out="$ROOT/target/linux/$NAME"
[ -s "$out/config.bin" ] && [ -s "$out/modules.bin" ] || fail "graph artefacts missing"

echo "── booting on udp:$PORT ──"
"$RUNTIME" --config "$out/config.bin" --modules "$out/modules.bin" >"$WORK/runtime.log" 2>&1 &
RUNTIME_PID=$!
for _ in $(seq 1 60); do
  ss -ulnp 2>/dev/null | grep -q ":$PORT " && break
  sleep 0.25
done
ss -ulnp 2>/dev/null | grep -q ":$PORT " || fail "nothing bound on udp:$PORT — the graph never booted"
sleep 1

check() { # path expected_status expected_body
  local got
  got="$(timeout 20 python3 "$WORK/client.py" 127.0.0.1 "$PORT" "$1" 2>/dev/null | head -1)"
  local status body
  status="$(printf '%s' "$got" | cut -f2)"
  body="$(printf '%s' "$got" | cut -f3)"
  [ "$status" = "$2" ] || fail "$1: status $status, expected $2 (raw: $got)"
  [ "$body" = "$3" ] || fail "$1: body '$body', expected '$3'"
  echo "   ok  $1 -> $status $body"
}

echo "── routed responses ──"
check /        200 "wave h3 ok"
check /health  200 "ok"
check /nowhere 404 "Not Found"

echo "── template route, rendered by the shared renderer ──"
tmpl="$(timeout 20 python3 "$WORK/client.py" 127.0.0.1 "$PORT" /page 2>/dev/null | head -1)"
echo "$tmpl" | cut -f2 | grep -q '^200$' || fail "/page: not 200 ($tmpl)"
# A STATIC handler would echo the literal `{{name}}`; its absence is the proof
# the template renderer ran.
echo "$tmpl" | grep -q '{{' && fail "/page: placeholder survived — template not rendered ($tmpl)"
echo "$tmpl" | grep -q 'from h3' || fail "/page: literal text lost ($tmpl)"
echo "   ok  /page -> 200 template rendered (placeholder substituted)"

echo "── connection pool is reusable (not one-shot) ──"
for i in 1 2 3 4; do
  check / 200 "wave h3 ok" >/dev/null || fail "connection $i failed"
done
echo "   ok  4 further connections served"

echo "── multiplexing: two requests in flight on ONE connection ──"
conc="$(timeout 25 python3 "$WORK/client.py" 127.0.0.1 "$PORT" / /health 2>/dev/null)"
echo "$conc" | grep -q $'/\t200\twave h3 ok' || fail "concurrent / not served: $conc"
echo "$conc" | grep -q $'/health\t200\tok' || fail "concurrent /health not served: $conc"
echo "   ok  both streams served on one connection"

echo "── RFC 9220: extended CONNECT upgrades a stream to a WebSocket tunnel ──"
ws="$(timeout 25 python3 "$WORK/ws.py" 127.0.0.1 "$PORT" /ws "hello over h3" 2>/dev/null)"
# $'...' so the TAB is a real tab: basic grep does not interpret \t.
printf '%s' "$ws" | grep -qF $'status\t200' || fail "extended CONNECT not accepted: $ws"
# opcode 1 = TEXT, and a SERVER frame must be unmasked (RFC 6455 5.1).
printf '%s' "$ws" | grep -qF $'frame\t1\tFalse\thello over h3' \
  || fail "tunnelled frame not echoed correctly: $ws"
echo "   ok  CONNECT -> 200, and a masked TEXT frame echoed back unmasked"

echo
echo "PASS: HTTP/3 served end to end — aioquic -> fluxor quic -> wave http."
