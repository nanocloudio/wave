#!/usr/bin/env bash
# THE `wave-s3` SERVICE, END TO END, WITH REAL S3 TRAFFIC.
#
#   publish examples/s3_service as a bundle (+ the fluxor-linux runtime)
#   into an isolated store
#   → a scratch consumer pins both, syncs, and checks the materialised bundle
#     carries exactly the pinned .fmod bytes
#   → an unknown param, a missing required param and a wrong type each refuse
#     the run before anything starts
#   → `fluxor run` serves it over the node's `storage.object` store, holding
#     a mesh root this script mints, with two access keys whose capabilities
#     name two buckets
#   → tools/e2e/s3_traffic.py drives it: object lifecycle, ranges, listings
#     and their pagination, multipart complete and abort, large bodies
#     streamed both ways in every payload form, concurrent clients, the
#     refusals (unsigned, wrong signature, skew, expired presigned, out of
#     scope, every oversize limit) and a client cut off mid-body
#   → `max_object_mib` and `part_min_kib` are run parameters, and the traffic
#     meets the ceilings this run set rather than the defaults
#   → wave's own `s3` connector, in examples/linux/wave_s3_client.yaml,
#     signs and streams requests to the same server: bodies written through
#     it read back byte for byte directly, and the reverse
#   → a credentials file holding a chain no root signed serves nothing.
#
# The run is launched from this project: `fluxor run` resolves the manifests
# of a bundle's modules from the project that built them.
set -euo pipefail

# The connector stage imports s3_traffic.py by path, and Python caches the
# bytecode beside whatever it imports. The source tree is not a build
# directory: a test that leaves artefacts in it has not finished running.
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$(cd "$ROOT/../fluxor" && pwd)}"
# The fluxor tree's own CLI, never one resolved from a store: the run below
# swaps in an isolated store, and a store-resolved CLI cannot find itself there.
FLUXOR="$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/release/fluxor"
[ -x "$FLUXOR" ] || { echo "FAIL: no fluxor CLI at $FLUXOR"; exit 1; }
[ -x "$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux" ] \
  || { echo "FAIL: no runtime in $FLUXOR_ROOT (make build there)"; exit 1; }

D="$(mktemp -d "${TMPDIR:-/tmp}/wave-s3-e2e-XXXXXX")"
RUN_PID=""
stop() {
  if [ -n "$RUN_PID" ]; then kill "$RUN_PID" 2>/dev/null || true; wait "$RUN_PID" 2>/dev/null || true; fi
  RUN_PID=""
}
stop_client() {
  if [ -n "${CLIENT_PID:-}" ]; then kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; fi
  CLIENT_PID=""
}
# `fluxor run` is the parent of the runtime that holds the listener, so the
# port outlives the wait above by however long the child takes to go. The
# script starts a second server after stopping the first, and a bind that
# loses that race reads as a server answering nothing rather than as a port
# still in use.
port_free() { ! ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN; }
await_port_free() {
  for _ in $(seq 1 60); do
    port_free "$1" && return 0
    sleep 0.25
  done
  return 1
}
cleanup() { stop_client; stop; rm -rf "$D"; }
trap cleanup EXIT
# On failure, show the node's own complaints BEFORE the tail: a store that
# could not be opened is reported once at startup and then never again, while
# the tail is whatever the last connection did. Answering every object call
# `ENOSYS` looks like a broken module from the outside, so the line that names
# the real cause must not scroll away.
# WAVE_KEEP_LOGS=<dir>: copy the run's logs there before cleanup, so a
# failure that needs correlating across both graphs can be read whole rather
# than through a 30-line tail.
fail() {
  if [ -n "${WAVE_KEEP_LOGS:-}" ]; then
    mkdir -p "$WAVE_KEEP_LOGS"
    for l in run.log client.log; do
      [ -f "$D/$l" ] && cp "$D/$l" "$WAVE_KEEP_LOGS/$l"
    done
    echo "  logs kept in $WAVE_KEEP_LOGS"
  fi
  echo "FAIL: $1"
  if [ -f "$D/run.log" ]; then
    grep -iE '\[store\]|ERROR' "$D/run.log" | head -10 | sed 's/^/--- /'
    echo "--- run.log ---"
    grep -v '\] \(tlm\|state\) \|MON_' "$D/run.log" | tail -30
  fi
  exit 1
}

# The modules build against this project's own pins, before the store is
# swapped for an isolated one.
(cd "$ROOT" && "$FLUXOR" modules build --target bcm2712) >"$D/build.log" 2>&1 \
  || { tail -20 "$D/build.log"; fail "modules build"; }

# Nothing here may touch the user's store, catalogue or workspace.
export FLUXOR_STORE="$D/store"
export XDG_DATA_HOME="$D/data"
export FLUXOR_APPLETS="$D/applets.toml"
export FLUXOR_WORKSPACE="$D/workspace.toml"
export FLUXOR_INSTALL_ROOT="$FLUXOR_ROOT"
unset FLUXOR_PROJECT_ROOT

echo "== publish =="
(cd "$ROOT" && "$FLUXOR" publish bundle examples/s3_service/workload.toml) >"$D/publish.log" 2>&1 \
  || { cat "$D/publish.log"; fail "publish bundle"; }
(cd "$FLUXOR_ROOT" && "$FLUXOR" publish runtime) >>"$D/publish.log" 2>&1 \
  || { cat "$D/publish.log"; fail "publish runtime"; }

echo "== consumer: pin + sync =="
C="$D/consumer"
mkdir -p "$C"
printf '[project]\nname = "s3-consumer"\nversion = "0.1.0"\n' >"$C/fluxor.toml"
(
  cd "$C"
  "$FLUXOR" store pin wave-s3:latest >/dev/null || fail "store pin bundle"
  "$FLUXOR" store pin fluxor/run/fluxor-linux-aarch64-unknown-linux-gnu:latest >/dev/null \
    || fail "store pin runtime"
  grep -q 'kind = "bundle"' fluxor.lock || fail "fluxor.lock has no bundle pin"
  "$FLUXOR" sync >"$D/sync.log" 2>&1 || { cat "$D/sync.log"; fail "sync"; }
)
B="$C/target/fluxor/bundles/wave-s3"
RUNTIME="$C/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
[ -x "$RUNTIME" ] || fail "sync materialised no runtime"
for f in workload.json graph.yaml resources.json modules/http.fmod modules/s3_serve.fmod; do
  [ -f "$B/$f" ] || fail "materialised bundle lacks $f"
done
python3 - "$B" <<'PY' || fail "materialised fmods do not match the pinned digests"
import hashlib, json, sys, pathlib
b = pathlib.Path(sys.argv[1])
m = json.loads((b / "workload.json").read_text())
imp = next(i for i in m["implementations"] if i["target"]["family"] == "linux")
assert m["role"] == "service", "not a service bundle"
for p in ("port", "credentials", "mesh_roots", "max_object_mib", "part_min_kib"):
    assert p in m["params"], f"schema lacks {p}"
for mod in imp["modules"]:
    got = "sha256:" + hashlib.sha256((b / "modules" / f"{mod['name']}.fmod").read_bytes()).hexdigest()
    assert got == mod["digest"], f"{mod['name']}: {got} != {mod['digest']}"
    print(f"  {mod['name']}.fmod = {got[:19]}… (pinned)")
PY

echo "== credentials =="
# A mesh root, and one capability per bucket over the storage scope the
# naming contract gives it (docs/reference/storage-object-naming.md).
head -c 32 /dev/urandom >"$D/root.seed"
MESH_ROOT="$("$FLUXOR" modules keygen --key "$D/root.seed" | tail -1)"
case "$MESH_ROOT" in [0-9a-f]*) [ "${#MESH_ROOT}" -eq 64 ] || fail "keygen printed '$MESH_ROOT'" ;; *) fail "keygen printed '$MESH_ROOT'" ;; esac
NOW="$(date +%s)"
mint() {
  "$FLUXOR" modules cap mint --key "$1" --scope "$2" --perms read_state,send_command \
    --not-before "$((NOW - 60))" --not-after "$((NOW + 86400))" | tail -1
}
{
  echo "# access-key secret scope capability"
  echo "AKALPHA0000000000001 alpha-secret-key alpha/ $(mint "$D/root.seed" alpha/)"
  echo "AKBETA00000000000002 beta-secret-key beta/ $(mint "$D/root.seed" beta/)"
} >"$D/credentials"
head -c 32 /dev/urandom >"$D/rogue.seed"
"$FLUXOR" modules keygen --key "$D/rogue.seed" >/dev/null
echo "AKROGUE0000000000003 rogue-secret rogue/ $(mint "$D/rogue.seed" rogue/)" >"$D/rogue-credentials"

echo "== refusals (nothing starts) =="
refuse() {
  local want="$1"; shift
  if (cd "$ROOT" && timeout 30 "$FLUXOR" run "$B" "$@") >"$D/refuse.log" 2>&1; then
    fail "run $* succeeded; expected a refusal"
  fi
  grep -q "$want" "$D/refuse.log" || { cat "$D/refuse.log"; fail "run $*: refusal does not say '$want'"; }
  if grep -q "Running bundle" "$D/refuse.log"; then fail "run $* started the graph before refusing"; fi
  echo "  refused: $*"
}
refuse "unknown param 'bogus'" --param credentials=/x --param mesh_roots=x --param bogus=1
refuse "missing required param 'credentials'" --param mesh_roots="$MESH_ROOT"
refuse "missing required param 'mesh_roots'" --param credentials="$D/credentials"
refuse "'max_object_mib' is an integer" --param credentials=/x --param mesh_roots=x --param max_object_mib=big

# Fixed, because examples/linux/wave_s3_client.yaml dials it.
PORT=18093
CLIENT_PORT=18094
# Said once, before anything is built: a port already in use fails every check
# that follows, and the reason is nowhere in the failures.
for p in "$PORT" "$CLIENT_PORT"; do
  port_free "$p" || fail "port $p is already in use — another run of this script, or a graph left behind by one"
done
CLIENT_PID=""

# `run <credentials> <max_object_mib> <part_min_kib>`: serve over a fresh
# object store, and wait until it answers.
run() {
  await_port_free "$PORT" || fail "port $PORT is still held; the previous server has not let it go"
  rm -rf "$D/objects" && mkdir -p "$D/objects"
  (cd "$ROOT" && FLUXOR_STORE_DIR="$D/objects" FLUXOR_MESH_ROOTS="$MESH_ROOT" \
    exec "$FLUXOR" run "$B" --param "port=$PORT" --param "credentials=$1" \
      --param "mesh_roots=$MESH_ROOT" --param "max_object_mib=$2" --param "part_min_kib=$3") \
    >"$D/run.log" 2>&1 &
  RUN_PID=$!
  for _ in $(seq 1 60); do
    kill -0 "$RUN_PID" 2>/dev/null || fail "fluxor run exited early"
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/"; then return; fi
    sleep 0.5
  done
  fail "nothing answered on :$PORT"
}

echo "== traffic =="
MAX_OBJECT_MIB=40
PART_MIN_KIB=64
run "$D/credentials" "$MAX_OBJECT_MIB" "$PART_MIN_KIB"
cat >"$D/traffic.json" <<EOF
{"region": "us-east-1", "max_object_mib": $MAX_OBJECT_MIB, "part_min_kib": $PART_MIN_KIB,
 "alpha": {"key": "AKALPHA0000000000001", "secret": "alpha-secret-key", "bucket": "alpha"},
 "beta":  {"key": "AKBETA00000000000002", "secret": "beta-secret-key", "bucket": "beta"}}
EOF
python3 "$ROOT/tools/e2e/s3_traffic.py" "127.0.0.1:$PORT" "$D/traffic.json" || fail "s3 traffic"

echo "== curl's own SigV4 =="
AWS="aws:amz:us-east-1:s3"
U="AKALPHA0000000000001:alpha-secret-key"
printf 'signed by curl' >"$D/curl.txt"
code="$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "$AWS" --user "$U" -T "$D/curl.txt" \
  "http://127.0.0.1:$PORT/alpha/curl.txt")"
[ "$code" = 200 ] || fail "curl --aws-sigv4 PUT answered $code"
got="$(curl -s --aws-sigv4 "$AWS" --user "$U" "http://127.0.0.1:$PORT/alpha/curl.txt")"
[ "$got" = "signed by curl" ] || fail "curl --aws-sigv4 GET returned '$got'"
echo "  ok  curl --aws-sigv4 PUT and GET"

echo "== wave's s3 connector against it =="
(cd "$ROOT" && "$FLUXOR" build examples/linux/wave_s3_client.yaml) >"$D/client-build.log" 2>&1 \
  || { cat "$D/client-build.log"; fail "build the client graph"; }
CG="$ROOT/target/linux/wave_s3_client"
"$RUNTIME" --config "$CG/config.bin" --modules "$CG/modules.bin" >"$D/client.log" 2>&1 &
CLIENT_PID=$!
for _ in $(seq 1 40); do
  curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$CLIENT_PORT/" && break
  sleep 0.25
done
python3 - "127.0.0.1:$PORT" "127.0.0.1:$CLIENT_PORT" "$D/traffic.json" "$ROOT/tools/e2e/s3_traffic.py" <<'PY' || { tail -20 "$D/client.log"; fail "the s3 connector"; }
import hashlib, http.client, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("s3_traffic", sys.argv[4])
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
server, via = sys.argv[1], sys.argv[2]
cfg = json.load(open(sys.argv[3]))
direct = t.Client(server, cfg["alpha"]["key"], cfg["alpha"]["secret"], cfg["region"])

def plain(method, path, body=None, headers=None):
    c = http.client.HTTPConnection(via, timeout=120)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data

ok = True
def check(cond, what):
    global ok
    print(("  ok  " if cond else "  FAIL ") + what)
    ok &= bool(cond)

small = b"through the connector"
s, _, _ = plain("PUT", "/alpha/via/small.txt", small)
check(s == 200, "a small PUT through the connector is signed and stored")
s, _, d = direct.request("GET", "/alpha/via/small.txt")
check(s == 200 and d == small, "and reads back directly")
big = t.pattern(6 * 1024 * 1024 + 123, 13, 239)
s, _, _ = plain("PUT", "/alpha/via/big.bin", big)
check(s == 200, "a 6 MiB PUT streams through the connector aws-chunked")
s, _, d = direct.request("GET", "/alpha/via/big.bin")
check(s == 200 and hashlib.sha256(d).digest() == hashlib.sha256(big).digest(), "and reads back byte for byte")
other = t.pattern(9 * 1024 * 1024, 3, 233)
direct.request("PUT", "/alpha/via/direct.bin", body=other, mode="chunked")
s, h, d = plain("GET", "/alpha/via/direct.bin")
check(s == 200 and d == other, "an object written directly streams back through the connector")
s, h, d = plain("GET", "/alpha/via/direct.bin", headers={"range": "bytes=10-19"})
check(s == 206 and d == other[10:20], "a Range passes through it")
s, h, _ = plain("HEAD", "/alpha/via/direct.bin")
check(s == 200 and h.get("content-length") == str(len(other)), "HEAD reports the size")
s, _, d = plain("GET", "/alpha?list-type=2&prefix=via/")
check(s == 200 and d.count(b"<Key>") == 3, "a listing passes through it")
s, _, _ = plain("DELETE", "/alpha/via/small.txt")
check(s == 204, "DELETE through it")
s, _, d = plain("GET", "/alpha/via/small.txt")
check(s == 404 and b"NoSuchKey" in d, "and the endpoint's 404 comes back")
s, _, d = plain("PUT", "/beta/via/x", b"nope")
check(s == 403 and b"AccessDenied" in d, "the endpoint's authority refusal comes back")
sys.exit(0 if ok else 1)
PY
stop_client
stop

echo "== a chain no root signed serves nothing =="
run "$D/rogue-credentials" 64 64
code="$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "$AWS" \
  --user AKROGUE0000000000003:rogue-secret "http://127.0.0.1:$PORT/rogue/x")"
[ "$code" = 503 ] || fail "a server with an unverified credential answered $code, not 503"
grep -q "s3_serve" "$D/run.log" || fail "the refusal left no trace in the log"
echo "  ok  every request is 503"
stop

echo "PASS: wave-s3 published, pinned, synced, run with params; S3 traffic served and refused"
