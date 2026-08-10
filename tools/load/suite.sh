#!/usr/bin/env bash
# Wave load suite — protocol × rate ladder against a live DUT.
#
# Boots a Wave graph on the linux target, then runs `wave-loadgen` across every
# protocol at an increasing offered rate, emitting one JSON line per cell plus a
# human summary. Designed to be the L4 layer of `.context/planning/test-strategy.md`
# and the linux-proxy gate every rig scenario must pass first (../standards/rig.md §7).
#
# Usage:
#   tools/load/suite.sh                       # full ladder, local graph
#   tools/load/suite.sh --host 192.168.1.9:80 # against a rig DUT, no local graph
#   tools/load/suite.sh --protocols h1,ws --rates 1000,8000
#   tools/load/suite.sh --duration 30 --out results.ndjson
#
# Measurement discipline (../standards/rig.md §6, ../lattice/.context/perf_budgets.md):
#
#  * Localhost numbers are a FLOOR, not a prediction. Loopback has no NIC, and
#    the generator competes with the DUT for the same cores. A clean number
#    needs a separate driver host over a real link — that is what the rig is for.
#  * A run whose achieved rate falls below 90% of offered is HARNESS_BOUND and
#    its tail must not be quoted.
#  * Report p50/p99/p999, never a bare mean. The knee shows up in the tail long
#    before it shows up in throughput.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

HOST=""
PROTOCOLS="h1,h2c,ws"
RATES="1000,4000,16000,32000"
DURATION=6
CONNS=16
WARMUP=1
OUT=""
GRAPH=""
PORT=18080

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)      HOST="$2"; shift 2 ;;
    --protocols) PROTOCOLS="$2"; shift 2 ;;
    --rates)     RATES="$2"; shift 2 ;;
    --duration)  DURATION="$2"; shift 2 ;;
    --conns)     CONNS="$2"; shift 2 ;;
    --warmup)    WARMUP="$2"; shift 2 ;;
    --out)       OUT="$2"; shift 2 ;;
    --graph)     GRAPH="$2"; shift 2 ;;
    -h|--help)   sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# `wave-bench` declares its own `[workspace]` — Wave has no root crate to run
# `cargo -p` from, so build it where it lives and read the binary out of ITS
# target dir. A `$ROOT/target/release` path here silently referred to a
# workspace that no longer exists.
LOADGEN="$ROOT/tools/load/wave-bench/target/release/wave-loadgen"
[[ -x "$LOADGEN" ]] || (cd "$ROOT/tools/load/wave-bench" && cargo build --release --bin wave-loadgen)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [[ -n "${DUT_PID:-}" ]] && kill "$DUT_PID" 2>/dev/null || true' EXIT

# ── Bring up a DUT unless one was named ──────────────────────────────────
if [[ -z "$HOST" ]]; then
  if [[ -z "$GRAPH" ]]; then
    GRAPH="$WORK/loadsuite.yaml"
    cat > "$GRAPH" <<YAML
target: linux
tick_us: 100
scheduler:
  accept_cycles: true
platform:
  net: {}
modules:
  - name: http
    port: $PORT
    host_tcp: 1
    routes:
      - path: "/"
        body: "<html><body>wave loadsuite target</body></html>"
      - path: "/ws"
        websocket: true
wiring:
  - from: linux_net.net_out
    to: http.net_in
  - from: http.net_out
    to: linux_net.net_in
YAML
  fi
  HOST="127.0.0.1:$PORT"
  echo "[loadsuite] booting DUT graph $GRAPH -> $HOST" >&2
  fluxor run "$GRAPH" > "$WORK/dut.log" 2>&1 &
  DUT_PID=$!
  for _ in $(seq 1 40); do
    if exec 3<>"/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then exec 3>&-; break; fi
    sleep 0.5
  done
  echo "[loadsuite] DUT up (pid $DUT_PID)" >&2
  LOCAL_DUT=1
else
  echo "[loadsuite] driving external DUT $HOST (no local graph)" >&2
  LOCAL_DUT=0
fi

# ── Ladder ───────────────────────────────────────────────────────────────
printf '%-6s %8s %10s %9s %9s %7s %7s %8s %9s %s\n' \
  PROTO OFFERED ACHIEVED ACCEPTED COMMITTED FAILED P50us P99us P999us VERDICT

FAILED_CELLS=0
IFS=',' read -ra PROTO_LIST <<< "$PROTOCOLS"
IFS=',' read -ra RATE_LIST <<< "$RATES"

for proto in "${PROTO_LIST[@]}"; do
  case "$proto" in
    ws)   path="/ws" ;;
    grpc) path="/grpcbin.GRPCBin/DummyUnary" ;;
    *)    path="/" ;;
  esac
  for rate in "${RATE_LIST[@]}"; do
    json="$("$LOADGEN" --host "$HOST" --protocol "$proto" --rate "$rate" \
              --duration "$DURATION" --conns "$CONNS" --warmup "$WARMUP" \
              --path "$path" 2>/dev/null || true)"
    [[ -n "$OUT" ]] && printf '%s\n' "$json" >> "$OUT"
    if [[ -z "$json" ]]; then
      printf '%-6s %8s %10s %9s %9s %7s %7s %8s %9s %s\n' \
        "$proto" "$rate" - - - - - - - "NO_OUTPUT"
      FAILED_CELLS=$((FAILED_CELLS + 1))
      continue
    fi
    line="$(printf '%s' "$json" | python3 -c '
import sys, json
d = json.load(sys.stdin); t = d["ok_tail"]
print("%-6s %8d %10.1f %9d %9d %7d %7d %8d %9d %s" % (
    d["protocol"], d["offered_rate"], float(d["achieved_rate"]), d["accepted"],
    d["committed"], d["failed"], t["p50_us"], t["p99_us"], t["p999_us"],
    d["headroom_verdict"]))
sys.exit(0 if d["headroom_verdict"] == "DUT_ATTRIBUTABLE" and d["clean"] == "true" else 1)
')" && ok=0 || ok=1
    echo "$line"
    [[ $ok -ne 0 ]] && FAILED_CELLS=$((FAILED_CELLS + 1))
  done
done

echo
if [[ "$LOCAL_DUT" == "1" ]]; then
  echo "NOTE: localhost run — no NIC, and the generator shares cores with the DUT."
  echo "      These are a FLOOR. The rig (separate driver host, real link) is the"
  echo "      quotable number. See ../standards/rig.md §6."
fi
if [[ $FAILED_CELLS -gt 0 ]]; then
  echo "RESULT: $FAILED_CELLS cell(s) not clean or not DUT-attributable." >&2
  exit 1
fi
echo "RESULT: all cells clean and DUT-attributable."
