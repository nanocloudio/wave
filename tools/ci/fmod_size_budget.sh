#!/usr/bin/env bash
# Flash budget for the built `.fmod` artefacts.
#
# Wave's variant split exists to fit smaller devices. That
# claim is a NUMBER, and until now nothing held it: the 37% saving `http-web`
# gives over `http` on rp2350 was true because someone measured it once, and any
# change could have eaten it silently. A variant that quietly stops being smaller
# than the thing it is a subset of has stopped doing its job.
#
# Ceilings are set ~8% above the measured size — tight enough that a real
# regression trips, loose enough that ordinary work does not. When a ceiling is
# hit deliberately, RAISE IT IN THIS FILE in the same commit as the change, so
# the growth is a decision with a diff rather than a discovery months later.
#
# Also enforces the RELATION, not just the absolutes: a subset variant must be
# strictly smaller than its superset. That check needs no maintenance and cannot
# be satisfied by bumping a number.
#
# Usage: tools/ci/fmod_size_budget.sh [--print]
#   --print   report sizes and exit 0 without enforcing (for re-baselining)
#
# BUDGETS and RELATIONS are SINGLE-quoted. They have to be: a note reading
# "run `fluxor sync`" inside a double-quoted string is a command substitution,
# and the script then runs it and reports whatever that says instead of a
# budget. That has happened twice. Single quotes make a backtick a backtick, at
# the cost of no apostrophes in a note.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-}"

# target|artefact|ceiling bytes|measured on
#
# Two things drive the http sizes apart. Request-body ingestion
# (modules/foundation/http/server/reqbody.rs) is in every variant including
# `web`, since a server that does not consume a POST body leaves those bytes to
# be read as the next request on a keep-alive connection. HANDLER_APP
# (modules/foundation/http/server/app.rs) is behind the `app` feature, which
# `web` does not carry, so the flash-constrained variant does not pay for a
# handler that forwards to a module the device does not run.
#
# EVERY artefact this project builds for a flash-constrained silicon must have
# a row here. `wasm` is out of scope — it has no flash to fit — and no other
# target is. An artefact with no row is the one place a regression can land
# unmeasured, which is exactly where it lands: the variant added because a
# netboot ceiling was being crossed is the variant whose ceiling is missed. A budget that
# silently omits an artefact is worse than no budget, because the omission
# reads as coverage.
BUDGETS='
rp2040|http.fmod|192000|182276 (2026-09-08, first RP2040 qualification)
rp2040|http-h2.fmod|150000|138220 (2026-09-07, first RP2040 qualification)
rp2040|http-web.fmod|102000|93780 (2026-09-07, first RP2040 qualification)
rp2040|http-app.fmod|108000|99476 (2026-09-07, first RP2040 qualification)
rp2040|http-exchange.fmod|197000|186340 (2026-09-08, first RP2040 qualification)
rp2040|http-h1_exchange.fmod|105000|97108 (2026-09-07, first RP2040 qualification)
rp2350|http-h1_exchange.fmod|100000|92572 (2026-09-08, first row; HTTP/1.1 plus the graph-driven exchange client and nothing else)
bcm2712|http-h1_exchange.fmod|217000|201220 (2026-09-08, first row; HTTP/1.1 plus the graph-driven exchange client and nothing else)
rp2350|http.fmod|187000|172940 (2026-09-07, current ABI and readiness hardening)
rp2350|http-h2.fmod|147000|135460 (2026-09-07, current ABI and readiness hardening)
rp2350|http-web.fmod|98000|90020 (2026-09-07, current ABI and readiness hardening)
rp2350|http-app.fmod|103000|95004 (2026-09-07, current ABI and readiness hardening)
rp2350|http-exchange.fmod|191000|177108 (2026-09-07, current ABI and readiness hardening)
rp2350|rtp.fmod|20700|19109 (2026-09-08, +14.1K: negotiated media — the SRTP profiles and their key derivation, the H.264/VP8 packetizers and Annex-B scanner, the MID/PT/SSRC route table, the pacer, the congestion controller, the RTP-to-wall-clock map and the TURN relay path)
rp2350|rtcp.fmod|14600|13501 (2026-09-08, +7.0K: SRTCP protection over the RFC 3550 §6 control plane (see `rtcp_core.rs`) — AES-GCM, the 31-bit SRTCP index and its replay window, plus RFC 4585 NACK and PLI feedback)
bcm2712|rtp.fmod|29600|27394 (2026-09-08, +22.2K: negotiated media — the SRTP profiles, the video packetizers, the route table, pacing, congestion control, clock sync and the TURN relay path)
bcm2712|rtcp.fmod|15700|14485 (2026-09-08, +7.1K: SRTCP protection over the RFC 3550 §6 control plane, both report directions, plus RFC 4585 NACK and PLI feedback)
bcm2712|sip.fmod|22300|20651 (2026-09-08, first row)
rp2350|sip.fmod|17000|16295 (2026-08-23, +2.7K: the application command/event contract — a call is offered and decided rather than auto-answered, and every terminal outcome is reported)
rp2350|stun.fmod|8000|7353 (2026-08-29, +2.5K: the Binding CLIENT role — RFC 5389 transaction schedule, response matching, and the result record)
bcm2712|stun.fmod|9100|8337 (2026-08-29, +3.5K: the Binding CLIENT role — RFC 5389 transaction schedule, response matching, and the result record)
bcm2712|mail.fmod|24000|21081 (2026-08-23, first row; RFC 5322 + MIME assembly over the smtp connector)
rp2350|ws_stream.fmod|3000|2717 (2026-08-07)
rp2040|ws_stream.fmod|2800|2589 (2026-09-08, first row)
bcm2712|ws_stream.fmod|2510|2325 (2026-09-08, first row)
rp2350|jitter.fmod|4340|4021 (2026-09-08, first row; the reorder ring and its playout clock)
bcm2712|jitter.fmod|4410|4085 (2026-09-08, first row; the reorder ring and its playout clock)
bcm2712|http.fmod|332000|307638 (2026-09-05, +2.4K: connection lifetime deadlines, idle eviction and the WebSocket ping policy; ceiling re-based to 8% above measured — it had drifted to 1%)
bcm2712|http-h2.fmod|284000|262830 (2026-09-05, +12.8K since the 2026-08-12 row: request metrics, upstream-status surfacing and the connection lifetime deadlines)
bcm2712|http-web.fmod|207000|191646 (2026-09-05, +9.1K since the 2026-08-16 row: request metrics and the connection lifetime deadlines with the WebSocket ping policy)
bcm2712|http-app.fmod|212000|196158 (2026-09-05, +9.1K since the 2026-08-16 row: request metrics and the connection lifetime deadlines)
bcm2712|http-exchange.fmod|336500|311686 (2026-09-05, +3.6K: connection lifetime deadlines and idle eviction)
bcm2712|s3.fmod|22000|19647 (2026-08-16, first row; SigV4 signing connector)
bcm2712|smtp.fmod|14000|13231 (2026-08-26, +3.7K: SASL PLAIN submission — base64 encoder, EHLO capability parsing, the AUTH phase, its credential buffers, and the volatile zeroing of every stack copy of a credential)
bcm2712|websocket.fmod|16500|14934 (2026-09-07, current ABI and readiness hardening)
'

# subset|superset|target — the subset must be strictly smaller.
#
# The variants are a LATTICE, not a chain, and the relations have to say so.
# `web` is h1+ws and `app` is h1+app: neither contains the other, so no relation
# between them is assertable and claiming one would be a false gate. Both sit
# under `h2` (h1+h2+ws+app), which sits under `full`.
RELATIONS='
http-web.fmod|http.fmod|rp2040
http-h2.fmod|http.fmod|rp2040
http-web.fmod|http-h2.fmod|rp2040
http-app.fmod|http-h2.fmod|rp2040
http-app.fmod|http.fmod|rp2040
http.fmod|http-exchange.fmod|rp2040
http-web.fmod|http.fmod|rp2350
http-web.fmod|http.fmod|bcm2712
http-h2.fmod|http.fmod|rp2350
http-h2.fmod|http.fmod|bcm2712
http-web.fmod|http-h2.fmod|rp2350
http-web.fmod|http-h2.fmod|bcm2712
http-app.fmod|http-h2.fmod|rp2350
http-app.fmod|http-h2.fmod|bcm2712
http-app.fmod|http.fmod|rp2350
http-app.fmod|http.fmod|bcm2712
http.fmod|http-exchange.fmod|rp2350
http.fmod|http-exchange.fmod|bcm2712
http-h1_exchange.fmod|http-exchange.fmod|rp2040
http-h1_exchange.fmod|http-exchange.fmod|rp2350
http-h1_exchange.fmod|http-exchange.fmod|bcm2712
'

fail=0
missing=0

printf '%-9s %-18s %10s %10s   %s\n' TARGET ARTEFACT SIZE CEILING STATUS
while IFS='|' read -r target artefact ceiling _measured; do
  [ -n "${target:-}" ] || continue
  path="$ROOT/target/fluxor/$target/modules/$artefact"
  if [ ! -f "$path" ]; then
    printf '%-9s %-18s %10s %10s   MISSING — build it first\n' "$target" "$artefact" - "$ceiling"
    missing=1
    continue
  fi
  size=$(stat -c %s "$path")
  if [ "$MODE" = "--print" ]; then
    printf '%-9s %-18s %10d %10d\n' "$target" "$artefact" "$size" "$ceiling"
  elif [ "$size" -gt "$ceiling" ]; then
    printf '%-9s %-18s %10d %10d   OVER by %d B\n' \
      "$target" "$artefact" "$size" "$ceiling" "$((size - ceiling))"
    fail=1
  else
    printf '%-9s %-18s %10d %10d   ok (%d%% of budget)\n' \
      "$target" "$artefact" "$size" "$ceiling" "$((size * 100 / ceiling))"
  fi
done <<< "$BUDGETS"

echo
while IFS='|' read -r subset superset target; do
  [ -n "${subset:-}" ] || continue
  a="$ROOT/target/fluxor/$target/modules/$subset"
  b="$ROOT/target/fluxor/$target/modules/$superset"
  [ -f "$a" ] && [ -f "$b" ] || continue
  sa=$(stat -c %s "$a")
  sb=$(stat -c %s "$b")
  if [ "$sa" -lt "$sb" ]; then
    printf '%-9s %s < %s   ok (-%d%%)\n' "$target" "$subset" "$superset" \
      "$(((sb - sa) * 100 / sb))"
  else
    printf '%-9s %s is NOT smaller than %s (%d vs %d) — the variant has stopped paying for itself\n' \
      "$target" "$subset" "$superset" "$sa" "$sb"
    fail=1
  fi
done <<< "$RELATIONS"

if [ "$MODE" = "--print" ]; then
  exit 0
fi

if [ "$missing" = 1 ]; then
  echo
  echo "FAIL: an artefact under budget is missing. Run 'fluxor modules build --all'."
  echo "      (Reporting green for a file that was never built is the failure this"
  echo "      check exists to prevent.)"
  exit 1
fi
if [ "$fail" = 1 ]; then
  echo
  echo "FAIL: a module exceeded its flash budget, or a variant stopped being"
  echo "      smaller than its superset. If the growth is intended, raise the"
  echo "      ceiling in this file in the same commit."
  exit 1
fi
echo
echo "PASS: every artefact is within budget."
