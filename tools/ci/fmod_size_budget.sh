#!/usr/bin/env bash
# Flash budget for the built `.fmod` artefacts.
#
# Wave's variant split exists to fit smaller devices (`rfc_module_variants`). That
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
# EVERY artefact the build produces must have a row here. `http-app` and `s3`
# were both absent while this file's own header claimed to gate the variant
# split — so the newest variant, added specifically because a netboot image
# ceiling was being crossed, was the one variant with no ceiling. A budget that
# silently omits an artefact is worse than no budget, because the omission
# reads as coverage.
BUDGETS='
rp2350|http.fmod|162000|150332 (2026-08-29, +1.2K: the client request head carries a real verb and a Content-Length, and fails closed instead of truncating)
rp2350|http-h2.fmod|119000|110760 (2026-08-12, +5.1K)
rp2350|http-web.fmod|85000|78868 (2026-08-29, +536 B: the client request head carries a real verb and a Content-Length, and fails closed instead of truncating)
rp2350|http-app.fmod|80000|73368 (2026-08-16, first row; h1 + app fan-out only)
rp2350|http-exchange.fmod|167000|154236 (2026-08-29, first row; the full variant plus the graph-driven client exchange — publish_in/reply_out, the reply accumulator and the staging frame)
rp2350|rtp.fmod|5400|4980 (2026-08-30, +788 B: the appended rtcp_stats output — tagged reception and transmission records for the rtcp module, best-effort and counted)
rp2350|rtcp.fmod|7000|6462 (2026-08-30, first row; RFC 3550 §6 control plane (see `rtcp_core.rs`) — compound framing, SR/RR/SDES, receiver statistics, the §6.2 interval)
bcm2712|rtp.fmod|5700|5164 (2026-08-30, first row; includes the appended rtcp_stats output)
bcm2712|rtcp.fmod|7900|7350 (2026-08-30, first row; RFC 3550 §6 control plane, both report directions)
rp2350|sip.fmod|17000|16295 (2026-08-23, +2.7K: the application command/event contract — a call is offered and decided rather than auto-answered, and every terminal outcome is reported)
rp2350|stun.fmod|8000|7353 (2026-08-29, +2.5K: the Binding CLIENT role — RFC 5389 transaction schedule, response matching, and the result record)
bcm2712|stun.fmod|9100|8337 (2026-08-29, +3.5K: the Binding CLIENT role — RFC 5389 transaction schedule, response matching, and the result record)
bcm2712|mail.fmod|24000|21081 (2026-08-23, first row; RFC 5322 + MIME assembly over the smtp connector)
rp2350|ws_stream.fmod|3000|2717 (2026-08-07)
bcm2712|http.fmod|309000|305212 (2026-08-26, +9.9K: h3 ceiling fails closed — 8-session/16-stream tables on aarch64 and the refused-session close queue. Deliberate: a session past the table used to hang the client)
bcm2712|http-h2.fmod|270000|250032 (2026-08-12, +6.2K)
bcm2712|http-web.fmod|196000|182504 (2026-08-16, +1.3K for the shedding counters)
bcm2712|http-app.fmod|203000|187064 (2026-08-16, first row; h1 + app fan-out only)
bcm2712|http-exchange.fmod|333000|308092 (2026-08-29, first row; the full variant plus the graph-driven client exchange — publish_in/reply_out, the reply accumulator and the staging frame)
bcm2712|s3.fmod|22000|19647 (2026-08-16, first row; SigV4 signing connector)
bcm2712|smtp.fmod|14000|13231 (2026-08-26, +3.7K: SASL PLAIN submission — base64 encoder, EHLO capability parsing, the AUTH phase, its credential buffers, and the volatile zeroing of every stack copy of a credential)
bcm2712|websocket.fmod|12700|10912 (2026-08-12)
'

# subset|superset|target — the subset must be strictly smaller.
#
# The variants are a LATTICE, not a chain, and the relations have to say so.
# `web` is h1+ws and `app` is h1+app: neither contains the other, so no relation
# between them is assertable and claiming one would be a false gate. Both sit
# under `h2` (h1+h2+ws+app), which sits under `full`.
RELATIONS='
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
