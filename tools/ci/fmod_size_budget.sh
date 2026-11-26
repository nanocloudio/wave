#!/usr/bin/env bash
# Flash budget for the built `.fmod` artefacts.
#
# Wave's variant split exists to fit smaller devices, and that claim is a
# NUMBER: the saving `http-web` gives over `http` on rp2350 holds only while
# something checks it. A variant that quietly stops being smaller than the
# thing it is a subset of has stopped doing its job.
#
# Ceilings sit 5-8% above the measured size — tight enough that a real
# regression trips, loose enough that ordinary work does not. A row re-based
# after deliberate growth takes the 5% end, the tightest margin that does not
# trip on noise. Growth that is meant RAISES THE CEILING IN THIS FILE
# alongside it, so it arrives as a decision with a diff rather than as a
# discovery months later.
#
# Also enforces the RELATION, not just the absolutes: a subset variant must be
# strictly smaller than its superset. That check needs no maintenance and cannot
# be satisfied by bumping a number.
#
# Usage: tools/ci/fmod_size_budget.sh [--print]
#   --print   report sizes and exit 0 without enforcing (for re-baselining)
#
# BUDGETS and RELATIONS are SINGLE-quoted, and have to be: a note reading
# "run `fluxor sync`" inside a double-quoted string is a command
# substitution, so the script would run it and report whatever it printed in
# place of a budget. Single quotes make a backtick a backtick, at the cost of
# no apostrophes in a note.
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
thumbv6m|http.fmod|245400|233709 (2026-11-13, +14129 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv6m|http-h2.fmod|185200|176333 (2026-11-13, +14469 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv6m|http-web.fmod|110400|105061 (2026-11-13, +11281 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv6m|http-app.fmod|126500|120461 (2026-11-13, +12449 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv6m|http-exchange.fmod|273400|260326 (2026-11-03, +22.2K since the 2026-10-26 row: the exchange client HTTP/2 streams (many exchanges on one connection, per-stream credit as window, resets and GOAWAY per stream, PING keepalive), ALPN-chosen generation and the LINK DOWN re-owed for every dropped exchange; ceiling re-based 5% above measured)
thumbv6m|http-h1_exchange.fmod|123500|117557 (2026-11-13, +10093 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|http-h1_exchange.fmod|125300|119261 (2026-11-13, +12309 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
aarch64|http-h1_exchange.fmod|217000|201220 (2026-09-08, first row; HTTP/1.1 plus the graph-driven exchange client and nothing else)
thumbv8m|http.fmod|242400|230853 (2026-11-13, +13853 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|http-h2.fmod|186000|177093 (2026-11-13, +10073 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|http-web.fmod|111800|106469 (2026-11-13, +8127 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|http-app.fmod|125800|119797 (2026-11-13, +11205 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|http-exchange.fmod|280900|267513 (2026-11-27, +12747 B since the previous measurement, +1133 B of it with the module source unchanged, measured at the Fluxor D17 epoch 8b77544a8eea: param schema bounds, resource claim bytes and conditions; ceiling re-based 5% above measured)
thumbv8m|rtp.fmod|29490|28082 (2026-11-13, +2882 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|rtcp.fmod|18570|17679 (2026-11-26, +951 B since the previous measurement with the module source unchanged, measured at the Fluxor Stage 5 epoch 8f1677c24adf (d69f806e); ceiling re-based 5% above measured)
aarch64|rtp.fmod|32700|31096 (2026-09-24, +3.7K: the encoded-media record stream in, and the RFC 3551/7587/6184/7741 payload formats packetizing it; the private media record and its codec table are gone; ceiling re-based 5% above measured)
aarch64|rtcp.fmod|15700|14485 (2026-09-08, +7.1K: SRTCP protection over the RFC 3550 §6 control plane, both report directions, plus RFC 4585 NACK and PLI feedback)
aarch64|sip.fmod|22300|20651 (2026-09-08, first row)
thumbv8m|sip.fmod|18100|17234 (2026-11-23, +939 B since the 2026-08-23 row: the SDK linked as crates, whose shared helpers are called rather than inlined; ceiling re-based 5% above measured)
thumbv8m|stun.fmod|11450|10903 (2026-11-26, +591 B since the previous measurement with the module source unchanged, measured at the Fluxor Stage 5 epoch 8f1677c24adf (d69f806e); ceiling re-based 5% above measured)
aarch64|stun.fmod|12330|11736 (2026-11-13, +2354 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers are out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
aarch64|mail.fmod|24000|21081 (2026-08-23, first row; RFC 5322 + MIME assembly over the smtp connector)
thumbv8m|ws_stream.fmod|3160|3007 (2026-11-13, +290 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers such as encoded::write_unit and net_read_frame are now out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv6m|ws_stream.fmod|3170|3015 (2026-11-13, +426 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers such as encoded::write_unit and net_read_frame are now out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
aarch64|ws_stream.fmod|3750|3567 (2026-11-13, +488 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers such as encoded::write_unit and net_read_frame are now out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
thumbv8m|jitter.fmod|7650|7278 (2026-11-13, +1434 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers such as encoded::write_unit and net_read_frame are now out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
aarch64|jitter.fmod|11390|10846 (2026-11-13, +1400 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers such as encoded::write_unit and net_read_frame are now out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
aarch64|http.fmod|359000|341855 (2026-09-10, +34.2K since the 2026-09-05 row: the session anchor and the h2 tunnel seam (+16.2K) on top of the HTTP/3 client, RTP media stack and lifetime deadlines that landed unmeasured; ceiling re-based 5% above measured)
aarch64|http-h2.fmod|301000|286423 (2026-09-10, +23.6K since the 2026-09-05 row: the session anchor and the h2 tunnel seam on top of work that landed unmeasured; ceiling re-based 5% above measured)
aarch64|http-web.fmod|207000|191646 (2026-09-05, +9.1K since the 2026-08-16 row: request metrics and the connection lifetime deadlines with the WebSocket ping policy)
aarch64|http-app.fmod|212000|196158 (2026-09-05, +9.1K since the 2026-08-16 row: request metrics and the connection lifetime deadlines)
aarch64|http-exchange.fmod|367000|349111 (2026-09-10: the session anchor and the h2 tunnel seam; ceiling re-based 5% above measured)
aarch64|s3.fmod|44600|42478 (2026-10-03, +22.8K: bodies of any size streamed in the HTTP application records, aws-chunked chunk signing, response framing by length, chunks or close; ceiling re-based 5% above measured)
aarch64|s3_serve.fmod|130500|124274 (2026-11-18, +7.7K: storage.object on flat argument records (Fluxor Stage 3): codecs for every op, data spans, the fence trailer, and the exchange answer head with its meta; ceiling re-based 5% above measured)
aarch64|smtp.fmod|22100|21039 (2026-11-18, +2.4K: the neutral exchange head (Fluxor Stage 3): verb and meta records, the meta TLV codec and outcome mapping in place of the HTTP-shaped head; ceiling re-based 5% above measured)
aarch64|websocket.fmod|22700|21619 (2026-11-13, +2480 B since the previous measurement, chiefly because the SDK becomes linked crates (Fluxor 9fb61099): contract and runtime helpers such as encoded::write_unit and net_read_frame are now out-of-line calls into fluxor_abi/fluxor_rt instead of include!-inlined, plus the 32 B FLUXOR_ABI_SURFACE digest; ceiling re-based 5% above measured)
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
