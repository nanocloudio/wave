#!/usr/bin/env bash
# Connection-identity accessor guard.
#
# The conn_id u8→u16 widening was missed in exactly one consumer because
# call sites hand-rolled `from_le_bytes` against literal offsets — invisible
# to review and to the compiler. The Fluxor net contracts now export typed
# accessors (net_proto::conn_id/connected_parts/error_parts/accepted_parts,
# mux::session_id/stream_id, ws_frame::*), and this gate keeps the module
# pumps on them:
#
#   1. Any `from_le_bytes` / `to_le_bytes` in a module PUMP (the files that
#      consume contract surfaces) must be individually justified in the
#      allow-list below. A new hand-rolled decode fails here, with the RFC
#      section to read.
#   2. No module may redeclare a contract identity width or envelope size
#      as a local constant.
#   3. Every allow-list entry must still match a real line — a stale entry
#      fails, so the list can only describe the tree as it is.
#
# SCOPE: modules/foundation/**. The wire codecs (`http/wire/`) and the
# I/O-free cores (`modules/common/`) are the OWNING parsers of protocol
# bytes and Wave-local record layouts — a layout's owner hand-rolling its
# own bytes is the accessor, so they are out of scope for rule 1.
#
# Allow-list format (identity_accessor_allowlist.txt):
#   <path>|<exact trimmed line text>|<justification>
#
# Wired as `[ci.test] scripts` in fluxor.toml (CI phase 3.5), beside
# shadow_guard.sh and host_crates.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."

ALLOWLIST="tools/ci/identity_accessor_allowlist.txt"
fail=0

# ── Rule 2: no locally redeclared contract widths ─────────────────────
# The envelope/identity constants live on the contracts
# (net_proto::CONN_ID_LEN, mux::SESSION_ID_BYTES/STREAM_ID_BYTES,
# ws_frame::FRAME_HDR/CONN_ID_LEN). A local redeclaration is the drift
# vector the widening defect proved.
while IFS= read -r hit; do
  echo "identity-guard: locally redeclared contract width:" >&2
  echo "  $hit" >&2
  echo "  use the contract's constant" >&2
  fail=1
done < <(grep -rn --include='*.rs' \
  -E 'const (WS_FRAME_HDR|CONN_ID_LEN|SESSION_ID_BYTES|STREAM_ID_BYTES)\b' \
  modules/ | grep -v 'sdk/' || true)

# ── Rule 1: hand-rolled identity decodes in module pumps ──────────────
# Scope: the pump files. Wire codecs and cores are the owning parsers of
# their layouts and are exempt (see header).
scope() {
  find modules/foundation -name '*.rs' ! -path '*/wire/*'
}

declare -A allowed
if [ -f "$ALLOWLIST" ]; then
  while IFS='|' read -r path line _just; do
    [ -z "$path" ] && continue
    case "$path" in \#*) continue ;; esac
    allowed["$path|$line"]=0
  done < "$ALLOWLIST"
fi

while IFS= read -r file; do
  while IFS= read -r hit; do
    lineno="${hit%%:*}"
    text="${hit#*:}"
    trimmed="$(printf '%s' "$text" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    key="$file|$trimmed"
    if [ -n "${allowed[$key]+x}" ]; then
      allowed["$key"]=1
      continue
    fi
    echo "identity-guard: unjustified hand-rolled byte decode:" >&2
    echo "  $file:$lineno: $trimmed" >&2
    echo "  use the owning contract accessor, or justify the site in" >&2
    echo "  $ALLOWLIST" >&2
    fail=1
  done < <(grep -n -E 'from_le_bytes|to_le_bytes' "$file" || true)
done < <(scope)

# ── Rule 3: the allow-list may only describe the tree as it is ────────
for key in "${!allowed[@]}"; do
  if [ "${allowed[$key]}" = 0 ]; then
    echo "identity-guard: stale allow-list entry (no matching line):" >&2
    echo "  $key" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "identity-accessor guard FAILED" >&2
  exit 1
fi
echo "identity-accessor guard: ok"
