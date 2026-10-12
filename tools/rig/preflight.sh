#!/usr/bin/env bash
# Rig pre-flight guard (../standards/rig.md §4, §1a).
#
# Called by the rig build recipe before and after `fluxor build`. Each check
# corresponds to a failure mode that reports itself as something else:
#
#   0-byte fmods      -> "Module file too small: 0 bytes"
#   dangling backend  -> "backend not found on any search path"
#   stale artifact    -> a green build line, and the DUT runs old code
#
# Usage: preflight.sh modules <silicon>
#        preflight.sh artifact <path> <started-epoch>
set -euo pipefail

die() { printf '\nrig pre-flight FAILED: %s\n\n' "$1" >&2; shift; printf '  %s\n' "$@" >&2; exit 1; }

check_modules() {
  local silicon="$1" bad=0 dir abi
  # The target's modules live on its module-ABI shelf; ask fluxor which.
  abi=$(basename "$(dirname "$(fluxor modules resolve --target "$silicon")")")
  # Check this project's module dir and the Fluxor checkout it symlinks into.
  # A consuming project cannot repair the platform fmods: its own
  # `fluxor modules build` only builds its own modules.
  for dir in "target/fluxor/$abi/modules" "deps/fluxor/target/fluxor/$abi/modules"; do
    [ -d "$dir" ] || continue
    # -L so a symlink to a zeroed original is caught, not just a local zero.
    local n
    n=$(find -L "$dir" -name '*.fmod' -size 0 2>/dev/null | wc -l)
    if [ "$n" -gt 0 ]; then
      printf '  %s: %s zero-byte fmod(s)\n' "$dir" "$n" >&2
      find -L "$dir" -name '*.fmod' -size 0 2>/dev/null | sed 's|.*/|    |' >&2
      bad=1
    fi
  done
  [ "$bad" -eq 0 ] || die "zero-byte module artefacts" \
    "Rebuild them where they are PRODUCED, not where they are consumed:" \
    "  cd deps/fluxor && fluxor modules build --target $silicon"
}

check_backends() {
  local dir="${XDG_DATA_HOME:-$HOME/.local/share}/fluxor/backends" b missing=()
  [ -d "$dir" ] || return 0
  for b in "$dir"/*; do
    [ -e "$b" ] || missing+=("$(basename "$b")")
  done
  # Recovery names the symlink, because that is what a backend IS: a link in
  # the shared backend dir pointing at the script in this repo. It must be a
  # command the reader can actually run — advice naming a make target that does
  # not exist is worse than no advice.
  [ "${#missing[@]}" -eq 0 ] || die "rig backend symlink(s) dangling: ${missing[*]}" \
    "A backend is a symlink in $dir pointing at its script." \
    "Wave's own backend is restored with:" \
    "  ln -sfn \"$PWD/tools/rig/backends/observe-proto_load\" \\" \
    "     \"$dir/observe-proto_load\"" \
    "Fluxor's own backends are reinstalled from its checkout (see its Makefile)."
}

# The artifact must have been written by THIS build. `fluxor build` does not
# rewrite an up-to-date image, so a recipe that stages a fixed path can deploy
# a stale one and report success.
check_artifact() {
  local path="$1" started="$2" mtime
  [ -f "$path" ] || die "build produced no artifact at $path" "Check the recipe's build step."
  mtime=$(stat -c %Y "$path")
  [ "$mtime" -ge "$started" ] || die "artifact is older than this build" \
    "  $path" \
    "  modified $(( started - mtime ))s before the build started" \
    "The build no-op'd and the rig would deploy stale code (rig.md §4)."
}

# Every file a graph embeds at BUILD time must exist on the build host now.
# `fluxor build` refuses a graph whose embed it cannot read, one file at a time;
# this provisions the throwaway certificate the example graphs embed
# (`tools/ci/dev_certs.sh`, into `target/pki/`) and then names every file
# still missing at once, before a build starts.
check_embeds() {
  local config="$1" missing=() f
  [ -f "$config" ] || die "no such config: $config"
  bash "$(dirname "${BASH_SOURCE[0]}")/../ci/dev_certs.sh" || die "could not provision the example certificate"
  # `key: /path` for the file-valued params a graph embeds.
  while IFS= read -r f; do
    [ -s "$f" ] || missing+=("$f")
  done < <(sed -nE 's/^[[:space:]]*(cert_file|key_file|file|body_file):[[:space:]]*"?([^"#]+)"?[[:space:]]*$/\2/p' "$config")

  [ "${#missing[@]}" -eq 0 ] || die "config embeds file(s) that do not exist on this host" \
    "$(printf '  %s\n' "${missing[@]}")" \
    "  config: $config" \
    "A graph names its embeds relative to the project root."
}

case "${1:-}" in
  modules)  check_modules "${2:?silicon required}"; check_backends ;;
  artifact) check_artifact "${2:?path required}" "${3:?start epoch required}" ;;
  embeds)   check_embeds "${2:?config path required}" ;;
  *) echo "usage: $0 modules <silicon> | artifact <path> <started-epoch> | embeds <config>" >&2; exit 2 ;;
esac
