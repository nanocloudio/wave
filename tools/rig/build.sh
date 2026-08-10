#!/usr/bin/env bash
# Rig build recipe for the pi5 target — the script `fluxor rig test` runs before
# deploying. Invoked from the machine-local rig profile
# ($XDG_CONFIG_HOME/fluxor/projects/wave/rig.toml) as:
#
#   command = ["bash", "tools/rig/build.sh", "${scenario.config}"]
#
# WHY THIS IS IN THE REPO. It used to be a 55-line script inlined in that
# profile, which is not version controlled and does not travel. Everything it
# knows was learned from a failed run — always rebuild the firmware, never
# filter the image by mtime, run the pre-flight guards — and none of that
# survived on a second machine or a fresh checkout. Worse, `preflight.sh`
# lives here and is only ever CALLED from there, so a checkout could carry the
# guards and never invoke them. The profile is now a pointer; the knowledge is
# reviewable, diffable, and the same everywhere.
#
# $1 is the scenario's graph config, passed through as `${scenario.config}`.
set -euo pipefail

# 1. Stage Fluxor's kernel firmware. Build it in the pinned tree if absent.
# ALWAYS rebuild, never "only if absent". A firmware.bin that merely EXISTS
# can be older than the SDK the modules were built against, and the kernel
# embeds an ABI-surface expectation: a stale kernel refuses the new modules at
# load and the board comes up with nothing listening. That failed a run on
# 2026-08-04 in the most confusing possible way — DHCP bound, [ip] telemetry
# flowing from the PREVIOUS boot's heartbeats, empty serial, and a probe timing
# out on a port that was never bound. `make` is incremental, so this is cheap
# when nothing changed.
make -C deps/fluxor firmware TARGET=pi5
mkdir -p target/pi5/images
if ! cmp -s deps/fluxor/target/pi5/firmware.bin target/pi5/firmware.bin 2>/dev/null; then
  cp deps/fluxor/target/pi5/firmware.bin target/pi5/firmware.bin
fi
# 2. Build Wave's own modules for the target silicon, then combine.
# Pre-flight (../standards/rig.md §4). Versioned in the repo so a fresh
# clone gets it; catches 0-byte fmods and dangling rig backends before
# they surface as unrelated-looking errors.
RIG_STARTED=$(date +%s)
bash tools/rig/preflight.sh modules bcm2712
fluxor modules build --target bcm2712
# Files the graph EMBEDS must exist now: `fluxor build` only warns on one it
# cannot read, so a missing cert_file yields a green build, a tls module with no
# certificate, and a load phase that commits nothing — a DUT-looking failure for
# a build-host problem. Cost a run on 2026-08-10 when /tmp was swept.
bash tools/rig/preflight.sh embeds "$1"
fluxor build "$1"
# 3. Surface the image at a stable path so ANY scenario config deploys, not
#    just the one whose stem matches the artifact name. `fluxor build` mirrors
#    the config's subdirectory under images/ — a config at examples/rig/<name>.yaml
#    lands at images/rig/<name>.img — so locate it by name rather than assuming a
#    flat layout.
STEM="$(basename "$1" .yaml)"
DST=target/pi5/images/wave-pi5.img
# NO mtime filter. An earlier version required the image to be newer than 10
# minutes, intending a freshness guard. That is exactly backwards: when
# `fluxor build` finds everything up to date it does NOT rewrite the .img, so
# the filter matched nothing, the recipe exited 1, and the rig deployed
# whatever was last staged — a 19-hour-old image in practice. rig.md §4 warns
# about precisely this ("a recipe that stages a fixed artifact path ... must
# copy fresh->fixed every run"). `fluxor build` ran three lines above, so the
# image is fresh by construction; copy unconditionally.
SRC="$(find target/pi5/images -name "$STEM.img" -not -name "$(basename $DST)" | head -1)"
[ -n "$SRC" ] || { echo "rig recipe: no $STEM.img under target/pi5/images" >&2; exit 1; }
[ "$SRC" -ef "$DST" ] || cp -f "$SRC" "$DST"
bash tools/rig/preflight.sh artifact "$DST" "$RIG_STARTED"
echo "rig recipe: staged $SRC -> $DST ($(stat -c %y "$SRC"))"
