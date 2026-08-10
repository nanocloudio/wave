#!/usr/bin/env bash
# Shadow-checkout guard (../standards/test-tracking.md §7): tests/ and
# examples/ are shadow-tracked (.git-shadow/), so a runner holding only
# the primary repo has zero files there and the test phases would pass
# vacuously. Hard-fail instead of reporting a green gate that ran
# nothing. Wired as `[ci.test] scripts` in fluxor.toml (CI phase 3.5).
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ -z "$(ls -A tests 2>/dev/null)" ]; then
  echo "ci-shadow-guard: tests/ is empty or absent — the shadow-tracked tree" >&2
  echo "is not materialised on this machine (../standards/test-tracking.md §7)." >&2
  exit 1
fi
if [ ! -f tests/harness/Cargo.toml ]; then
  echo "ci-shadow-guard: tests/harness/Cargo.toml missing — the protocol harness" >&2
  echo "would silently not build and every host test would not run — it is the" >&2
  echo "ONLY host crate that holds tests since the root workspace and" >&2
  echo "crates/wave-cores were retired." >&2
  exit 1
fi
