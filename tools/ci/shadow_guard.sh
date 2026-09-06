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
# A tier being gitignored does not untrack what is already committed, so a
# force-add puts shadow-tracked sources into the primary history — where they
# reach the shared remote — while every ignore rule still reads as correct.
# The lint checks the exclusion; only the index says whether it held.
leaked="$(git ls-files tests examples)"
if [ -n "$leaked" ]; then
  echo "ci-shadow-guard: the primary repo tracks shadow-tracked paths:" >&2
  echo "$leaked" | sed 's/^/  /' >&2
  echo "Untrack them with 'git rm -r --cached <path>' — the files stay on" >&2
  echo "disk — then stage and commit them in the shadow repo:" >&2
  echo "  git shadow add -f -- tests examples ':(exclude)**/target/**'" >&2
  exit 1
fi
if [ ! -f tests/harness/Cargo.toml ]; then
  echo "ci-shadow-guard: tests/harness/Cargo.toml missing — the protocol harness" >&2
  echo "would silently not build and every host test would not run — it is the" >&2
  echo "ONLY host crate that holds tests since the root workspace and" >&2
  echo "crates/wave-cores were retired." >&2
  exit 1
fi
