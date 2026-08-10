#!/usr/bin/env bash
# THE HOST CRATES' fmt/clippy/test, AS A CI GATE.
#
# Wave has no root cargo workspace (retired 2026-08-08 with `crates/wave-cores`;
# the cores now live in `modules/common` and are `include!`d, not linked). That
# changes what `fluxor ci` runs, in two ways:
#
#   * Phases 1.1/1.2 see no root `Cargo.toml` and switch to fmt-checking and
#     clippying the PIC module sources directly (ci.rs:94,124) — a GAIN, since
#     `modules/**` was previously linted by neither. But it means the two
#     remaining host crates are now fmt/clippy'd by nothing.
#   * Phase 2 is omitted (no root manifest, no `host_tools_crate`), and phase 4's
#     built-in `cargo-test (harness)` covers `tests/harness` — so the harness's
#     suites do run, but `tools/load/wave-bench` is built and tested by nothing.
#
# This closes both holes. Without it CI would summarise GREEN with the loadgen
# unbuilt and neither host crate linted (../standards/make.md §5 — the loam trap):
# exactly the failure mode Chronicle hit when it removed its crates, and why it
# carries ../chronicle/scripts/module-tests-e2e.sh.
#
# `[ci.test] scripts` in fluxor.toml is what makes this run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# `tests/harness` — lint only. Its tests are phase 4's job (`cargo-test
# (harness)`, built into fluxor ci); running them here would double the slowest
# phase in every CI run.
# `tools/load/wave-bench` — lint AND test: nothing else builds it at all.
CRATES=("tests/harness" "tools/load/wave-bench")
TEST_CRATES=("tools/load/wave-bench")

# `cargo fmt --all` would follow the harness's PATH DEPENDENCIES into
# `modules/foundation/**` and `modules/common/**` and reformat the PIC sources —
# which phase 1.1 of `fluxor ci` now owns directly (modules_fmt_check), because
# there is no root manifest. Two formatters over one tree is churn, so each
# crate is formatted BY NAME. Clippy needs no such guard: it lints the local
# package, not its dependencies.
declare -A PKG=( ["tests/harness"]="wave-test-harness" ["tools/load/wave-bench"]="wave-bench" )

fail=0

for c in "${CRATES[@]}"; do
  dir="$ROOT/$c"
  if [ ! -f "$dir/Cargo.toml" ]; then
    echo "FAIL $c: no Cargo.toml — a host crate this gate names has moved or gone."
    fail=1
    continue
  fi

  echo "== $c: fmt =="
  if ! (cd "$dir" && cargo fmt -p "${PKG[$c]}" -- --check); then
    echo "FAIL $c: rustfmt"
    fail=1
  fi

  echo "== $c: clippy =="
  if ! (cd "$dir" && cargo clippy --all-targets --all-features -- -D warnings); then
    echo "FAIL $c: clippy"
    fail=1
  fi
done

for c in "${TEST_CRATES[@]}"; do
  echo "== $c: test =="
  if ! (cd "$ROOT/$c" && cargo test --all-targets --all-features); then
    echo "FAIL $c: cargo test"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "host-crates gate: FAILED"
  exit 1
fi
echo "host-crates gate: OK"
