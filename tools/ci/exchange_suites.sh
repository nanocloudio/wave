#!/usr/bin/env bash
# THE EXCHANGE CLIENT'S HARNESS SUITES, AS A CI GATE.
#
# `fluxor ci`'s `cargo-test (harness)` runs default features, and `exchange` is
# deliberately not one: it widens `MAX_PATH_LEN` and `REQUEST_BODY_SIZE`, and
# every other http suite should test the sizes the default artefacts ship with.
# A suite or test gated `cfg(feature = "exchange")` therefore compiles to nothing
# there and reports green. This gate runs each such suite with the feature on.
#
# The suites are found by that attribute rather than listed, so a new one cannot
# be left out, and a suite that runs no test fails: an empty binary is what the
# gate is here to rule out.
#
# `[ci.test] scripts` in fluxor.toml is what makes this run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$ROOT/tests/harness"

if [ ! -d "$HARNESS/tests" ]; then
  echo "FAIL no $HARNESS/tests: shadow_guard.sh names the checkout that lacks it."
  exit 1
fi

mapfile -t suites < <(
  grep -lE '^#!?\[cfg\(.*feature = "exchange"' "$HARNESS"/tests/*.rs |
    xargs -r -n1 basename | sed 's/\.rs$//' | sort
)
if [ "${#suites[@]}" -eq 0 ]; then
  echo "FAIL no suite carries the exchange attribute; the exchange client is tested by nothing."
  exit 1
fi

args=()
for s in "${suites[@]}"; do
  args+=(--test "$s")
done

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
if ! (cd "$HARNESS" && cargo test --target aarch64-unknown-linux-gnu --no-fail-fast \
  --features exchange "${args[@]}") 2>&1 | tee "$log"; then
  echo "exchange-suites gate: FAILED"
  exit 1
fi

if grep -q '^running 0 tests' "$log"; then
  echo "FAIL a suite ran no test with the exchange feature on."
  exit 1
fi
echo "exchange-suites gate: OK (${#suites[@]} suites)"
