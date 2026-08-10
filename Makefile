# Wave lifecycle. Runtime and module operations remain Fluxor CLI commands.

.PHONY: help build test lint ci publish clean shadow-status shadow-log

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.DEFAULT_GOAL := build

help:
	@echo "wave lifecycle:"
	@echo "  make build     cargo build --all-targets, per host crate"
	@echo "  make test      both lanes: cargo per host crate + fluxor modules test"
	@echo "  make lint      rustfmt --check + clippy -D warnings, per host crate"
	@echo "  make ci        fluxor ci — the full gate (lints, hygiene, tests,"
	@echo "                 strict module build, shadow guard, size budget)"
	@echo "  make publish   fluxor publish"
	@echo "  make clean     cargo clean + module artefacts"
	@echo ""
	@echo "shadow-tracked tests/examples (standards/test-tracking.md):"
	@echo "  make shadow-status   git shadow status"
	@echo "  make shadow-log      git shadow log --oneline -20"
	@echo "  Staging NEW files needs -f (the primary .gitignore outranks the shadow"
	@echo "  exclude) and MUST keep the exclude pathspec (or -f force-adds every"
	@echo "  cargo blob under tests/harness/target/):"
	@echo "    git shadow add -Af tests examples ':(exclude)*target/*'"
	@echo ""
	@echo "Not make targets (use the CLI / scripts directly):"
	@echo "  fluxor modules build [--target …]     PIC modules"
	@echo "  tools/ci/fmod_size_budget.sh [--print]   variant flash budget (also enforced"
	@echo "                                        in 'fluxor ci' phase 3.5)"
	@echo "  tools/ci/shadow_guard.sh              shadow-checkout hard-fail (ci 3.5)"
	@echo "  tools/ci/host_crates.sh              host-crate fmt/clippy/build (ci 3.5)"
	@echo "  tools/e2e/h3_server.sh / h3_client_e2e.sh    HTTP/3 e2e drivers"
	@echo "  tools/e2e/sip.sh                      SIP e2e against sip_ua.py"
	@echo "  tools/load/suite.sh                    load suite driver"
	@echo "  tools/rig/preflight.sh                rig preflight checks"
	@echo "  tools/e2e/linux_graph.sh              run a graph on the linux host"
	@echo "One-time setup: make -C deps/fluxor install"

# There is no root workspace to pass `--workspace` to: Wave's cores are
# `include!`d out of `modules/common` by the PIC modules, not linked, so the crate
# that used to wrap them (`crates/wave-cores`) is gone along with the workspace
# root. The two remaining host crates each declare their own `[workspace]`, so
# every cargo target below iterates them explicitly. Adding a third host crate
# means adding it here AND to tools/ci/host_crates.sh.
HOST_CRATES := tests/harness tools/load/wave-bench

build:
	@for c in $(HOST_CRATES); do echo "== $$c =="; (cd $$c && cargo build --all-targets); done

# Wave's tests live in TWO lanes and `make test` must run both, or it reports
# green having skipped one. The cargo lane is the host crates (365 tests); the
# module lane is the per-module `[test] harness` declarations that
# `fluxor modules test` builds hermetically (47 tests, in sip/smtp/websocket).
# Adding the module lane here is not redundant with `fluxor ci` — ci runs them as
# its own `module-tests` phase, but `make test` is what a developer types.
test:
	@for c in $(HOST_CRATES); do echo "== $$c =="; (cd $$c && cargo test --all-targets --all-features); done
	@echo "== module lane (fluxor modules test) =="
	@fluxor modules test

lint:
	@for c in $(HOST_CRATES); do \
	  echo "== $$c =="; \
	  (cd $$c && cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings); \
	done

# The shadow-checkout guard (test-tracking.md §7) and the variant size budget
# both run INSIDE `fluxor ci` as phase 3.5 project scripts (fluxor.toml
# [ci.test]): tools/ci/shadow_guard.sh, tools/ci/host_crates.sh,
# tools/ci/fmod_size_budget.sh. One gate, no parallel names.
ci:
	fluxor ci

publish:
	fluxor publish

# Three kinds of build state, and `fluxor modules clean` only knows the second:
# the host crates' cargo dirs, the .fmod/.elf artefacts, and the crates
# `fluxor modules test` generates under target/fluxor/moduletests/ (~78 MB of
# disposable state nothing else prunes).
#
# The third is worth clearing rather than letting accumulate. A module-test run
# interrupted mid-compile — a timeout, or a test that aborts the binary, which a
# mock syscall shim panicking across `extern "C"` does — leaves an orphaned
# `s-*-working` incremental session behind, and the next run emits one
#   warning: file-system error deleting outdated file ...: No such file (os error 2)
# per object file while garbage-collecting it. Harmless and self-limiting, but
# 70+ warning lines over a passing suite is indistinguishable at a glance from a
# real problem.
clean:
	@for c in $(HOST_CRATES); do (cd $$c && cargo clean); done
	fluxor modules clean
	@rm -rf target/fluxor/moduletests

# §5 reminder: shadow-tracked edits are invisible to `git status` on the primary.
# (Staging new files: see `make help` — the add command needs -f plus the
# target-excluding pathspec.)
shadow-status: ; git shadow status
shadow-log:    ; git shadow log --oneline -20
