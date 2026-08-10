//! Module-core test harness for `sip` — declared by `manifest.toml
//! [test] harness` and run via `fluxor modules test` (../standards/fluxor-modules.md
//! §0.2 lane 1). The generated harness crate enables `host-test`, which
//! switches `mod.rs` away from `#![no_std]` and makes the shared cores
//! (`sip_core` / `sip_dialog` / `jitter_core`) public, so these vectors
//! pin the exact bytes and transitions the `.fmod` compiles.
//!
//! Relocated from `tests/harness/tests/{sip_vectors,sip_dialog_vectors,
//! jitter_vectors}.rs` (registry_consolidation P7): they exercise only
//! this module's own cores — no mock syscall table, no channels — so
//! they belong in the hermetic module-test lane, tracked in git with the
//! sources they freeze.

#[path = "../mod.rs"]
#[cfg(test)]
mod sip;

#[cfg(test)]
mod jitter_vectors;
#[cfg(test)]
mod sip_dialog_vectors;
#[cfg(test)]
mod sip_vectors;
