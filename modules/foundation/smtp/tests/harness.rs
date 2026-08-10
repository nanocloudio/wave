//! Module-core test harness for `smtp` — declared by `manifest.toml
//! [test] harness` and run via `fluxor modules test` (../standards/fluxor-modules.md
//! §0.2 lane 1). The generated harness crate enables `host-test`, which
//! switches `mod.rs` away from `#![no_std]` and makes `smtp_core` public,
//! so these vectors pin the exact reply parsing, dot-stuffing, and phase
//! machine the `.fmod` compiles.
//!
//! Relocated from `modules/foundation/smtp/tests/smtp_core.rs`
//! (registry_consolidation P7): it exercises only this module's own core —
//! no mock syscall table — so it belongs in the hermetic module-test
//! lane, tracked in git with the source it freezes. The socket-level
//! suites (`smtp.rs`, `smtp_interop.rs`) stay in `tests/harness/`, which
//! plays the peer server over mock channels.

#[path = "../mod.rs"]
#[cfg(test)]
mod smtp;

#[cfg(test)]
mod smtp_core;
