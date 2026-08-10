//! Module-core test harness for `rtp` — declared by `manifest.toml [test]
//! harness` and run via `fluxor modules test` (../standards/fluxor-modules.md
//! §0.2 lane 1). The generated harness crate enables `host-test`, which
//! switches `mod.rs` away from `#![no_std]` and makes the shared cores
//! public, so these vectors pin the exact bytes the `.fmod` compiles.
//!
//! `rtp_core` is mounted by this module and by `sip`, so the vectors here
//! cover the header decode both of them depend on: which bytes of a packet
//! are payload, and which are CSRC list, extension, or padding.

#[path = "../mod.rs"]
#[cfg(test)]
mod rtp;

#[cfg(test)]
mod rtp_core_vectors;
