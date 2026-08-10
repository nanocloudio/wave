//! Module-core test harness for `websocket` — declared by `manifest.toml
//! [test] harness` and run via `fluxor modules test` (../standards/fluxor-modules.md
//! §0.2 lane 1). The generated harness crate enables `host-test`, which
//! switches `mod.rs` away from `#![no_std]` and exposes the shared cores
//! (`ws_core`, `ws_frame_core`, SDK `sha1`/`b64`), so these RFC 6455
//! vectors pin the same bytes the `websocket` client `.fmod`, `http`'s
//! upgrade path, and `ws_stream`'s adapter all compile.
//!
//! Relocated from `modules/foundation/websocket/tests/ws_core_conformance.rs`
//! (registry_consolidation P7): it exercises only this module's own cores —
//! no mock syscall table — so it belongs in the hermetic module-test
//! lane, tracked in git with the sources it freezes. The channel-driven
//! suites (`ws.rs`, `websocket_client.rs`, `ws_interop.rs`) stay in
//! `tests/harness/`.

#[path = "../mod.rs"]
#[cfg(test)]
mod websocket;

#[cfg(test)]
mod ws_core_conformance;
