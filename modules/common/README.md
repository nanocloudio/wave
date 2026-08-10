# `modules/common` — shared protocol cores

Pure, `no_std`, I/O-free codecs mounted by Wave's `.fmod` modules. They are
domain-neutral by construction: framing only, no session, no I/O, no allocation.

Each file carries **no inner attributes and no test module**, so the PIC module
build can `include!` it verbatim — the host build and the device build compile
the same bytes. `tests/harness/tests/project_contract.rs` enforces that, and
also that no core sits here unmounted.

| Core | Owns | Mounted by |
| --- | --- | --- |
| `ws_frame_core` | RFC 6455 frame-header decode + validation | `websocket`, `http` (`wire::ws`) |
| `ws_core` | RFC 6455 upgrade request/verify and the masked frame codec | `websocket` |
| `huffman_core` | RFC 7541 Appendix B Huffman table + decoder. RFC 9204 §4.1.2 specifies the SAME table for QPACK, so h2 and h3 share one transcription | `http` (`wire::hpack`, `wire::qpack`) |
| `sip_core` | RFC 3261 PCMU-dialog message formatters + response/SDP parsers | `sip` |
| `sip_dialog` | Bounded UAC/UAS dialog transaction machine — protocol-fact transitions | `sip` |
| `jitter_core` | Bounded RTP reorder window + loss-concealing playout | `sip` |
| `rtp_core` | RFC 3550 header decode — fixed header, CSRC list, §5.3.1 extension, §5.1 padding — and therefore which bytes of a packet are payload | `rtp`, `sip` |
| `smtp_core` | RFC 5321 reply-line parsing, dot-stuffed command builders, lockstep submission phase machine | `smtp` |
| `hex_core` | ASCII hex, for byte-valued module parameters | `websocket`, `smtp` |

SHA-1 (`Sec-WebSocket-Accept`) and Base64 (the key nonce and accept proof) are
**Fluxor SDK-owned**, mounted from `target/fluxor/fluxor-abi/sdk/crypto/`. Wave
does not carry its own copy.

Mount order matters where cores call each other: `ws_core` needs `sha1` and
`b64_encode` in scope, so the SDK crypto sources are `include!`d before it.
