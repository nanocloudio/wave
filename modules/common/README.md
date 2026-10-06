# `modules/common` — shared protocol cores

Pure, `no_std`, I/O-free cores mounted by Wave's `.fmod` modules. They are
domain-neutral by construction: no I/O, no allocation, and no knowledge of the
module that mounts them. Most are framing only. A core that keeps state keeps
it in the caller's storage and touches nothing else — `ws_session_worker` holds
one array of sessions and moves bytes between them, which is why it can be the
worker half of a handoff without owning a channel.

Each file carries no inner attributes and no test module, so the PIC module
build can `include!` it verbatim — every consumer compiles the same bytes. A
core with no module mount is a level-1 capability, tested through its own
direct fixture in `tests/harness` and never presented as a deployable role.

| Core | Owns | Mounted by |
| --- | --- | --- |
| `ws_frame_core` | RFC 6455 frame-header decode + validation | `websocket`, `http` (`wire::ws`) |
| `ws_core` | RFC 6455 upgrade request/verify and the masked frame codec | `websocket` |
| `ws_admit` | The server-side WS admission records (upgrade report, decision, events) | `http` |
| `ws_session_worker` | The worker's half of session continuity for a `WsFrame` consumer: SessionCtrlV1 attach/drain/export/import/resume, the connection-to-session map, the delivery cursors, export gated on a message boundary | `ws_echo_worker` (fixture); a product worker outside Wave mounts it the same way |
| `huffman_core` | RFC 7541 Appendix B Huffman table + decoder. RFC 9204 §4.1.2 specifies the SAME table for QPACK, so h2 and h3 share one transcription | `http` (`wire::hpack`, `wire::qpack`) |
| `sip_core` | RFC 3261 PCMU-dialog message formatters + response/SDP parsers | `sip` |
| `sip_dialog` | Bounded UAC/UAS dialog transaction machine — protocol-fact transitions | `sip` |
| `sip_wire` | The `command_in` / `event_out` record layouts for driving a call | `sip` |
| `jitter_core` | Bounded RTP reorder window + loss-concealing playout | `jitter` |
| `rtp_core` | RFC 3550 header decode — fixed header, CSRC list, §5.3.1 extension, §5.1 padding — and therefore which bytes of a packet are payload | `rtp`, `sip` |
| `smtp_core` | RFC 5321 reply-line parsing, dot-stuffed command builders, lockstep submission phase machine | `smtp` |
| `smtp_wire` | The `SmtpResult` layout an answer's body carries, and the outcome classification | `smtp` |
| `rfc5322` | RFC 5322 header-block parsing: addresses, identifiers, date, subject | `mail` |
| `mime` | MIME structure walking: multipart boundaries, part headers, encodings | `mail` |
| `mail_wire` | The inbound-message span and facts/body record layouts | `mail` |
| `hex_core` | ASCII hex, for byte-valued module parameters and bounded evidence lines | `websocket`, `smtp`, `rtp` |
| `sigv4_core` | AWS SigV4 signing and verification | `s3`, `s3_serve` |
| `s3_serve_core` | S3 server mechanics: operation classification, the bucket/key → `storage.object` naming contract, error codes and documents, ranges, `aws-chunked` decoding, the credentials file, listing tokens, `CompleteMultipartUpload` part lists | `s3_serve` |
| `s3_core` | S3 client mechanics over HTTP/1.1 on top of `sigv4_core`: the signed request head, `aws-chunked` body framing, response head and body framing (`Content-Length`, chunked, close) | `s3` |
| `stun_core` | RFC 5389 message mechanics: header, attribute walk, MESSAGE-INTEGRITY, FINGERPRINT, long-term credential key. RFC 5769-pinned | `stun` |
| `turn_core` | TURN's relay extension to STUN: allocate/refresh/permission/channel methods, relay attributes, ChannelData framing | — (direct fixture only; no module presents relay mechanics it does not have) |
| `sframe_core` | RFC 9605 SFrame framing: clear header, sealed payload boundary, what a cipher must authenticate. All 289 published header vectors. Framing, not encryption | — (direct fixture only) |
| `webrtc_sdp` | The SDP attributes that make a description a WebRTC one: ICE credentials, candidates, DTLS fingerprint. Facts, not a WebRTC stack | — (direct fixture only) |

SHA-1 (`Sec-WebSocket-Accept`) and Base64 (the key nonce and accept proof) are
**Fluxor SDK-owned**, mounted from `target/fluxor/fluxor-abi/sdk/crypto/`. Wave
does not carry its own copy.

Mount order matters where cores call each other: `ws_core` needs `sha1` and
`b64_encode` in scope, so the SDK crypto sources are `include!`d before it.
`ws_session_worker` needs the SDK's `../fluxor/modules/sdk/cores/session_handoff.rs`
(the chunk walk and the cursors) before it, and the `session_ctrl` contract reachable as `sc`.
`sigv4_core` needs the SDK's `sha256` and `Sha256` in scope, and `s3_core` needs
`sigv4_core`, so `s3` mounts the SDK's SHA-256, then `sigv4_core`, then `s3_core`;
`s3_serve` mounts the SDK's SHA-256, then `sigv4_core`, then `s3_serve_core`.
