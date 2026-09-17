# Limit register

The ceilings this project chose, why each is where it is, and what a caller
meets on the far side of it.

A ceiling found in one of the source files named below but absent from this
document is a bug. That is a claim about the code, and an unchecked claim
about code decays into a claim about whoever last edited the register — so
`fluxor ci`'s `limit-register` phase checks it. Every row in the fenced block
at the end must still be declared, with the value quoted, in the file it
names; every name in that block must also appear in the prose here; and any
ceiling-shaped constant in a named file that is neither registered nor
exempted fails the gate.

Scope is deliberate. A file named here is one the register vouches for
entirely, so adding a file means accounting for every ceiling in it. The set
starts at the ceilings already published to readers in
[docs/reference/envelope.md](../reference/envelope.md) and owned by Wave rather
than by a Fluxor profile constant. Growing it is an act of ownership, not
bookkeeping.

## HTTP/2

| Ceiling | Value | What one past it meets |
|---|---|---|
| `MAX_STREAMS` | 4 | `REFUSED_STREAM`, counted as `h2_streams_refused` |

Four concurrent streams per connection, the same on every target. A browser
opening a fifth is told to retry it rather than queued, because a queue here
is indistinguishable from a slow server and costs the memory the refusal
exists to protect.

## HTTP/3

| Ceiling | aarch64 | elsewhere | What one past it meets |
|---|---|---|---|
| `MAX_H3_SESSIONS` | 8 | 2 | session closed, `H3_REQUEST_REJECTED` |
| `MAX_H3_STREAMS` | 16 | 4 | stream refused |
| `MAX_PEER_UNI` | 4 | 4 | `H3_STREAM_CREATION_ERROR` |

The session and stream tables split by architecture because HTTP/3 rides
Fluxor's `quic`, which targets bcm2712 only: on every other target this state
is structurally idle and sized to pay for nothing beyond existing. The stream
table is shared across sessions, so it is the total in flight rather than a
per-session allowance.

`MAX_PEER_UNI` is four because HTTP/3 defines three peer-initiated
unidirectional streams — control, QPACK encoder, QPACK decoder — and the
fourth is the spare that lets a push or a greased stream arrive without
costing the peer an error it did not earn.

| Ceiling | Value | What one past it meets |
|---|---|---|
| `H3_WS_PAYLOAD_MAX` | 512 | oversized frame refused |
| `TUNNEL_FRAME_MAX` | `H3_SEND_BUF - 24` | frame split to fit |

`H3_WS_PAYLOAD_MAX` bounds one WebSocket payload carried over an HTTP/3
extended-CONNECT stream. `TUNNEL_FRAME_MAX` is not an independent choice: it
is the send buffer less the largest frame header the tunnel can prepend, and
it is registered as that expression so the derivation stays visible and a
change to the buffer cannot silently outgrow the header allowance.

## Not ceilings

Three constants in the named files match the naming convention without being
policy. They are exempted in the second block below, each with its reason:
`WS_BUF_SIZE` is per-stream reassembly scratch, `H2_HDR_CAP` is an alias of a
ceiling owned by the application fan-out, and `H3_VARINT_MAX` is the width
RFC 9000 gives a QUIC varint — a wire fact, not a decision this project made.

## Elsewhere

Ceilings this register does not yet cover, and where they are enforced today:

- **The connection envelope** — the transport, TLS and HTTP slot tables are
  Fluxor profile constants, not Wave's. They are generated into
  [docs/reference/envelope.md](../reference/envelope.md) straight from the
  compiled constants by `tools/ci/envelope_table.sh`, which fails when the
  document and the profile disagree.
- **Flash budgets** — every artefact's ceiling lives in
  `tools/ci/fmod_size_budget.sh`, which also enforces that a variant stays
  smaller than the superset it is a subset of.

```limit-register
MAX_STREAMS | modules/foundation/http/server/h2.rs | 4
MAX_H3_SESSIONS | modules/foundation/http/server/h3.rs | 8
MAX_H3_SESSIONS | modules/foundation/http/server/h3.rs | 2
MAX_H3_STREAMS | modules/foundation/http/server/h3.rs | 16
MAX_H3_STREAMS | modules/foundation/http/server/h3.rs | 4
MAX_PEER_UNI | modules/foundation/http/server/h3.rs | 4
H3_WS_PAYLOAD_MAX | modules/foundation/http/server/h3.rs | 512
TUNNEL_FRAME_MAX | modules/foundation/http/server/h3.rs | H3_SEND_BUF - 24
```

```limit-register-exempt
WS_BUF_SIZE | modules/foundation/http/server/h2.rs | per-stream WebSocket reassembly scratch, sized to the frame codec rather than chosen as a limit
H2_HDR_CAP | modules/foundation/http/server/h2.rs | alias of app::MAX_FWD_HEADERS; the ceiling is owned and registered where that constant lives
H3_VARINT_MAX | modules/foundation/http/server/h3.rs | the width RFC 9000 gives a QUIC varint, not a choice this project makes
```
