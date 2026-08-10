# Wave

**Bounded application-protocol modules for Fluxor — HTTP, WebSocket, gRPC, RTP, SIP and SMTP, in one implementation the whole ecosystem shares.**

Wave owns protocol *mechanics*: message parsing and serialization, framing, header
compression, connection and stream state, packetization, and dialog transactions.
It owns no protocol *meaning* — no routing policy, no call semantics, no message
intent. That split is what lets Nanocloud, Quantum, Truffle, Grove, Zedex and
Conclave reuse one HTTP implementation without any of them, or Fluxor, becoming
the owner of what a request means.

```text
        application bytes or records
                    |
                    v
   Wave  http | websocket | ws_stream | rtp | sip | smtp
                    |
                    v
   Fluxor  NetProto  ->  IP/TCP/UDP · TLS · QUIC providers
```

Fluxor stays authoritative for the module ABI, graph execution, channels,
content-type identifiers, `NetProto`, `WsFrame`, transports, security providers,
timers, and target capabilities. Wave modules are ordinary position-independent
modules that consume those contracts and add no second ABI.

## Modules

| Module | Role | Targets |
| --- | --- | --- |
| `http` | HTTP/1.1, HTTP/2 and HTTP/3 **server and client**; WebSocket upgrade; gRPC-over-HTTP/2 | rp2350, bcm2712 |
| `websocket` | RFC 6455 HTTP/1.1 **client** — upgrade, verified accept, masked frames | bcm2712 |
| `ws_stream` | `WsFrame` ⇄ `OctetStream` adapter for the server fan-out path | rp2350, bcm2712, linux, wasm |
| `rtp` | RFC 3550 transmitter and receiver, PCMU/G.711 | rp2350, bcm2712 |
| `sip` | RFC 3261 subset UAC/UAS for two-party PCMU voice, with receive-side jitter and playout | rp2350, bcm2712 |
| `smtp` | RFC 5321 mail submission **client** — lockstep ESMTP, unauthenticated | bcm2712 |

Roles are deliberately asymmetric: `http` is both server and client, `websocket`
and `smtp` are clients only, `ws_stream` is an adapter, and `rtp`/`sip` are peer
user agents. Nothing here promises a server for every protocol with a client.
Targets are asymmetric too — the smallest silicon serves WebSocket without being
able to dial one.

`http` ships as three variants selected in its manifest: `web` (HTTP/1.1 + WS),
`h2` (adds HTTP/2) and `full` (adds HTTP/3). The split is about flash — `http-web`
is roughly 45% smaller than `http`, which is what makes the h1-only path viable on
rp2350. `tools/ci/fmod_size_budget.sh` gates every variant against a byte ceiling and
asserts each subset stays smaller than its superset.

Each module carries a `README.md` beside its `manifest.toml` documenting ports,
parameters, timer class, and — as importantly — what it does not claim.
`modules/common/` holds the pure `no_std`, I/O-free cores the modules `include!`
verbatim, so the device build and the host tests compile identical bytes.

## Composition, not more modules

Two capabilities exist without a module of their own, and should stay that way.

**gRPC** is the HTTP/2 client plus length-prefixed-message framing. Setting
`grpc = 1` on the `http` client sends `content-type: application/grpc` and
`te: trailers`, and surfaces the `grpc-status` trailer. Service definitions,
method dispatch and protobuf schemas stay with the application; unary and
server-streaming both fall out of the same client.

**TLS** is never terminated by Wave. Fluxor's `tls` module is a `NetProto`-in,
`NetProto`-out wrapper wired *between* the transport and the Wave module, so the
same protocol code serves `http://` and `https://`:

```yaml
- { from: linux_net.net_out, to: tls.cipher_in }
- { from: tls.cipher_out,    to: linux_net.net_in }
- { from: tls.clear_out,     to: http.net_in }
- { from: http.net_out,      to: tls.clear_in }
```

HTTP/3 inverts that wiring — QUIC carries its own packet protection, so `http` in
h3 mode binds Fluxor's `quic` provider directly. Wave parses authenticated
transport output but never decides peer identity or authorization; identity
arrives out of band on `tls.peer_identity`.

## Quick Start

One-time setup: `make -C deps/fluxor install`, then `fluxor sync` to materialise
the SDK at `target/fluxor/fluxor-abi`.

```bash
fluxor modules build --all --strict     # rp2350, bcm2712, wasm
fluxor modules test                     # each module's own core vectors
tools/ci/fmod_size_budget.sh --print       # per-variant flash sizes
```

Those work from a fresh clone. `make build`, `make test`, `make lint` and
`make ci` additionally need the host harness, which is not in this repository —
see [Tests](#tests).

## Repository Layout

```text
wave/
├── modules/
│   ├── common/         # I/O-free no_std cores, include!d by the modules
│   └── foundation/     # The protocol modules: http, websocket, ws_stream, rtp, sip, smtp
├── tools/              # Rig recipe, size budget, e2e drivers, wave-bench load generator
└── docs/               # Specification and architecture references
```

Two tiers exist in a working checkout and are **not in this repository**:
`examples/` (runnable graphs) and `tests/` (the host harness and hardware
scenarios). Each module's own core vectors do ship, under
`modules/foundation/<name>/tests/`, so `fluxor modules test` works from a clone.
See [Tests](#tests).

A module is a directory, never a crate — there are no `Cargo.toml` files under
`modules/**`, and `tests/harness/tests/project_contract.rs` fails if one appears.
`fluxor modules build` invokes `rustc` directly against each `mod.rs`; cargo is
never involved in producing a `.fmod`. Wave has no root cargo workspace either:
the two host crates, `tests/harness` and `tools/load/wave-bench`, each declare their
own `[workspace]`.

## Tests

Two lanes, both run by `make test` and both `fluxor ci` phases, so neither can
quietly stop running. Counts come from the command, not from this page. One lane
ships with this repository and one does not.

**Module lane — in this repository.** A module's own core vectors live beside it in
`modules/foundation/<name>/tests/`, declared by `[test] harness` in its
`manifest.toml` and built hermetically by `fluxor modules test` with zero
dependencies. A suite belongs here when it exercises one module's cores and needs
nothing mocked.

**Cargo lane — not in this repository.** `tests/harness/tests/`, for everything
needing the mock syscall table and channels: module I/O pumps, HTTP over a
virtual TCP stack, interop against real third-party servers, the codec suites,
and the repo-structure contracts.

Per the team's test-tracking standard (`../standards/test-tracking.md`, alongside
this checkout), `tests/` and `examples/` are versioned in a second, local-only Git
repo rooted at `.git-shadow/`. It shares this working tree and has no path to the
GitHub remote, so rig topology and unoptimised performance numbers stay off a
public history without losing version control over them.

For contributors holding that repo: shadow edits are invisible to `git status` on
the primary, so run `make shadow-status` alongside it out of habit. `fluxor ci`
hard-fails when the shadow checkout is missing rather than reporting green having
run nothing.

## Documentation

1. [docs/specification.md](docs/specification.md) — the ownership boundary,
   per-module scope and declared limits, correctness and bounds requirements
2. [docs/architecture/http3-ownership.md](docs/architecture/http3-ownership.md) —
   the HTTP/3 boundary and the stream-record seam with Fluxor's `quic`
3. [docs/reference/protocol-surfaces.md](docs/reference/protocol-surfaces.md) —
   the Fluxor content surfaces Wave consumes
4. [modules/common/README.md](modules/common/README.md) — what each shared core
   owns and which modules mount it

## Contributing

Issues and PRs are welcome. A protocol module earns its place by owning
mechanics and declaring what it refuses:

- A `manifest.toml` with ports, content types, timer class and capability
  declarations, and `hardware_targets` limited to silicon that can carry it
- Deterministic `module_step` — bounded time, no blocking, no unbounded
  allocation. Wave runs bare-metal with no allocator and no unwinding, so a
  panic is not a caught exception, it is the device
- Malformed or adversarial input produces a bounded protocol error, never a
  panic, overrun, or a crossed connection boundary
- Conformance vectors against the RFC, and interop against an independent
  implementation where one exists — grading Wave against Wave's own reading of a
  spec proves only self-consistency

Before adding a module, check whether the capability is a composition of ones
that exist. gRPC and TLS both are, and neither should become a module.

## License

Apache-2.0
