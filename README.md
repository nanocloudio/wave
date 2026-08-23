# Wave

Wave is the application-protocol module palette for the
[fluxor](../fluxor/) runtime: HTTP/1.1, HTTP/2 and HTTP/3, WebSocket,
RTP, SIP, SMTP, internet mail parsing (RFC 5322 and MIME), the NAT
traversal codecs STUN and TURN, SFrame media framing and the WebRTC
session-description attributes, plus a SigV4 S3 client, with gRPC
available as a composition of the HTTP/2 client. The modules ship as
position-independent `no_std` ELFs and run on a wired fluxor module
graph, from a single-connection rp2350 server to a multi-connection
Linux or bcm2712 host.

Wave owns protocol mechanics: message parsing and serialisation,
framing, header compression, connection and stream state,
packetisation, and dialog transactions. It owns no protocol meaning
(no routing policy, no call semantics, no message intent), which is
what lets Nanocloud, Quantum, Truffle, Grove, Zedex and Conclave
share one HTTP implementation without any of them, or fluxor,
becoming the owner of what a request means.

The STUN and TURN modules are where that line is easiest to cross, so
it is stated: Wave owns how a Binding request is encoded, which
attributes it carries, and how message integrity and a long-term
credential key are computed. Whether to send one, to whom, in what
order, which candidate pair wins, whether to allocate a relay, and
when to give up are reachability decisions and belong to
[wormhole](../wormhole/). A wire format is a codec; a decision about
the network is not. The same line puts the WebRTC session-description
attributes here and ICE policy there.

```text
        application bytes or records
                    |
                    v
   Wave   http | websocket | ws_stream | rtp | sip | smtp | s3
                    |
                    v
   fluxor  NetProto / mux  ->  IP/TCP/UDP · TLS · QUIC providers
```

Fluxor stays authoritative for the module ABI, graph execution,
channels, content-type identifiers, transports, security providers,
timers, and target capabilities. Wave modules consume those contracts
and add no second ABI.

## Modules

| Module | Role | Targets |
| --- | --- | --- |
| `http` | HTTP/1.1, HTTP/2 and HTTP/3 server and client; WebSocket upgrade; gRPC-over-HTTP/2 | rp2350, bcm2712 |
| `websocket` | RFC 6455 HTTP/1.1 client: upgrade, verified accept, masked frames | bcm2712 |
| `ws_stream` | `WsFrame` ⇄ `OctetStream` adapter for the server fan-out path | rp2350, bcm2712, linux, wasm |
| `rtp` | RFC 3550 transmitter and receiver, PCMU/G.711 | rp2350, bcm2712 |
| `sip` | RFC 3261 subset UAC/UAS for two-party PCMU voice, with receive-side jitter and playout | rp2350, bcm2712 |
| `smtp` | RFC 5321 mail submission client: lockstep ESMTP, unauthenticated | bcm2712 |
| `s3` | SigV4-signed S3 object client: GET/PUT/HEAD/DELETE, driven or probe | bcm2712 |

Roles are deliberately asymmetric: `http` is both server and client,
`websocket`, `smtp` and `s3` are clients only, `ws_stream` is an
adapter, and `rtp`/`sip` are peer user agents. Nothing here promises
a server for every protocol with a client. Targets are asymmetric
too: the smallest silicon serves WebSocket without being able to dial
one.

`http` ships as four variants selected in its manifest: `web`
(HTTP/1.1 + WebSocket), `app` (HTTP/1.1 + the application fan-out,
nothing else), `h2` (adds HTTP/2) and `full` (the default, adds
HTTP/3). The split is about flash: a target takes only the protocol
generations it serves. The variants form a lattice, not a chain
(`web` and `app` are not subsets of each other).

Each module carries a `README.md` beside its `manifest.toml`
documenting ports, parameters, timer class, and what it does not
claim. `modules/common/` holds the pure `no_std`, I/O-free cores the
modules `include!` verbatim.

## Composition, not more modules

Two capabilities exist without a module of their own, and should stay
that way.

**gRPC** is the HTTP/2 client plus length-prefixed-message framing.
Setting `grpc = 1` on the `http` client sends
`content-type: application/grpc` and `te: trailers`, and surfaces the
`grpc-status` trailer. Service definitions, method dispatch and
protobuf schemas stay with the application; unary and
server-streaming both fall out of the same client.

**TLS** is never terminated by Wave. Fluxor's `tls` module is a
`NetProto`-in, `NetProto`-out wrapper wired between the transport and
the Wave module, so the same protocol code serves `http://` and
`https://`:

```yaml
- { from: linux_net.net_out, to: tls.cipher_in }
- { from: tls.cipher_out,    to: linux_net.net_in }
- { from: tls.clear_out,     to: http.net_in }
- { from: http.net_out,      to: tls.clear_in }
```

HTTP/3 inverts that wiring: QUIC carries its own packet protection,
so `http` in h3 mode sits behind fluxor's `quic` module instead
([docs/architecture/http3-ownership.md](docs/architecture/http3-ownership.md)).
Wave parses authenticated transport output but never decides peer
identity or authorisation; identity arrives out of band.

## Quick start

Setup, once per machine: Wave consumes fluxor through the local OCI
store (`$FLUXOR_STORE`, default `~/.local/share/fluxor/store`).

```sh
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
make -C ../fluxor install    # put the fluxor CLI launcher on PATH
make -C ../fluxor publish    # publish SDK, module palette, runtime into the store
```

Then, in this checkout:

```sh
fluxor modules build --all   # build every module for rp2350, bcm2712, wasm
```

[docs/guides/running.md](docs/guides/running.md) carries the smallest
useful graph inline and pipes it straight into `fluxor run` on stdin,
so bringing one up is a single command with nothing else to fetch. It
is live when `curl http://127.0.0.1:18080/healthz` answers `ok`; the
guide has the smoke checks and how to stop.

To pick up new fluxor changes: `make publish` in fluxor, then
`fluxor update` here to advance `fluxor.lock`, and commit the
lockfile. When iterating on both repos at once, add them to
`~/.fluxor/workspace.toml`; workspace members resolve `:latest`
automatically and `fluxor sync` writes the resolved digests through
the lockfile.

## Repository layout

| Path | Contents |
| --- | --- |
| `modules/foundation/` | The protocol modules: `http`, `websocket`, `ws_stream`, `rtp`, `sip`, `smtp`, `s3`. `fluxor modules build` packs each into a `.fmod`, plus one per declared variant. |
| `modules/common/` | I/O-free `no_std` codec cores, `include!`d verbatim by the modules. See [modules/common/README.md](modules/common/README.md). |
| `tools/` | Repository scripts. |
| `docs/` | Stable reference: guides, architecture, reference. Indexed by [docs/overview.md](docs/overview.md). |
| `fluxor.toml` | Project manifest for the `fluxor` CLI: identity, dependencies, targets. |
| `Makefile` | Thin alias layer over the `fluxor` CLI; `make help` lists the targets. |

A module is a directory, never a crate: there are no `Cargo.toml`
files under `modules/**`, and `fluxor modules build` invokes `rustc`
directly against each `mod.rs`. Wave has no root cargo workspace.

## Documentation

- [docs/overview.md](docs/overview.md) — index of the full doc set
- [docs/guides/running.md](docs/guides/running.md) — validated bring-up on a Linux host
- [docs/specification.md](docs/specification.md) — the ownership boundary, per-module scope and declared limits
- [docs/architecture/http3-ownership.md](docs/architecture/http3-ownership.md) — the HTTP/3 boundary and the stream-record seam with fluxor's `quic`

## Licence

Apache-2.0
