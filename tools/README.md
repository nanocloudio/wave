# Tools

Five roles, one directory each. A file is named for what it is, its directory
for whose it is — the same convention `modules/foundation/http/` uses.

The language split is not arbitrary. Shell orchestrates processes: boot a graph,
wait for a port, drive it, assert on the output. Python holds the independent
protocol peers, because that is what their libraries are written in. Rust holds
the load generator, which needs the throughput and must share no code with Wave.

| Directory | Role |
| --- | --- |
| `ci/` | Gates `fluxor ci` runs as `[ci.test]` scripts |
| `rig/` | Hardware-rig build recipe, pre-flight guards, and the observer backend |
| `e2e/` | End-to-end drivers: boot a real graph and drive it over the wire |
| `peers/` | Independent implementations Wave is graded against |
| `load/` | Throughput: the rate ladder and the off-DUT generator |

## `ci/`

| Script | Gate |
| --- | --- |
| `shadow_guard.sh` | Hard-fails when the shadow checkout is missing, so CI cannot run zero tests and report green (`../standards/test-tracking.md` §7) |
| `host_crates.sh` | fmt, clippy and build for the host crates, which no `fluxor` phase reaches |
| `fmod_size_budget.sh` | Flash ceiling per `.fmod`, and asserts each variant stays smaller than its superset |

## `rig/`

`build.sh` is the recipe `fluxor rig test` runs before deploying; the
machine-local rig profile is a pointer at it. `preflight.sh` holds the guards it
calls — zero-byte artefacts, dangling backends, a stale staged image, and files a
graph embeds at build time. `backends/observe-proto_load` is the protocol-load
observer, reached through a symlink in the shared Fluxor backend directory.

## `e2e/`

| Script | Drives |
| --- | --- |
| `h3_server.sh` | aioquic → Fluxor `quic` → Wave `http` — the HTTP/3 server path |
| `h3_client.sh` | Wave `http` → Fluxor `quic` → an aioquic server — the client path |
| `sip.sh` | SIP signalling and the RTP media path |
| `linux_graph.sh` | Boots any example graph on the Linux runtime |

## `peers/`

`h3_server.py` (aioquic) and `sip_ua.py`. Peers are independent implementations
wherever one exists — a driver that grades Wave against Wave's own reading of an
RFC proves only self-consistency. ffmpeg plays the same role for RTP.

## `load/`

`suite.sh` runs a protocol × rate ladder against a live DUT. `wave-bench` is the
off-DUT generator (`wave-loadgen`) it calls, and it shares **no code** with Wave
by design: a load test built from the DUT's own parser cannot fail on a shared
codec defect, because the bug cancels out on both sides and the run goes green.
Its SHA-1, Base64, HPACK and frame codecs are deliberate re-implementations, and
that they interoperate is itself a cross-validation.
