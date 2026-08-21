# Wave documentation

Wave is the application-protocol module palette for the
[fluxor](../../fluxor/) runtime; the [README](../README.md) is the
front door. This page indexes the doc set.

## Start here

- [guides/running.md](guides/running.md) — the smallest validated
  bring-up: the `http` module on a Linux host, config embedded,
  smoke checked with curl.
- [specification.md](specification.md) — what Wave is and is not:
  the ownership boundary with fluxor, per-module scope and declared
  limits, correctness and bounds requirements.

## Architecture

- [architecture/http3-ownership.md](architecture/http3-ownership.md) —
  the HTTP/3 boundary: Wave owns the protocol, fluxor's `quic` owns
  the transport, and the seam is fluxor's `mux` stream-record
  contract.
- [architecture/http_multiconn.md](architecture/http_multiconn.md) —
  how one `http` instance serves many concurrent HTTP/1, HTTP/2 and
  WebSocket connections: slot table, step iterator, demux,
  backpressure, and the WebSocket and application fan-outs.

## Reference

- [reference/protocol-surfaces.md](reference/protocol-surfaces.md) —
  the fluxor content surfaces Wave consumes, and which module
  declares which.
- [../modules/common/README.md](../modules/common/README.md) — the
  shared I/O-free codec cores and which modules mount them.
