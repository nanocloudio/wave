# Running Wave

This guide brings up the smallest useful Wave graph on a Linux host
and smoke checks it: the `http` module serving two routes over the
host network surface. It is self-contained: the config is embedded
below and piped straight into `fluxor run` on stdin, so there is
nothing else to fetch.

Source: `modules/foundation/http/mod.rs` (the module the graph runs);
the `run` command and the hosted runtime are fluxor's.

## Prerequisites

Follow the setup in the repository [README](../../README.md) (fluxor
CLI on PATH, fluxor published into the local OCI store), then build
the module palette:

```sh
fluxor modules build --all
```

The Linux host loads the bcm2712 artefacts directly: both are
aarch64, so `linux` is a runtime host rather than a separate build
target.

## Run

The graph is one `http` module listening on TCP port 18080, wired to
the host network surface (`platform: net` provides the built-in
`linux_net` module). `host_tcp: 1` tells the module the kernel owns
TCP segmentation, so it pushes whole buffers instead of capping at
one MSS. Passing `-` as the config argument makes `fluxor run` read
the YAML from stdin, so the whole bring-up is one shell command:

```sh
fluxor run - <<'EOF'
target: linux
tick_us: 100

# linux_net and http feed each other, so the scheduler must accept
# the two-module cycle.
scheduler:
  accept_cycles: true

platform:
  net: {}

modules:
  - name: http
    port: 18080
    host_tcp: 1
    routes:
      - path: "/healthz"
        body: "ok"
        content_type: "text/plain"
      - path: "/"
        body: "<html><body>wave http ok</body></html>"

wiring:
  - from: linux_net.net_out
    to: http.net_in
  - from: http.net_out
    to: linux_net.net_in
EOF
```

To serve on a different port, change `port:` in the config. Startup
logs similar to these mean the graph is live:

```text
[... INFO fluxor_linux] [fluxor] linux platform boot
[... INFO fluxor::kernel::exec::scheduler::setup] [graph] modules=2 edges=2
[... INFO fluxor::kernel::module::syscalls] [http] server ready
[... INFO fluxor_linux] [inst] module 1 ready
```

## Smoke check

From another terminal:

```sh
curl http://127.0.0.1:18080/healthz
# ok
curl http://127.0.0.1:18080/
# <html><body>wave http ok</body></html>
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/nowhere
# 404
```

The answers come from the running graph: bytes enter through
`linux_net`, the `http` module matches the path against its route
table, and the response leaves the same way. The 404 for an
unmatched path is rendered by the module.

## Stopping

Ctrl+C in the terminal running `fluxor run` stops the runtime. Each
run is stateless; running the command again starts fresh.

## Richer graphs

The same module serves TLS by wiring fluxor's `tls` module between
`linux_net` and `http`, and HTTP/3 by wiring fluxor's `quic` module
there instead — the wiring shapes are in the
[README](../../README.md#composition-not-more-modules) and
[../architecture/http3-ownership.md](../architecture/http3-ownership.md).
[docs/overview.md](../overview.md) indexes the full doc set.
