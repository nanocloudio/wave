#!/usr/bin/env bash
# The throwaway certificate the TLS and QUIC example graphs serve.
#
# A graph names its certificate and key on disk (`target/pki/server_cert.der`,
# `target/pki/server_key.der`), and `fluxor build` reads them, so every build
# of one needs the pair present. No key is committed: a fixture key in the
# tree is a key someone eventually uses somewhere real. This script mints one
# per machine instead, under `target/`, which is ignored, survives a reboot,
# and goes with `fluxor clean`.
#
# It is the gate's `[ci.setup]` script, so the pair exists before any phase
# reads it, and every other path that builds such a graph runs it first too:
# the end-to-end scripts, the rig preflight and the H3 interop test. It mints
# only when the pair is missing, or expires within a day, so running it is
# free once a machine has one.
#
# The pair is self-signed P-256, CN=wave with subject alternative names
# localhost and 127.0.0.1, valid for 30 days: DER for the graphs, PEM for the
# aioquic peers. It exists to exercise a handshake and a record layer and must
# never protect anything.
#
# Usage: tools/ci/dev_certs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKI="$ROOT/target/pki"

current() {
  local f
  for f in server_cert.der server_key.der server_cert.pem server_key.pem; do
    [[ -s "$PKI/$f" ]] || return 1
  done
  openssl x509 -in "$PKI/server_cert.pem" -noout -checkend 86400 >/dev/null 2>&1
}

command -v openssl >/dev/null 2>&1 || {
  echo "dev_certs: openssl not on PATH" >&2
  exit 1
}

current && exit 0

mkdir -p "$PKI"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 30 -subj "/CN=wave" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || {
  echo "dev_certs: openssl could not mint a certificate" >&2
  exit 1
}
openssl ec -in "$work/key.pem" -out "$work/key.sec1.pem" >/dev/null 2>&1
openssl x509 -in "$work/cert.pem" -outform DER -out "$work/cert.der"
openssl ec -in "$work/key.pem" -outform DER -out "$work/key.der" >/dev/null 2>&1
chmod 600 "$work/key.sec1.pem" "$work/key.der"
mv "$work/cert.der" "$PKI/server_cert.der"
mv "$work/key.der" "$PKI/server_key.der"
mv "$work/cert.pem" "$PKI/server_cert.pem"
mv "$work/key.sec1.pem" "$PKI/server_key.pem"
echo "dev_certs: minted target/pki/server_{cert,key}.{der,pem}"
