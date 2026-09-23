#!/usr/bin/env bash
# The throwaway certificates the example graphs name.
#
# A TLS graph names a certificate and a key on disk, and `fluxor build --check`
# reads them, so the `examples` gate fails when they are absent. The paths the
# examples use are under `/tmp`, which on this host is RAM-backed and empty
# after a reboot — and the end-to-end script that mints them runs in a later
# phase than the gate that reads them. That made the gate pass on residue from
# an earlier run and fail on a clean boot, which is the opposite of what a gate
# is for.
#
# This script mints whatever is missing, before anything reads it. The paths are
# read out of the example graphs rather than listed here, so a new TLS example
# is provisioned by adding the example and nothing else.
#
# Certificates are self-signed P-256, valid for a day, and exist only to
# exercise a handshake and a record layer. They are not a PKI decision, and
# nothing outside a test run should ever meet one.
#
# Usage: tools/ci/dev_certs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

[[ -d examples ]] || exit 0

command -v openssl >/dev/null 2>&1 || {
  echo "dev_certs: openssl not on PATH" >&2
  exit 1
}

# `cert_file:`/`key_file:` values under /tmp, paired by the stem they share:
# `/tmp/server_cert.der` and `/tmp/server_key.der` are one pair, minted once.
mapfile -t certs < <(
  grep -rhoE '(cert|key)_file:[[:space:]]*"/tmp/[A-Za-z0-9_./-]+"' examples \
    | grep -oE '/tmp/[A-Za-z0-9_./-]+' | sort -u
)

minted=0
for cert in "${certs[@]}"; do
  case "$cert" in *_cert.*) ;; *) continue ;; esac
  ext="${cert##*.}"
  key="${cert%_cert.$ext}_key.$ext"
  [[ -f "$cert" && -f "$key" ]] && continue

  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 -subj "/CN=wave" \
    >/dev/null 2>&1 || {
    echo "dev_certs: openssl could not mint a certificate" >&2
    exit 1
  }
  case "$ext" in
    der)
      openssl x509 -in "$work/cert.pem" -outform DER -out "$cert" 2>/dev/null
      openssl ec -in "$work/key.pem" -outform DER -out "$key" 2>/dev/null
      ;;
    pem)
      cp "$work/cert.pem" "$cert"
      cp "$work/key.pem" "$key"
      ;;
    *)
      echo "dev_certs: $cert names an encoding this script does not mint: $ext" >&2
      exit 1
      ;;
  esac
  chmod 600 "$key"
  rm -rf "$work"
  trap - EXIT
  minted=$((minted + 1))
done

if (( minted > 0 )); then
  echo "dev_certs: minted $minted certificate pair(s)"
fi
