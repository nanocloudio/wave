#!/usr/bin/env bash
# A SCENARIO'S BROWSER HOST, SERVED BY WAVE'S OWN FILE SERVER, END TO END.
#
# `fluxor run` on a scenario with a `host:` block writes the scenario's
# document root and runs a host graph that includes `@file_server`. Wave binds
# that name to its own `wave_files` stack (fluxor.toml `[uses.stacks]`), so
# this is the one place the whole chain runs against a real provider: the
# binding resolved, the stack composed, `http`'s `fs_root` serving the root
# through the runtime's FS provider.
#
# Each assertion is something the browser shell depends on:
#
#   * a file under a `list:` binding is served at the URL its
#     `fluxor-manifest.json` key names, typed by its extension — the root
#     links the listed directory in, so this is a link followed;
#   * a path naming a directory serves its `index.html` as `text/html`;
#   * `scenario.json` is served as JSON, and a `..` segment is refused;
#   * the component the scenario runs is up beside the host, on the port its
#     `port:` declares.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCENARIO="examples/linux/wave_browser_host.yaml"
# Fixed, because the scenario names them.
HOST_PORT=18084
SERVER_PORT=18085
LOG="$(mktemp /tmp/wave-browser-host-XXXXXX.log)"
PID=""
cleanup() {
  # `fluxor run` tears its children down when it is signalled.
  [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  rm -f "$LOG"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; tail -20 "$LOG" >&2 || true; exit 1; }

command -v curl >/dev/null 2>&1 || { echo "SKIP: curl not available"; exit 0; }
for port in "$HOST_PORT" "$SERVER_PORT"; do
  ! ss -ltn 2>/dev/null | grep -q ":$port " || fail "port $port is already in use"
done

echo "── fluxor run $SCENARIO ──"
( cd "$ROOT" && exec fluxor run "$SCENARIO" ) >"$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 480); do
  ss -ltn 2>/dev/null | grep -q ":$HOST_PORT " && break
  kill -0 "$PID" 2>/dev/null || fail "fluxor run exited before the host bound :$HOST_PORT"
  sleep 0.25
done
ss -ltn 2>/dev/null | grep -q ":$HOST_PORT " || fail "the host never bound :$HOST_PORT"

base="http://127.0.0.1:$HOST_PORT"
head_of() { curl -sS -D - -o /dev/null --max-time 10 "$1" | tr -d '\r'; }

manifest="$(curl -fsS --max-time 10 "$base/fluxor-manifest.json")" || fail "no fluxor-manifest.json"
case "$manifest" in
  *'"key":"media/a b.txt"'*) echo "   ok  the manifest lists the list: binding's file at its URL" ;;
  *) fail "fluxor-manifest.json is '$manifest'" ;;
esac

got="$(curl -fsS --max-time 10 "$base/media/a%20b.txt")" || fail "GET /media/a%20b.txt"
[ "$got" = "hello from the list binding" ] || fail "/media/a%20b.txt served '$got'"
head_of "$base/media/a%20b.txt" | grep -qi '^content-type: text/plain' \
  || fail "/media/a%20b.txt is not text/plain"
echo "   ok  a listed file is served through the linked directory, typed by extension"

for path in /media/sub /media/sub/; do
  got="$(curl -fsS --max-time 10 "$base$path")" || fail "GET $path"
  [ "$got" = "<html>sub index</html>" ] || fail "$path served '$got'"
  head_of "$base$path" | grep -qi '^content-type: text/html' || fail "$path is not text/html"
done
echo "   ok  a directory serves its index.html as text/html"

head_of "$base/scenario.json" | grep -qi '^content-type: application/json' \
  || fail "scenario.json is not application/json"
code="$(curl -sS -o /dev/null -w '%{http_code}' --path-as-is --max-time 10 "$base/media/../../fluxor.toml")"
[ "$code" = 400 ] || fail "a '..' segment answered $code"
echo "   ok  scenario.json is JSON and a '..' segment is refused"

code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$SERVER_PORT/healthz")"
[ "$code" = 200 ] || fail "the scenario's server component answered /healthz with $code"
echo "   ok  the component runs beside the host on its declared port"

echo "PASS: browser host served by wave_files"
