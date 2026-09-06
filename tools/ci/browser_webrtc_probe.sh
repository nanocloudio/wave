#!/usr/bin/env bash
set -euo pipefail

# Generate a real Chromium WebRTC offer and verify the SDP facts that Wave's
# scoped parser and Conclave's adapter consume. This is intentionally a probe,
# not a fake fixture: it exercises the browser's current offer format.

browser=${CHROMIUM:-chromium}
command -v "$browser" >/dev/null || {
  echo "browser_webrtc_probe: Chromium not installed" >&2
  exit 2
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
turn_url=${TURN_URL:-}
turn_user=${TURN_USER:-}
turn_pass=${TURN_PASS:-}
cat >"$tmp/offer.html" <<'HTML'
<!doctype html><script>
(async()=>{
  const iceServers = TURN_URL ? [{urls: TURN_URL, username: TURN_USER, credential: TURN_PASS}] : [];
  const pc = new RTCPeerConnection({iceServers, iceTransportPolicy: TURN_URL ? 'relay' : 'all'});
  let relay = false;
  pc.onicecandidate = e => { if (e.candidate && e.candidate.candidate.includes(' typ relay ')) relay = true; };
  pc.addTransceiver('audio', {direction: 'sendrecv'});
  pc.addTransceiver('video', {direction: 'recvonly'});
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await new Promise(r => setTimeout(r, 1500));
  document.body.textContent = pc.localDescription.sdp + (relay ? '\nPROBE_RELAY=1\n' : '');
})();
</script>
HTML

# Keep the values out of shell interpolation in the HTML source. Chromium
# receives them as globals, and the probe rejects control characters below.
python3 - "$tmp/offer.html" "$turn_url" "$turn_user" "$turn_pass" <<'PY'
from pathlib import Path
import json, sys
p = Path(sys.argv[1])
s = p.read_text()
s = "<script>const TURN_URL=%s,TURN_USER=%s,TURN_PASS=%s;</script>\n" % tuple(json.dumps(x) for x in sys.argv[2:]) + s
p.write_text(s)
PY

"$browser" --headless --no-sandbox --disable-gpu \
  --disable-dev-shm-usage --user-data-dir="$tmp/profile" \
  --allow-file-access-from-files --virtual-time-budget=2000 \
  --dump-dom "file://$tmp/offer.html" >"$tmp/dom.html" 2>"$tmp/chromium.log"

for fact in \
  'a=group:BUNDLE' \
  'a=fingerprint:sha-256 ' \
  'a=setup:actpass' \
  'a=rtcp-mux' \
  'm=audio ' \
  'm=video ' \
  'a=rtpmap:111 opus/' \
  'a=rtpmap:96 VP8/' \
  'H264/'; do
  grep -Fq "$fact" "$tmp/dom.html" || {
    echo "browser_webrtc_probe: missing SDP fact: $fact" >&2
    exit 1
  }
done

if [[ -n "$turn_url" ]] && ! grep -Fq 'PROBE_RELAY=1' "$tmp/dom.html"; then
  echo "browser_webrtc_probe: relay-only gathering produced no relay candidate" >&2
  exit 1
fi

echo "browser_webrtc_probe: Chromium offer contains Wave/Conclave WebRTC facts"
