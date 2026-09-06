#!/usr/bin/env bash
set -euo pipefail

# Live relay-only browser qualification. Start coturn separately, then run:
#   TURN_URL=turn:127.0.0.1:3478?transport=udp \
#   TURN_USER=test TURN_PASS=test tools/ci/browser_turn_probe.sh

: "${TURN_URL:?TURN_URL is required}"
: "${TURN_USER:?TURN_USER is required}"
: "${TURN_PASS:?TURN_PASS is required}"
browser=${CHROMIUM:-chromium}
command -v "$browser" >/dev/null || { echo "Chromium is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

tmp=$(mktemp -d)
port=$((9227 + ($$ % 100)))
trap 'kill "$browser_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

python3 - "$tmp/probe.html" "$TURN_URL" "$TURN_USER" "$TURN_PASS" <<'PY'
from pathlib import Path
import json, sys
p, url, user, password = sys.argv[1:]
Path(p).write_text("""<!doctype html><pre id=o>starting</pre><script>
const TURN_URL=%s,TURN_USER=%s,TURN_PASS=%s;
(async()=>{const out=s=>document.getElementById('o').textContent=s;try{
 const cfg={iceServers:[{urls:TURN_URL,username:TURN_USER,credential:TURN_PASS}],iceTransportPolicy:'relay'};
 const a=new RTCPeerConnection(cfg),b=new RTCPeerConnection(cfg),aq=[],bq=[];
 let ar=false,br=false,ae=false,be=false,pong=false,gotVideo=false;
 a.onicecandidate=e=>{if(e.candidate){if(e.candidate.candidate.includes(' typ relay '))ar=true;aq.push(e.candidate)}else ae=true};
 b.onicecandidate=e=>{if(e.candidate){if(e.candidate.candidate.includes(' typ relay '))br=true;bq.push(e.candidate)}else be=true};
 const add=(pc,q)=>Promise.all(q.map(c=>pc.addIceCandidate(c).catch(()=>{})));
 b.ondatachannel=e=>e.channel.onmessage=x=>{if(x.data==='ping')e.channel.send('pong')};
 b.ontrack=e=>{if(e.track.kind==='video')gotVideo=true};
 const ch=a.createDataChannel('relay-probe');ch.onmessage=e=>{if(e.data==='pong')pong=true};
 a.addTransceiver('audio',{direction:'sendrecv'});b.addTransceiver('audio',{direction:'sendrecv'});
 const canvas=document.createElement('canvas');canvas.width=16;canvas.height=16;
 const video=canvas.captureStream(5).getVideoTracks()[0];a.addTrack(video,new MediaStream([video]));
 b.addTransceiver('video',{direction:'recvonly'});
 const offer=await a.createOffer();await a.setLocalDescription(offer);while(!ae)await new Promise(r=>setTimeout(r,100));
 await b.setRemoteDescription(a.localDescription);await add(b,aq);const answer=await b.createAnswer();await b.setLocalDescription(answer);while(!be)await new Promise(r=>setTimeout(r,100));
 await a.setRemoteDescription(b.localDescription);await add(a,bq);for(let i=0;i<100&&a.connectionState!=='connected';i++)await new Promise(r=>setTimeout(r,100));
 if(!ar||!br)throw Error('missing relay candidate');if(a.connectionState!=='connected'||b.connectionState!=='connected')throw Error(a.connectionState+'/'+b.connectionState);
 ch.send('ping');for(let i=0;i<30&&(!pong||!gotVideo);i++)await new Promise(r=>setTimeout(r,100));if(!pong)throw Error('data channel failed');if(!gotVideo)throw Error('video track not received');out('PASS relay-only ICE/DTLS/SRTP video/data-channel');
}catch(e){out('FAIL '+e)}})();
</script>""" % tuple(json.dumps(x) for x in (url,user,password)))
PY

"$browser" --headless=new --no-sandbox --disable-gpu --disable-extensions \
  --disable-dev-shm-usage --user-data-dir="$tmp/profile" \
  --remote-debugging-port="$port" --allow-file-access-from-files \
  "file://$tmp/probe.html" >"$tmp/chromium.log" 2>&1 &
browser_pid=$!

for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$port/json/list" >"$tmp/pages.json"; then break; fi
  sleep 0.2
done

python3 - "$port" <<'PY'
import asyncio, json, sys, urllib.request
import websockets
port = sys.argv[1]
pages = json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list'))
url = next(p['webSocketDebuggerUrl'] for p in pages if p.get('type') == 'page')
async def main():
    async with websockets.connect(url) as ws:
        for n in range(60):
            await asyncio.sleep(1)
            await ws.send(json.dumps({'id': n + 1, 'method': 'Runtime.evaluate',
                                      'params': {'expression': 'document.getElementById("o").textContent'}}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get('id') == n + 1:
                    value = msg.get('result', {}).get('result', {}).get('value', '')
                    if value.startswith(('PASS', 'FAIL')):
                        print(value)
                        raise SystemExit(0 if value.startswith('PASS') else 1)
                    break
        print('FAIL browser probe timeout')
        raise SystemExit(1)
asyncio.run(main())
PY
