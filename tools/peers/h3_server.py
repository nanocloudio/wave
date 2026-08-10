"""Minimal HTTP/3 server (aioquic) — the independent oracle for Wave's h3 CLIENT.

The mirror of tools/e2e/h3_server.sh, which points aioquic at Wave's server. Here
aioquic IS the server and grades what Wave sends: it prints the method, path,
authority and scheme it decoded, so the assertion is an outside party's reading
of our request rather than our own.
"""

import asyncio, ssl, sys
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

SEEN = []

class Server(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._http = None
    def quic_event_received(self, event):
        from aioquic.quic.events import ProtocolNegotiated
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
            return
        if self._http is None:
            return
        for ev in self._http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                hdrs = dict(ev.headers)
                path = hdrs.get(b":path", b"?")
                SEEN.append((hdrs.get(b":method"), path, hdrs.get(b":authority")))
                print(f"SERVER-SAW method={hdrs.get(b':method')!r} path={path!r} "
                      f"authority={hdrs.get(b':authority')!r} scheme={hdrs.get(b':scheme')!r}",
                      flush=True)
                body = b"from aioquic\n"
                self._http.send_headers(ev.stream_id, [
                    (b":status", b"200"), (b"content-type", b"text/plain"),
                ], end_stream=False)
                self._http.send_data(ev.stream_id, body, end_stream=True)
                self.transmit()

async def main(port, cert, key):
    cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    cfg.load_cert_chain(cert, key)
    await serve("127.0.0.1", port, configuration=cfg, create_protocol=Server)
    await asyncio.sleep(40)

asyncio.run(main(int(sys.argv[1]), sys.argv[2], sys.argv[3]))
