#!/usr/bin/env python3
"""An HTTP/1.1 origin for the exchange-client E2E.

Answers every request with a body that ECHOES THE PATH, and records the whole
request head -- every line of it -- to <outfile>. Echoing the path is what
makes the assertion meaningful: a reply carrying the path the graph built
proves the request reached the origin, not merely that some response came
back. Recording every line, not just the request line, is what lets a test
assert on a header the graph sent.

Binds the port it is given and serves until killed, so a graph that dials it
more than once — a retry, a second publish — is answered every time rather
than seeing a closed port on the second attempt.

    http_origin.py <outfile> <port>
"""
import pathlib
import socket
import sys
import threading

REQUEST_TIMEOUT_S = 20


def serve(conn, out):
    try:
        conn.settimeout(REQUEST_TIMEOUT_S)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        # The whole head, so a test can assert on a header the graph sent
        # and not only on the request line.
        head = data.split(b"\r\n\r\n", 1)[0]
        out.write_bytes(head)
        head = head.split(b"\r\n", 1)[0]
        parts = head.split(b" ")
        path = parts[1] if len(parts) > 1 else b"/"
        body = b"echo:" + path
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"X-Origin-Note: seen\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
    except Exception:
        pass
    finally:
        conn.close()


def main():
    out = pathlib.Path(sys.argv[1])
    port = int(sys.argv[2])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"origin listening on {port}", flush=True)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=serve, args=(conn, out), daemon=True).start()


if __name__ == "__main__":
    main()
