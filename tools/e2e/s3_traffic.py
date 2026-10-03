#!/usr/bin/env python3
"""Real S3 traffic against a running `wave-s3` service.

Standard library only: SigV4 in the header and presigned forms, the three
payload forms (hashed, UNSIGNED-PAYLOAD, signed aws-chunked), multipart
uploads, listings, ranges, concurrent clients, and the refusals.

usage: s3_traffic.py <endpoint host:port> <config.json>

config.json: {"region": ..., "max_object_mib": N, "part_min_kib": N,
              "alpha": {"key": ..., "secret": ..., "bucket": ...},
              "beta":  {"key": ..., "secret": ..., "bucket": ...}}
"""

import datetime
import hashlib
import hmac
import http.client
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
EMPTY = hashlib.sha256(b"").hexdigest()
CHUNK = 64 * 1024


def quote(s, safe="-_.~"):
    return urllib.parse.quote(s, safe=safe)


def hmac256(key, msg):
    return hmac.new(key, msg.encode() if isinstance(msg, str) else msg, hashlib.sha256).digest()


class Client:
    def __init__(self, endpoint, key, secret, region):
        self.endpoint = endpoint
        self.key = key
        self.secret = secret
        self.region = region
        self.skew = 0

    def _now(self):
        return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.skew)

    def _signing_key(self, date):
        k = hmac256(("AWS4" + self.secret).encode(), date)
        k = hmac256(k, self.region)
        k = hmac256(k, "s3")
        return hmac256(k, "aws4_request")

    def _canonical_query(self, query):
        pairs = sorted((quote(k), quote(v)) for k, v in query)
        return "&".join(f"{k}={v}" for k, v in pairs)

    def sign(self, method, path, query, headers, payload_hash, amz_date):
        date = amz_date[:8]
        names = sorted(h.lower() for h in headers)
        canon_headers = "".join(
            f"{n}:{' '.join(str(headers_ci(headers, n)).split())}\n" for n in names
        )
        signed = ";".join(names)
        cr = "\n".join(
            [method, quote(path, safe="/-_.~"), self._canonical_query(query), canon_headers, signed, payload_hash]
        )
        scope = f"{date}/{self.region}/s3/aws4_request"
        sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(cr.encode()).hexdigest()])
        k = self._signing_key(date)
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        return sig, scope, signed, k

    def request(self, method, path, query=(), headers=None, body=b"", mode="hash", sign=True,
                tamper=None, expect=False, conn=None):
        """One request. `mode`: 'hash', 'unsigned', 'chunked'. Returns
        (status, headers dict, body)."""
        headers = dict(headers or {})
        query = list(query)
        amz_date = self._now().strftime("%Y%m%dT%H%M%SZ")
        headers["host"] = self.endpoint
        headers["x-amz-date"] = amz_date
        wire_body = body
        if mode == "chunked":
            headers["x-amz-content-sha256"] = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
            headers["content-encoding"] = "aws-chunked"
            headers["x-amz-decoded-content-length"] = str(len(body))
            headers["content-length"] = str(chunked_len(len(body)))
            payload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        elif mode == "unsigned":
            headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
            payload = "UNSIGNED-PAYLOAD"
        else:
            payload = hashlib.sha256(body).hexdigest()
            headers["x-amz-content-sha256"] = payload
        if mode != "chunked" and (body or method in ("PUT", "POST")):
            headers["content-length"] = str(len(body))
        if sign:
            sig, scope, signed, k = self.sign(method, path, query, headers, payload, amz_date)
            headers["authorization"] = (
                f"AWS4-HMAC-SHA256 Credential={self.key}/{scope}, SignedHeaders={signed}, Signature={sig}"
            )
            if mode == "chunked":
                wire_body = aws_chunked(body, k, amz_date, scope, sig)
        if tamper is not None:
            wire_body = tamper
        if expect:
            headers["expect"] = "100-continue"
        target = quote(path, safe="/-_.~") + ("?" + self._canonical_query(query) if query else "")
        c = conn or http.client.HTTPConnection(self.endpoint, timeout=60)
        c.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        for k2, v in headers.items():
            c.putheader(k2, v)
        c.endheaders()
        if wire_body and not expect:
            try:
                for i in range(0, len(wire_body), CHUNK):
                    c.send(wire_body[i : i + CHUNK])
            except (BrokenPipeError, ConnectionResetError):
                # The server answered before taking the whole body; read
                # what it said.
                pass
        elif wire_body and expect:
            # The client waits for the 100 (or a final answer) before its body.
            sock = c.sock
            sock.settimeout(10)
            first = sock.recv(64, socket.MSG_PEEK)
            if first.startswith(b"HTTP/1.1 100"):
                line = b""
                while not line.endswith(b"\r\n\r\n"):
                    line += sock.recv(1)
                for i in range(0, len(wire_body), CHUNK):
                    c.send(wire_body[i : i + CHUNK])
        try:
            r = c.getresponse()
            data = r.read()
        except (ConnectionResetError, http.client.RemoteDisconnected):
            c.close()
            return 0, {}, b""
        hdrs = {k2.lower(): v for k2, v in r.getheaders()}
        if conn is None:
            c.close()
        return r.status, hdrs, data

    def presign(self, method, path, expires, at=None):
        t = at or self._now()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date = amz_date[:8]
        scope = f"{date}/{self.region}/s3/aws4_request"
        query = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self.key}/{scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", str(expires)),
            ("X-Amz-SignedHeaders", "host"),
        ]
        sig, _, _, _ = self.sign(method, path, query, {"host": self.endpoint}, "UNSIGNED-PAYLOAD", amz_date)
        return quote(path, safe="/-_.~") + "?" + self._canonical_query(query) + "&X-Amz-Signature=" + sig

    def get_url(self, url):
        c = http.client.HTTPConnection(self.endpoint, timeout=60)
        c.putrequest("GET", url, skip_host=True, skip_accept_encoding=True)
        c.putheader("host", self.endpoint)
        c.endheaders()
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data


def headers_ci(headers, name):
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return ""


def chunked_len(n):
    total = 0
    full, rest = divmod(n, CHUNK)
    for size in [CHUNK] * full + ([rest] if rest else []):
        total += len(f"{size:x}") + len(";chunk-signature=") + 64 + 2 + size + 2
    total += len("0;chunk-signature=") + 64 + 4
    return total


def aws_chunked(body, k, amz_date, scope, seed):
    out = bytearray()
    prev = seed
    chunks = [body[i : i + CHUNK] for i in range(0, len(body), CHUNK)] + [b""]
    for c in chunks:
        sts = "\n".join(
            ["AWS4-HMAC-SHA256-PAYLOAD", amz_date, scope, prev, EMPTY, hashlib.sha256(c).hexdigest()]
        )
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        out += f"{len(c):x};chunk-signature={sig}\r\n".encode() + c + b"\r\n"
        prev = sig
    return bytes(out)


def code_of(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except ET.ParseError:
        return None


FAILURES = []


def check(cond, what):
    if cond:
        print(f"  ok  {what}")
    else:
        print(f"  FAIL {what}")
        FAILURES.append(what)


def pattern(n, a, b):
    return bytes((i * a) % b for i in range(n))


def main():
    endpoint = sys.argv[1]
    cfg = json.load(open(sys.argv[2]))
    region = cfg["region"]
    A = Client(endpoint, cfg["alpha"]["key"], cfg["alpha"]["secret"], region)
    B = Client(endpoint, cfg["beta"]["key"], cfg["beta"]["secret"], region)
    ab = cfg["alpha"]["bucket"]
    bb = cfg["beta"]["bucket"]

    print("== object lifecycle")
    s, h, _ = A.request("PUT", f"/{ab}/greeting.txt", body=b"hello from wave s3")
    check(s == 200 and h.get("etag", "").startswith('"'), "PUT answers 200 with an ETag")
    check(h.get("x-fluxor-fence", "") != "", "PUT reports the fence it was acknowledged at")
    s, _, d = A.request("GET", f"/{ab}/greeting.txt")
    check(s == 200 and d == b"hello from wave s3", "GET returns the body")
    s, h, d = A.request("HEAD", f"/{ab}/greeting.txt")
    check(s == 200 and h.get("content-length") == "18" and d == b"", "HEAD reports the length, no body")
    s, _, _ = A.request("PUT", f"/{ab}/greeting.txt", body=b"a newer greeting, longer than before", mode="unsigned")
    s, _, d = A.request("GET", f"/{ab}/greeting.txt")
    check(d == b"a newer greeting, longer than before", "the later write wins")
    s, h, d = A.request("GET", f"/{ab}/greeting.txt", headers={"range": "bytes=2-6"})
    check(s == 206 and d == b"newer" and h.get("content-range") == "bytes 2-6/36", "Range answers 206 with Content-Range")
    s, h, d = A.request("GET", f"/{ab}/greeting.txt", headers={"range": "bytes=100-"})
    check(s == 416 and code_of(d) == "InvalidRange", "an unsatisfiable Range is 416 InvalidRange")
    A.request("PUT", f"/{ab}/nested/deep.txt", body=b"deep")
    s, _, d = A.request("GET", f"/{ab}", query=[("list-type", "2")])
    root = ET.fromstring(d)
    keys = [e.findtext(NS + "Key") for e in root.iter(NS + "Contents")]
    check(s == 200 and keys == ["greeting.txt", "nested/deep.txt"] and root.findtext(NS + "KeyCount") == "2", "ListObjectsV2 lists both keys")
    s, _, d = A.request("GET", f"/{ab}", query=[("list-type", "2"), ("delimiter", "/")])
    root = ET.fromstring(d)
    keys = [e.findtext(NS + "Key") for e in root.iter(NS + "Contents")]
    cps = [e.findtext(NS + "Prefix") for e in root.iter(NS + "CommonPrefixes")]
    check(keys == ["greeting.txt"] and cps == ["nested/"], "delimiter rolls nested keys into a common prefix")
    s, _, d = A.request("GET", f"/{ab}", query=[("prefix", "nested/")])
    root = ET.fromstring(d)
    keys = [e.findtext(NS + "Key") for e in root.iter(NS + "Contents")]
    check(keys == ["nested/deep.txt"] and root.findtext(NS + "Prefix") == "nested/", "ListObjects (v1) honours prefix")
    s, _, _ = A.request("DELETE", f"/{ab}/greeting.txt")
    check(s == 204, "DELETE answers 204")
    s, _, d = A.request("GET", f"/{ab}/greeting.txt")
    check(s == 404 and code_of(d) == "NoSuchKey", "a deleted key is 404 NoSuchKey")
    s, _, _ = A.request("DELETE", f"/{ab}/greeting.txt")
    check(s == 204, "deleting a missing key is 204")
    s, _, d = A.request("GET", "/")
    check(s == 200 and ab.encode() in d, "ListBuckets names the key's bucket")
    s, _, _ = A.request("HEAD", f"/{ab}")
    check(s == 200, "HeadBucket on the key's own bucket")

    print("== list pagination")
    for i in range(25):
        A.request("PUT", f"/{ab}/page/k{i:03}", body=b"x")
    seen, token, pages = [], None, 0
    while True:
        q = [("list-type", "2"), ("prefix", "page/"), ("max-keys", "7")]
        if token:
            q.append(("continuation-token", token))
        s, _, d = A.request("GET", f"/{ab}", query=q)
        root = ET.fromstring(d)
        seen += [e.findtext(NS + "Key") for e in root.iter(NS + "Contents")]
        pages += 1
        if root.findtext(NS + "IsTruncated") != "true":
            break
        token = root.findtext(NS + "NextContinuationToken")
    check(seen == [f"page/k{i:03}" for i in range(25)] and pages == 4, "25 keys page as 7+7+7+4, each once, in order")
    s, _, d = A.request("GET", f"/{ab}", query=[("list-type", "2"), ("start-after", "page/k020")])
    keys = [e.findtext(NS + "Key") for e in ET.fromstring(d).iter(NS + "Contents")]
    check(keys[:4] == [f"page/k{i:03}" for i in range(21, 25)], "start-after resumes after the named key")
    s, _, d = A.request("GET", f"/{ab}", query=[("list-type", "2"), ("max-keys", "1001")])
    check(s == 400 and code_of(d) == "InvalidArgument", "max-keys past 1000 is refused, not clamped")

    print("== large streaming, both directions")
    big = pattern(24 * 1024 * 1024, 7, 251)
    for mode in ("chunked", "hash", "unsigned"):
        s, _, _ = A.request("PUT", f"/{ab}/big-{mode}.bin", body=big, mode=mode)
        check(s == 200, f"a 24 MiB PUT ({mode}) is accepted")
        s, h, d = A.request("GET", f"/{ab}/big-{mode}.bin")
        check(s == 200 and d == big, f"its GET returns every byte ({mode})")
    # Sign one body, send another of the same length.
    s, _, d = A.request("PUT", f"/{ab}/tampered", body=b"signed body!!!", tamper=b"TAMPERED BODY!")
    check(s == 400 and code_of(d) == "XAmzContentSHA256Mismatch", "a body that is not the signed one is refused")
    s, _, _ = A.request("GET", f"/{ab}/tampered")
    check(s == 404, "and nothing of it is stored")
    signed = pattern(3 * CHUNK, 5, 241)
    s, _, d = A.request("PUT", f"/{ab}/tampered-chunks", body=signed, mode="chunked", tamper=None)
    check(s == 200, "a signed aws-chunked body is accepted")
    forged = bytearray(aws_chunked(signed, b"\0" * 32, "x", "x", "0" * 64))
    s, _, d = A.request("PUT", f"/{ab}/forged-chunks", body=signed, mode="chunked", tamper=bytes(forged))
    check(s == 403 and code_of(d) == "SignatureDoesNotMatch", "aws-chunked chunks under forged signatures are refused")
    s, _, _ = A.request("GET", f"/{ab}/forged-chunks")
    check(s == 404, "and nothing of them is stored")

    print("== multipart")
    part_min = cfg["part_min_kib"] * 1024

    def doc(tags):
        return ("<CompleteMultipartUpload>" + "".join(
            f"<Part><PartNumber>{n}</PartNumber><ETag>{t}</ETag></Part>" for n, t in tags)
            + "</CompleteMultipartUpload>").encode()

    s, _, d = A.request("POST", f"/{ab}/mp/asm.bin", query=[("uploads", "")])
    upload = ET.fromstring(d).findtext(NS + "UploadId")
    check(s == 200 and upload, "CreateMultipartUpload answers an UploadId")
    parts = {n: pattern(part_min + n * 1000, 11 + n, 251) for n in (1, 2, 3)}
    tag = {}
    for n in (2, 1, 3):
        s, h, _ = A.request("PUT", f"/{ab}/mp/asm.bin", query=[("partNumber", str(n)), ("uploadId", upload)],
                            body=parts[n], mode="chunked")
        tag[n] = h.get("etag", "")
        check(s == 200 and tag[n].startswith('"'), f"part {n} uploaded")
    s, _, d = A.request("PUT", f"/{ab}/mp/asm.bin", query=[("partNumber", "1"), ("uploadId", "deadbeef")], body=b"z")
    check(s == 404 and code_of(d) == "NoSuchUpload", "a part for an unknown upload is 404 NoSuchUpload")
    s, _, d = A.request("POST", f"/{ab}/mp/asm.bin", query=[("uploadId", upload)], body=doc([(2, tag[2]), (1, tag[1])]))
    check(s == 400 and code_of(d) == "InvalidPartOrder", "parts listed out of order are refused")
    s, _, d = A.request("POST", f"/{ab}/mp/asm.bin", query=[("uploadId", upload)],
                        body=doc([(1, tag[2]), (2, tag[2]), (3, tag[3])]))
    check(s == 400 and code_of(d) == "InvalidPart", "a part listed under another part's ETag is InvalidPart")
    body = doc([(n, tag[n]) for n in (1, 2, 3)])
    s, _, d = A.request("POST", f"/{ab}/mp/asm.bin", query=[("uploadId", upload)], body=body)
    check(s == 200 and b"CompleteMultipartUploadResult" in d and b"<Error>" not in d, "CompleteMultipartUpload completes")
    s, _, d = A.request("POST", f"/{ab}/mp/asm.bin", query=[("uploadId", upload)], body=body)
    check(s == 404, "completing it again is 404")
    s, _, d = A.request("GET", f"/{ab}/mp/asm.bin")
    check(d == parts[1] + parts[2] + parts[3], "the object is the parts in order")
    s, _, d = A.request("POST", f"/{ab}/mp/gone.bin", query=[("uploads", "")])
    upload = ET.fromstring(d).findtext(NS + "UploadId")
    _, h, _ = A.request("PUT", f"/{ab}/mp/gone.bin", query=[("partNumber", "1"), ("uploadId", upload)], body=b"abc")
    gone = doc([(1, h.get("etag", ""))])
    s, _, _ = A.request("DELETE", f"/{ab}/mp/gone.bin", query=[("uploadId", upload)])
    check(s == 204, "AbortMultipartUpload answers 204")
    s, _, _ = A.request("POST", f"/{ab}/mp/gone.bin", query=[("uploadId", upload)], body=gone)
    s2, _, _ = A.request("GET", f"/{ab}/mp/gone.bin")
    check(s == 404 and s2 == 404, "an aborted upload completes nothing")
    s, _, d = A.request("POST", f"/{ab}/mp/small.bin", query=[("uploads", "")])
    upload = ET.fromstring(d).findtext(NS + "UploadId")
    _, h1, _ = A.request("PUT", f"/{ab}/mp/small.bin", query=[("partNumber", "1"), ("uploadId", upload)], body=b"tiny")
    _, h2, _ = A.request("PUT", f"/{ab}/mp/small.bin", query=[("partNumber", "2"), ("uploadId", upload)], body=b"tail")
    s, _, d = A.request("POST", f"/{ab}/mp/small.bin", query=[("uploadId", upload)],
                        body=doc([(1, h1.get("etag", "")), (2, h2.get("etag", ""))]))
    check(s == 400 and code_of(d) == "EntityTooSmall", "a part below the minimum is EntityTooSmall")
    s, _, d = A.request("PUT", f"/{ab}/mp/x", query=[("partNumber", "10001"), ("uploadId", upload)], body=b"x")
    check(s == 400, "a part number past 10000 is refused")

    print("== authentication and authority")
    s, _, d = A.request("PUT", f"/{ab}/doc", body=b"nope", sign=False)
    check(s == 403, "an unsigned PUT is refused")
    s, _, _ = A.request("GET", f"/{ab}/nested/deep.txt", sign=False)
    check(s == 403, "an unsigned GET is refused")
    wrong = Client(endpoint, cfg["alpha"]["key"], "WRONG", region)
    s, _, d = wrong.request("GET", f"/{ab}/nested/deep.txt")
    check(s == 403 and code_of(d) == "SignatureDoesNotMatch", "a wrong secret is SignatureDoesNotMatch")
    nobody = Client(endpoint, "AKIANOBODY", "x", region)
    s, _, d = nobody.request("GET", f"/{ab}/nested/deep.txt")
    check(s == 403 and code_of(d) == "InvalidAccessKeyId", "an unknown key is InvalidAccessKeyId")
    late = Client(endpoint, cfg["alpha"]["key"], cfg["alpha"]["secret"], region)
    late.skew = -3600
    s, _, d = late.request("GET", f"/{ab}/nested/deep.txt")
    check(s == 403 and code_of(d) == "RequestTimeTooSkewed", "a request an hour old is RequestTimeTooSkewed")
    s, _, d = A.request("PUT", f"/{bb}/doc", body=b"cross")
    check(s == 403 and code_of(d) == "AccessDenied", "a key's write outside its scope is refused by authority")
    s, _, d = A.request("GET", f"/{bb}", query=[("list-type", "2")])
    check(s == 403, "a listing outside the scope is refused")
    s, _, _ = B.request("PUT", f"/{bb}/doc", body=b"authenticated content")
    check(s == 200, "the other key writes its own bucket")
    url = B.presign("GET", f"/{bb}/doc", 300)
    s, d = B.get_url(url)
    check(s == 200 and d == b"authenticated content", "a presigned GET is served")
    old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=600)
    s, _ = B.get_url(B.presign("GET", f"/{bb}/doc", 300, at=old))
    check(s == 403, "an expired presigned URL is refused")
    s, _ = B.get_url(url.replace("/doc?", "/other?"))
    check(s == 403, "a presigned URL used for another key is refused")
    s, _ = A.get_url(A.presign("GET", f"/{bb}/doc", 300))
    check(s == 403, "a presigned URL outside the signer's scope is refused")

    print("== limits refuse, never clamp")
    max_obj = cfg["max_object_mib"] * 1024 * 1024
    c = http.client.HTTPConnection(endpoint, timeout=30)
    s, _, d = A.request("PUT", f"/{ab}/huge", body=b"\0" * (max_obj + 1), expect=True, conn=c)
    check(s == 400 and code_of(d) == "EntityTooLarge", "an object past max_object_mib is EntityTooLarge before its body")
    long_key = "k" * 300
    s, _, d = A.request("PUT", f"/{ab}/{long_key}", body=b"x")
    check(s == 400 and code_of(d) == "KeyTooLongError", "a key past the name bound is KeyTooLongError")
    s, _, d = A.request("PUT", "/Bad_Bucket/x", body=b"x")
    check(s == 400 and code_of(d) == "InvalidBucketName", "an invalid bucket name is refused")

    print("== concurrent clients")
    idle = socket.create_connection(tuple(endpoint.rsplit(":", 1)[0:1]) + (int(endpoint.rsplit(":", 1)[1]),))
    results = []

    def worker(i):
        body = f"parallel-object-{i}".encode() * 1000
        s1, _, _ = A.request("PUT", f"/{ab}/par/obj{i}", body=body, mode="chunked")
        s2, _, d2 = A.request("GET", f"/{ab}/par/obj{i}")
        results.append(s1 == 200 and s2 == 200 and d2 == body)

    t0 = time.time()
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check(len(results) == 16 and all(results), "16 clients each PUT and GET their own object while one connection idles")
    check(time.time() - t0 < 60, "and an idle connection holds none of them up")
    idle.close()

    print("== a client that disconnects mid-body")
    host, port = endpoint.rsplit(":", 1)
    sock = socket.create_connection((host, int(port)))
    amz = A._now().strftime("%Y%m%dT%H%M%SZ")
    hdrs = {"host": endpoint, "x-amz-date": amz, "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            "content-length": str(1024 * 1024)}
    sig, scope, signed, _ = A.sign("PUT", f"/{ab}/cut.bin", [], hdrs, "UNSIGNED-PAYLOAD", amz)
    head = f"PUT /{ab}/cut.bin HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    head += f"authorization: AWS4-HMAC-SHA256 Credential={A.key}/{scope}, SignedHeaders={signed}, Signature={sig}\r\n\r\n"
    sock.sendall(head.encode() + b"y" * 300_000)
    time.sleep(0.5)
    sock.close()
    time.sleep(1.0)
    s, _, d = A.request("GET", f"/{ab}/cut.bin")
    check(s == 404, "a body cut off by the peer stores nothing")
    s, _, d = A.request("GET", f"/{ab}/nested/deep.txt")
    check(s == 200 and d == b"deep", "and the server carries on serving")

    if FAILURES:
        print(f"FAIL: {len(FAILURES)} check(s) failed")
        sys.exit(1)
    print("PASS: s3 traffic")


if __name__ == "__main__":
    main()
