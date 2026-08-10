//! Independent protocol clients for the load harness.
//!
//! Every codec here is written from the RFC, not lifted from Wave. That is the
//! point: if the generator shared `modules/common` or the module `wire_*` files, a
//! defect in a shared codec would cancel out on both sides and the run would go
//! green. Interoperating with Wave despite being a separate implementation is
//! itself a cross-validation.
//!
//! Implemented: HTTP/1.1 keep-alive, HTTP/2 cleartext (h2c), RFC 6455
//! WebSocket, gRPC-over-h2 unary. All plaintext — TLS would need a third-party
//! crate and is tracked separately.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use crate::IO_TIMEOUT;

/// The result of one measured request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Completed with the protocol's success signal (2xx, echo match, grpc-status 0).
    Ok,
    /// The peer answered, but not with success. Counted separately from an I/O
    /// failure — a load test that lumps "500" in with "connection reset" cannot
    /// tell an overloaded server from a broken one.
    Rejected,
    /// Transport failure, timeout, or malformed framing. Connection is dead.
    Failed,
}

/// A protocol client the open-loop driver can pace. One instance per shard,
/// owning one connection.
pub trait LoadClient {
    /// Issue one request and await its completion. Latency is measured around
    /// this call by the driver.
    fn round_trip(&mut self) -> Outcome;
    /// Wire name for the report.
    fn protocol(&self) -> &'static str;
}

// ───────────────────────────── SHA-1 (RFC 3174) ──────────────────────────

/// Independent SHA-1. Required by RFC 6455 for `Sec-WebSocket-Accept`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Independent Base64 (RFC 4648, padded).
pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ─────────────────────────── minimal HPACK (RFC 7541) ────────────────────

/// HPACK integer with an `n`-bit prefix.
fn hpack_int(out: &mut Vec<u8>, prefix: u8, nbits: u32, value: u32) {
    let max = (1u32 << nbits) - 1;
    if value < max {
        out.push(prefix | value as u8);
        return;
    }
    out.push(prefix | max as u8);
    let mut v = value - max;
    while v >= 128 {
        out.push((v % 128 + 128) as u8);
        v /= 128;
    }
    out.push(v as u8);
}

/// Raw (never Huffman) length-prefixed string — the simplest form every
/// conformant decoder must accept.
fn hpack_str(out: &mut Vec<u8>, s: &[u8]) {
    hpack_int(out, 0x00, 7, s.len() as u32);
    out.extend_from_slice(s);
}

/// Static-table index for a few names we send, or 0.
fn static_idx(name: &[u8]) -> u32 {
    match name {
        b":authority" => 1,
        b":method" => 2,
        b":path" => 4,
        b":scheme" => 6,
        b"content-type" => 31,
        b"user-agent" => 58,
        _ => 0,
    }
}

/// Literal header field **without indexing** (RFC 7541 §6.2.2) — no dynamic
/// table on either side, so the encoder stays stateless and the decoder cannot
/// desync across requests.
pub fn hpack_header(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let idx = static_idx(name);
    if idx > 0 {
        hpack_int(out, 0x00, 4, idx);
    } else {
        out.push(0x00);
        hpack_str(out, name);
    }
    hpack_str(out, value);
}

/// Pull `:status` out of a response header block.
///
/// Handles indexed static entries (`0x80|idx`) and the literal forms Wave's
/// server emits. A Huffman-flagged string is skipped rather than decoded — the
/// load driver only needs the status, and treating an unparsed field as fatal
/// would report the DUT as broken for using a legal encoding.
pub fn hpack_status(block: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            // Indexed header field — static table statuses.
            let idx = b & 0x7f;
            i += 1;
            match idx {
                8 => return Some(200),
                9 => return Some(204),
                10 => return Some(206),
                11 => return Some(304),
                12 => return Some(400),
                13 => return Some(404),
                14 => return Some(500),
                _ => continue,
            }
        }
        // Literal forms: 0x40 (incremental), 0x00 (without), 0x10 (never).
        let nbits = if b & 0xc0 == 0x40 { 6 } else { 4 };
        let mask = (1u8 << nbits) - 1;
        let name_idx = b & mask;
        i += 1;
        if name_idx == mask {
            // Multi-byte integer continuation.
            while i < block.len() && block[i] & 0x80 != 0 {
                i += 1;
            }
            i += 1;
        }
        let mut is_status = name_idx == 8;
        if name_idx == 0 {
            // New name, length-prefixed.
            let (name, next) = read_hpack_str(block, i)?;
            is_status = name.as_deref() == Some(b":status".as_ref());
            i = next;
        }
        let (value, next) = read_hpack_str(block, i)?;
        i = next;
        if is_status {
            let v = value?;
            let s = std::str::from_utf8(&v).ok()?;
            return s.trim().parse().ok();
        }
    }
    None
}

/// Read a length-prefixed HPACK string. Returns `(Some(bytes), next)` for a raw
/// string, `(None, next)` for a Huffman-coded one (skipped, not decoded).
fn read_hpack_str(buf: &[u8], mut i: usize) -> Option<(Option<Vec<u8>>, usize)> {
    let b = *buf.get(i)?;
    let huffman = b & 0x80 != 0;
    let mut len = (b & 0x7f) as usize;
    i += 1;
    if len == 0x7f {
        let mut m = 0;
        loop {
            let c = *buf.get(i)?;
            i += 1;
            len += ((c & 0x7f) as usize) << m;
            m += 7;
            if c & 0x80 == 0 {
                break;
            }
        }
    }
    let end = i.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let out = if huffman {
        None
    } else {
        Some(buf[i..end].to_vec())
    };
    Some((out, end))
}

// ────────────────────────────── HTTP/1.1 ─────────────────────────────────

pub struct H1Client {
    conn: Conn,
    request: Vec<u8>,
}

impl H1Client {
    pub fn connect(host: &str, path: &str, authority: &str, tls: bool) -> std::io::Result<Self> {
        let conn = dial_opt(host, tls, "h1", "")?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\nUser-Agent: wave-loadgen\r\n\r\n"
        )
        .into_bytes();
        Ok(H1Client { conn, request })
    }
}

impl LoadClient for H1Client {
    fn protocol(&self) -> &'static str {
        "http/1.1"
    }

    fn round_trip(&mut self) -> Outcome {
        if self
            .conn
            .write_all(&self.request)
            .and_then(|()| self.conn.flush())
            .is_err()
        {
            return Outcome::Failed;
        }
        // Status line.
        let mut line = String::new();
        match self.conn.read_line(&mut line) {
            Ok(0) | Err(_) => return Outcome::Failed,
            Ok(_) => {}
        }
        let status: u16 = match line.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
            Some(s) => s,
            None => return Outcome::Failed,
        };
        // Headers — we need content-length / chunked to consume the body, or the
        // next request's response would be read out of a desynced stream.
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        loop {
            let mut h = String::new();
            match self.conn.read_line(&mut h) {
                Ok(0) | Err(_) => return Outcome::Failed,
                Ok(_) => {}
            }
            let t = h.trim_end();
            if t.is_empty() {
                break;
            }
            let lower = t.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().ok();
            } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
        }
        if chunked {
            if read_chunked(&mut self.conn).is_err() {
                return Outcome::Failed;
            }
        } else if let Some(n) = content_length {
            let mut body = vec![0u8; n];
            if self.conn.read_exact(&mut body).is_err() {
                return Outcome::Failed;
            }
        }
        if (200..300).contains(&status) {
            Outcome::Ok
        } else {
            Outcome::Rejected
        }
    }
}

fn read_chunked(r: &mut Conn) -> std::io::Result<()> {
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Err(eof());
        }
        let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|_| eof())?;
        let mut buf = vec![0u8; n + 2]; // chunk + CRLF
        r.read_exact(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
    }
}

// ──────────────────────────── HTTP/2 (h2c) ───────────────────────────────

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_ACK: u8 = 0x1;

pub struct H2Client {
    conn: Conn,
    next_stream: u32,
    path: String,
    authority: String,
    /// gRPC mode: `application/grpc` + `te: trailers` + a length-prefixed body.
    grpc: bool,
    grpc_body: Vec<u8>,
    /// Bytes received since the last connection-level WINDOW_UPDATE.
    unacked: u32,
}

impl H2Client {
    pub fn connect(
        host: &str,
        path: &str,
        authority: &str,
        grpc: bool,
        tls: bool,
    ) -> std::io::Result<Self> {
        let mut conn = dial_opt(host, tls, if grpc { "grpc" } else { "h2" }, "")?;
        conn.write_all(PREFACE)?;
        write_frame(&mut conn, FRAME_SETTINGS, 0, 0, &[])?;
        conn.flush()?;
        // Drain until the server's SETTINGS arrives, then ACK it.
        loop {
            let (ty, flags, _sid, payload) = read_frame(&mut conn)?;
            if ty == FRAME_SETTINGS && flags & FLAG_ACK == 0 {
                write_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                conn.flush()?;
                break;
            }
            if ty == FRAME_GOAWAY {
                return Err(eof());
            }
            let _ = payload;
        }
        // gRPC Length-Prefixed Message: [compressed:0][len:4 BE][protobuf].
        // Field 1, wire type 2, "hi" — the grpcbin DummyUnary echo payload.
        let msg: &[u8] = &[0x0a, 0x02, b'h', b'i'];
        let mut grpc_body = vec![0u8];
        grpc_body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        grpc_body.extend_from_slice(msg);

        Ok(H2Client {
            conn,
            next_stream: 1,
            path: path.to_string(),
            authority: authority.to_string(),
            grpc,
            grpc_body,
            unacked: 0,
        })
    }

    fn build_headers(&self, sid: u32) -> Vec<u8> {
        let mut hb = Vec::with_capacity(128);
        hpack_header(
            &mut hb,
            b":method",
            if self.grpc { b"POST" } else { b"GET" },
        );
        hpack_header(&mut hb, b":scheme", b"http");
        hpack_header(&mut hb, b":path", self.path.as_bytes());
        hpack_header(&mut hb, b":authority", self.authority.as_bytes());
        if self.grpc {
            hpack_header(&mut hb, b"content-type", b"application/grpc");
            hpack_header(&mut hb, b"te", b"trailers");
        }
        hpack_header(&mut hb, b"user-agent", b"wave-loadgen");
        let _ = sid;
        hb
    }
}

impl LoadClient for H2Client {
    fn protocol(&self) -> &'static str {
        if self.grpc {
            "grpc/h2c"
        } else {
            "h2c"
        }
    }

    fn round_trip(&mut self) -> Outcome {
        let sid = self.next_stream;
        self.next_stream += 2;

        let hb = self.build_headers(sid);
        // gRPC sends a body, so HEADERS does not end the stream.
        let hflags = if self.grpc {
            FLAG_END_HEADERS
        } else {
            FLAG_END_HEADERS | FLAG_END_STREAM
        };
        if write_frame(&mut self.conn, FRAME_HEADERS, hflags, sid, &hb).is_err() {
            return Outcome::Failed;
        }
        if self.grpc {
            let body = self.grpc_body.clone();
            if write_frame(&mut self.conn, FRAME_DATA, FLAG_END_STREAM, sid, &body).is_err() {
                return Outcome::Failed;
            }
        }
        if self.conn.flush().is_err() {
            return Outcome::Failed;
        }

        let mut status: Option<u16> = None;
        let mut grpc_status: Option<i32> = None;
        loop {
            let (ty, flags, fsid, payload) = match read_frame(&mut self.conn) {
                Ok(f) => f,
                Err(_) => return Outcome::Failed,
            };
            match ty {
                FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                    if write_frame(&mut self.conn, FRAME_SETTINGS, FLAG_ACK, 0, &[]).is_err() {
                        return Outcome::Failed;
                    }
                    let _ = self.conn.flush();
                }
                FRAME_PING if flags & FLAG_ACK == 0 => {
                    // §6.7: a PING must be answered or the peer may drop us.
                    if write_frame(&mut self.conn, FRAME_PING, FLAG_ACK, 0, &payload).is_err() {
                        return Outcome::Failed;
                    }
                    let _ = self.conn.flush();
                }
                FRAME_GOAWAY => return Outcome::Failed,
                FRAME_RST_STREAM if fsid == sid => return Outcome::Rejected,
                FRAME_HEADERS if fsid == sid => {
                    if status.is_none() {
                        status = hpack_status(&payload);
                    }
                    // A trailing HEADERS in gRPC mode carries grpc-status.
                    if self.grpc {
                        if let Some(gs) = grpc_trailer_status(&payload) {
                            grpc_status = Some(gs);
                        }
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                FRAME_DATA if fsid == sid => {
                    self.unacked += payload.len() as u32;
                    if self.unacked >= 32_768 {
                        let inc = self.unacked.to_be_bytes();
                        let _ = write_frame(&mut self.conn, FRAME_WINDOW_UPDATE, 0, 0, &inc);
                        let _ = write_frame(&mut self.conn, FRAME_WINDOW_UPDATE, 0, sid, &inc);
                        let _ = self.conn.flush();
                        self.unacked = 0;
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                _ => {}
            }
        }

        if self.grpc {
            // The definitive gRPC outcome is `grpc-status`, and its ABSENCE is
            // a failure, not an implied 0.
            //
            // This previously read `grpc_status.unwrap_or(0)`, treating a
            // missing trailer as OK. That makes the check unable to tell "the
            // server spoke gRPC and succeeded" from "the server ignored gRPC
            // entirely" — and the second case is exactly what a load generator
            // meets when pointed at a route that isn't gRPC. Measured
            // 2026-07-29 against the rig, whose only route returns static
            // HTML: 1504/1504 reported OK, a pure false positive. An oracle
            // must not report success it did not verify.
            return match grpc_status {
                Some(0) => Outcome::Ok,
                Some(_) => Outcome::Rejected,
                None => Outcome::Rejected,
            };
        }
        match status {
            Some(s) if (200..300).contains(&s) => Outcome::Ok,
            Some(_) => Outcome::Rejected,
            // Stream completed cleanly but the status used an encoding we skip
            // (e.g. Huffman). Completion is the signal; do not fail the DUT.
            None => Outcome::Ok,
        }
    }
}

/// Find `grpc-status` in a trailing header block. Same skip-Huffman posture as
/// [`hpack_status`].
fn grpc_trailer_status(block: &[u8]) -> Option<i32> {
    let mut i = 0;
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            i += 1;
            continue;
        }
        let nbits = if b & 0xc0 == 0x40 { 6 } else { 4 };
        let mask = (1u8 << nbits) - 1;
        let name_idx = b & mask;
        i += 1;
        let mut is_gs = false;
        if name_idx == 0 {
            let (name, next) = read_hpack_str(block, i)?;
            is_gs = name.as_deref() == Some(b"grpc-status".as_ref());
            i = next;
        }
        let (value, next) = read_hpack_str(block, i)?;
        i = next;
        if is_gs {
            let v = value?;
            return std::str::from_utf8(&v).ok()?.trim().parse().ok();
        }
    }
    None
}

fn write_frame(w: &mut Conn, ty: u8, flags: u8, sid: u32, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len();
    let hdr = [
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        ty,
        flags,
        (sid >> 24) as u8,
        (sid >> 16) as u8,
        (sid >> 8) as u8,
        sid as u8,
    ];
    w.write_all(&hdr)?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    Ok(())
}

fn read_frame(r: &mut Conn) -> std::io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    r.read_exact(&mut hdr)?;
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
    if len > 1 << 20 {
        return Err(eof());
    }
    let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((hdr[3], hdr[4], sid, payload))
}

// ────────────────────────── WebSocket (RFC 6455) ─────────────────────────

pub struct WsClient {
    conn: Conn,
    payload: Vec<u8>,
    mask_seed: u64,
}

impl WsClient {
    pub fn connect(
        host: &str,
        path: &str,
        authority: &str,
        payload_size: usize,
        shard: u64,
        tls: bool,
    ) -> std::io::Result<Self> {
        let mut conn = dial_opt(host, tls, "ws", "")?;

        // A per-shard nonce. Not cryptographic — RFC 6455 requires only that it
        // be unpredictable enough to defeat caching intermediaries.
        let seed = shard
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(std::process::id() as u64);
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (seed >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(31);
        }
        let key = b64_encode(&nonce);

        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        conn.write_all(req.as_bytes())?;
        conn.flush()?;

        // Verify the accept proof before trusting the switch.
        let mut expect_src = key.into_bytes();
        expect_src.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let expected = b64_encode(&sha1(&expect_src));

        let mut status = String::new();
        conn.read_line(&mut status)?;
        if !status.contains(" 101") {
            return Err(eof());
        }
        let mut accept_ok = false;
        loop {
            let mut h = String::new();
            if conn.read_line(&mut h)? == 0 {
                return Err(eof());
            }
            let t = h.trim_end();
            if t.is_empty() {
                break;
            }
            // Case-fold the NAME only. The accept proof is Base64 and
            // case-significant — lowercasing the whole line silently breaks
            // every comparison.
            if let Some((name, value)) = t.split_once(':') {
                if name.trim().eq_ignore_ascii_case("sec-websocket-accept") {
                    accept_ok = value.trim() == expected;
                }
            }
        }
        if !accept_ok {
            return Err(eof());
        }

        Ok(WsClient {
            conn,
            payload: vec![b'w'; payload_size],
            mask_seed: seed,
        })
    }
}

impl LoadClient for WsClient {
    fn protocol(&self) -> &'static str {
        "websocket"
    }

    fn round_trip(&mut self) -> Outcome {
        self.mask_seed = self
            .mask_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let mask = (self.mask_seed >> 16).to_le_bytes();
        let mask = [mask[0], mask[1], mask[2], mask[3]];

        let mut frame = Vec::with_capacity(self.payload.len() + 14);
        frame.push(0x80 | 0x2); // FIN + BINARY
        let n = self.payload.len();
        if n < 126 {
            frame.push(0x80 | n as u8);
        } else if n < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, b) in self.payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }

        if self
            .conn
            .write_all(&frame)
            .and_then(|()| self.conn.flush())
            .is_err()
        {
            return Outcome::Failed;
        }

        // Read frames until the echo comes back; answer PING, honour CLOSE.
        loop {
            let mut h2 = [0u8; 2];
            if self.conn.read_exact(&mut h2).is_err() {
                return Outcome::Failed;
            }
            let opcode = h2[0] & 0x0f;
            let masked = h2[1] & 0x80 != 0;
            let mut len = (h2[1] & 0x7f) as usize;
            if len == 126 {
                let mut e = [0u8; 2];
                if self.conn.read_exact(&mut e).is_err() {
                    return Outcome::Failed;
                }
                len = u16::from_be_bytes(e) as usize;
            } else if len == 127 {
                let mut e = [0u8; 8];
                if self.conn.read_exact(&mut e).is_err() {
                    return Outcome::Failed;
                }
                len = u64::from_be_bytes(e) as usize;
            }
            if masked {
                let mut mk = [0u8; 4];
                if self.conn.read_exact(&mut mk).is_err() {
                    return Outcome::Failed;
                }
            }
            if len > 1 << 22 {
                return Outcome::Failed;
            }
            let mut body = vec![0u8; len];
            if self.conn.read_exact(&mut body).is_err() {
                return Outcome::Failed;
            }
            match opcode {
                0x1 | 0x2 => return Outcome::Ok, // echoed text/binary
                0x8 => return Outcome::Rejected, // peer closed
                0x9 => {
                    // PONG the payload back, masked.
                    let mut p = Vec::with_capacity(body.len() + 6);
                    p.push(0x80 | 0xA);
                    p.push(0x80 | body.len() as u8);
                    p.extend_from_slice(&mask);
                    for (i, b) in body.iter().enumerate() {
                        p.push(b ^ mask[i % 4]);
                    }
                    if self
                        .conn
                        .write_all(&p)
                        .and_then(|()| self.conn.flush())
                        .is_err()
                    {
                        return Outcome::Failed;
                    }
                }
                _ => {} // PONG or continuation — keep reading
            }
        }
    }
}

// ────────────────────────────── plumbing ─────────────────────────────────

/// Byte transport under every protocol client: plaintext or TLS 1.2/1.3.
///
/// TLS is a single session object, so the previous `(writer, BufReader<reader>)`
/// pair built from `TcpStream::try_clone` cannot work — two handles would each
/// need the same record-layer state. Hence one `Conn` carrying one transport,
/// with buffered reads and unbuffered writes through the same object.
///
/// On the dependency boundary: `rustls` is a third-party TLS stack, not a
/// re-implementation of anything in Wave. It therefore does NOT weaken the
/// oracle-independence rule this crate exists to uphold (see Cargo.toml) — the
/// HTTP/1.1, HPACK, h2-frame, WebSocket and gRPC codecs in this file remain
/// wave-bench's own, and those are what the DUT's parsers are tested against.
/// TLS is transport, and a shared TLS bug would surface as a handshake failure,
/// not as a silently-cancelling codec defect.
pub enum Transport {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// A buffered connection. Implements `Read`/`BufRead` for the protocol parsers
/// and forwards `write_all`/`flush` to the underlying transport, so a client
/// needs one field instead of a reader/writer pair.
pub struct Conn {
    io: BufReader<Transport>,
}

impl Conn {
    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.io.get_mut().write_all(buf)
    }
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.io.get_mut().flush()
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.io.read(buf)
    }
}

impl std::io::BufRead for Conn {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.io.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        self.io.consume(amt);
    }
}

/// Accept any server certificate. This is a load generator pointed at a test
/// fixture whose self-signed cert is part of the setup; it authenticates
/// nothing and must never be reused as a client library.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// ALPN protocol to offer, by wave-bench protocol name. The DUT's `http`
/// server switches to h2 by sniffing the connection preface rather than by
/// reading ALPN, but offering it keeps the handshake honest and lets the same
/// client work against servers that do require it.
fn alpn_for(protocol: &str) -> Vec<Vec<u8>> {
    match protocol {
        "h2" | "grpc" => vec![b"h2".to_vec()],
        _ => vec![b"http/1.1".to_vec()],
    }
}

/// Open a connection, optionally wrapping it in TLS.
pub fn dial_opt(host: &str, tls: bool, protocol: &str, sni: &str) -> std::io::Result<Conn> {
    let stream = TcpStream::connect(host)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    if !tls {
        return Ok(Conn {
            io: BufReader::new(Transport::Plain(stream)),
        });
    }
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn_for(protocol);
    // SNI must be a DNS name; the rig target is a bare IP, so fall back to a
    // fixed placeholder the fixture cert does not need to match (verification
    // is disabled above).
    let name = if sni.is_empty() {
        "wave-bench.invalid"
    } else {
        sni
    };
    let server_name = rustls::pki_types::ServerName::try_from(name.to_string())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "server_name"))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), server_name)
        .map_err(std::io::Error::other)?;
    Ok(Conn {
        io: BufReader::new(Transport::Tls(Box::new(rustls::StreamOwned::new(
            conn, stream,
        )))),
    })
}

fn eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "protocol")
}
