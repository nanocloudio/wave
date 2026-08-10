//! Response-head staging.
//!
//! One job: put the status line and headers for the current slot into its
//! `send_buf` and set `send_offset`/`send_len` so the send phase can drain it.
//! The wire format itself is `super::super::wire::h1` — these are the SERVER's
//! choices of which head to emit, and the keep-alive consequence of each.
//!
//! That consequence is the reason they are one file. `build_header` is
//! close-delimited: no Content-Length, so the body's end IS the connection's
//! end, and it clears `keepalive`. Every other builder here is self-delimited
//! and preserves it. Choosing the wrong one silently converts a keep-alive
//! connection into a one-shot, which is invisible in a single-request test.

use super::super::wire::h1;
use super::{cur_send_buf_mut_ptr, cur_slot, cur_slot_mut, HttpState, SEND_BUF_SIZE};

// ── Byte helpers ──────────────────────────────────────────────────────────
//
// Bounded append into a raw `[dst, dst+cap)`: each returns the new offset and
// writes nothing once the offset reaches `cap`, so a truncating head comes out
// short rather than overrunning the buffer.

/// Append a decimal u32 at `off` in `dst`, returning the new offset.
///
/// Helper for the Content-Range / Content-Length writers below.
pub(crate) unsafe fn put_u32_decimal(
    dst: *mut u8,
    dst_cap: usize,
    mut off: usize,
    mut v: u32,
) -> usize {
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    if v == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    while n > 0 {
        n -= 1;
        if off < dst_cap {
            *dst.add(off) = digits[n];
            off += 1;
        }
    }
    off
}

pub(crate) unsafe fn put_bytes(dst: *mut u8, dst_cap: usize, mut off: usize, src: &[u8]) -> usize {
    let mut k = 0usize;
    while k < src.len() && off < dst_cap {
        *dst.add(off) = src[k];
        off += 1;
        k += 1;
    }
    off
}

/// Append a dotted-quad IPv4 (`a.b.c.d`) for a big-endian-packed u32.
pub(crate) unsafe fn put_ipv4_decimal(dst: *mut u8, cap: usize, mut off: usize, ip: u32) -> usize {
    let o = ip.to_be_bytes();
    off = put_u32_decimal(dst, cap, off, o[0] as u32);
    off = put_bytes(dst, cap, off, b".");
    off = put_u32_decimal(dst, cap, off, o[1] as u32);
    off = put_bytes(dst, cap, off, b".");
    off = put_u32_decimal(dst, cap, off, o[2] as u32);
    off = put_bytes(dst, cap, off, b".");
    off = put_u32_decimal(dst, cap, off, o[3] as u32);
    off
}

// ── Header builders ───────────────────────────────────────────────────────

/// Close-delimited response header (no Content-Length). Forces
/// `Connection: close` and clears the slot's keepalive flag. For
/// self-delimited responses use `build_header_with_len` /
/// `build_header_fs_full` / `build_header_fs_partial` so keep-alive
/// is preserved.
pub(crate) unsafe fn build_header(s: &mut HttpState, status: &[u8], content_type: &[u8]) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    let len = h1::write_status_line(
        cur_send_buf_mut_ptr(s),
        SEND_BUF_SIZE,
        status,
        content_type,
        false,
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = len as u16;
    }
}

/// Like `build_header` but also emits a `Content-Length: <n>` header.
/// Used for responses whose body length is known up-front (e.g. the
/// FS_CONTRACT path queries `FS_STAT` for the file size before
/// streaming).
pub(crate) unsafe fn build_header_with_len(
    s: &mut HttpState,
    status: &[u8],
    content_type: &[u8],
    content_length: u32,
) {
    // Write the standard status line (which terminates with \r\n\r\n)
    // then strip the trailing blank line, append the Content-Length
    // header, and re-terminate.
    let keepalive = cur_slot(s).map(|c| c.keepalive != 0).unwrap_or(false);
    let mut off = h1::write_status_line(
        cur_send_buf_mut_ptr(s),
        SEND_BUF_SIZE,
        status,
        content_type,
        keepalive,
    );
    if off >= 4 {
        off -= 4;
    }
    let dst = cur_send_buf_mut_ptr(s);
    let prefix: &[u8] = b"\r\nContent-Length: ";
    let mut k = 0usize;
    while k < prefix.len() && off < SEND_BUF_SIZE {
        *dst.add(off) = prefix[k];
        off += 1;
        k += 1;
    }
    // Decimal Content-Length value (max 10 digits for u32).
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    let mut v = content_length;
    if v == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    while n > 0 {
        n -= 1;
        if off < SEND_BUF_SIZE {
            *dst.add(off) = digits[n];
            off += 1;
        }
    }
    let suffix: &[u8] = b"\r\n\r\n";
    let mut k = 0usize;
    while k < suffix.len() && off < SEND_BUF_SIZE {
        *dst.add(off) = suffix[k];
        off += 1;
        k += 1;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = off as u16;
    }
}

pub(crate) unsafe fn build_error(s: &mut HttpState, code: &[u8], body: &[u8]) {
    // Error responses are close-delimited — keep wire + slot in sync.
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    let len = h1::write_error_response(cur_send_buf_mut_ptr(s), SEND_BUF_SIZE, code, body);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = len as u16;
    }
}

/// Like `build_header_with_len` but also emits `Accept-Ranges: bytes` so
/// clients (browser media elements, iOS players, curl) know they can seek. Used
/// by `HANDLER_FS_FILE` on the no-Range happy path.
pub(crate) unsafe fn build_header_fs_full(
    s: &mut HttpState,
    status: &[u8],
    content_type: &[u8],
    content_length: u32,
) {
    let cap = SEND_BUF_SIZE;
    let keepalive = cur_slot(s).map(|c| c.keepalive != 0).unwrap_or(false);
    let dst = cur_send_buf_mut_ptr(s);
    let mut off = h1::write_status_line(dst, cap, status, content_type, keepalive);
    if off >= 4 {
        off -= 4; // strip the trailing \r\n\r\n; we'll re-add it.
    }
    off = put_bytes(
        dst,
        cap,
        off,
        b"\r\nAccept-Ranges: bytes\r\nContent-Length: ",
    );
    off = put_u32_decimal(dst, cap, off, content_length);
    off = put_bytes(dst, cap, off, b"\r\n\r\n");
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}

/// Compose a 206 Partial Content head: status line + Content-Type +
/// Accept-Ranges + Content-Range + Content-Length, terminated by the
/// blank line. `start`/`end` are inclusive byte offsets into the file;
/// `total` is the full file size.
pub(crate) unsafe fn build_header_fs_partial(
    s: &mut HttpState,
    content_type: &[u8],
    start: u32,
    end: u32,
    total: u32,
) {
    let cap = SEND_BUF_SIZE;
    let keepalive = cur_slot(s).map(|c| c.keepalive != 0).unwrap_or(false);
    let dst = cur_send_buf_mut_ptr(s);
    let mut off = h1::write_status_line(dst, cap, b"206 Partial Content", content_type, keepalive);
    if off >= 4 {
        off -= 4;
    }
    off = put_bytes(
        dst,
        cap,
        off,
        b"\r\nAccept-Ranges: bytes\r\nContent-Range: bytes ",
    );
    off = put_u32_decimal(dst, cap, off, start);
    off = put_bytes(dst, cap, off, b"-");
    off = put_u32_decimal(dst, cap, off, end);
    off = put_bytes(dst, cap, off, b"/");
    off = put_u32_decimal(dst, cap, off, total);
    off = put_bytes(dst, cap, off, b"\r\nContent-Length: ");
    off = put_u32_decimal(dst, cap, off, end - start + 1);
    off = put_bytes(dst, cap, off, b"\r\n\r\n");
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}

/// 416 Range Not Satisfiable response: status line + `Content-Range:
/// bytes */<total>` so the client learns the resource length.
pub(crate) unsafe fn build_error_416(s: &mut HttpState, total: u32) {
    // Close-delimited error — keep wire + slot in sync.
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    let cap = SEND_BUF_SIZE;
    let dst = cur_send_buf_mut_ptr(s);
    let mut off = put_bytes(
        dst,
        cap,
        0,
        b"HTTP/1.1 416 Range Not Satisfiable\r\nConnection: close\r\nContent-Range: bytes */",
    );
    off = put_u32_decimal(dst, cap, off, total);
    off = put_bytes(
        dst,
        cap,
        off,
        b"\r\nContent-Length: 22\r\n\r\nRange Not Satisfiable\n",
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}
