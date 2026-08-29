//! HTTP/1.1 client — the request/response state machine.
//!
//! `step` is one loop over `Phase`, and is the whole file. It drives a single
//! connection: connect, send the request, parse the status line and headers,
//! stream the body out to the module's data port, close.
//!
//! Symmetric with `super::super::server::h1`: the connection lifecycle lives
//! with the generation whose model it is, and `super::h2` is the other front end
//! onto the same `ClientState`. There is no `h3.rs` — Fluxor's `quic` owns the
//! h3 client (`docs/architecture/http3-ownership.md`), and that absence is
//! deliberate rather than pending.

use super::super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_CLOSE, NET_CMD_CONNECT, NET_CMD_SEND, NET_MSG_CLOSED,
    NET_MSG_CONNECTED, NET_MSG_DATA, NET_MSG_ERROR,
};
use super::super::wire::h1;
use super::super::{
    dev_channel_port, dev_log, dev_millis, dev_requester_tag, net_read_frame,
    net_read_frame_aligned, net_write_frame, NET_FRAME_HDR, POLL_IN, POLL_OUT, SOCK_TYPE_STREAM,
};
use super::{
    build_request, is_foreign_frame, log, send_close_frame, HttpState, Phase, CONNECT_TIMEOUT_MS,
    E_AGAIN, E_CONNECT_FAILED, E_NET_FAILED, E_SEND_FAILED, E_WRITE_FAILED, RECV_BUF_SIZE,
};

pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    loop {
        match s.client.phase {
            Phase::Init => {
                log(s, b"[http] connecting");
                s.client.phase = Phase::Connecting;
                continue;
            }

            Phase::Connecting => {
                if s.net_out_chan < 0 {
                    s.client.phase = Phase::Error;
                    return E_NET_FAILED;
                }
                let sys = &*s.syscalls;
                let chan = s.net_out_chan;
                let buf = s.net_buf.as_mut_ptr();
                // CMD_CONNECT payload: [sock_type][ip:4][port:2][requester_tag].
                // The tag (our module index) is echoed in MSG_CONNECTED so that
                // when ip.net_out is fanned to another stream consumer (e.g. an
                // OTLP exporter) we claim only our own outbound connection.
                let mut payload = [0u8; 8];
                payload[0] = SOCK_TYPE_STREAM;
                let ip_bytes = s.client.host_ip.to_le_bytes();
                payload[1] = ip_bytes[0];
                payload[2] = ip_bytes[1];
                payload[3] = ip_bytes[2];
                payload[4] = ip_bytes[3];
                payload[5] = (s.client.port & 0xFF) as u8;
                payload[6] = (s.client.port >> 8) as u8;
                payload[7] = dev_requester_tag(sys);
                let wrote = net_write_frame(
                    sys,
                    chan,
                    NET_CMD_CONNECT,
                    payload.as_ptr(),
                    8,
                    buf,
                    NET_BUF_SIZE,
                );
                if wrote == 0 {
                    return 0;
                }
                s.client.connect_start_ms = dev_millis(sys);
                s.client.phase = Phase::WaitConnect;
                return 0;
            }

            Phase::WaitConnect => {
                if s.net_in_chan < 0 {
                    return 0;
                }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                    let buf = s.net_buf.as_mut_ptr();
                    let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
                    if msg_type == NET_MSG_CONNECTED && payload_len >= 2 {
                        // Claim only our own outbound connection: MSG_CONNECTED
                        // is `[conn_id][requester_tag]`; the tag echoes our
                        // CMD_CONNECT index. Untagged (legacy/sole-consumer) or
                        // our tag → ours; any other tag belongs to a co-wired
                        // consumer sharing this fanned queue, so ignore it.
                        let (_, tag) = net_proto::connected_parts(core::slice::from_raw_parts(
                            buf.add(NET_FRAME_HDR),
                            payload_len,
                        ));
                        let me = dev_requester_tag(sys);
                        if tag != 0 && tag != me {
                            return 0; // another consumer's connection — keep waiting.
                        }
                        s.client.conn_id = net_proto::conn_id(core::slice::from_raw_parts(
                            buf.add(NET_FRAME_HDR),
                            payload_len,
                        ));
                        s.client.conn_present = 1;
                        log(s, b"[http] connected");
                        if !build_request(s) {
                            // The head does not fit or names no verb. Failing
                            // here, before a byte goes out, is what keeps a
                            // half-composed request off the wire.
                            log(s, b"[http] request too long");
                            s.client.phase = Phase::Error;
                            return E_SEND_FAILED;
                        }
                        s.client.phase = Phase::SendRequest;
                        continue;
                    } else if msg_type == NET_MSG_ERROR {
                        // Connect failure carries our tag at payload[3]
                        // ([conn_id][errno][tag]); ignore another consumer's.
                        let etag = if payload_len >= 3 {
                            net_proto::error_parts(core::slice::from_raw_parts(
                                buf.add(NET_FRAME_HDR),
                                payload_len,
                            ))
                            .2
                        } else {
                            net_proto::REQUESTER_TAG_NONE
                        };
                        if etag == 0 || etag == dev_requester_tag(sys) {
                            log(s, b"[http] connect error");
                            s.client.phase = Phase::Error;
                            return E_CONNECT_FAILED;
                        }
                    }
                }
                if dev_millis(sys).wrapping_sub(s.client.connect_start_ms) >= CONNECT_TIMEOUT_MS {
                    log(s, b"[http] connect timeout");
                    s.client.phase = Phase::Error;
                    return E_CONNECT_FAILED;
                }
                return 0;
            }

            Phase::SendRequest => {
                if s.net_out_chan < 0 {
                    return E_SEND_FAILED;
                }
                let sys = &*s.syscalls;
                let out_chan = s.net_out_chan;
                let conn_id = s.client.conn_id;
                // Head first, then the body. Two buffers, one drain loop:
                // `Content-Length` was declared in the head, so the body is
                // just the bytes that follow it on the same connection.
                let head_left = (s.client.request_len - s.client.request_sent) as usize;
                let (data_ptr, remaining) = if head_left > 0 {
                    (
                        s.client
                            .request_buf
                            .as_ptr()
                            .add(s.client.request_sent as usize),
                        head_left,
                    )
                } else {
                    (
                        s.client
                            .request_body
                            .as_ptr()
                            .add(s.client.request_body_sent as usize),
                        (s.client.request_body_len - s.client.request_body_sent) as usize,
                    )
                };

                let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 2;
                let to_send = remaining.min(max_data);
                let scratch = s.net_buf.as_mut_ptr();
                let payload_len = 2 + to_send;
                let mut cb = [0u8; 2];
                net_proto::put_conn_id(&mut cb, conn_id);
                *scratch = NET_CMD_SEND;
                *scratch.add(1) = (payload_len & 0xFF) as u8;
                *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
                *scratch.add(3) = cb[0];
                *scratch.add(4) = cb[1];
                core::ptr::copy_nonoverlapping(data_ptr, scratch.add(5), to_send);
                let total = NET_FRAME_HDR + payload_len;
                let written = (sys.channel_write)(out_chan, scratch, total);

                if written < total as i32 {
                    return 0;
                }

                if head_left > 0 {
                    s.client.request_sent += to_send as u16;
                } else {
                    s.client.request_body_sent += to_send as u16;
                }
                if s.client.request_sent >= s.client.request_len
                    && s.client.request_body_sent >= s.client.request_body_len
                {
                    log(s, b"[http] request sent");
                    s.client.headers_done = 0;
                    s.client.recv_len = 0;
                    s.client.phase = Phase::RecvHeaders;
                }
                return 0;
            }

            Phase::RecvHeaders => {
                if s.net_in_chan < 0 {
                    return 0;
                }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                    return 0;
                }

                let nbuf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len, _full) =
                    net_read_frame_aligned(sys, chan, nbuf, NET_BUF_SIZE);

                // Established-stream isolation: ip.net_out may be fanned to other
                // stream consumers (e.g. an OTLP exporter); ignore any DATA/CLOSED
                // /ERROR frame that isn't for our own connection.
                if is_foreign_frame(s, msg_type, payload_len, nbuf) {
                    return 0;
                }

                if msg_type == NET_MSG_CLOSED {
                    log(s, b"[http] premature close");
                    s.client.phase = Phase::Done;
                    // Emitted HERE, not in the `Phase::Done` arm: this path
                    // returns straight to the caller and never falls through
                    // to it, so a hook there answers nothing.
                    #[cfg(feature = "exchange")]
                    super::exchange::complete(s);
                    return 1;
                }

                if msg_type == NET_MSG_DATA && payload_len > 1 {
                    let data_ptr = nbuf.add(NET_FRAME_HDR + 2) as *const u8;
                    let data_len = payload_len - 2;

                    let cur = s.client.recv_len as usize;
                    let space = RECV_BUF_SIZE - cur;
                    let to_copy = data_len.min(space);
                    if to_copy > 0 {
                        core::ptr::copy_nonoverlapping(
                            data_ptr,
                            s.client.recv_buf.as_mut_ptr().add(cur),
                            to_copy,
                        );
                        s.client.recv_len += to_copy as u16;
                    }

                    if let Some(body_start) =
                        h1::find_header_end(&s.client.recv_buf, s.client.recv_len as usize)
                    {
                        let body_len = (s.client.recv_len as usize) - body_start;
                        if body_len > 0 {
                            let buf_ptr = s.client.recv_buf.as_mut_ptr();
                            let mut i = 0;
                            while i < body_len {
                                *buf_ptr.add(i) = *buf_ptr.add(body_start + i);
                                i += 1;
                            }
                            s.client.recv_len = body_len as u16;
                            s.client.pending_offset = 0;
                            s.client.phase = Phase::Writing;
                        } else {
                            s.client.recv_len = 0;
                            s.client.phase = Phase::RecvBody;
                        }
                        log(s, b"[http] headers done");
                        continue;
                    }
                }

                return 0;
            }

            Phase::RecvBody => {
                let sys = &*s.syscalls;
                if s.client.out_chan >= 0 {
                    let poll = (sys.channel_poll)(s.client.out_chan, POLL_OUT);
                    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
                        return 0;
                    }
                }

                if s.net_in_chan < 0 {
                    return 0;
                }
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                    return 0;
                }

                let nbuf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len, _full) =
                    net_read_frame_aligned(sys, chan, nbuf, NET_BUF_SIZE);

                if is_foreign_frame(s, msg_type, payload_len, nbuf) {
                    return 0;
                }

                if msg_type == NET_MSG_CLOSED {
                    log(s, b"[http] transfer done");
                    s.client.phase = Phase::Done;
                    // Emitted HERE, not in the `Phase::Done` arm: this path
                    // returns straight to the caller and never falls through
                    // to it, so a hook there answers nothing.
                    #[cfg(feature = "exchange")]
                    super::exchange::complete(s);
                    return 1;
                }

                if msg_type == NET_MSG_DATA && payload_len > 1 {
                    let data_ptr = nbuf.add(NET_FRAME_HDR + 2) as *const u8;
                    let data_len = payload_len - 2;

                    let to_copy = data_len.min(RECV_BUF_SIZE);
                    core::ptr::copy_nonoverlapping(
                        data_ptr,
                        s.client.recv_buf.as_mut_ptr(),
                        to_copy,
                    );
                    s.client.recv_len = to_copy as u16;
                    s.client.pending_offset = 0;
                    s.client.bytes_received += to_copy as u32;
                    s.client.phase = Phase::Writing;
                    continue;
                }

                return 0;
            }

            Phase::Writing => {
                // Graph-driven: a reply is ONE frame, so the body is
                // accumulated here rather than streamed to `file_ctrl`.
                #[cfg(feature = "exchange")]
                if super::exchange::busy(s) {
                    let off = s.client.pending_offset as usize;
                    let end = (s.client.recv_len as usize).max(off);
                    let src = s.client.recv_buf.as_ptr().add(off);
                    super::exchange::accumulate(s, src, end - off);
                    s.client.pending_offset = s.client.recv_len;
                    s.client.phase = Phase::RecvBody;
                    return 0;
                }

                if s.client.out_chan < 0 {
                    s.client.phase = Phase::RecvBody;
                    continue;
                }

                let sys = &*s.syscalls;
                let out_chan = s.client.out_chan;
                let offset = s.client.pending_offset as usize;
                let remaining = (s.client.recv_len as usize) - offset;

                let written = (sys.channel_write)(
                    out_chan,
                    s.client.recv_buf.as_ptr().add(offset),
                    remaining,
                );

                if written < 0 {
                    if written == E_AGAIN {
                        return 0;
                    }
                    log(s, b"[http] write failed");
                    s.client.phase = Phase::Error;
                    return E_WRITE_FAILED;
                }

                s.client.pending_offset += written as u16;
                if s.client.pending_offset >= s.client.recv_len {
                    s.client.phase = Phase::RecvBody;
                }
                return 0;
            }

            Phase::Done => {
                let _ = send_close_frame(s);
                // Answer the request that produced this response, then go
                // idle so the next one on `publish_in` can be taken.
                #[cfg(feature = "exchange")]
                super::exchange::complete(s);
                return 1;
            }

            Phase::Error => {
                let _ = send_close_frame(s);
                // A failed exchange is still an answer: the contract admits
                // no silent drops, so the producer gets a typed refusal
                // rather than waiting out its own timeout.
                #[cfg(feature = "exchange")]
                super::exchange::fail(s);
                return -1;
            }

            _ => return -1,
        }
    }
}
