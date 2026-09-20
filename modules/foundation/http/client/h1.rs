//! HTTP/1.1 client — the request/response state machine.
//!
//! `step` is one loop over `Phase`, and is the whole file. It drives a single
//! connection: connect, send the request, parse the status line and headers,
//! stream the body out to the module's data port, close.
//!

use super::super::connection::{
    net_proto, NET_BUF_SIZE, NET_CMD_CLOSE, NET_CMD_SEND, NET_MSG_CLOSED, NET_MSG_CONNECTED,
    NET_MSG_DATA, NET_MSG_ERROR,
};
use super::super::wire::h1;
use super::super::{
    dev_channel_port, dev_log, dev_millis, dev_requester_tag, net_read_frame,
    net_read_frame_aligned, net_write_frame, NET_FRAME_HDR, POLL_IN, POLL_OUT,
};
use super::{
    build_request, is_foreign_frame, log, send_close_frame, HttpState, Phase, CONNECT_TIMEOUT_MS,
    E_AGAIN, E_CONNECT_FAILED, E_NET_FAILED, E_SEND_FAILED, E_WRITE_FAILED, RECV_BUF_SIZE,
};

/// The numeric status of an HTTP/1.x status line — the three digits after the
/// first space, as in `HTTP/1.1 503 Service Unavailable`.
///
/// Zero for anything this will not read whole: a refusal carrying a status is
/// only worth acting on if the status was actually sent, so a partial or
/// non-numeric line yields nothing rather than a guess.
pub fn parse_status_line(head: &[u8]) -> u16 {
    let sp = head.iter().position(|&b| b == b' ');
    let Some(sp) = sp else { return 0 };
    if head.len() < sp + 4 {
        return 0;
    }
    let d = &head[sp + 1..sp + 4];
    if d.iter().all(|b| b.is_ascii_digit()) {
        (d[0] - b'0') as u16 * 100 + (d[1] - b'0') as u16 * 10 + (d[2] - b'0') as u16
    } else {
        0
    }
}

/// Write the zero-length chunk that ends an extended body, if one is owed.
///
/// Answers whether the body is ended — `false` when the channel took only part
/// of the chunk, and the caller must come back rather than move on. Owed means
/// the head has gone and the closing chunk has not: before the head there is
/// no stream for a consumer to be reading, and an unwired `file_ctrl` carries
/// nothing to end.
///
/// The flags stay set afterwards until `complete` has seen them: clearing them
/// here would leave it looking at an ordinary exchange and answering a second
/// time, with an empty reply, for a correlation already spent.
#[cfg(feature = "exchange")]
unsafe fn end_extended_body(s: &mut HttpState) -> bool {
    if s.client.exchange_extended == 0
        || s.client.exchange_head_sent == 0
        || s.client.exchange_terminated != 0
    {
        return true;
    }
    if s.client.out_chan >= 0 {
        let sys = &*s.syscalls;
        if s.client.ext_len == 0 {
            let Some(framed) = super::exchange::write_chunk(&[], &mut s.client.ext_frame) else {
                return false;
            };
            s.client.ext_len = framed as u16;
            s.client.ext_sent = 0;
        }
        let sent = s.client.ext_sent as usize;
        let left = s.client.ext_len as usize - sent;
        let wrote = (sys.channel_write)(
            s.client.out_chan,
            s.client.ext_frame.as_ptr().add(sent),
            left,
        );
        if wrote <= 0 {
            return false;
        }
        s.client.ext_sent += wrote as u16;
        if s.client.ext_sent < s.client.ext_len {
            return false;
        }
        s.client.ext_len = 0;
        s.client.ext_sent = 0;
    }
    s.client.exchange_terminated = 1;
    true
}

pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    let now = dev_millis(&*s.syscalls);
    if !matches!(s.client.phase, Phase::Init | Phase::Done | Phase::Error) {
        let expired =
            |start, budget: u32| budget != 0 && now.wrapping_sub(start) >= u64::from(budget);
        let waiting_head = matches!(s.client.phase, Phase::RecvHeaders | Phase::RecvBody)
            && !s.client.response.has_head();
        let moving = matches!(
            s.client.phase,
            Phase::SendRequest | Phase::RecvHeaders | Phase::RecvBody | Phase::Writing
        );
        if expired(s.client.request_start_ms, s.client.client_total_ms)
            || (waiting_head && expired(s.client.response_start_ms, s.client.client_header_ms))
            || (moving && expired(s.client.progress_ms, s.client.client_stall_ms))
        {
            s.client.phase = Phase::Error;
        }
    }
    loop {
        match s.client.phase {
            Phase::Init => {
                if s.client.request_invalid != 0 {
                    s.client.phase = Phase::Error;
                    continue;
                }
                s.client.request_start_ms = now;
                s.client.progress_ms = now;
                s.client.response = super::super::wire::response::ResponseDecoder::new(
                    s.client.method == super::super::wire::method::METHOD_HEAD,
                    s.client.method == super::super::wire::method::METHOD_CONNECT,
                );
                s.client.h1_input_len = 0;
                s.client.h1_input_offset = 0;
                // A connection held open for another authority is closed
                // before anything else: reusing it would put this request on
                // a socket to a peer it does not name. A refused CLOSE keeps
                // the phase here so it is offered again.
                if s.client.conn_stale != 0 {
                    // Park it for its own authority if it is cleanly idle;
                    // only a connection that cannot be kept is closed. Either
                    // way this client is not holding it any more.
                    if !super::park_connection(s) && !send_close_frame(s) {
                        return 0;
                    }
                    s.client.conn_stale = 0;
                }
                // A connection parked for this very authority is resumed
                // rather than dialled again.
                if s.client.conn_present == 0 {
                    let n = s.client.conn_authority_len as usize;
                    let mut authority = [0u8; super::AUTHORITY_MAX];
                    authority[..n].copy_from_slice(&s.client.conn_authority[..n]);
                    if super::resume_parked(s, &authority[..n]) {
                        log(s, b"[http] resumed a parked connection");
                    }
                }
                if s.client.conn_present != 0 {
                    s.client.phase = if build_request(s) {
                        Phase::SendRequest
                    } else {
                        Phase::Error
                    };
                    continue;
                }
                if s.client.conn_authority_len == 0 {
                    // An open client with no record in hand has nowhere to go;
                    // a pinned one always has its authority here.
                    log(s, b"[http] no authority to dial");
                    s.client.phase = Phase::Error;
                    return E_CONNECT_FAILED;
                }
                log(s, b"[http] connecting");
                s.client.phase = Phase::Connecting;
                continue;
            }

            Phase::Connecting => {
                if s.net_out_chan < 0 {
                    s.client.phase = Phase::Error;
                    return E_NET_FAILED;
                }
                // The tag (our module index) is echoed in MSG_CONNECTED so that
                // when ip.net_out is fanned to another stream consumer (e.g. an
                // OTLP exporter) we claim only our own outbound connection.
                match super::dial(s) {
                    Some(true) => {}
                    Some(false) => return 0,
                    None => {
                        log(s, b"[http] authority cannot be dialled");
                        s.client.phase = Phase::Error;
                        return E_CONNECT_FAILED;
                    }
                }
                s.client.connect_start_ms = dev_millis(&*s.syscalls);
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
                        // CMD_CONNECT_TO index. Untagged — which is what a sole
                        // consumer sees — or our tag → ours; any other tag
                        // belongs to a co-wired consumer sharing this fanned
                        // queue, so ignore it.
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
                        s.client.progress_ms = now;
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

                s.client.progress_ms = now;
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
                    s.client.response_start_ms = now;
                    s.client.phase = Phase::RecvHeaders;
                }
                return 0;
            }

            Phase::RecvHeaders | Phase::RecvBody => {
                if s.client.response.done() {
                    s.client.phase = Phase::Done;
                    continue;
                }
                let sys = &*s.syscalls;
                if s.client.h1_input_offset == s.client.h1_input_len {
                    if s.net_in_chan < 0 {
                        return 0;
                    }
                    let nbuf = s.net_buf.as_mut_ptr();
                    let (kind, len, declared) =
                        net_read_frame_aligned(sys, s.net_in_chan, nbuf, NET_BUF_SIZE);
                    if kind == 0 {
                        return 0;
                    }
                    if len < 2 || len != declared {
                        s.client.phase = Phase::Error;
                        continue;
                    }
                    if is_foreign_frame(s, kind, len, nbuf) {
                        return 0;
                    }
                    if kind == NET_MSG_ERROR {
                        s.client.phase = Phase::Error;
                        continue;
                    }
                    if kind == NET_MSG_CLOSED {
                        s.client.phase = if s.client.response.eof().is_ok() {
                            Phase::Done
                        } else {
                            Phase::Error
                        };
                        continue;
                    }
                    if kind != NET_MSG_DATA {
                        return 0;
                    }
                    s.client.h1_input_offset = (NET_FRAME_HDR + 2) as u16;
                    s.client.h1_input_len = (NET_FRAME_HDR + len) as u16;
                }
                let input =
                    &s.net_buf[s.client.h1_input_offset as usize..s.client.h1_input_len as usize];
                match s.client.response.consume(input, &mut s.client.recv_buf) {
                    Ok((used, produced)) => {
                        if used > 0 {
                            s.client.progress_ms = now;
                        }
                        s.client.h1_input_offset += used as u16;
                        s.client.last_status = s.client.response.status;
                        // An extended exchange is answered as soon as there
                        // is a head to answer with, so a consumer can read
                        // the body as it arrives rather than after all of it
                        // has.
                        #[cfg(feature = "exchange")]
                        if s.client.exchange_extended != 0 {
                            super::exchange::send_head(s);
                        }
                        s.client.bytes_received =
                            s.client.bytes_received.saturating_add(produced as u32);
                        // One request is outstanding: unsolicited bytes after its
                        // framing boundary are not a second successful response.
                        if s.client.response.done()
                            && s.client.h1_input_offset != s.client.h1_input_len
                        {
                            s.client.phase = Phase::Error;
                            continue;
                        }
                        if produced > 0 {
                            s.client.recv_len = produced as u16;
                            s.client.pending_offset = 0;
                            s.client.phase = Phase::Writing;
                        } else if s.client.response.done() {
                            s.client.phase = Phase::Done;
                        } else {
                            return 0;
                        }
                    }
                    Err(_) => {
                        s.client.phase = Phase::Error;
                    }
                }
                continue;
            }

            Phase::Writing => {
                // Graph-driven, answering with the body alone: a reply is ONE
                // frame, so the body is accumulated here rather than streamed.
                //
                // A caller that asked for the whole response takes the other
                // path. Its body streams to `file_ctrl` as it arrives and its
                // reply carries the head, because a response is not bounded by
                // what one record may hold and this surface says a reply is
                // exactly one of them.
                #[cfg(feature = "exchange")]
                if super::exchange::busy(s) && s.client.exchange_extended == 0 {
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

                // An extended body is written in length-framed chunks, and a
                // zero-length one ends it. The reply has already gone, so
                // nothing else says where the body stops: without a frame a
                // consumer could not tell a pause from an ending.
                #[cfg(feature = "exchange")]
                if s.client.exchange_extended != 0 {
                    // Compose the next chunk once, then send it from wherever
                    // the last write got to.
                    if s.client.ext_len == 0 {
                        let take = remaining.min(super::EXT_CHUNK - super::exchange::CHUNK_HEAD);
                        let bytes = core::slice::from_raw_parts(
                            s.client.recv_buf.as_ptr().add(offset),
                            take,
                        );
                        let Some(framed) =
                            super::exchange::write_chunk(bytes, &mut s.client.ext_frame)
                        else {
                            s.client.phase = Phase::Error;
                            return E_WRITE_FAILED;
                        };
                        s.client.ext_len = framed as u16;
                        s.client.ext_sent = 0;
                        s.client.pending_offset += take as u16;
                    }
                    let sent = s.client.ext_sent as usize;
                    let left = s.client.ext_len as usize - sent;
                    let wrote =
                        (sys.channel_write)(out_chan, s.client.ext_frame.as_ptr().add(sent), left);
                    if wrote < 0 {
                        if wrote == E_AGAIN {
                            return 0;
                        }
                        log(s, b"[http] write failed");
                        s.client.phase = Phase::Error;
                        return E_WRITE_FAILED;
                    }
                    if wrote > 0 {
                        s.client.progress_ms = now;
                    }
                    s.client.ext_sent += wrote as u16;
                    if s.client.ext_sent < s.client.ext_len {
                        return 0;
                    }
                    s.client.ext_len = 0;
                    s.client.ext_sent = 0;
                    if s.client.pending_offset >= s.client.recv_len {
                        s.client.phase = Phase::RecvBody;
                    }
                    return 0;
                }

                let written = (sys.channel_write)(
                    out_chan,
                    s.client.recv_buf.as_ptr().add(offset),
                    remaining.min(super::OUTPUT_CHUNK),
                );

                if written < 0 {
                    if written == E_AGAIN {
                        return 0;
                    }
                    log(s, b"[http] write failed");
                    s.client.phase = Phase::Error;
                    return E_WRITE_FAILED;
                }

                if written > 0 {
                    s.client.progress_ms = now;
                }
                s.client.pending_offset += written as u16;
                if s.client.pending_offset >= s.client.recv_len {
                    s.client.phase = Phase::RecvBody;
                }
                return 0;
            }

            Phase::Done => {
                // The chunk that ends an extended body, before anything else
                // here: a consumer reading the stream has no other way to
                // learn the response is whole.
                #[cfg(feature = "exchange")]
                if !end_extended_body(s) {
                    return 0;
                }
                #[cfg(not(feature = "exchange"))]
                let reuse = false;
                #[cfg(feature = "exchange")]
                let reuse = super::exchange::armed(s)
                    && s.client.keep_alive != 0
                    && s.client.response.reusable
                    && s.client.draining == 0;
                if !reuse && !send_close_frame(s) {
                    return 0;
                }
                // Answer the request that produced this response, then go
                // idle so the next one on `publish_in` can be taken.
                #[cfg(feature = "exchange")]
                {
                    s.client.idle_since_ms = now;
                    super::exchange::complete(s);
                    if super::exchange::armed(s) {
                        // A graph-driven client is RESIDENT: `Done` ends one
                        // exchange, not the module. Retiring here would answer
                        // the first request and strand every one after it.
                        // The step dispatch idles an armed client with nothing
                        // in flight, and the next publish re-arms the phase
                        // machine.
                        return 0;
                    }
                }
                return 1;
            }

            Phase::Error => {
                if !send_close_frame(s) {
                    return 0;
                }
                // A failed exchange is still an answer: the contract admits
                // no silent drops, so the producer gets a typed refusal
                // rather than waiting out its own timeout.
                //
                // A body that started has to end the same way a whole one
                // does. Without the closing chunk a consumer cannot tell a
                // response that failed from one still arriving, and it is the
                // only thing left to tell it with — the one reply this
                // exchange had was spent on the head.
                #[cfg(feature = "exchange")]
                {
                    if !end_extended_body(s) {
                        return 0;
                    }
                    super::exchange::fail(s);
                    if super::exchange::armed(s) {
                        // The same rule on the failure path: the refusal
                        // answered THIS exchange. Faulting the module instead
                        // would let one refused request end every later one.
                        return 0;
                    }
                }
                return -1;
            }

            _ => return -1,
        }
    }
}

/// Drain what the step machine is not reading, and clear an idle connection
/// on peer EOF, unsolicited bytes, or idle expiry. A closed idle socket is
/// never automatically replayed after a request write.
pub(crate) unsafe fn idle(s: &mut HttpState) {
    // Only the phases that do not read `net_in` themselves. While an exchange
    // is in flight the step machine drains the channel — foreign frames
    // included, by `is_foreign_frame` — and taking frames from under it here
    // would strip a response of its own bytes.
    if !matches!(s.client.phase, Phase::Init | Phase::Done | Phase::Error) {
        return;
    }
    if s.net_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.client.conn_present != 0
        && s.client.phase == Phase::Done
        && s.client.client_stall_ms != 0
        && dev_millis(sys).wrapping_sub(s.client.idle_since_ms)
            >= u64::from(s.client.client_stall_ms)
    {
        let _ = send_close_frame(s);
        return;
    }
    // `net_in` is fanned from a lane that other stream consumers share, so
    // frames for THEIR connections arrive here too and this client has to read
    // and drop them. That holds in every idle phase, including before it has
    // ever dialled: a copy left unread fills its edge, and the back-pressure
    // from a full edge reaches the provider, which then cannot deliver to the
    // consumer the bytes were for. One leg the deployment wired but the
    // program never used would otherwise stall the leg doing the work — and
    // only once a response outgrew the edge, so small ones would pass.
    for _ in 0..8 {
        let (kind, n) = net_read_frame(sys, s.net_in_chan, s.net_buf.as_mut_ptr(), NET_BUF_SIZE);
        if kind == 0 {
            break;
        }
        let frame_conn = if n >= 2 {
            Some(net_proto::conn_id(
                &s.net_buf[NET_FRAME_HDR..NET_FRAME_HDR + n],
            ))
        } else {
            None
        };
        // Anything at all on the PARKED connection ends its parking. It was
        // kept on the promise that it was idle, and a frame is proof it was
        // not — a close from the peer as much as unsolicited data.
        if s.client.parked_present != 0 && frame_conn == Some(s.client.parked_id) {
            let _ = super::close_parked(s);
        }
        // Ours is the only connection that means anything here: a frame on it
        // between exchanges is the peer saying something the response decoder
        // never asked for, so the connection cannot be reused. Without a
        // connection of our own, nothing that arrives can be ours.
        if s.client.conn_present != 0 && frame_conn == Some(s.client.conn_id) {
            s.client.response.reusable = false;
            let _ = send_close_frame(s);
            break;
        }
    }
}
