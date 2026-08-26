//! HTTP/3 load client over `quiche` (RFC hardening §7.2).
//!
//! The compiled independent driver the HTTP/3 envelope needs: the Python
//! oracle (aioquic) proved FUNCTIONAL correctness but cannot distinguish a
//! driver GC pause from DUT latency at rate, so nothing measured through it
//! is an envelope. `quiche` is Cloudflare's QUIC + HTTP/3 stack — no shared
//! lineage with Wave or fluxor, so it keeps the oracle-independence rule this
//! crate is built on (see `Cargo.toml`): the transport AND the h3 codec on
//! this side are somebody else's reading of the RFCs.
//!
//! Sans-IO, driven synchronously over a `std::net::UdpSocket` with short read
//! timeouts — the same blocking `round_trip` shape as every other client
//! here, so the open-loop driver and its coordinated-omission accounting
//! apply unchanged.

use quiche::h3::NameValue;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::proto::{LoadClient, Outcome};

/// One waiting bound per round trip: a response slower than this is a
/// failure, exactly as the TCP clients treat a read timeout.
const ROUND_TRIP_DEADLINE: Duration = Duration::from_secs(5);

/// UDP receive buffer — one datagram, QUIC max.
const RECV_BUF: usize = 65535;

/// Egress scratch — `max_send_udp_payload_size` sized.
const SEND_BUF: usize = 1350;

pub struct H3Client {
    socket: UdpSocket,
    conn: quiche::Connection,
    h3: quiche::h3::Connection,
    authority: String,
    path: String,
    recv_buf: Box<[u8; RECV_BUF]>,
    send_buf: [u8; SEND_BUF],
    body_scratch: Vec<u8>,
}

/// stderr logger armed by WAVE_H3_DEBUG — surfaces quiche's TLS detail, which
/// is where a handshake refusal actually says why.
struct DbgLog;
static DBG_LOG: DbgLog = DbgLog;
impl log::Log for DbgLog {
    fn enabled(&self, _m: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        eprintln!("[quiche {}] {}", r.level(), r.args());
    }
    fn flush(&self) {}
}

impl H3Client {
    pub fn connect(host: &str, path: &str, authority: &str) -> std::io::Result<Self> {
        if std::env::var_os("WAVE_H3_DEBUG").is_some() {
            let _ = log::set_logger(&DBG_LOG);
            log::set_max_level(log::LevelFilter::Trace);
        }
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(host)?;
        socket.set_read_timeout(Some(Duration::from_millis(20)))?;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| std::io::Error::other(format!("quiche config: {e}")))?;
        config
            .set_application_protos(&[b"h3"])
            .map_err(|e| std::io::Error::other(format!("alpn: {e}")))?;
        // The DUT's certificate is the rig's own; the driver measures load,
        // not PKI. Identity assurance on the rig comes from the wiring.
        config.verify_peer(false);
        config.set_max_idle_timeout(30_000);
        config.set_max_recv_udp_payload_size(RECV_BUF);
        config.set_max_send_udp_payload_size(SEND_BUF);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(128);
        config.set_initial_max_streams_uni(16);

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        // Distinct per connection; quality is irrelevant, collision across a
        // handful of driver connections is what matters.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, b) in scid.iter_mut().enumerate() {
            *b = ((seed >> ((i % 16) * 8)) as u8) ^ (i as u8).wrapping_mul(0x9E);
        }
        let scid = quiche::ConnectionId::from_ref(&scid);
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let mut conn = quiche::connect(Some(authority), &scid, local, peer, &mut config)
            .map_err(|e| std::io::Error::other(format!("quiche connect: {e}")))?;

        // Handshake before the struct exists: quiche's h3 layer refuses a
        // transport that is not established, so there is no h3 value to hold
        // until this loop completes.
        let mut recv_buf = Box::new([0u8; RECV_BUF]);
        let mut send_buf = [0u8; SEND_BUF];
        let deadline = Instant::now() + ROUND_TRIP_DEADLINE;
        loop {
            loop {
                match conn.send(&mut send_buf) {
                    Ok((n, _)) => {
                        let sent = socket.send(&send_buf[..n])?;
                        if std::env::var_os("WAVE_H3_DEBUG").is_some() {
                            eprintln!("[h3dbg] tx {n}B sent {sent}");
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        return Err(std::io::Error::other(format!("quic send: {e}")));
                    }
                }
            }
            if conn.is_established() {
                break;
            }
            if Instant::now() > deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "QUIC handshake timed out",
                ));
            }
            match socket.recv(&mut recv_buf[..]) {
                Ok(n) => {
                    let info = quiche::RecvInfo {
                        from: peer,
                        to: local,
                    };
                    let r = conn.recv(&mut recv_buf[..n], info);
                    if std::env::var_os("WAVE_H3_DEBUG").is_some() {
                        eprintln!("[h3dbg] rx {n}B -> {r:?}");
                    }
                }
                Err(e) => {
                    if std::env::var_os("WAVE_H3_DEBUG").is_some() {
                        eprintln!("[h3dbg] recv err {e:?}");
                    }
                    conn.on_timeout();
                }
            }
        }

        let h3_config = quiche::h3::Config::new()
            .map_err(|e| std::io::Error::other(format!("h3 config: {e}")))?;
        let h3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
            .map_err(|e| std::io::Error::other(format!("h3 setup: {e}")))?;

        let mut c = H3Client {
            socket,
            conn,
            h3,
            authority: authority.to_string(),
            path: path.to_string(),
            recv_buf,
            send_buf,
            body_scratch: vec![0u8; 65536],
        };
        c.flush_egress()?;
        Ok(c)
    }

    /// Send every packet quiche has staged.
    fn flush_egress(&mut self) -> std::io::Result<()> {
        loop {
            match self.conn.send(&mut self.send_buf) {
                Ok((n, _info)) => {
                    self.socket.send(&self.send_buf[..n])?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => {
                    return Err(std::io::Error::other(format!("quic send: {e}")));
                }
            }
        }
    }

    /// Receive at most one socket-timeout's worth of datagrams into quiche.
    fn pump_ingress_once(&mut self) {
        let local = match self.socket.local_addr() {
            Ok(a) => a,
            Err(_) => return,
        };
        let peer = match self.socket.peer_addr() {
            Ok(a) => a,
            Err(_) => return,
        };
        match self.socket.recv(&mut self.recv_buf[..]) {
            Ok(n) => {
                let info = quiche::RecvInfo {
                    from: peer,
                    to: local,
                };
                let _ = self.conn.recv(&mut self.recv_buf[..n], info);
            }
            Err(_) => {
                // Timeout or transient: let quiche's timers run.
                self.conn.on_timeout();
            }
        }
    }
}

impl LoadClient for H3Client {
    fn protocol(&self) -> &'static str {
        "h3"
    }

    fn round_trip(&mut self) -> Outcome {
        let req = [
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", self.authority.as_bytes()),
            quiche::h3::Header::new(b":path", self.path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", b"wave-loadgen"),
        ];
        let stream_id = match self.h3.send_request(&mut self.conn, &req, true) {
            Ok(id) => id,
            Err(_) => return Outcome::Failed,
        };
        if self.flush_egress().is_err() {
            return Outcome::Failed;
        }

        let deadline = Instant::now() + ROUND_TRIP_DEADLINE;
        let mut status: Option<u16> = None;
        loop {
            if Instant::now() > deadline {
                return Outcome::Failed;
            }
            // Drain h3 events before waiting for more datagrams.
            loop {
                match self.h3.poll(&mut self.conn) {
                    Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                        if id == stream_id {
                            status = list
                                .iter()
                                .find(|h| h.name() == b":status")
                                .and_then(|h| std::str::from_utf8(h.value()).ok())
                                .and_then(|v| v.parse().ok());
                        }
                    }
                    Ok((id, quiche::h3::Event::Data)) => {
                        while let Ok(n) =
                            self.h3
                                .recv_body(&mut self.conn, id, &mut self.body_scratch)
                        {
                            if n == 0 {
                                break;
                            }
                        }
                    }
                    Ok((id, quiche::h3::Event::Finished)) => {
                        if id == stream_id {
                            return match status {
                                Some(s) if (200..300).contains(&s) => Outcome::Ok,
                                Some(_) => Outcome::Rejected,
                                None => Outcome::Failed,
                            };
                        }
                    }
                    Ok((id, quiche::h3::Event::Reset(_))) => {
                        if id == stream_id {
                            return Outcome::Failed;
                        }
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(_) => return Outcome::Failed,
                }
            }
            if self.conn.is_closed() {
                return Outcome::Failed;
            }
            self.pump_ingress_once();
            if self.flush_egress().is_err() {
                return Outcome::Failed;
            }
        }
    }
}
