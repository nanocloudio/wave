//! `wave-loadgen` — off-DUT open-loop multi-protocol load generator.
//!
//! Drives a Wave DUT over the real wire path at a fixed **offered** rate using a
//! fixed-interval arrival process, sharded across worker threads, each with its
//! own latency histogram merged at the end.
//!
//! Method, inherited from `lattice-bench` because it is the part that makes the
//! numbers mean anything:
//!
//! - **Open loop.** A closed loop (send, wait, send) paces itself to the
//!   server's speed, hides coordinated omission, and reports a flattering tail
//!   that describes the harness rather than the DUT.
//! - **Coordinated-omission corrected.** Each request's latency is measured
//!   from its *intended* send time, not from when the loop got around to it, so
//!   a stall shows up as a growing tail instead of silently reducing the rate.
//! - **offered / accepted / committed accounting.** A budget is met only if
//!   `accepted == committed` at the offered rate. Anything else is a partial.
//! - **HARNESS_BOUND verdict.** If achieved throughput falls below 90 % of
//!   offered, the generator says so — the run measured the generator, not the
//!   DUT, and the tail must not be quoted.
//! - **Per-outcome tails are separate.** `Rejected` (the peer answered, badly)
//!   never merges with `Failed` (the transport died). Averaging an overloaded
//!   server with a broken one describes neither.
//!
//! Usage:
//!   wave-loadgen --host 127.0.0.1:8080 --protocol h1 --rate 2000 --duration 10 \
//!       --conns 8 --path / --payload 64
//!
//! Protocols: `h1`, `h2c`, `h3`, `ws`, `grpc`. `h3` rides `quiche`
//! (independent QUIC + HTTP/3, see `../h3.rs`); the rest are std-only; see `../lib.rs` on why this
//! shares no code with Wave.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use wave_bench::h3::H3Client;
use wave_bench::proto::{H1Client, H2Client, LoadClient, Outcome, WsClient};
use wave_bench::{JsonObj, LatencyHist};

struct Args {
    host: String,
    protocol: String,
    rate: u64,
    duration_secs: u64,
    conns: u64,
    path: String,
    authority: String,
    payload: usize,
    tls: bool,
    warmup_secs: u64,
    /// One connection per request: dial, one round trip, close. Measures the
    /// accept path — SYN admission, the slot table, TLS handshakes, slot
    /// release — which keepalive never touches after the first request.
    churn: bool,
}

fn usage() -> ! {
    eprintln!(
        "wave-loadgen --host <addr:port> [--protocol h1|h2c|h3|ws|grpc] [--tls] [--rate N]\n\
         \x20  [--duration N] [--conns N] [--path P] [--authority H] [--payload B]\n\
         \x20  [--warmup N] [--churn]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        host: String::new(),
        protocol: "h1".to_string(),
        rate: 1000,
        duration_secs: 10,
        conns: 8,
        path: "/".to_string(),
        authority: String::new(),
        payload: 64,
        tls: false,
        warmup_secs: 1,
        churn: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--host" => a.host = next(),
            "--protocol" => a.protocol = next(),
            "--rate" => a.rate = next().parse().unwrap_or_else(|_| usage()),
            "--duration" => a.duration_secs = next().parse().unwrap_or_else(|_| usage()),
            "--conns" => a.conns = next().parse().unwrap_or_else(|_| usage()),
            "--path" => a.path = next(),
            "--authority" => a.authority = next(),
            "--payload" => a.payload = next().parse().unwrap_or_else(|_| usage()),
            "--tls" => a.tls = true,
            "--churn" => a.churn = true,
            "--warmup" => a.warmup_secs = next().parse().unwrap_or_else(|_| usage()),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown flag: {other}");
                usage();
            }
        }
    }
    if a.host.is_empty() || a.rate == 0 || a.conns == 0 {
        usage();
    }
    if a.authority.is_empty() {
        a.authority = a.host.clone();
    }
    if !matches!(a.protocol.as_str(), "h1" | "h2c" | "h3" | "ws" | "grpc") {
        eprintln!("unknown protocol: {}", a.protocol);
        usage();
    }
    a
}

struct ShardResult {
    ok: LatencyHist,
    /// Kept apart from `ok`: a rejected request's latency describes the error
    /// path, and folding it into the success tail flatters or slanders the DUT
    /// depending on which is faster.
    rejected: LatencyHist,
    sent: u64,
    n_ok: u64,
    n_rejected: u64,
    n_failed: u64,
    connect_err: u64,
    /// Round-trips that failed during WARM-UP, before the measured phase.
    /// Deliberately not folded into `n_failed`: warm-up is unrecorded by
    /// design, so a failure there says the run was disturbed, not that the DUT
    /// rejected measured work. Reported so it can never be silent.
    warmup_failed: u64,
}

impl ShardResult {
    fn empty() -> Self {
        ShardResult {
            ok: LatencyHist::new(),
            rejected: LatencyHist::new(),
            sent: 0,
            n_ok: 0,
            n_rejected: 0,
            n_failed: 0,
            connect_err: 0,
            warmup_failed: 0,
        }
    }
}

/// This process's user+system CPU seconds (`/proc/self/stat` fields 14/15).
/// 0.0 where /proc is unreadable — the field then reads as a driver that used
/// no CPU, which the verdict discipline treats as suspicious rather than
/// clean.
fn self_cpu_seconds() -> f64 {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return 0.0;
    };
    // Fields after the parenthesised comm; utime is the 14th overall.
    let Some(rest) = stat.rsplit(") ").next() else {
        return 0.0;
    };
    let f: Vec<&str> = rest.split_whitespace().collect();
    let (Some(ut), Some(st)) = (f.get(11), f.get(12)) else {
        return 0.0;
    };
    let ticks: f64 = ut.parse::<f64>().unwrap_or(0.0) + st.parse::<f64>().unwrap_or(0.0);
    ticks / 100.0 // USER_HZ
}

fn make_client(a: &Args, shard: u64) -> std::io::Result<Box<dyn LoadClient>> {
    Ok(match a.protocol.as_str() {
        // Churn dials per request but asks for keep-alive and closes from
        // the CLIENT side. A `Connection: close` would make the server
        // initiate every close and hold every TIME_WAIT, which measures the
        // transport's close-state capacity rather than its accept path, and
        // shows up as a p50 shaped like the client's SYN retransmit ladder. A
        // browser or a pooled client closes its own idle sockets; that is the
        // churn worth measuring.
        "h1" => Box::new(H1Client::connect(&a.host, &a.path, &a.authority, a.tls)?),
        "h2c" => Box::new(H2Client::connect(
            &a.host,
            &a.path,
            &a.authority,
            false,
            a.tls,
        )?),
        "grpc" => Box::new(H2Client::connect(
            &a.host,
            &a.path,
            &a.authority,
            true,
            a.tls,
        )?),
        "h3" => Box::new(H3Client::connect(&a.host, &a.path, &a.authority)?),
        "ws" => Box::new(WsClient::connect(
            &a.host,
            &a.path,
            &a.authority,
            a.payload,
            shard,
            a.tls,
        )?),
        _ => unreachable!("protocol validated in parse_args"),
    })
}

/// Reconnects allowed during warm-up before the shard gives up. Warm-up is
/// short and paced, so repeated failures there mean the target cannot hold a
/// connection at all — retrying forever would spend the whole run dialling.
const WARMUP_RECONNECT_LIMIT: u64 = 3;

fn run_shard(shard: u64, a: &Args, per_shard_rate: f64) -> ShardResult {
    let mut r = ShardResult::empty();

    let mut client = match make_client(a, shard) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[loadgen] shard {shard} connect {}: {e}", a.host);
            r.connect_err = 1;
            return r;
        }
    };

    let interval = Duration::from_secs_f64(1.0 / per_shard_rate);

    // Warm-up requests are issued but not recorded: the first request on a
    // connection pays TCP/handshake/slow-start costs that would otherwise land
    // in the steady-state tail as a phantom outlier.
    //
    // PACED AT `interval`, exactly like the measured loop below. An
    // unthrottled warm-up would be the heaviest phase of the run — every shard
    // hammering as fast as it could, ignoring `--rate` entirely — and at 8
    // concurrent h2-over-TLS connections that burst is enough to push a Pi 5
    // past saturation. A warm-up failure reconnects rather than retiring the
    // shard, for the same reason: a warm-up burst that killed every shard
    // before the measured phase began would report `committed=0 failed=8` —
    // a total DUT failure — for a DUT that serves the requested rate cleanly.
    // Warm-up must not be a load test.
    let warmup_end = Instant::now() + Duration::from_secs(a.warmup_secs);
    let mut w: u64 = 0;
    let warmup_start = Instant::now();
    while Instant::now() < warmup_end {
        let intended = warmup_start + interval.mul_f64(w as f64);
        let now = Instant::now();
        if intended > now {
            std::thread::sleep(intended - now);
        }
        w += 1;
        let outcome = client.round_trip();
        // Churn: the connection is spent after its one request, in warm-up
        // as in the measured loop. Reusing it would read EOF and count a
        // healthy server as a warm-up failure.
        if a.churn && outcome != Outcome::Failed {
            drop(client);
            match make_client(a, shard) {
                Ok(c) => client = c,
                Err(_) => {
                    r.connect_err += 1;
                    return r;
                }
            }
            continue;
        }
        if outcome == Outcome::Failed {
            // Reconnect rather than retire, matching the measured loop: one
            // reset must not silently remove a shard and leave the survivors
            // looking healthy. Counted apart from `n_failed` so an unmeasured
            // phase can never be mistaken for a measured result.
            r.warmup_failed += 1;
            if r.warmup_failed > WARMUP_RECONNECT_LIMIT {
                r.connect_err += 1;
                return r;
            }
            match make_client(a, shard) {
                Ok(c) => client = c,
                Err(_) => {
                    r.connect_err += 1;
                    return r;
                }
            }
        }
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(a.duration_secs);
    let mut i: u64 = 0;

    loop {
        // The intended send time for request i — fixed by the schedule, never
        // by how long request i-1 took. This is the coordinated-omission fix.
        let intended = start + interval.mul_f64(i as f64);
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if intended > now {
            std::thread::sleep(intended - now);
        }

        let outcome = client.round_trip();
        let done = Instant::now();
        // Churn: this connection has done its one request. Dial the next
        // before the schedule's next slot so the reconnect is not charged to
        // the following request's latency — the round trip above already
        // paid the handshake it was meant to measure.
        if a.churn && outcome != Outcome::Failed {
            drop(client);
            match make_client(a, shard) {
                Ok(c) => client = c,
                Err(_) => {
                    r.connect_err += 1;
                    r.sent += 1;
                    match outcome {
                        Outcome::Ok => {
                            r.ok.record(done.saturating_duration_since(intended).as_micros() as u64);
                            r.n_ok += 1;
                        }
                        Outcome::Rejected => {
                            r.rejected.record(done.saturating_duration_since(intended).as_micros() as u64);
                            r.n_rejected += 1;
                        }
                        Outcome::Failed => {}
                    }
                    break;
                }
            }
        }
        // Latency from `intended`, not from the actual send.
        let us = done.saturating_duration_since(intended).as_micros() as u64;

        r.sent += 1;
        i += 1;
        match outcome {
            Outcome::Ok => {
                r.ok.record(us);
                r.n_ok += 1;
            }
            Outcome::Rejected => {
                r.rejected.record(us);
                r.n_rejected += 1;
            }
            Outcome::Failed => {
                r.n_failed += 1;
                // The connection is dead; reconnect so one reset doesn't silently
                // retire a shard and make the remaining shards look healthy.
                match make_client(a, shard) {
                    Ok(c) => client = c,
                    Err(_) => {
                        r.connect_err += 1;
                        break;
                    }
                }
            }
        }
    }
    r
}

/// quiche reports its packet-level decisions through the `log` facade; with
/// no logger installed they vanish. `RUST_LOG=<level>` installs this one,
/// which writes each record to stderr, so a handshake that "timed out" can
/// say which packet it discarded and why. Off unless the variable is set.
struct StderrLog(log::LevelFilter);

impl log::Log for StderrLog {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= self.0
    }
    fn log(&self, r: &log::Record<'_>) {
        if self.enabled(r.metadata()) {
            eprintln!("[{}] {}: {}", r.level(), r.target(), r.args());
        }
    }
    fn flush(&self) {}
}

fn install_logger() {
    let Ok(v) = std::env::var("RUST_LOG") else {
        return;
    };
    let level = match v.to_ascii_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => return,
    };
    static LOGGER: std::sync::OnceLock<StderrLog> = std::sync::OnceLock::new();
    let l = LOGGER.get_or_init(|| StderrLog(level));
    if log::set_logger(l).is_ok() {
        log::set_max_level(level);
    }
}

fn main() {
    install_logger();
    let a = parse_args();
    let per_shard = a.rate as f64 / a.conns as f64;

    eprintln!(
        "[loadgen] host={} proto={} offered={}/s conns={} dur={}s warmup={}s path={} payload={}B",
        a.host, a.protocol, a.rate, a.conns, a.duration_secs, a.warmup_secs, a.path, a.payload
    );

    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();
    for shard in 0..a.conns {
        let args = Args {
            host: a.host.clone(),
            protocol: a.protocol.clone(),
            path: a.path.clone(),
            authority: a.authority.clone(),
            ..a
        };
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            let _ = tx.send(run_shard(shard, &args, per_shard));
        }));
    }
    drop(tx);

    // Wall clock starts after the shards have warmed up, so connection setup
    // does not deflate the achieved rate and trip a false HARNESS_BOUND.
    let wall = Instant::now() + Duration::from_secs(a.warmup_secs);
    let cpu_start = self_cpu_seconds();

    let mut agg = ShardResult::empty();
    for s in rx {
        agg.ok.merge(&s.ok);
        agg.rejected.merge(&s.rejected);
        agg.sent += s.sent;
        agg.n_ok += s.n_ok;
        agg.n_rejected += s.n_rejected;
        agg.n_failed += s.n_failed;
        agg.connect_err += s.connect_err;
        agg.warmup_failed += s.warmup_failed;
    }
    for h in handles {
        let _ = h.join();
    }

    let elapsed = wall.elapsed().as_secs_f64().max(0.001);
    // Driver self-attribution: the generator's own CPU
    // over the measured window, as a percentage of ONE core. A driver near a
    // core per shard is measuring itself, whatever the latency numbers say.
    let cpu_pct = (self_cpu_seconds() - cpu_start).max(0.0) / elapsed * 100.0;
    let achieved = agg.sent as f64 / elapsed;
    let ratio = achieved / a.rate as f64;

    // Verdict discipline: a run the generator bottlenecked cannot be quoted as
    // a DUT measurement, and a run where nothing connected is neither.
    let verdict = if agg.connect_err > 0 && agg.sent == 0 {
        "NO_CONNECTION"
    } else if ratio < 0.9 {
        "HARNESS_BOUND"
    } else {
        "DUT_ATTRIBUTABLE"
    };
    let committed = agg.n_ok;
    // `warmup_failed` counts too: a run that had to reconnect mid-warm-up did
    // not observe an undisturbed DUT, so calling it clean would launder the
    // disturbance into a quotable number.
    let clean =
        agg.n_failed == 0 && agg.n_rejected == 0 && agg.warmup_failed == 0 && committed == agg.sent;

    let report = JsonObj::new()
        .str("schema", "wave-loadgen/1")
        .str("protocol", &a.protocol)
        .str("host", &a.host)
        .str("path", &a.path)
        .num("offered_rate", a.rate)
        .num("achieved_rate", format!("{achieved:.1}"))
        .num("conns", a.conns)
        .str("mode", if a.churn { "churn" } else { "keepalive" })
        .num("duration_s", a.duration_secs)
        .num("payload_bytes", a.payload)
        .num("offered", a.rate * a.duration_secs)
        .num("accepted", agg.sent)
        .num("committed", committed)
        .num("rejected", agg.n_rejected)
        .num("failed", agg.n_failed)
        .num("connect_errors", agg.connect_err)
        .num("warmup_failed", agg.warmup_failed)
        .raw("ok_tail", agg.ok.tail_json())
        .raw("rejected_tail", agg.rejected.tail_json())
        .num("driver_cpu_pct", format!("{cpu_pct:.0}"))
        .str("headroom_verdict", verdict)
        .str("clean", if clean { "true" } else { "false" })
        .render();
    println!("{report}");

    eprintln!(
        "[loadgen] accepted={} committed={} rejected={} failed={} warmup_failed={} \
         achieved={:.0}/s p50={}us p99={}us p999={}us max={}us verdict={verdict}",
        agg.sent,
        committed,
        agg.n_rejected,
        agg.n_failed,
        agg.warmup_failed,
        achieved,
        agg.ok.percentile(50.0),
        agg.ok.percentile(99.0),
        agg.ok.percentile(99.9),
        agg.ok.max(),
    );

    // Non-zero exit on a run that cannot be quoted, so CI and rig scenarios
    // fail loudly instead of recording a meaningless number.
    if verdict == "NO_CONNECTION" {
        std::process::exit(1);
    }
}
