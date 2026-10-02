//! Traffic generator and data sink for the Zray benchmark harness.
//!
//! One executable with two roles, because the sink and the generator have to
//! agree on the wire format, and splitting them invites a mismatch that shows
//! up as a suspiciously good number.
//!
//! Rules, each of them a number that was once published without it:
//!
//! * **The payload is validated.** An unvalidated stream measures how fast the
//!   harness can read, not how fast the core moves bytes. Validation is a
//!   deterministic keystream the sink writes and the generator checks.
//! * **The transfer window excludes setup.** Setup is reported separately
//!   (`connect_us`). A core that answers SOCKS before it dials and one that
//!   dials first hide that difference inside a wall-clock rate, so the two
//!   windows are never averaged into a single number.
//! * **The harness ceiling is published.** `selftest` runs the same validation
//!   loop over a bare socket. A core that reaches the ceiling is limited by the
//!   harness, and the report says so instead of implying the core could go
//!   faster.
//! * **No dependencies.** std only, so CI builds it in seconds and nobody has
//!   to reason about whether a patched transitive crate moved the number.
//!
//! ```text
//! loadgen sink     --port N
//! loadgen sink-udp --port N
//! loadgen run      --proxy HOST:PORT --target HOST:PORT --mode MODE [...]
//! loadgen selftest --target HOST:PORT [--bytes N] [--streams N] [--json]
//! ```
//!
//! | mode | what it does | options |
//! |---|---|---|
//! | `down` | sink to generator | `--bytes`, `--streams` |
//! | `up` | generator to sink | `--bytes`, `--streams` |
//! | `duplex` | both directions at once | `--bytes`, `--streams` |
//! | `hold` | open N flows, send nothing, hold | `--streams`, `--hold-ms` |
//! | `latency` | small validated round trips | `--iterations`, `--payload`, `--warmup` |
//! | `udp-down` | UDP through SOCKS5 UDP ASSOCIATE | `--iterations`, `--payload`, `--warmup` |
//! | `udp-latency` | UDP echo round trips | same options as `udp-down` |
//! | `probe` | establish the tunnel, send nothing | `--iterations`, `--warmup` |
//!
//! Every mode prints one JSON object on stdout and exits 1 when it carries a
//! non-empty `error` or `errors` list, so the harness can trust the exit status
//! and never has to scrape prose.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SCHEMA: &str = "zray-bench-loadgen/2";
const DEFAULT_SEED: u64 = 0x5eed_0f_fa_ce_u64;
const BLOCK: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

fn arg(name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
        if let Some(rest) = a.strip_prefix(&prefix) {
            return Some(rest.to_string());
        }
    }
    None
}

fn opt_str(name: &str) -> Option<String> {
    arg(name).filter(|v| !v.is_empty())
}

/// A count with an optional `k`/`m`/`g` multiplier and `_` separators, so a
/// matrix row can read `2G` in a shell and in a config file alike.
fn opt_count(name: &str) -> Option<u64> {
    let raw = opt_str(name)?;
    let cleaned = raw.replace('_', "");
    let digits = cleaned
        .trim_end_matches(['k', 'K', 'm', 'M', 'g', 'G'])
        .to_string();
    let base = digits.parse::<u64>().ok()?;
    let suffix = cleaned[digits.len()..].chars().next().unwrap_or('0');
    Some(match suffix.to_ascii_lowercase() {
        'k' => base * 1_000,
        'm' => base * 1_000_000,
        'g' => base * 1_000_000_000,
        _ => base,
    })
}

fn opt_usize(name: &str) -> Option<usize> {
    opt_count(name).map(|v| v as usize)
}

fn req_usize(name: &str) -> usize {
    opt_usize(name).unwrap_or_else(|| {
        eprintln!("loadgen: {name} is required");
        std::process::exit(2);
    })
}

fn endpoint(name: &str) -> SocketAddr {
    let text = opt_str(name).unwrap_or_else(|| {
        eprintln!("loadgen: {name} is required");
        std::process::exit(2);
    });
    // Literal addresses only. Every target the harness uses is on loopback, and
    // accepting a hostname would put a resolver outside the measured window.
    match text.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("loadgen: bad {name} {text}: {e}");
            std::process::exit(2);
        }
    }
}

fn die(msg: impl Into<String>) -> J {
    J::O(vec![
        ("schema".into(), s(SCHEMA)),
        ("error".into(), J::S(msg.into())),
    ])
}

// ---------------------------------------------------------------------------
// Deterministic payload
// ---------------------------------------------------------------------------

/// Keystream window size. One megabyte keeps the pattern resident in L2 while
/// being large enough that a reordered stream cannot alias onto a matching
/// offset by accident.
const PATTERN_LEN: usize = 1 << 20;

/// Every flow validates against a different region of the keystream, so a core
/// that interleaves two sessions' bytes onto one carrier is caught rather than
/// hidden behind a correct total.
fn flow_offset(index: usize) -> usize {
    index.wrapping_mul(7919) % PATTERN_LEN
}

struct Pattern {
    buf: Vec<u8>,
}

impl Pattern {
    fn new(seed: u64) -> Self {
        let mut buf = vec![0u8; PATTERN_LEN];
        // xorshift64*: cheap, and the same arithmetic on every platform, so a
        // pattern generated on one host validates on another.
        let mut state = seed | 1;
        for chunk in buf.chunks_exact_mut(8) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let word = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Pattern { buf }
    }

    /// `len` keystream bytes starting at `offset`, wrapping.
    fn slice(&self, offset: usize, len: usize, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(len);
        let mut at = offset % PATTERN_LEN;
        while out.len() < len {
            let take = (PATTERN_LEN - at).min(len - out.len());
            out.extend_from_slice(&self.buf[at..at + take]);
            at = 0;
        }
    }

    /// Compare a received block against the keystream, 8 bytes at a time, with
    /// the tail compared byte by byte.
    ///
    /// The tail is not an edge case to be avoided: `--bytes 100M --streams 3`
    /// gives each flow 33,333,333.33 bytes, and refusing to validate the last
    /// block of that reports corruption where there is none. A harness that
    /// invents a failure is worse than one that misses a real one, because the
    /// reader has to go and check.
    fn verify(&self, offset: usize, got: &[u8]) -> Result<(), usize> {
        let mut expect_at = offset % PATTERN_LEN;
        let mut i = 0;
        while i < got.len() {
            let take = ((PATTERN_LEN - expect_at).min(got.len() - i)) & !7;
            if take > 0 {
                for (a, b) in self.buf[expect_at..expect_at + take]
                    .chunks_exact(8)
                    .zip(got[i..i + take].chunks_exact(8))
                {
                    if a != b {
                        return Err(i);
                    }
                }
                i += take;
                expect_at = (expect_at + take) % PATTERN_LEN;
                continue;
            }
            // Fewer than 8 bytes left before the end of the keystream: wrap and
            // compare the remainder in at most two slices.
            let mut want = got.len() - i;
            while want > 0 {
                let take = (PATTERN_LEN - expect_at).min(want);
                if self.buf[expect_at..expect_at + take] != got[i..i + take] {
                    return Err(i);
                }
                i += take;
                want -= take;
                expect_at = 0;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Timing and statistics
// ---------------------------------------------------------------------------

/// A process-lifetime monotonic base. A transfer window taken from the wall
/// clock is wrong whenever NTP steps mid-run, and a benchmark that runs for
/// minutes is exactly when that happens.
fn monotonic_ns() -> u64 {
    use std::sync::OnceLock;
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

#[derive(Default, Clone)]
struct Samples {
    values: Vec<f64>,
}

impl Samples {
    fn push(&mut self, v: f64) {
        self.values.push(v);
    }
    fn sorted(&self) -> Vec<f64> {
        let mut v = self.values.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        v
    }
    /// Nearest-rank percentile: p95 of five samples is the largest of them, so
    /// an interpolated value is never reported as something that was measured.
    fn rank(&self, p: f64) -> f64 {
        let sorted = self.sorted();
        if sorted.is_empty() {
            return 0.0;
        }
        let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize)
            .max(1)
            .saturating_sub(1)
            .min(sorted.len() - 1);
        sorted[idx]
    }
    fn median(&self) -> f64 {
        let sorted = self.sorted();
        match sorted.len() {
            0 => 0.0,
            n if n % 2 == 1 => sorted[n / 2],
            n => (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0,
        }
    }
    fn min(&self) -> f64 {
        self.sorted().first().copied().unwrap_or(0.0)
    }
    fn max(&self) -> f64 {
        self.sorted().last().copied().unwrap_or(0.0)
    }
}

// ---------------------------------------------------------------------------
// Minimal JSON writer
// ---------------------------------------------------------------------------

enum J {
    S(String),
    N(f64),
    U(u64),
    /// An empty sample set. Written as null rather than as a zeroed object so
    /// a reader can tell "not measured" from "measured as zero".
    Null,
    A(Vec<J>),
    O(Vec<(String, J)>),
}

impl J {
    fn render(&self, out: &mut String, indent: usize) {
        let pad = |n: usize, o: &mut String| o.push_str(&" ".repeat(n));
        match self {
            J::S(v) => out.push_str(&json_string(v)),
            J::N(v) => {
                if v.is_finite() {
                    // Three decimals is finer than any harness resolution and
                    // keeps a committed results file diffable.
                    let r = (v * 1000.0).round() / 1000.0;
                    if (r - r.trunc()).abs() < 1e-12 && r.abs() < 1e15 {
                        out.push_str(&format!("{r:.1}"));
                    } else {
                        out.push_str(&format!("{r}"));
                    }
                } else {
                    out.push_str("null");
                }
            }
            J::U(v) => out.push_str(&v.to_string()),
            J::Null => out.push_str("null"),
            J::A(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                let scalar = items.iter().all(|i| matches!(i, J::N(_) | J::U(_)));
                if scalar {
                    out.push('[');
                    for (i, it) in items.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        it.render(out, indent);
                    }
                    out.push(']');
                } else {
                    out.push_str("[\n");
                    for (i, it) in items.iter().enumerate() {
                        pad(indent + 2, out);
                        it.render(out, indent + 2);
                        if i != items.len() - 1 {
                            out.push(',');
                        }
                        out.push('\n');
                    }
                    pad(indent, out);
                    out.push(']');
                }
            }
            J::O(fields) => {
                if fields.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                let last = fields.len() - 1;
                for (i, (k, v)) in fields.iter().enumerate() {
                    pad(indent + 2, out);
                    out.push_str(&json_string(k));
                    out.push_str(": ");
                    v.render(out, indent + 2);
                    if i != last {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(indent, out);
                out.push('}');
            }
        }
    }
    fn pretty(&self) -> String {
        let mut out = String::new();
        self.render(&mut out, 0);
        out
    }
    /// True when the object reports a failure, so the process can exit
    /// non-zero and the harness can trust the status alone.
    fn failed(&self) -> bool {
        match self {
            J::O(fields) => fields.iter().any(|(k, v)| match (k.as_str(), v) {
                ("error", _) => true,
                ("errors", J::A(items)) => !items.is_empty(),
                _ => false,
            }),
            _ => false,
        }
    }
}

fn json_string(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn samples_json(v: &Samples, unit: &str) -> J {
    if v.values.is_empty() {
        return J::Null;
    }
    J::O(vec![
        ("count".into(), J::U(v.values.len() as u64)),
        ("min".into(), J::N(v.min())),
        ("median".into(), J::N(v.median())),
        ("p95".into(), J::N(v.rank(95.0))),
        ("p99".into(), J::N(v.rank(99.0))),
        ("max".into(), J::N(v.max())),
        ("unit".into(), s(unit)),
    ])
}

fn s(v: impl Into<String>) -> J {
    J::S(v.into())
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Proxy {
    addr: SocketAddr,
    user: Option<(String, String)>,
}

/// Per-stage connect timing. "How long does connecting take" has three
/// different answers depending on which stage a core answers the SOCKS request
/// at, and collapsing them hides exactly the difference people want to see.
#[derive(Clone, Copy, Default)]
struct ConnectTiming {
    tcp_connect: Duration,
    socks_greeting: Duration,
    socks_connect: Duration,
    total: Duration,
}

impl ConnectTiming {
    /// Kept next to the type it describes: the harness reads the same three
    /// fields out of the JSON, and a fourth stage appearing here without a
    /// matching field there would be a silent gap in every report.
    #[allow(dead_code)]
    fn to_json(self) -> J {
        J::O(vec![
            ("tcp_connect".into(), one(self.tcp_connect)),
            ("socks_greeting".into(), one(self.socks_greeting)),
            ("socks_connect".into(), one(self.socks_connect)),
            ("total".into(), one(self.total)),
        ])
    }
}

fn one(d: Duration) -> J {
    let mut v = Samples::default();
    v.push(d.as_secs_f64() * 1e6);
    samples_json(&v, "microseconds")
}

impl Proxy {
    fn from_flags() -> Self {
        Proxy {
            addr: endpoint("--proxy"),
            user: match (opt_str("--proxy-user"), opt_str("--proxy-pass")) {
                (Some(u), Some(p)) => Some((u, p)),
                _ => None,
            },
        }
    }

    fn connect(&self, target: SocketAddr) -> io::Result<(TcpStream, ConnectTiming)> {
        self.request(target, 1).map(|(s, t, _)| (s, t))
    }

    /// Issue a SOCKS5 request. Returns the stream, the per-stage timing, and
    /// the bound address from the reply (the UDP ASSOCIATE relay endpoint).
    fn request(
        &self,
        target: SocketAddr,
        cmd: u8,
    ) -> io::Result<(TcpStream, ConnectTiming, Vec<u8>)> {
        let t0 = Instant::now();
        let mut sock = TcpStream::connect(self.addr)?;
        sock.set_nodelay(true)?;
        // Without a deadline a peer that accepts and then says nothing blocks
        // the sample forever. The harness has its own wall-clock timeout, but a
        // socket deadline turns the hang into an error that names the stage.
        sock.set_read_timeout(Some(handshake_timeout()))?;
        sock.set_write_timeout(Some(handshake_timeout()))?;
        let tcp_connect = t0.elapsed();

        let t1 = Instant::now();
        match &self.user {
            None => {
                sock.write_all(&[5, 1, 0])?;
                let mut r = [0u8; 2];
                read_exact(&mut sock, &mut r)?;
                if r != [5, 0] {
                    return Err(io::Error::other("socks: no acceptable auth method"));
                }
            }
            Some((u, p)) => {
                sock.write_all(&[5, 2, 0, 2])?;
                let mut r = [0u8; 2];
                read_exact(&mut sock, &mut r)?;
                if r[1] != 2 {
                    return Err(io::Error::other("socks: server refused username auth"));
                }
                if u.len() > 255 || p.len() > 255 {
                    return Err(io::Error::other("socks: credential over 255 bytes"));
                }
                sock.write_all(&[1, u.len() as u8])?;
                sock.write_all(u.as_bytes())?;
                sock.write_all(&[p.len() as u8])?;
                sock.write_all(p.as_bytes())?;
                let mut r = [0u8; 2];
                read_exact(&mut sock, &mut r)?;
                if r[1] != 0 {
                    return Err(io::Error::other("socks: credentials rejected"));
                }
            }
        }
        let socks_greeting = t1.elapsed();

        let t2 = Instant::now();
        let mut req = vec![5, cmd, 0];
        req.push(match target.ip() {
            IpAddr::V4(_) => 1,
            IpAddr::V6(_) => 4,
        });
        match target.ip() {
            IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => req.extend_from_slice(&v6.octets()),
        }
        req.extend_from_slice(&target.port().to_be_bytes());
        sock.write_all(&req)?;
        let mut head = [0u8; 4];
        read_exact(&mut sock, &mut head)?;
        if head[0] != 5 {
            return Err(io::Error::other("socks: reply is not SOCKS5"));
        }
        if head[1] != 0 {
            return Err(io::Error::other(format!(
                "socks request failed, reply code {}",
                head[1]
            )));
        }
        // Drain the bound address so the stream sits exactly at payload.
        let bound_len = match head[3] {
            1 => 6,
            4 => 18,
            3 => {
                let mut n = [0u8; 1];
                read_exact(&mut sock, &mut n)?;
                n[0] as usize
            }
            other => {
                return Err(io::Error::other(format!(
                    "socks: unknown address type {other}"
                )))
            }
        };
        let mut bound = vec![0u8; bound_len];
        read_exact(&mut sock, &mut bound)?;
        let socks_connect = t2.elapsed();
        Ok((
            sock,
            ConnectTiming {
                tcp_connect,
                socks_greeting,
                socks_connect,
                total: t0.elapsed(),
            },
            bound,
        ))
    }
}

/// A transfer deadline scaled to the size of the transfer, with a floor that
/// keeps a small transfer from tripping on scheduling noise.
fn payload_timeout(bytes: u64) -> Duration {
    let seconds = (bytes / (8 * 1024 * 1024)).max(30);
    Duration::from_millis(opt_count("--timeout-ms").unwrap_or(seconds * 1_000))
}

fn handshake_timeout() -> Duration {
    Duration::from_millis(opt_count("--handshake-timeout-ms").unwrap_or(10_000))
}

fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        match sock.read(&mut buf[at..]) {
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(k) => at += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream wire format
// ---------------------------------------------------------------------------
//
// One 24-byte header, then payload. Both counts are stated from the *client's*
// point of view, so the sink's job is always "write down_n, read up_n":
//
//     down_n     i64   bytes the client reads   (the sink writes them)
//     up_n       i64   bytes the client writes  (the sink reads them)
//     offset     u64   where this flow's bytes start in the keystream
//
// Naming the counts for the client is what keeps the duplex path from being
// written backwards: a field named after the sender invites the reader to swap
// the two halves. The offset travels in the header because the sink cannot
// otherwise know which region of the keystream this flow is using, and giving
// every concurrent flow a different region is what catches a core that
// interleaves two sessions' bytes onto one carrier.
//
// Zero in a count means that direction is idle. The sink always finishes with a
// single completion byte, so the client's clock stops on a real event rather
// than on a close whose timing it would have to infer. `hold` sends two zero
// counts and never completes, which is the whole point of it.

fn header(down_n: u64, up_n: u64, offset: u64) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[..8].copy_from_slice(&(down_n as i64).to_be_bytes());
    h[8..16].copy_from_slice(&(up_n as i64).to_be_bytes());
    h[16..].copy_from_slice(&offset.to_be_bytes());
    h
}

fn sink_stream(mut sock: TcpStream, pattern: Arc<Pattern>) -> io::Result<()> {
    sock.set_nodelay(true)?;
    let mut head = [0u8; 24];
    read_exact(&mut sock, &mut head)?;
    let down_n = u64::try_from(i64::from_be_bytes(head[..8].try_into().unwrap())).unwrap_or(0);
    let up_n = u64::try_from(i64::from_be_bytes(head[8..16].try_into().unwrap())).unwrap_or(0);
    let offset = u64::from_be_bytes(head[16..].try_into().unwrap()) as usize % PATTERN_LEN;

    let result = match (down_n, up_n) {
        (0, 0) => {
            // `hold`: no payload and no completion. Idle until the client goes.
            let mut scratch = [0u8; 256];
            let _ = sock.read(&mut scratch);
            Ok(())
        }
        // One direction: `down` is a write from here, `up` is a read.
        (n, 0) => write_blocks(&mut sock, &pattern, n, offset),
        (0, n) => read_blocks(&mut sock, n),
        (down, up) => {
            // Both at once. The reader takes its own handle so the writer keeps
            // the real one and stays on this thread; joining before the
            // completion byte is what makes that completion mean "both halves
            // finished" rather than "one half finished".
            let mut reader = sock.try_clone()?;
            let handle = thread::spawn(move || read_blocks(&mut reader, up));
            let write = write_blocks(&mut sock, &pattern, down, offset);
            let read = match handle.join() {
                Ok(r) => r,
                Err(_) => Err(io::Error::other("sink reader panicked")),
            };
            write.and(read)
        }
    };
    if result.is_ok() && (down_n > 0 || up_n > 0) {
        let _ = sock.write_all(&[1u8]);
    }
    result
}

/// Write `total` keystream bytes towards the client, starting at `start`.
fn write_blocks(
    sock: &mut TcpStream,
    pattern: &Pattern,
    total: u64,
    start: usize,
) -> io::Result<()> {
    let mut block = Vec::with_capacity(BLOCK);
    let mut left = total;
    let mut offset = start;
    while left > 0 {
        let take = left.min(BLOCK as u64) as usize;
        pattern.slice(offset, take, &mut block);
        sock.write_all(&block)?;
        offset = (offset + take) % PATTERN_LEN;
        left -= take as u64;
    }
    sock.flush()
}

/// Discard `total` bytes from the client. The client validates; the sink only
/// has to keep the socket drained.
fn read_blocks(sock: &mut TcpStream, total: u64) -> io::Result<()> {
    let mut buf = vec![0u8; BLOCK];
    let mut left = total;
    while left > 0 {
        let take = left.min(BLOCK as u64) as usize;
        read_exact(sock, &mut buf[..take])?;
        left -= take as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

fn cmd_sink(port: u16) -> io::Result<()> {
    let pattern = Arc::new(Pattern::new(opt_count("--seed").unwrap_or(DEFAULT_SEED)));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    eprintln!("loadgen sink listening on 127.0.0.1:{port}");
    for sock in listener.incoming() {
        let Ok(sock) = sock else { continue };
        let p = pattern.clone();
        thread::spawn(move || {
            let _ = sink_stream(sock, p);
        });
    }
    Ok(())
}

/// Echo one datagram per received datagram. The generator sends a SOCKS5 UDP
/// request header followed by a keystream block and expects the same bytes
/// back, so validation works the same way it does on a stream.
fn cmd_sink_udp(port: u16) -> io::Result<()> {
    let pattern = Arc::new(Pattern::new(opt_count("--seed").unwrap_or(DEFAULT_SEED)));
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))?;
    eprintln!("loadgen sink-udp listening on 127.0.0.1:{port}");
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        let Some(overhead) = socks_udp_header_len(&buf[..n]) else {
            continue;
        };
        let body = &buf[overhead..n];
        let mut block = Vec::with_capacity(body.len());
        // Offset 0 on both sides: a UDP datagram has nowhere to carry a flow
        // index, and per-flow separation only matters where flows share a
        // carrier, which is a TCP property.
        pattern.slice(0, body.len(), &mut block);
        let mut out = Vec::with_capacity(overhead + block.len());
        out.extend_from_slice(&buf[..overhead]);
        out.extend_from_slice(&block);
        let _ = sock.send_to(&out, from);
    }
}

/// Length of a SOCKS5 UDP request header, or None when the datagram is not a
/// well-formed request.
fn socks_udp_header_len(d: &[u8]) -> Option<usize> {
    if d.len() < 5 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
        return None;
    }
    Some(match d[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 5 + *d.get(4)? as usize + 2,
        _ => return None,
    })
}

fn socks_udp_addr(reply: &[u8]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([*reply.last()?, *reply.get(reply.len() - 2)?]);
    Some(match reply.first()? {
        1 => SocketAddr::from((Ipv4Addr::from(<[u8; 4]>::try_from(&reply[1..5]).ok()?), port)),
        4 => SocketAddr::from((Ipv6Addr::from(<[u8; 16]>::try_from(&reply[1..17]).ok()?), port)),
        3 => {
            let len = *reply.get(1)? as usize;
            let host = std::str::from_utf8(&reply[2..2 + len]).ok()?;
            SocketAddr::from((host.parse::<Ipv4Addr>().ok()?, port))
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Shared byte accounting
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    first_ns: AtomicU64,
    last_ns: AtomicU64,
}

impl Counters {
    fn new() -> Self {
        Counters {
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            first_ns: AtomicU64::new(u64::MAX),
            last_ns: AtomicU64::new(0),
        }
    }
    /// Open and extend the transfer window. `moved` is a running payload total,
    /// so the window never opens on a zero-byte event.
    fn mark(&self, moved: u64) {
        if moved == 0 {
            return;
        }
        let now = monotonic_ns();
        let _ = self.first_ns.compare_exchange(
            u64::MAX,
            now,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.last_ns.store(now, Ordering::SeqCst);
    }
    fn transfer_s(&self) -> f64 {
        let first = self.first_ns.load(Ordering::Relaxed);
        let last = self.last_ns.load(Ordering::Relaxed);
        if first == u64::MAX || last <= first {
            0.0
        } else {
            (last - first) as f64 / 1e9
        }
    }
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

/// What one flow did, kept per flow so a fast median cannot hide the fact that
/// one stream in sixty-four never validated.
struct Flow {
    setup_us: f64,
    result: io::Result<u64>,
}

/// Drive one flow. `duplex` spawns a writer thread holding its own `Arc`s, so
/// there is no borrow to reason about and nothing unsafe.
fn run_flow(
    mut sock: TcpStream,
    index: usize,
    down_n: u64,
    up_n: u64,
    counters: &Arc<Counters>,
    pattern: &Arc<Pattern>,
    chunk: usize,
) -> io::Result<u64> {
    let base = flow_offset(index);
    sock.write_all(&header(down_n, up_n, base as u64))?;
    // The payload window is generous: it only has to catch a peer that has
    // stopped responding, not one that is merely slower than another core.
    if down_n > 0 || up_n > 0 {
        sock.set_read_timeout(Some(payload_timeout(down_n + up_n)))?;
        sock.set_write_timeout(Some(payload_timeout(down_n + up_n)))?;
    }

    match (down_n, up_n) {
        (0, 0) => {
            let mut scratch = [0u8; 256];
            let _ = sock.read(&mut scratch);
            Ok(0)
        }
        (n, 0) => {
            recv_side(&mut sock, base, n, counters, pattern, chunk)?;
            read_exact(&mut sock, &mut [0u8; 1])?;
            Ok(n)
        }
        (0, n) => {
            send_side(&mut sock, base, n, counters, pattern)?;
            read_exact(&mut sock, &mut [0u8; 1])?;
            Ok(n)
        }
        (down, up) => {
            // Both halves at once. The writer thread carries its own pattern
            // handle and writes into its own counters, so the window this side
            // times is the receive window: on loopback the reader is the side
            // that can stall, and timing the writer instead would flatter a core
            // whose send path is slower than its receive path.
            // The writer shares the real counters. They are atomic, so there is
            // nothing to synchronise beyond the join, and giving the writer a
            // private pair is how a duplex run reported `bytes_sent: 0` after
            // writing a hundred megabytes and a rate half of the truth.
            let mut writer = sock.try_clone()?;
            let write_pattern = pattern.clone();
            let write_counters = counters.clone();
            let handle = thread::spawn(move || {
                send_side(&mut writer, base, up, &write_counters, &write_pattern)
            });
            let received = recv_side(&mut sock, base, down, counters, pattern, chunk);
            // No half-close here. The reader has already returned, so there is
            // nobody to unblock, and shutting the write side at this point
            // discards the sink's completion byte through any relay that tears a
            // connection down on EOF -- which a proxy, or a user's own forwarder,
            // very well might.
            let sent = match handle.join() {
                Ok(r) => r,
                Err(_) => Err(io::Error::other("duplex writer panicked")),
            };
            received?;
            sent?;
            let mut ack = [0u8; 1];
            read_exact(&mut sock, &mut ack)?;
            Ok(counters.sent.load(Ordering::Relaxed) + counters.received.load(Ordering::Relaxed))
        }
    }
}

fn send_side(
    sock: &mut TcpStream,
    base: usize,
    total: u64,
    counters: &Arc<Counters>,
    pattern: &Arc<Pattern>,
) -> io::Result<()> {
    let mut block = Vec::with_capacity(BLOCK);
    let mut left = total;
    let mut offset = base;
    while left > 0 {
        let take = left.min(BLOCK as u64) as usize;
        pattern.slice(offset, take, &mut block);
        sock.write_all(&block)?;
        offset = (offset + take) % PATTERN_LEN;
        left -= take as u64;
        let moved = counters.sent.fetch_add(take as u64, Ordering::Relaxed) + take as u64;
        // The window tracks whichever side is carrying payload, so `up` and
        // `duplex` are timed on real bytes rather than on a reader stalling.
        counters.mark(moved);
    }
    sock.flush()
}

fn recv_side(
    sock: &mut TcpStream,
    base: usize,
    total: u64,
    counters: &Arc<Counters>,
    pattern: &Arc<Pattern>,
    chunk: usize,
) -> io::Result<u64> {
    // A multiple of 8 so the 8-byte-at-a-time compare stays aligned, and never
    // larger than the sink's own block.
    let block = (chunk.clamp(8, BLOCK) / 8 * 8).max(8);
    let mut buf = vec![0u8; block];
    let mut left = total;
    let mut offset = base;
    while left > 0 {
        let take = left.min(block as u64) as usize;
        read_exact(sock, &mut buf[..take])?;
        if let Err(at) = pattern.verify(offset, &buf[..take]) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "payload mismatch at flow offset {} (pattern offset {})",
                    at,
                    (offset + at) % PATTERN_LEN
                ),
            ));
        }
        offset = (offset + take) % PATTERN_LEN;
        left -= take as u64;
        let moved = counters.received.fetch_add(take as u64, Ordering::Relaxed) + take as u64;
        counters.mark(moved);
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Bulk workloads
// ---------------------------------------------------------------------------

/// How many flows one worker thread opens at a time.
///
/// Bulk modes get one thread per flow, because a throughput measurement with
/// fewer threads than flows measures the thread count. `hold` is the opposite:
/// it opens a thousand flows and then sends nothing, so a thousand threads
/// would measure the harness's scheduler instead of the core's memory.
/// A direction's byte count for one flow: the flow's own share in the
/// download or upload direction, and nothing in the other.
fn flow_counts(share: u64, direction: u64) -> u64 {
    if direction == 0 {
        0
    } else {
        share
    }
}

fn worker_count(mode: &str, streams: usize) -> usize {
    if mode == "hold" {
        return opt_usize("--concurrency").unwrap_or(32).clamp(1, streams);
    }
    opt_usize("--concurrency")
        .unwrap_or(512)
        .clamp(1, streams)
}

fn cmd_bulk(proxy: Proxy, target: SocketAddr, mode: &str) -> J {
    let bytes = opt_count("--bytes").unwrap_or(256 * 1024 * 1024);
    if bytes == 0 && mode != "hold" {
        // A zero-length transfer encodes as "no payload in either direction",
        // which is the hold shape. Taking it as a request to move no bytes and
        // report a rate of zero would be a plausible-looking wrong answer.
        return die("--bytes must be at least 1 unless the mode is `hold`");
    }
    let streams = opt_usize("--streams").unwrap_or(1).max(1);
    let chunk = opt_usize("--chunk").unwrap_or(BLOCK);
    let hold_ms = opt_count("--hold-ms").unwrap_or(0);
    // Opening a thousand flows in the same millisecond measures the listen
    // backlog rather than the core. A short ramp keeps the rate honest and the
    // time taken to open every flow is reported on its own.
    let ramp_us = opt_count("--ramp-us").unwrap_or(0);
    let pattern = Arc::new(Pattern::new(opt_count("--seed").unwrap_or(DEFAULT_SEED)));
    let per = bytes / streams as u64;
    // The remainder goes to the first `bytes % streams` flows, so the flows add
    // up to exactly what was requested. Truncating instead loses up to
    // `streams - 1` bytes, and a request that silently moves less than it asked
    // for is a defect a reader has to notice on their own.
    let remainder = bytes % streams as u64;
    let counters = Arc::new(Counters::new());
    let (down_n, up_n) = match mode {
        "down" => (per, 0),
        "up" => (0, per),
        "duplex" => (per, per),
        "hold" => (0, 0),
        other => return die(format!("unknown mode {other}")),
    };

    let workers = worker_count(mode, streams);
    // Copied into the workers: a `&str` borrowed from the argument does not
    // outlive the spawn, and the only thing the workers need to know is whether
    // this is the idle-flow shape.
    let is_hold = down_n == 0 && up_n == 0;
    let next = Arc::new(AtomicU64::new(0));
    let opened = Arc::new(AtomicU64::new(0));
    let failed_open = Arc::new(AtomicU64::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let flows: Arc<Mutex<Vec<Flow>>> = Arc::new(Mutex::new(Vec::new()));

    let started = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..workers {
        let proxy = proxy.clone();
        let counters = counters.clone();
        let pattern = pattern.clone();
        let flows = flows.clone();
        let next = next.clone();
        let opened = opened.clone();
        let failed_open = failed_open.clone();
        let release = release.clone();
        handles.push(thread::spawn(move || {
            let mut held: Vec<TcpStream> = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::SeqCst) as usize;
                if index >= streams {
                    break;
                }
                let share = per + u64::from((index as u64) < remainder);
                if ramp_us > 0 {
                    thread::sleep(Duration::from_micros(ramp_us));
                }
                match proxy.connect(target) {
                    Ok((mut sock, timing)) => {
                        opened.fetch_add(1, Ordering::Relaxed);
                        if is_hold {
                            // A held flow sends nothing; the sink waits for a
                            // header that never arrives, which is the point.
                            sock.write_all(&header(0, 0, 0)).ok();
                            held.push(sock);
                            flows.lock().unwrap().push(Flow {
                                setup_us: timing.total.as_secs_f64() * 1e6,
                                result: Ok(0),
                            });
                        } else {
                            let flow = Flow {
                                setup_us: timing.total.as_secs_f64() * 1e6,
                                result: run_flow(
                                    sock,
                                    index,
                                    flow_counts(share, down_n),
                                    flow_counts(share, up_n),
                                    &counters,
                                    &pattern,
                                    chunk,
                                ),
                            };
                            opened.fetch_add(1, Ordering::Relaxed);
                            flows.lock().unwrap().push(flow);
                        }
                    }
                    Err(e) => {
                        failed_open.fetch_add(1, Ordering::Relaxed);
                        flows.lock().unwrap().push(Flow {
                            setup_us: 0.0,
                            result: Err(io::Error::other(format!("connect: {e}"))),
                        });
                    }
                }
            }
            if is_hold {
                while !release.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(20));
                }
                drop(held);
            }
        }));
    }

    // Wait for every flow to be open before the hold window starts, so the
    // scenario measures a settled number of open flows.
    let open_deadline = started + Duration::from_millis(opt_count("--open-timeout-ms").unwrap_or(60_000));
    while opened.load(Ordering::Relaxed) + failed_open.load(Ordering::Relaxed) < streams as u64
        && Instant::now() < open_deadline
        && !release.load(Ordering::Relaxed)
    {
        thread::sleep(Duration::from_millis(5));
    }
    let open_ms = started.elapsed().as_secs_f64() * 1e3;
    if hold_ms > 0 {
        thread::sleep(Duration::from_millis(hold_ms));
        release.store(true, Ordering::Relaxed);
    }
    let mut panicked = 0usize;
    for h in handles {
        if h.join().is_err() {
            panicked += 1;
        }
    }
    let total = started.elapsed();
    let flows = flows.lock().unwrap();

    let mut errors: Vec<String> = Vec::new();
    let mut setups = Samples::default();
    for (i, f) in flows.iter().enumerate() {
        setups.push(f.setup_us);
        if let Err(e) = &f.result {
            if errors.len() < 8 {
                errors.push(format!("flow {i}: {e}"));
            }
        }
    }
    if panicked > 0 {
        errors.push(format!("{panicked} of {streams} flows panicked"));
    }

    let sent = counters.sent.load(Ordering::Relaxed);
    let received = counters.received.load(Ordering::Relaxed);
    let moved = match mode {
        "down" => received,
        "up" => sent,
        "duplex" => sent + received,
        _ => 0,
    };
    let transfer_s = counters.transfer_s();
    let denom = if transfer_s > 0.0 { transfer_s } else { total.as_secs_f64() };
    let measured = if transfer_s > 0.0 { transfer_s } else { 0.0 };

    J::O(vec![
        ("schema".into(), s(SCHEMA)),
        ("mode".into(), s(mode)),
        ("streams".into(), J::U(streams as u64)),
        ("worker_threads".into(), J::U(workers as u64)),
        ("flows_opened".into(), J::U(opened.load(Ordering::Relaxed))),
        ("open_ms".into(), J::N(open_ms)),
        ("ramp_us".into(), J::U(ramp_us)),
        // `--bytes` is the request *per direction*: `down` and `up` move it
        // once, `duplex` moves it once each way. Stated here because
        // `bytes_moved` is the total, and the ratio between the two is 1 or 2.
        ("bytes_requested_per_direction".into(), J::U(bytes)),
        ("directions".into(), J::U(if down_n > 0 && up_n > 0 { 2 } else { 1 })),
        ("bytes_sent".into(), J::U(sent)),
        ("bytes_received".into(), J::U(received)),
        ("bytes_moved".into(), J::U(moved)),
        ("connect_us".into(), samples_json(&setups, "microseconds")),
        ("transfer_ms".into(), J::N(measured * 1e3)),
        ("total_ms".into(), J::N(total.as_secs_f64() * 1e3)),
        (
            "throughput_mbps".into(),
            J::N(if denom > 0.0 { moved as f64 * 8.0 / denom / 1e6 } else { 0.0 }),
        ),
        (
            "MBps".into(),
            J::N(if denom > 0.0 { moved as f64 / denom / 1e6 } else { 0.0 }),
        ),
        ("errors".into(), J::A(errors.into_iter().map(s).collect())),
    ])
}

// ---------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------

fn cmd_latency(proxy: Proxy, target: SocketAddr) -> J {
    let iterations = opt_count("--iterations").unwrap_or(1000);
    let warmup = opt_count("--warmup").unwrap_or(50);
    // A whole number of 8-byte blocks, so the fast compare path stays aligned.
    let payload = (opt_usize("--payload").unwrap_or(1024) / 8 * 8).max(8);
    let pattern = Arc::new(Pattern::new(opt_count("--seed").unwrap_or(DEFAULT_SEED)));
    let mut got = vec![0u8; payload];

    let mut rtt = Samples::default();
    let mut connect_total = Samples::default();
    let mut phases: BTreeMap<&str, Samples> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();
    let started = Instant::now();
    // `wall_ms` covers the warmup too, and an operations rate that divides a
    // measured count by a window that includes unmeasured iterations is biased
    // low by exactly the warmup's share. So the clock for the measured phase is
    // started at the first recorded iteration, not at the loop.
    let mut measured_at: Option<Instant> = None;

    for i in 0..(iterations + warmup) {
        let (mut sock, t) = match proxy.connect(target) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("iteration {i}: connect: {e}"));
                break;
            }
        };
        let t0 = Instant::now();
        let outcome = (|| -> io::Result<()> {
            // One payload block from the start of the keystream.
            sock.write_all(&header(payload as u64, 0, 0))?;
            read_exact(&mut sock, &mut got)?;
            if let Err(at) = pattern.verify(0, &got) {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("payload mismatch at offset {at}"),
                ));
            }
            read_exact(&mut sock, &mut [0u8; 1])?;
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                if i >= warmup {
                    let _ = measured_at.get_or_insert_with(Instant::now);
                    rtt.push(t0.elapsed().as_secs_f64() * 1e6);
                    connect_total.push(t.total.as_secs_f64() * 1e6);
                    phases
                        .entry("tcp_connect")
                        .or_default()
                        .push(t.tcp_connect.as_secs_f64() * 1e6);
                    phases
                        .entry("socks_greeting")
                        .or_default()
                        .push(t.socks_greeting.as_secs_f64() * 1e6);
                    phases
                        .entry("socks_connect")
                        .or_default()
                        .push(t.socks_connect.as_secs_f64() * 1e6);
                }
            }
            Err(e) => {
                errors.push(format!("iteration {i}: {e}"));
                break;
            }
        }
    }

    if rtt.values.is_empty() {
        return die(if errors.is_empty() {
            "no latency samples collected".to_string()
        } else {
            errors[0].clone()
        });
    }
    J::O(vec![
        ("schema".into(), s(SCHEMA)),
        ("mode".into(), s("latency")),
        ("iterations".into(), J::U(iterations)),
        ("warmup".into(), J::U(warmup)),
        ("payload_bytes".into(), J::U(payload as u64)),
        ("wall_ms".into(), J::N(started.elapsed().as_secs_f64() * 1e3)),
        (
            "measured_ms".into(),
            J::N(
                measured_at
                    .map(|t| t.elapsed().as_secs_f64() * 1e3)
                    .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1e3),
            ),
        ),
        ("latency_us".into(), samples_json(&rtt, "microseconds")),
        (
            "connect_us".into(),
            J::O(vec![
                ("total".into(), samples_json(&connect_total, "microseconds")),
                (
                    "stages".into(),
                    J::O(phases
                        .iter()
                        .map(|(k, v)| (k.to_string(), samples_json(v, "microseconds")))
                        .collect()),
                ),
            ]),
        ),
        ("errors".into(), J::A(errors.into_iter().map(s).collect())),
    ])
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

fn cmd_udp(proxy: Proxy, target: SocketAddr) -> J {
    let iterations = opt_count("--iterations").unwrap_or(1000);
    let warmup = opt_count("--warmup").unwrap_or(50);
    let payload = (opt_usize("--payload").unwrap_or(512) / 8 * 8).max(8);
    let timeout = Duration::from_millis(opt_count("--timeout-ms").unwrap_or(3_000));
    let pattern = Arc::new(Pattern::new(opt_count("--seed").unwrap_or(DEFAULT_SEED)));

    // The relay endpoint exists only in the ASSOCIATE reply, so it is requested
    // first and the control socket is held open for the life of the run.
    let (mut ctl, _timing, reply) = match proxy.request(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), 3) {
        Ok(v) => v,
        Err(e) => return die(format!("socks udp associate: {e}")),
    };
    let Some(relay) = socks_udp_addr(&reply) else {
        return die("socks: UDP ASSOCIATE reply carried no usable relay address");
    };

    let sock = match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(v) => v,
        Err(e) => return die(format!("bind udp: {e}")),
    };
    let _ = sock.set_read_timeout(Some(timeout));
    let local = sock.local_addr().map(|a| a.port()).unwrap_or(0);

    let mut udp_header = vec![0u8, 0, 0];
    match target.ip() {
        IpAddr::V4(v4) => {
            udp_header.push(1);
            udp_header.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            udp_header.push(4);
            udp_header.extend_from_slice(&v6.octets());
        }
    }
    udp_header.extend_from_slice(&target.port().to_be_bytes());
    // SOCKS5 UDP requests carry the sender's own address. A bound address is
    // what the relay has to send the reply to, so a zero port here means lost
    // replies rather than a faster path.
    udp_header.extend_from_slice(&[127, 0, 0, 1]);
    udp_header.extend_from_slice(&local.to_be_bytes());

    let payload_block = {
        let mut v = Vec::with_capacity(payload);
        pattern.slice(0, payload, &mut v);
        v
    };
    let mut dgram = udp_header.clone();
    dgram.extend_from_slice(&payload_block);

    let mut rtt = Samples::default();
    let mut errors: Vec<String> = Vec::new();
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut buf = vec![0u8; 128 * 1024];
    let started = Instant::now();
    let mut measured_at: Option<Instant> = None;

    for i in 0..(iterations + warmup) {
        let t0 = Instant::now();
        if let Err(e) = sock.send_to(&dgram, relay) {
            errors.push(format!("iteration {i}: send: {e}"));
            break;
        }
        sent += 1;
        match sock.recv(&mut buf) {
            Ok(n) => {
                let Some(overhead) = socks_udp_header_len(&buf[..n]) else {
                    errors.push(format!("iteration {i}: reply was not a SOCKS5 UDP datagram"));
                    break;
                };
                let body = &buf[overhead..n];
                let usable = body.len().min(payload);
                if let Err(at) = pattern.verify(0, &body[..usable]) {
                    errors.push(format!("iteration {i}: payload mismatch at {at}"));
                    break;
                }
                received += usable as u64;
                if i >= warmup {
                    let _ = measured_at.get_or_insert_with(Instant::now);
                    rtt.push(t0.elapsed().as_secs_f64() * 1e6);
                }
            }
            Err(e) => {
                errors.push(format!("iteration {i}: recv: {e}"));
                break;
            }
        }
    }
    let wall = started.elapsed();
    let _ = &mut ctl;

    if rtt.values.is_empty() {
        return die(if errors.is_empty() {
            "no UDP samples collected".to_string()
        } else {
            errors[0].clone()
        });
    }
    J::O(vec![
        ("schema".into(), s(SCHEMA)),
        ("mode".into(), s("udp")),
        ("iterations".into(), J::U(iterations)),
        ("warmup".into(), J::U(warmup)),
        ("payload_bytes".into(), J::U(payload as u64)),
        ("datagrams_sent".into(), J::U(sent)),
        ("bytes_received".into(), J::U(received)),
        ("wall_ms".into(), J::N(wall.as_secs_f64() * 1e3)),
        (
            "measured_ms".into(),
            J::N(measured_at.map(|t| t.elapsed().as_secs_f64() * 1e3).unwrap_or(wall.as_secs_f64() * 1e3)),
        ),
        ("latency_us".into(), samples_json(&rtt, "microseconds")),
        (
            "throughput_mbps".into(),
            J::N(if wall.as_secs_f64() > 0.0 {
                received as f64 * 8.0 / wall.as_secs_f64() / 1e6
            } else {
                0.0
            }),
        ),
        ("errors".into(), J::A(errors.into_iter().map(s).collect())),
    ])
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

/// Establish the tunnel and close it. No payload is exchanged.
///
/// This exists because a throughput run needs a destination that speaks the
/// harness's own framed keystream, and the only endpoint a supplied
/// configuration reliably names is its own proxy server -- which speaks the
/// proxy protocol, not this one. Pointing a `down` run at that port fails by
/// construction, so the only honest measurements available for an arbitrary
/// config are the ones that stop once the tunnel is up: whether it comes up at
/// all, and how long the whole path takes.
fn cmd_probe(proxy: Proxy, target: SocketAddr) -> J {
    let iterations = opt_count("--iterations").unwrap_or(200);
    let warmup = opt_count("--warmup").unwrap_or(10);
    let mut rtt = Samples::default();
    let mut connect_total = Samples::default();
    let mut phases: BTreeMap<&str, Samples> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();
    let started = Instant::now();
    let mut measured_at: Option<Instant> = None;

    for i in 0..(iterations + warmup) {
        let t0 = Instant::now();
        match proxy.connect(target) {
            Ok((sock, timing)) => {
                drop(sock);
                if i >= warmup {
                    let _ = measured_at.get_or_insert_with(Instant::now);
                    rtt.push(t0.elapsed().as_secs_f64() * 1e6);
                    connect_total.push(timing.total.as_secs_f64() * 1e6);
                    phases.entry("tcp_connect").or_default()
                        .push(timing.tcp_connect.as_secs_f64() * 1e6);
                    phases.entry("socks_greeting").or_default()
                        .push(timing.socks_greeting.as_secs_f64() * 1e6);
                    phases.entry("socks_connect").or_default()
                        .push(timing.socks_connect.as_secs_f64() * 1e6);
                }
            }
            Err(e) => {
                errors.push(format!("iteration {i}: connect: {e}"));
                break;
            }
        }
    }

    let succeeded = rtt.values.len() as u64;
    J::O(vec![
        ("schema".into(), s(SCHEMA)),
        ("mode".into(), s("probe")),
        ("iterations".into(), J::U(iterations)),
        ("warmup".into(), J::U(warmup)),
        ("succeeded".into(), J::U(succeeded)),
        ("wall_ms".into(), J::N(started.elapsed().as_secs_f64() * 1e3)),
        (
            "measured_ms".into(),
            J::N(
                measured_at
                    .map(|t| t.elapsed().as_secs_f64() * 1e3)
                    .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1e3),
            ),
        ),
        ("tunnel_us".into(), samples_json(&rtt, "microseconds")),
        (
            "connect_us".into(),
            J::O(vec![
                ("total".into(), samples_json(&connect_total, "microseconds")),
                (
                    "stages".into(),
                    J::O(phases
                        .iter()
                        .map(|(k, v)| (k.to_string(), samples_json(v, "microseconds")))
                        .collect()),
                ),
            ]),
        ),
        ("errors".into(), J::A(errors.into_iter().map(s).collect())),
    ])
}

// ---------------------------------------------------------------------------
// Harness ceiling
// ---------------------------------------------------------------------------

/// The same validation loop over a bare socket, with no core in the path.
///
/// A core that lands near this number is limited by the harness rather than by
/// the core, and any remaining difference between cores at the ceiling is not
/// a property of the cores. Publishing the ceiling is what stops a chart from
/// implying a precision it does not have.
fn cmd_selftest(target: SocketAddr) -> J {
    let bytes = opt_count("--bytes").unwrap_or(512 * 1024 * 1024);
    let streams = opt_usize("--streams").unwrap_or(4).max(1);
    let chunk = opt_usize("--chunk").unwrap_or(BLOCK);
    let pattern = Arc::new(Pattern::new(opt_count("--seed").unwrap_or(DEFAULT_SEED)));
    let per = bytes / streams as u64;
    let remainder = bytes % streams as u64;
    let counters = Arc::new(Counters::new());
    let started = Instant::now();
    let mut handles = Vec::new();
    for i in 0..streams {
        let counters = counters.clone();
        let pattern = pattern.clone();
        let share = per + u64::from((i as u64) < remainder);
        handles.push(thread::spawn(move || {
            let sock = match TcpStream::connect(target) {
                Ok(sock) => sock,
                Err(e) => {
                    eprintln!("selftest: flow {i} could not connect: {e}");
                    return;
                }
            };
            let _ = sock.set_nodelay(true);
            // A download: the sink writes this flow's share, this side reads
            // and validates every byte of it.
            if let Err(e) = run_flow(sock, i, share, 0, &counters, &pattern, chunk) {
                eprintln!("selftest: flow {i} failed: {e}");
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let total = started.elapsed();
    let moved = counters.received.load(Ordering::Relaxed);
    let transfer_s = counters.transfer_s();
    let denom = if transfer_s > 0.0 { transfer_s } else { total.as_secs_f64() };
    J::O(vec![
        ("schema".into(), s(SCHEMA)),
        ("mode".into(), s("selftest")),
        ("streams".into(), J::U(streams as u64)),
        ("bytes_moved".into(), J::U(moved)),
        ("transfer_ms".into(), J::N(transfer_s * 1e3)),
        ("total_ms".into(), J::N(total.as_secs_f64() * 1e3)),
        (
            "throughput_mbps".into(),
            J::N(if denom > 0.0 { moved as f64 * 8.0 / denom / 1e6 } else { 0.0 }),
        ),
        (
            "MBps".into(),
            J::N(if denom > 0.0 { moved as f64 / denom / 1e6 } else { 0.0 }),
        ),
    ])
}

// ---------------------------------------------------------------------------

const USAGE: &str = "\
loadgen - traffic generator and sink for the Zray benchmark harness

  loadgen sink     --port N
  loadgen sink-udp --port N
  loadgen run      --proxy HOST:PORT --target HOST:PORT --mode MODE [--json]
  loadgen selftest --target HOST:PORT [--bytes N] [--streams N] [--json]

modes: down, up, duplex, hold, latency, probe, udp-down, udp-latency
";

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let sub = argv.get(1).map(String::as_str).unwrap_or("help");
    let result: J = match sub {
        "sink" | "sink-udp" => {
            let port = req_usize("--port") as u16;
            let outcome = if sub == "sink" {
                cmd_sink(port)
            } else {
                cmd_sink_udp(port)
            };
            match outcome {
                Ok(()) => return,
                Err(e) => die(e.to_string()),
            }
        }
        "run" => {
            let proxy = Proxy::from_flags();
            let target = endpoint("--target");
            match opt_str("--mode").unwrap_or_else(|| "down".into()).as_str() {
                "down" | "up" | "duplex" | "hold" => {
                    let mode = opt_str("--mode").unwrap_or_else(|| "down".into());
                    cmd_bulk(proxy, target, &mode)
                }
                "latency" => cmd_latency(proxy, target),
                "probe" => cmd_probe(proxy, target),
                "udp-down" | "udp-latency" => cmd_udp(proxy, target),
                other => die(format!("unknown --mode {other}\n\n{USAGE}")),
            }
        }
        "selftest" => cmd_selftest(endpoint("--target")),
        other => {
            eprintln!("loadgen: unknown subcommand {other}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if argv.iter().any(|a| a == "--json") {
        println!("{}", result.pretty());
    }
    if result.failed() {
        std::process::exit(1);
    }
}
