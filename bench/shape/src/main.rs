//! Shows what one proxied HTTPS page load looks like from outside the tunnel.
//!
//! How this works: a censor that cannot read a TLS stream can still see the
//! size and direction of every packet in it. A second TLS handshake travelling
//! inside the first has a shape of its own, and "Fingerprinting Obfuscated
//! Proxy Traffic with Encapsulated TLS Handshakes" (Xue et al., USENIX
//! Security 2024) detects proxies by it. This program replays the same inner
//! page load through each of the client's real framings, records every write
//! that reaches the carrier, turns the writes into packets, and prints the
//! features that paper's classifiers look at:
//!
//!  * packet sizes sorted into the paper's four bins (L1 1-160, L2 161-600,
//!    L3 601-1210, L4 1211+) with a sign for direction, read three at a time;
//!  * bursts, which are runs of packets in one direction added together;
//!  * the size of the first burst after the outer handshake and how many
//!    round trips follow it, the two numbers the paper says padding and
//!    multiplexing cannot hide.
//!
//! What it is not: the paper's classifier. That one is trained on an ISP's
//! traffic, which nobody outside has. This prints the inputs such a
//! classifier would get, so a change to the framing can be judged by what it
//! does to them rather than by guesswork. Lower is not automatically safer;
//! the numbers to watch are named next to each check below.
//!
//! The inner page load is a script, not a real handshake: records with real
//! TLS headers and typical sizes (a 517-byte ClientHello, a server flight of
//! a few kilobytes, a short client Finished, a request, a response). The
//! framings under test only ever look at those headers and sizes.
//!
//! Run with `cargo run --release -p shape-bench`. It exits non-zero when a
//! framing regresses on one of the checks.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use zero_core::{boxed, Address, Destination};
use zero_protocol::first_flight::{HeaderFirst, FIRST_PAYLOAD_WAIT};
use zero_protocol::vision::VisionStream;
use zero_protocol::{mux, vless};

const UUID: [u8; 16] = [0x5a; 16];
/// Bytes a TLS 1.3 record adds around its plaintext: header, tag, type byte.
const RECORD_OVERHEAD: usize = 22;
const RECORD_MAX: usize = 16 * 1024;
/// TCP payload per packet on an ordinary 1500-byte path with timestamps.
const MSS: usize = 1448;
/// Runs per framing. Vision pads at random, so one run says little.
const RUNS: usize = 200;

/// Every write that reached the carrier, in order: positive from the client,
/// negative from the server.
type Log = Arc<Mutex<Vec<i64>>>;

/// One end of the carrier. It passes everything through and notes the size of
/// each write, because each write is what the outer TLS layer seals into
/// records and the kernel sends as packets.
struct Tap {
    inner: DuplexStream,
    log: Log,
    sign: i64,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let wrote = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = wrote {
            let entry = self.sign * n as i64;
            self.log.lock().unwrap().push(entry);
        }
        wrote
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn carrier() -> (Tap, Tap, Log) {
    let log = Log::default();
    // Roomy enough that no write is ever split by back-pressure.
    let (client, server) = tokio::io::duplex(1 << 20);
    let tap = |inner, sign| Tap {
        inner,
        log: log.clone(),
        sign,
    };
    (tap(client, 1), tap(server, -1), log)
}

/// A TLS record of `total` bytes on the wire with a believable header.
fn record(content_type: u8, version: u8, total: usize, first_body_byte: u8) -> Vec<u8> {
    let body = total - 5;
    let mut out = vec![content_type, 3, version, (body >> 8) as u8, body as u8];
    out.resize(total, 0xa5);
    out[5] = first_body_byte;
    out
}

/// The inner page load, as the writes each side makes in turn.
struct Script {
    client_hello: Vec<u8>,
    server_flight: Vec<u8>,
    client_finished: Vec<u8>,
    request: Vec<u8>,
    response: Vec<u8>,
}

fn script() -> Script {
    let change_cipher_spec = [0x14, 3, 3, 0, 1, 1];
    let mut server_flight = record(0x16, 3, 127, 2);
    server_flight.extend_from_slice(&change_cipher_spec);
    server_flight.extend_from_slice(&record(0x17, 3, 3600, 0));
    let mut client_finished = change_cipher_spec.to_vec();
    client_finished.extend_from_slice(&record(0x17, 3, 58, 0));
    Script {
        client_hello: record(0x16, 1, 517, 1),
        server_flight,
        client_finished,
        request: record(0x17, 3, 425, 0),
        response: record(0x17, 3, 8000, 0),
    }
}

fn destination() -> Destination {
    Destination::tcp(Address::domain("example.com"), 443)
}

/// The client's half of the page load over whatever framing `stream` is.
async fn browse<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, script: &Script) {
    let mut sink = vec![0u8; script.response.len()];
    stream.write_all(&script.client_hello).await.unwrap();
    stream.flush().await.unwrap();
    stream
        .read_exact(&mut sink[..script.server_flight.len()])
        .await
        .unwrap();
    stream.write_all(&script.client_finished).await.unwrap();
    stream.flush().await.unwrap();
    stream.write_all(&script.request).await.unwrap();
    stream.flush().await.unwrap();
    stream.read_exact(&mut sink).await.unwrap();
}

/// The site's half: read each client write in full, then answer.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, script: &Script, prefix: &[u8]) {
    let mut sink = vec![0u8; 1024];
    stream
        .read_exact(&mut sink[..script.client_hello.len()])
        .await
        .unwrap();
    // A VLESS server answers with a two-byte header in front of its first
    // payload; `prefix` is that header where the framing has not sent it yet.
    let mut first = prefix.to_vec();
    first.extend_from_slice(&script.server_flight);
    stream.write_all(&first).await.unwrap();
    stream.flush().await.unwrap();
    let rest = script.client_finished.len() + script.request.len();
    stream.read_exact(&mut sink[..rest]).await.unwrap();
    stream.write_all(&script.response).await.unwrap();
    stream.flush().await.unwrap();
}

/// Consume the VLESS request header from the server end, a byte at a time so
/// nothing behind it is taken. The parser reports a header cut short inside a
/// field as an error, which here only means "keep reading".
async fn read_request(server: &mut Tap) {
    let mut seen = Vec::new();
    while !matches!(
        vless::parse_request(&seen),
        Ok(vless::RequestParse::Complete { .. })
    ) {
        assert!(seen.len() < 512, "no VLESS request header on the carrier");
        seen.push(server.read_u8().await.unwrap());
    }
}

/// What each scenario sends the header as.
#[derive(Clone, Copy, PartialEq)]
enum Header {
    /// Its own write, flushed, before any payload: the behaviour this bench
    /// was written to measure against.
    Alone,
    /// Held and sent in the first payload's write.
    WithPayload,
}

async fn plain(header: Header) -> Vec<i64> {
    let (mut client, mut server, log) = carrier();
    let script = script();
    let request = vless::encode_request(&UUID, "", &destination()).to_vec();
    let site = async {
        read_request(&mut server).await;
        serve(&mut server, &script, &[0, 0]).await;
    };
    let user = async {
        match header {
            Header::Alone => {
                client.write_all(&request).await.unwrap();
                client.flush().await.unwrap();
                browse(&mut vless::VlessStream::new(client), &script).await;
            }
            Header::WithPayload => {
                let held = HeaderFirst::new(client, request);
                browse(&mut vless::VlessStream::new(held), &script).await;
            }
        }
    };
    tokio::join!(site, user);
    let trace = log.lock().unwrap().clone();
    trace
}

async fn vision(header: Header) -> Vec<i64> {
    let (mut client, mut server, log) = carrier();
    let script = script();
    let request = vless::encode_request(&UUID, "xtls-rprx-vision", &destination()).to_vec();
    let site = async {
        read_request(&mut server).await;
        // The response header in front of the first frame, where the "alone"
        // run sends it by itself as the server used to.
        let server = match header {
            Header::Alone => {
                server.write_all(&[0, 0]).await.unwrap();
                HeaderFirst::hold(server, Vec::new())
            }
            Header::WithPayload => HeaderFirst::hold(server, vec![0, 0]),
        };
        let mut framed = VisionStream::new_server(server, UUID);
        serve(&mut framed, &script, &[]).await;
    };
    let user = async {
        match header {
            Header::Alone => {
                client.write_all(&request).await.unwrap();
                client.flush().await.unwrap();
                // An empty header makes the stream send its padded empty
                // first frame by itself once the wait runs out, which is the
                // three-write opening the client used to make.
                let framed = VisionStream::new_client(client, UUID).with_request_header(&[]);
                let mut framed = vless::VlessStream::new(framed);
                let mut byte = [0u8; 1];
                let waited =
                    tokio::time::timeout(FIRST_PAYLOAD_WAIT * 2, framed.read(&mut byte)).await;
                assert!(waited.is_err(), "the server has nothing to say yet");
                browse(&mut framed, &script).await;
            }
            Header::WithPayload => {
                let framed = VisionStream::new_client(client, UUID).with_request_header(&request);
                browse(&mut vless::VlessStream::new(framed), &script).await;
            }
        }
    };
    tokio::join!(site, user);
    let trace = log.lock().unwrap().clone();
    trace
}

async fn muxed(header: Header) -> Vec<i64> {
    let (mut client, mut server, log) = carrier();
    let script = script();
    let request = vless::encode_mux_request(&UUID, "").to_vec();
    let site = async {
        read_request(&mut server).await;
        let first = mux::read_frame(&mut server).await.unwrap();
        // The real server pool from here on, so the frames going back are
        // padded exactly as a Zray server pads them.
        let (remote, mut origin) = tokio::io::duplex(1 << 20);
        let carrier = boxed(HeaderFirst::hold(server, vec![0, 0]));
        let no_more = |_| async { Err(io::ErrorKind::ConnectionRefused.into()) };
        tokio::select! {
            _ = mux::relay_server_pool(carrier, first, boxed(remote), no_more) => {}
            () = async {
                serve(&mut origin, &script, &[]).await;
                // Keep the origin open until the user has read the response.
                std::future::pending::<()>().await
            } => {}
        }
    };
    let user = async {
        let pool = match header {
            Header::Alone => {
                client.write_all(&request).await.unwrap();
                client.flush().await.unwrap();
                mux::ClientPool::new(client, 8)
            }
            Header::WithPayload => mux::ClientPool::new(HeaderFirst::new(client, request), 8),
        };
        let mut session = pool.open(destination()).unwrap();
        browse(&mut session, &script).await;
    };
    tokio::select! {
        () = site => unreachable!("the site outlives the page load"),
        () = user => {}
    }
    let trace = log.lock().unwrap().clone();
    trace
}

/// One page load through Tide with uploads and downloads on connections of
/// their own. Returns each connection's writes: the first carries the front
/// page fetch, the handshake and the downloads, the second the uploads.
async fn tide_split() -> Vec<Vec<i64>> {
    use std::collections::HashMap;
    use std::sync::RwLock;
    use zero_transport::tide::{Client, ClientConfig, Decoy, Dialer, Server, ServerConfig};

    let (secret, public) = zero_protocol::tide::generate_keypair();
    let user = [1u8; 16];
    let users = Arc::new(RwLock::new(HashMap::from([(user, String::new())])));
    let (server, mut streams) = Server::new(ServerConfig {
        path: "/static/app".into(),
        admin: None,
        secret,
        users,
        decoy: Decoy::default(),
    });
    let origin = tokio::spawn(async move {
        let script = script();
        if let Some((_, _, mut stream)) = streams.recv().await {
            serve(&mut stream, &script, &[]).await;
            // Hold the stream until the client has read the response.
            std::future::pending::<()>().await;
        }
    });
    let logs: Arc<Mutex<Vec<Log>>> = Arc::default();
    let dial: Dialer = {
        let logs = logs.clone();
        Arc::new(move || {
            let (server, logs) = (server.clone(), logs.clone());
            Box::pin(async move {
                let (client, far, log) = carrier();
                logs.lock().unwrap().push(log);
                tokio::spawn(async move { server.serve_connection(boxed(far)).await });
                Ok(boxed(client))
            })
        })
    };
    let client = Client::new(
        ClientConfig {
            host: "example.test".into(),
            path: "/static/app".into(),
            server_public: public,
            user,
            split: true,
            linger: Duration::from_millis(50),
        },
        dial,
    );
    let mut stream = client.open(destination()).await.unwrap();
    browse(&mut stream, &script()).await;
    origin.abort();
    let traces = logs
        .lock()
        .unwrap()
        .iter()
        .map(|log| log.lock().unwrap().clone())
        .collect();
    traces
}

/// Carrier writes as the packets an observer sees: each write sealed into
/// TLS records, the records cut into MSS-sized segments.
fn packets(writes: &[i64]) -> Vec<i64> {
    let mut out = Vec::new();
    for &write in writes {
        let len = write.unsigned_abs() as usize;
        let mut wire = len + RECORD_OVERHEAD * len.div_ceil(RECORD_MAX);
        while wire > 0 {
            let segment = wire.min(MSS);
            out.push(write.signum() * segment as i64);
            wire -= segment;
        }
    }
    out
}

/// The paper's size bins, signed by direction.
fn bin(packet: i64) -> i8 {
    let level = match packet.unsigned_abs() {
        0..=160 => 1,
        161..=600 => 2,
        601..=1210 => 3,
        _ => 4,
    };
    level * packet.signum() as i8
}

/// Runs of packets in one direction, added together.
fn bursts(packets: &[i64]) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::new();
    for &packet in packets {
        match out.last_mut() {
            Some(last) if last.signum() == packet.signum() => *last += packet,
            _ => out.push(packet),
        }
    }
    out
}

/// Two of the 3-grams the paper ranks highest for telling a TLS handshake
/// apart (its Table 2): a ClientHello-sized packet up, then a full packet
/// down, then either more of the server's flight or a small packet up.
const HELLO_GRAMS: [[i8; 3]; 2] = [[2, -4, -4], [2, -4, 1]];

struct Shape {
    packets: Vec<i64>,
    first_packet: i64,
    first_burst: i64,
    round_trips: usize,
    upload: i64,
    /// A ClientHello-shaped opening is visible.
    hello_gram: bool,
    /// A small packet goes up straight after a download burst, which is what
    /// the inner client Finished looks like.
    finished_gram: bool,
}

fn shape(writes: &[i64]) -> Shape {
    let packets = packets(writes);
    let bins: Vec<i8> = packets.iter().map(|&p| bin(p)).collect();
    let bursts = bursts(&packets);
    Shape {
        first_packet: packets[0],
        first_burst: bursts[0],
        round_trips: bursts.iter().filter(|b| **b > 0).count(),
        upload: packets.iter().filter(|p| **p > 0).sum(),
        hello_gram: bins.windows(3).any(|w| HELLO_GRAMS.iter().any(|g| w == g)),
        finished_gram: bins.windows(2).any(|w| w[0] < 0 && w[1] == 1),
        packets,
    }
}

struct Summary {
    name: &'static str,
    sample: Vec<i64>,
    first_packet: (i64, i64, i64),
    first_burst: i64,
    round_trips: usize,
    upload: i64,
    hello_rate: f64,
    finished_rate: f64,
}

fn median(values: &mut [i64]) -> i64 {
    values.sort_unstable();
    values[values.len() / 2]
}

async fn measure<F, Fut>(name: &'static str, run: F) -> Summary
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Vec<i64>>,
{
    let mut shapes = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        shapes.push(shape(&run().await));
    }
    let mut first: Vec<i64> = shapes.iter().map(|s| s.first_packet).collect();
    let mut burst: Vec<i64> = shapes.iter().map(|s| s.first_burst).collect();
    let mut upload: Vec<i64> = shapes.iter().map(|s| s.upload).collect();
    let mut trips: Vec<i64> = shapes.iter().map(|s| s.round_trips as i64).collect();
    let rate = |seen: fn(&Shape) -> bool| {
        shapes.iter().filter(|s| seen(s)).count() as f64 / RUNS as f64 * 100.0
    };
    let (hello_rate, finished_rate) = (rate(|s| s.hello_gram), rate(|s| s.finished_gram));
    Summary {
        name,
        sample: shapes[0].packets.clone(),
        first_packet: (
            *first.iter().min().unwrap(),
            median(&mut first),
            *first.iter().max().unwrap(),
        ),
        first_burst: median(&mut burst),
        round_trips: median(&mut trips) as usize,
        upload: median(&mut upload),
        hello_rate,
        finished_rate,
    }
}

fn print(summary: &Summary) {
    let (low, mid, high) = summary.first_packet;
    println!("\n{}", summary.name);
    println!("  first packet        {mid} bytes (range {low}..{high})");
    println!("  first upload burst  {} bytes", summary.first_burst);
    println!("  upload bursts       {}", summary.round_trips);
    println!("  upload total        {} bytes", summary.upload);
    println!(
        "  ClientHello 3-gram  in {:.0}% of runs",
        summary.hello_rate
    );
    println!(
        "  Finished 2-gram     in {:.0}% of runs",
        summary.finished_rate
    );
    println!("  one run             {:?}", summary.sample);
}

/// One line per claim, and a count of the ones that do not hold.
fn check(failures: &mut u32, holds: bool, claim: &str) {
    println!("  [{}] {claim}", if holds { "ok" } else { "FAIL" });
    if !holds {
        *failures += 1;
    }
}

#[tokio::main(flavor = "current_thread", start_paused = true)]
async fn main() {
    // Paused time: the 100 ms waits in the "alone" runs cost nothing, and the
    // idle timers inside the mux pool never fire mid-run.
    let before = [
        measure("VLESS, header on its own", || plain(Header::Alone)).await,
        measure("VLESS + Vision, header on its own", || {
            vision(Header::Alone)
        })
        .await,
        measure("VLESS + Mux, header on its own", || muxed(Header::Alone)).await,
    ];
    let after = [
        measure("VLESS, header with the first payload", || {
            plain(Header::WithPayload)
        })
        .await,
        measure("VLESS + Vision, header with the first payload", || {
            vision(Header::WithPayload)
        })
        .await,
        measure("VLESS + Mux, header with the first payload", || {
            muxed(Header::WithPayload)
        })
        .await,
    ];
    for summary in before.iter().chain(&after) {
        print(summary);
    }

    println!("\nchecks");
    let mut failures = 0;
    for (old, new) in before.iter().zip(&after) {
        println!(" {}", new.name);
        check(
            &mut failures,
            new.first_packet.0 > 160,
            "the connection never opens with a small (L1) packet",
        );
        if new.name.contains("Mux") {
            // Both Mux runs are padded; the trade here is bytes for shape.
            check(
                &mut failures,
                new.hello_rate == 0.0 && new.finished_rate == 0.0,
                "neither handshake n-gram shows",
            );
            check(
                &mut failures,
                new.upload <= 4500,
                "padding keeps this page load's upload under 4500 bytes",
            );
            continue;
        }
        check(
            &mut failures,
            new.round_trips < old.round_trips || new.upload < old.upload,
            "fewer upload bursts or fewer upload bytes than sending the header alone",
        );
        check(
            &mut failures,
            new.upload <= old.upload,
            "no more upload bytes than before",
        );
    }
    println!("\nTide, one page load, each connection as an observer sees it");
    let mut hello = [0usize; 2];
    let mut finished = [0usize; 2];
    let mut upload = Vec::new();
    let mut sample = Vec::new();
    for run in 0..RUNS {
        let traces = tide_split().await;
        assert_eq!(traces.len(), 2, "one connection each way");
        let mut total = 0;
        for (index, trace) in traces.iter().enumerate() {
            let shape = shape(trace);
            hello[index] += usize::from(shape.hello_gram);
            finished[index] += usize::from(shape.finished_gram);
            total += shape.upload;
            if run == 0 {
                sample.push(shape.packets);
            }
        }
        upload.push(total);
    }
    for (index, name) in ["download connection", "upload connection"]
        .iter()
        .enumerate()
    {
        println!("  {name}");
        println!(
            "    ClientHello 3-gram  in {:.0}% of runs",
            hello[index] as f64 / RUNS as f64 * 100.0
        );
        println!(
            "    Finished 2-gram     in {:.0}% of runs",
            finished[index] as f64 / RUNS as f64 * 100.0
        );
        println!("    one run             {:?}", sample[index]);
    }
    println!(
        "  upload total, both    {} bytes (includes the front page fetch and handshake)",
        median(&mut upload)
    );
    println!(" Tide");
    check(
        &mut failures,
        hello == [0, 0],
        "no connection shows a ClientHello-shaped opening",
    );

    // Give spawned mux tasks a tick to finish before the runtime goes.
    tokio::time::sleep(Duration::from_millis(1)).await;
    if failures > 0 {
        eprintln!("\n{failures} check(s) failed");
        std::process::exit(1);
    }
}
