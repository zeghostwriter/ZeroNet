// Load generator for the core benchmark. Talks plain SOCKS5 to the client
// under test and drives a local TCP sink on the far side of the tunnel.
//
//   sink <port>
//       TCP server. Reads an 8-byte big-endian length, then sends that many
//       bytes; a negative length means "receive that many bytes, then ack".
//
//   run <socks_port> <sink_port> <bytes> <streams> <down|up>
//       Bulk transfer. Prints MB/s.
//
//   lat <socks_port> <sink_port> <count>
//       `count` short sequential connections, each one measured from the
//       first SOCKS byte to the first payload byte. Prints
//       "p50 p95 p99 errors" with the percentiles in milliseconds.
//
//   conn <socks_port> <sink_port> <count> <concurrency>
//       Same short connections, `concurrency` at a time. Prints
//       "conn_per_s errors".
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "sink" => sink(a[2].parse().unwrap()),
        "run" => run(
            a[2].parse().unwrap(),
            a[3].parse().unwrap(),
            a[4].parse().unwrap(),
            a[5].parse().unwrap(),
            a[6] == "up",
        ),
        "lat" => lat(
            a[2].parse().unwrap(),
            a[3].parse().unwrap(),
            a[4].parse().unwrap(),
        ),
        "conn" => conn(
            a[2].parse().unwrap(),
            a[3].parse().unwrap(),
            a[4].parse().unwrap(),
            a[5].parse().unwrap(),
        ),
        _ => panic!("unknown mode"),
    }
}

fn sink(port: u16) {
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    for s in l.incoming() {
        let mut s = s.unwrap();
        std::thread::spawn(move || {
            let _ = s.set_nodelay(true);
            let mut h = [0u8; 8];
            if s.read_exact(&mut h).is_err() {
                return;
            }
            let n = i64::from_be_bytes(h);
            let buf = vec![0x5au8; 256 * 1024];
            let mut rb = vec![0u8; 256 * 1024];
            if n > 0 {
                let mut left = n as usize;
                while left > 0 {
                    let k = left.min(buf.len());
                    if s.write_all(&buf[..k]).is_err() {
                        return;
                    }
                    left -= k;
                }
            } else {
                let mut left = (-n) as usize;
                while left > 0 {
                    match s.read(&mut rb) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => left -= k.min(left),
                    }
                }
                let _ = s.write_all(&[1]);
            }
        });
    }
}

/// SOCKS5 CONNECT to 127.0.0.1:`port` through the client under test.
fn socks(proxy: u16, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_nodelay(true)?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut r = [0u8; 10];
    s.read_exact(&mut r)?;
    if r[1] != 0 {
        return Err(std::io::Error::other("socks connect refused"));
    }
    Ok(s)
}

fn run(proxy: u16, port: u16, bytes: usize, streams: usize, up: bool) {
    let per = bytes / streams;
    let t = Instant::now();
    let hs: Vec<_> = (0..streams)
        .map(|_| {
            std::thread::spawn(move || {
                let mut s = socks(proxy, port).expect("socks");
                let n: i64 = if up { -(per as i64) } else { per as i64 };
                s.write_all(&n.to_be_bytes()).unwrap();
                let mut buf = vec![0u8; 256 * 1024];
                if up {
                    let data = vec![0xa5u8; 256 * 1024];
                    let mut left = per;
                    while left > 0 {
                        let k = left.min(data.len());
                        s.write_all(&data[..k]).unwrap();
                        left -= k;
                    }
                    let mut ack = [0u8; 1];
                    s.read_exact(&mut ack).unwrap();
                } else {
                    let mut left = per;
                    while left > 0 {
                        let k = s.read(&mut buf).unwrap();
                        assert!(k > 0, "eof");
                        left -= k;
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    println!("{:.1}", (per * streams) as f64 / secs / 1e6);
}

/// One short request: connect, ask the sink for a single byte, wait for it.
/// Returns the time to that first byte.
fn one_shot(proxy: u16, port: u16) -> std::io::Result<f64> {
    let t = Instant::now();
    let mut s = socks(proxy, port)?;
    s.write_all(&1i64.to_be_bytes())?;
    let mut b = [0u8; 1];
    s.read_exact(&mut b)?;
    Ok(t.elapsed().as_secs_f64() * 1e3)
}

fn pct(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    let i = ((v.len() - 1) as f64 * p).round() as usize;
    v[i]
}

fn lat(proxy: u16, port: u16, count: usize) {
    let mut v = Vec::with_capacity(count);
    let mut errs = 0usize;
    // A few warm-up connections so lazy per-core setup is not in the sample.
    for _ in 0..20 {
        let _ = one_shot(proxy, port);
    }
    for _ in 0..count {
        match one_shot(proxy, port) {
            Ok(ms) => v.push(ms),
            Err(_) => errs += 1,
        }
    }
    v.sort_by(f64::total_cmp);
    println!(
        "{:.3} {:.3} {:.3} {}",
        pct(&v, 0.50),
        pct(&v, 0.95),
        pct(&v, 0.99),
        errs
    );
}

fn conn(proxy: u16, port: u16, count: usize, concurrency: usize) {
    let issued = AtomicUsize::new(0);
    let errs = AtomicUsize::new(0);
    for _ in 0..concurrency {
        let _ = one_shot(proxy, port);
    }
    let t = Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..concurrency {
            sc.spawn(|| {
                while issued.fetch_add(1, Ordering::Relaxed) < count {
                    if one_shot(proxy, port).is_err() {
                        errs.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let secs = t.elapsed().as_secs_f64();
    println!(
        "{:.1} {}",
        count as f64 / secs,
        errs.load(Ordering::Relaxed)
    );
}
