// sink <port>                         : TCP server; reads 8-byte length, sends that many bytes (or receives if negative)
// run <socks_port> <sink_port> <bytes> <streams> <down|up>  : prints MB/s
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "sink" => sink(a[2].parse().unwrap()),
        "run" => run(a[2].parse().unwrap(), a[3].parse().unwrap(), a[4].parse().unwrap(), a[5].parse().unwrap(), a[6] == "up"),
        _ => panic!(),
    }
}

fn sink(port: u16) {
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    for s in l.incoming() {
        let mut s = s.unwrap();
        std::thread::spawn(move || {
            let mut h = [0u8; 8];
            if s.read_exact(&mut h).is_err() { return; }
            let n = i64::from_be_bytes(h);
            let buf = vec![0x5au8; 256 * 1024];
            let mut rb = vec![0u8; 256 * 1024];
            if n > 0 {
                let mut left = n as usize;
                while left > 0 { let k = left.min(buf.len()); if s.write_all(&buf[..k]).is_err() { return; } left -= k; }
            } else {
                let mut left = (-n) as usize;
                while left > 0 { match s.read(&mut rb) { Ok(0) | Err(_) => return, Ok(k) => left -= k.min(left) } }
                let _ = s.write_all(&[1]);
            }
        });
    }
}

fn socks(proxy: u16, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2]; s.read_exact(&mut r).unwrap();
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut r = [0u8; 10]; s.read_exact(&mut r).unwrap();
    assert_eq!(r[1], 0, "socks connect failed");
    s
}

fn run(proxy: u16, port: u16, bytes: usize, streams: usize, up: bool) {
    let per = bytes / streams;
    let t = Instant::now();
    let hs: Vec<_> = (0..streams).map(|_| std::thread::spawn(move || {
        let mut s = socks(proxy, port);
        let n: i64 = if up { -(per as i64) } else { per as i64 };
        s.write_all(&n.to_be_bytes()).unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        if up {
            let data = vec![0xa5u8; 256 * 1024];
            let mut left = per;
            while left > 0 { let k = left.min(data.len()); s.write_all(&data[..k]).unwrap(); left -= k; }
            let mut ack = [0u8; 1]; s.read_exact(&mut ack).unwrap();
        } else {
            let mut left = per;
            while left > 0 { let k = s.read(&mut buf).unwrap(); assert!(k > 0, "eof"); left -= k; }
        }
    })).collect();
    for h in hs { h.join().unwrap(); }
    let secs = t.elapsed().as_secs_f64();
    println!("{:.1}", (per * streams) as f64 / secs / 1e6);
}
