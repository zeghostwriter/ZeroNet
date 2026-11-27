//! Tests for the UDP carrier: the pure response filter and id source, plus a
//! few round-trips against a mock resolver socket on loopback.

use super::*;
use tokio::net::UdpSocket;

/// A bare 12-byte DNS header with a chosen id and the QR bit set or clear.
fn header(qr_set: bool) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0] = 0x12;
    h[1] = 0x34;
    h[2] = if qr_set { 0x81 } else { 0x01 };
    h
}

#[test]
fn filter_requires_a_full_header_and_the_qr_bit() {
    assert!(!is_dns_response(&[]));
    assert!(!is_dns_response(&[0u8; 11])); // one byte short of a header
    assert!(!is_dns_response(&header(false))); // header present, QR clear
    assert!(is_dns_response(&header(true)));
    // Trailing bytes after a valid response header are fine.
    let mut long = header(true).to_vec();
    long.extend_from_slice(b"answer");
    assert!(is_dns_response(&long));
}

#[test]
fn request_ids_increment_from_the_seed_and_wrap() {
    let ids = DnsRequestIds::seeded(0);
    assert_eq!(ids.next(), 1);
    assert_eq!(ids.next(), 2);
    assert_eq!(ids.next(), 3);

    // The low 16 bits roll over at 0x10000.
    let ids = DnsRequestIds::seeded(0xFFFF);
    assert_eq!(ids.next(), 0);

    // The u32 counter itself wraps too.
    let ids = DnsRequestIds::seeded(u32::MAX);
    assert_eq!(ids.next(), 0);
}

#[tokio::test]
async fn exchange_round_trips_through_a_mock_resolver() {
    let resolver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();

    let mut reply = header(true).to_vec();
    reply.extend_from_slice(b"payload");
    let reply_for_task = reply.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_n, from) = resolver.recv_from(&mut buf).await.unwrap();
        resolver.send_to(&reply_for_task, from).await.unwrap();
    });

    let sock = TunnelSocket::bind().await.unwrap();
    let mut buf = [0u8; RECV_BUFFER_SIZE];
    let out = exchange(
        &sock,
        b"question",
        resolver_addr,
        Duration::from_secs(2),
        &mut buf,
    )
    .await
    .unwrap();

    match out {
        Exchange::Response { len, from } => {
            assert_eq!(&buf[..len], reply.as_slice());
            assert_eq!(from, resolver_addr);
        }
        Exchange::TimedOut => panic!("expected a response, got a timeout"),
    }
}

#[tokio::test]
async fn recv_response_skips_a_non_response_then_returns_the_real_one() {
    let resolver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_n, from) = resolver.recv_from(&mut buf).await.unwrap();
        // A query-looking datagram (QR clear) first, then a real response.
        resolver.send_to(&header(false), from).await.unwrap();
        resolver.send_to(&header(true), from).await.unwrap();
    });

    let sock = TunnelSocket::bind().await.unwrap();
    sock.send_to(b"q", resolver_addr).await.unwrap();

    let mut buf = [0u8; RECV_BUFFER_SIZE];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_response(&mut buf))
        .await
        .expect("recv did not hang")
        .expect("recv succeeded");
    assert_eq!(from, resolver_addr);
    assert!(is_dns_response(&buf[..len]));
}

#[tokio::test]
async fn exchange_reports_timeout_when_the_resolver_is_silent() {
    // A bound-but-silent resolver: the port stays open (so no ICMP refusal)
    // but nothing ever answers, so the exchange must time out cleanly.
    let resolver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();

    let sock = TunnelSocket::bind().await.unwrap();
    let mut buf = [0u8; RECV_BUFFER_SIZE];
    let out = exchange(
        &sock,
        b"q",
        resolver_addr,
        Duration::from_millis(150),
        &mut buf,
    )
    .await
    .unwrap();
    assert!(matches!(out, Exchange::TimedOut));

    drop(resolver);
}
