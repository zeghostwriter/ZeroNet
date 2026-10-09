use super::*;

#[test]
fn a_generated_key_round_trips_through_pkcs8_and_spki() {
    let key = MasqueKey::generate().unwrap();
    let again = MasqueKey::from_der(key.pkcs8()).unwrap();
    assert_eq!(key.spki_der(), again.spki_der());
    let spki = key.spki_der();
    assert_eq!(spki.len(), 91);
    assert_eq!(point_of_spki(&spki).unwrap(), &key.point[..]);
}

#[test]
fn a_sec1_key_is_wrapped_into_the_same_key() {
    let key = MasqueKey::generate().unwrap();
    // PKCS#8 = version, algorithm, OCTET STRING { SEC1 }.
    let (_, body, _) = read_tlv(key.pkcs8()).unwrap();
    let after_header = &body[PKCS8_HEADER.len()..];
    let (tag, sec1, _) = read_tlv(after_header).unwrap();
    assert_eq!(tag, 0x04);
    let sec1_der = der(0x30, sec1_body(sec1));
    let from_sec1 = MasqueKey::from_der(&sec1_der).unwrap();
    assert_eq!(from_sec1.spki_der(), key.spki_der());
}

/// `ring` stores the SEC1 key as a bare SEQUENCE; return its content.
fn sec1_body(sec1: &[u8]) -> &[u8] {
    read_tlv(sec1).unwrap().1
}

#[test]
fn garbage_is_not_a_key() {
    assert!(MasqueKey::from_der(b"not a key").is_err());
    assert!(MasqueKey::from_der(&[0x30, 0x03, 0x02, 0x01, 0x07]).is_err());
}

#[test]
fn the_certificate_carries_the_key_and_the_24_hour_window() {
    let key = MasqueKey::generate().unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_790_000_000); // 2026-09-21
    let certificate = key.certificate(now).unwrap();
    // The key info is found where a verifier looks for it.
    let spki = spki_of_certificate(&certificate).unwrap();
    assert_eq!(spki, &key.spki_der()[..]);
    // The window: 23:30 after `now` and 30 minutes before it.
    let text = String::from_utf8_lossy(&certificate);
    assert!(text.contains("260921"), "{text:?}");
    // Rustls accepts it as an end-entity certificate.
    let cert = CertificateDer::from(certificate);
    rustls::server::ParsedCertificate::try_from(&cert).unwrap();
}

#[test]
fn utc_time_matches_known_dates() {
    assert_eq!(utc_time(0), der(0x17, b"700101000000Z"));
    assert_eq!(utc_time(951_782_400), der(0x17, b"000229000000Z")); // leap day
    assert_eq!(
        utc_time(1_790_000_000 - 1_790_000_000 % 86_400 + 3661),
        der(0x17, b"260921010101Z")
    );
}

#[test]
fn a_server_key_comes_out_of_pem_or_bare_base64() {
    use base64::Engine as _;
    let key = MasqueKey::generate().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(key.spki_der());
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
    assert_eq!(server_point_from_pem(&pem).unwrap(), key.point);
    assert_eq!(server_point_from_pem(&b64).unwrap(), key.point);
    assert!(server_point_from_pem("AAAA").is_err());
}

#[test]
fn varints_round_trip() {
    for value in [
        0u64,
        1,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        1 << 40,
    ] {
        let mut out = Vec::new();
        put_varint(&mut out, value);
        assert_eq!(get_varint(&out), Some((value, out.len())), "{value}");
    }
    assert_eq!(get_varint(&[0x40]), None);
}

#[test]
fn prefix_integers_round_trip() {
    for (bits, value) in [
        (3u8, 0u64),
        (3, 6),
        (3, 7),
        (3, 300),
        (4, 15),
        (6, 62),
        (6, 63),
        (7, 127),
        (7, 100_000),
        (8, 254),
        (8, 255),
    ] {
        let mut out = Vec::new();
        put_prefix_int(&mut out, 0, bits, value);
        assert_eq!(
            prefix_int(&out, bits),
            Some((value, out.len())),
            "{bits} {value}"
        );
    }
}

/// RFC 9204 Appendix A: the indices this client writes and reads.
#[test]
fn the_request_is_static_or_literal_and_names_cloudflares_protocol() {
    let frame = request_headers(DEFAULT_AUTHORITY);
    assert_eq!(frame[0], 0x01, "HEADERS");
    let (length, used) = get_varint(&frame[1..]).unwrap();
    let block = &frame[1 + used..];
    assert_eq!(block.len() as u64, length);
    assert_eq!(&block[..2], &[0, 0], "no dynamic table");
    assert_eq!(block[2], 0xcf, ":method CONNECT");
    assert_eq!(block[3], 0xd7, ":scheme https");
    let text = String::from_utf8_lossy(block);
    assert!(text.contains("cloudflareaccess.com"));
    assert!(text.contains(":protocol") && text.contains("cf-connect-ip"));
}

#[test]
fn a_status_is_read_from_static_and_literal_field_lines() {
    // Prefix, then :status 200 indexed (static 25).
    assert_eq!(response_status(&[0, 0, 0xc0 | 25]), Ok(200));
    // Index 63 (:status 100) does not fit the six-bit prefix and continues.
    let mut block = vec![0, 0];
    put_prefix_int(&mut block, 0xc0, 6, 63);
    assert_eq!(response_status(&block), Ok(100));
    // Literal with a static name reference to :status (index 25), value "403".
    let mut block = vec![0, 0];
    put_prefix_int(&mut block, 0x50, 4, 25);
    put_string(&mut block, "403");
    assert_eq!(response_status(&block), Ok(403));
    // The same with a Huffman-coded value: "302" is 0x64 0x02 (RFC 7541 C.6.1).
    let mut block = vec![0, 0];
    put_prefix_int(&mut block, 0x50, 4, 25);
    block.extend_from_slice(&[0x80 | 2, 0x64, 0x02]);
    assert_eq!(response_status(&block), Ok(302));
    // A literal name, and headers before the status are skipped.
    let mut block = vec![0, 0];
    put_literal(&mut block, "cf-team", "12345");
    put_literal(&mut block, ":status", "204");
    assert_eq!(response_status(&block), Ok(204));
    // No status, a dynamic reference, and truncation are all errors.
    assert!(response_status(&[0, 0, 0xc0 | 15]).is_err());
    assert!(response_status(&[1, 0, 0x80]).is_err());
    assert!(response_status(&[0, 0, 0x50 | 15]).is_err());
}

#[test]
fn a_certificate_from_another_key_is_not_the_pinned_server() {
    let server = MasqueKey::generate().unwrap();
    let other = MasqueKey::generate().unwrap();
    let provider = ring_provider::default_provider();
    let verifier = Pinned {
        point: server.point.to_vec(),
        algorithms: provider.signature_verification_algorithms,
    };
    let name = ServerName::try_from("www.speedtest.net").unwrap();
    let verify = |key: &MasqueKey| {
        let certificate = CertificateDer::from(key.certificate(SystemTime::now()).unwrap());
        verifier.verify_server_cert(&certificate, &[], &name, &[], UnixTime::now())
    };
    assert!(verify(&server).is_ok());
    assert!(verify(&other).is_err());
}

// ------------------------------------------------- end to end, on loopback

use super::mock::{h2_server, h3_server};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

struct Fixture {
    spec: Spec,
    client_point: Vec<u8>,
    /// Client keys the server saw, one per connection.
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
}

fn fixture(
    address: SocketAddr,
    http2: bool,
    server: &MasqueKey,
    client: MasqueKey,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
) -> Fixture {
    let client_point = client.point.to_vec();
    Fixture {
        spec: Spec {
            endpoints: vec![Endpoint {
                address,
                http2,
                sni: Arc::from("www.speedtest.net"),
            }],
            key: Arc::new(client),
            server_point: Arc::from(server.point.as_slice()),
            authority: Arc::from(DEFAULT_AUTHORITY),
        },
        client_point,
        seen,
        connections,
    }
}

/// An IPv4 packet of `length` bytes that starts `4 5 ..` and is otherwise
/// `fill`, the shape the pump checks and nothing more.
fn packet(length: usize, fill: u8) -> Vec<u8> {
    let mut packet = vec![fill; length];
    packet[0] = 0x45;
    packet
}

/// Send `packet` until it comes back or the time runs out, since packets sent
/// while a tunnel is reconnecting are dropped by design.
async fn round_trip(link: &mut Link, packet: &[u8]) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let _ = link.up.try_send(packet.to_vec());
        match timeout(Duration::from_millis(300), link.down.recv()).await {
            Ok(Some(reply)) => return reply,
            Ok(None) => panic!("the tunnel closed"),
            Err(_) => assert!(tokio::time::Instant::now() < deadline, "no reply"),
        }
    }
}

#[tokio::test]
async fn packets_cross_an_http2_tunnel_authenticated_by_the_enrolled_key() {
    let server = MasqueKey::generate().unwrap();
    let (address, seen, connections) = h2_server(&server, false).await;
    let fixture = fixture(
        address,
        true,
        &server,
        MasqueKey::generate().unwrap(),
        seen,
        connections,
    );
    let mut link = start(fixture.spec.clone()).await.unwrap();
    for size in [40, 600, 1280] {
        let sent = packet(size, size as u8);
        assert_eq!(round_trip(&mut link, &sent).await, sent);
    }
    // The server saw the enrolled key, and the one connection served all.
    assert_eq!(
        fixture.seen.lock().unwrap().as_slice(),
        std::slice::from_ref(&fixture.client_point)
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn packets_cross_an_http3_tunnel_authenticated_by_the_enrolled_key() {
    let server = MasqueKey::generate().unwrap();
    let (address, seen, connections) = h3_server(&server).await;
    let fixture = fixture(
        address,
        false,
        &server,
        MasqueKey::generate().unwrap(),
        seen,
        connections,
    );
    let mut link = start(fixture.spec.clone()).await.unwrap();
    for size in [40, 600, 1100] {
        let sent = packet(size, size as u8);
        assert_eq!(round_trip(&mut link, &sent).await, sent);
    }
    assert_eq!(
        fixture.seen.lock().unwrap().as_slice(),
        std::slice::from_ref(&fixture.client_point)
    );
}

#[tokio::test]
async fn a_server_with_another_key_is_refused_on_both_transports() {
    let real = MasqueKey::generate().unwrap();
    let impostor = MasqueKey::generate().unwrap();
    for http2 in [true, false] {
        let (address, seen, connections) = if http2 {
            h2_server(&impostor, false).await
        } else {
            h3_server(&impostor).await
        };
        let fixture = fixture(
            address,
            http2,
            &real,
            MasqueKey::generate().unwrap(),
            seen,
            connections,
        );
        let error = start(fixture.spec).await.err().expect("must not connect");
        assert!(!error.is_empty());
        // Never got as far as a request.
        assert!(fixture.seen.lock().unwrap().len() <= 1);
    }
}

#[tokio::test]
async fn the_tunnel_reconnects_by_itself_when_the_server_hangs_up() {
    let server = MasqueKey::generate().unwrap();
    let (address, seen, connections) = h2_server(&server, true).await;
    let fixture = fixture(
        address,
        true,
        &server,
        MasqueKey::generate().unwrap(),
        seen,
        connections,
    );
    let mut link = start(fixture.spec.clone()).await.unwrap();
    let sent = packet(200, 7);
    assert_eq!(round_trip(&mut link, &sent).await, sent);
    // The first connection is gone; keep going until the second carries one.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let sent = packet(300, 9);
    assert_eq!(round_trip(&mut link, &sent).await, sent);
    assert!(fixture.connections.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn the_first_endpoint_that_answers_wins_and_a_dead_one_is_skipped() {
    let server = MasqueKey::generate().unwrap();
    let (address, seen, connections) = h2_server(&server, false).await;
    let mut fixture = fixture(
        address,
        true,
        &server,
        MasqueKey::generate().unwrap(),
        seen,
        connections,
    );
    // Nothing listens on the first endpoint (a port that was just free).
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    fixture.spec.endpoints.insert(
        0,
        Endpoint {
            address: dead,
            http2: true,
            sni: Arc::from("www.speedtest.net"),
        },
    );
    let mut link = start(fixture.spec.clone()).await.unwrap();
    let sent = packet(100, 3);
    assert_eq!(round_trip(&mut link, &sent).await, sent);
}

#[test]
fn only_ip_packets_are_handed_to_the_stack() {
    let (down, mut receive) = mpsc::channel(8);
    deliver(&down, &[]);
    deliver(&down, &[0x45, 0, 0]); // too short for IPv4
    deliver(&down, &[0x10; 40]); // not IP
    deliver(&down, &packet(40, 0));
    deliver(&down, &[&[0x60][..], &[0; 39][..]].concat());
    assert_eq!(receive.try_recv().unwrap().len(), 40);
    assert_eq!(receive.try_recv().unwrap()[0], 0x60);
    assert!(receive.try_recv().is_err());
}

/// A `Spec` pointing at one loopback edge, for the carrying tests.
fn spec_to(server: &MasqueKey, address: std::net::SocketAddr, http2: bool) -> Spec {
    Spec {
        endpoints: vec![Endpoint {
            address,
            http2,
            sni: Arc::from("cloudflareaccess.com"),
        }],
        key: Arc::new(MasqueKey::from_der(server.pkcs8()).unwrap()),
        server_point: Arc::from(point_of_spki(&server.spki_der()).unwrap().to_vec()),
        authority: Arc::from("cloudflareaccess.com"),
    }
}

/// A stand-in for the server the `hybrid` order goes through: a TCP splice to
/// `edge` that counts the connections it carried, so a test can tell "went
/// through the hop" from "dialled the edge directly".
async fn relay_hop(edge: std::net::SocketAddr) -> (Opener, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop = listener.local_addr().unwrap();
    let carried = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&carried);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut target) = tokio::net::TcpStream::connect(edge).await {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                }
            });
        }
    });
    let opener: Opener = Arc::new(move |_edge| {
        Box::pin(async move {
            tokio::net::TcpStream::connect(hop)
                .await
                .map(zero_core::boxed)
                .map_err(|error| format!("hop: {error}"))
        })
    });
    (opener, carried)
}

/// A packet the mock edge echoes back, with `tag` in it.
fn probe(tag: u8) -> Vec<u8> {
    vec![
        0x45, 0, 0, 20, 9, 1, 7, 9, 1, 1, tag, 3, 4, 5, 6, 7, 8, 9, 0, 0,
    ]
}

#[tokio::test]
async fn a_tunnel_carried_by_another_server_carries_a_packet_through_it() {
    let server = MasqueKey::generate().unwrap();
    let (edge, _, _) = crate::masque::mock::h2_server(&server, false).await;
    let (opener, carried) = relay_hop(edge).await;
    let mut link = start_over(spec_to(&server, edge, true), opener)
        .await
        .expect("a carried tunnel");
    let packet = probe(1);
    link.up.send(packet.clone()).await.unwrap();
    let mut back = tokio::time::timeout(Duration::from_secs(5), link.down.recv())
        .await
        .expect("an answer came back")
        .expect("the link was open");
    back.truncate(packet.len());
    assert_eq!(back, packet);
    assert!(carried.load(Ordering::SeqCst) >= 1, "the hop was bypassed");
}

#[tokio::test]
async fn a_tunnel_that_would_need_http3_is_refused_before_it_dials() {
    let server = MasqueKey::generate().unwrap();
    let (edge, _, connections) = crate::masque::mock::h3_server(&server).await;
    let (opener, _) = relay_hop(edge).await;
    let Err(error) = start_over(spec_to(&server, edge, false), opener).await else {
        panic!("HTTP/3 cannot be carried");
    };
    assert!(error.contains("HTTP/2"), "{error}");
    assert_eq!(connections.load(Ordering::SeqCst), 0, "it dialled anyway");
}

/// `supervise` rebuilds a dropped session, and the rebuild must go through
/// the hop again rather than reuse a dead stream or dial the edge directly.
#[tokio::test]
async fn a_carried_tunnel_that_ends_opens_a_new_connection_through_the_hop() {
    let server = MasqueKey::generate().unwrap();
    // The mock edge hangs up on its first session.
    let (edge, _, connections) = crate::masque::mock::h2_server(&server, true).await;
    let (opener, carried) = relay_hop(edge).await;
    let mut link = start_over(spec_to(&server, edge, true), opener)
        .await
        .expect("a carried tunnel");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut tag = 1u8;
    while connections.load(Ordering::SeqCst) < 2 && tokio::time::Instant::now() < deadline {
        let _ = link.up.send(probe(tag)).await;
        tag = tag.wrapping_add(1);
        let _ = tokio::time::timeout(Duration::from_secs(2), link.down.recv()).await;
    }
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "the tunnel did not come back"
    );
    assert!(
        carried.load(Ordering::SeqCst) >= 2,
        "the rebuild skipped the hop"
    );
}

/// A hop like [`relay_hop`] whose first connection freezes on demand: it
/// stays open but stops forwarding either way, the way a connection looks
/// when a middlebox stops passing it or loss has pushed TCP's retransmission
/// timer out to a minute. Nothing errors and nothing closes.
async fn freezing_hop(
    edge: std::net::SocketAddr,
) -> (Opener, Arc<AtomicUsize>, Arc<std::sync::atomic::AtomicBool>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop = listener.local_addr().unwrap();
    let carried = Arc::new(AtomicUsize::new(0));
    let frozen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (counter, freeze) = (Arc::clone(&carried), Arc::clone(&frozen));
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let nth = counter.fetch_add(1, Ordering::SeqCst);
            let freeze = Arc::clone(&freeze);
            tokio::spawn(async move {
                let Ok(target) = tokio::net::TcpStream::connect(edge).await else {
                    return;
                };
                let (mut client_read, mut client_write) = client.into_split();
                let (mut target_read, mut target_write) = target.into_split();
                // Only the first connection freezes; later ones carry on.
                let stuck = move || nth == 0 && freeze.load(Ordering::SeqCst);
                let stuck_too = stuck.clone();
                let up = async move {
                    let mut buffer = vec![0u8; 16 * 1024];
                    while let Ok(n @ 1..) = client_read.read(&mut buffer).await {
                        if stuck() {
                            std::future::pending::<()>().await;
                        }
                        if target_write.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                let down = async move {
                    let mut buffer = vec![0u8; 16 * 1024];
                    while let Ok(n @ 1..) = target_read.read(&mut buffer).await {
                        if stuck_too() {
                            std::future::pending::<()>().await;
                        }
                        if client_write.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::join!(up, down);
            });
        }
    });
    let opener: Opener = Arc::new(move |_edge| {
        Box::pin(async move {
            tokio::net::TcpStream::connect(hop)
                .await
                .map(zero_core::boxed)
                .map_err(|error| format!("hop: {error}"))
        })
    });
    (opener, carried, frozen)
}

/// A connection that freezes without closing is noticed by its unanswered
/// PING and replaced, so the tunnel carries traffic again within seconds
/// instead of hanging until TCP gives up.
#[tokio::test]
async fn a_connection_that_freezes_without_closing_is_replaced() {
    let server = MasqueKey::generate().unwrap();
    let (edge, _, _) = h2_server(&server, false).await;
    let (opener, carried, frozen) = freezing_hop(edge).await;
    let spec = spec_to(&server, edge, true);
    let mut link = start_over(spec, opener).await.unwrap();
    let sent = probe(1);
    assert_eq!(round_trip(&mut link, &sent).await, sent);

    frozen.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let sent = probe(2);
    assert_eq!(round_trip(&mut link, &sent).await, sent);
    assert!(
        carried.load(Ordering::SeqCst) >= 2,
        "a fresh connection carried it"
    );
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "recovered in {:?}",
        started.elapsed()
    );
}
