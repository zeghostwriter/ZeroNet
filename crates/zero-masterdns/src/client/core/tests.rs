//! The tunnel core, driven by hand: packets in, packets out, no sockets.

use super::*;
use crate::arq::close::CloseConfig;
use crate::arq::control::ControlConfig;
use crate::arq::data::Config as DataConfig;
use crate::ping::PingConfig;

fn tuning() -> Tuning {
    Tuning {
        chunk: 100,
        data: DataConfig::client_defaults(),
        control: ControlConfig::client_defaults(),
        close: CloseConfig::client_defaults(),
        ping: PingConfig::default(),
    }
}

struct Open {
    id: u16,
    from_core: mpsc::UnboundedReceiver<Vec<u8>>,
    connected: oneshot::Receiver<Result<(), Error>>,
}

fn open(core: &mut Core, target: &[u8], now: Instant) -> Open {
    let (to_user, from_core) = mpsc::unbounded_channel();
    let (connect, connected) = oneshot::channel();
    let id = core
        .open(
            target,
            StreamPorts {
                to_user,
                connect,
                waker: Arc::new(Notify::new()),
            },
            now,
        )
        .expect("a stream opens");
    Open {
        id,
        from_core,
        connected,
    }
}

fn reply(packet_type: u8, stream_id: u16, seq: u16, payload: &[u8]) -> Reply {
    Reply {
        packet_type,
        stream_id,
        seq,
        fragment_id: 0,
        total_fragments: 0,
        payload: payload.to_vec(),
    }
}

/// Everything queued, in the order it would be sent.
fn drain(core: &mut Core, now: Instant) -> Vec<Out> {
    std::iter::from_fn(|| core.next_out(now)).collect()
}

fn kinds(out: &[Out]) -> Vec<u8> {
    out.iter().map(|o| o.packet_type).collect()
}

#[test]
fn a_socks_stream_sends_its_target_in_fragments_no_bigger_than_a_chunk() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Socks5, now);
    let target = vec![7u8; 250];
    let stream = open(&mut core, &target, now);
    let sent = drain(&mut core, now);
    assert_eq!(kinds(&sent), vec![PACKET_SOCKS5_SYN; 3]);
    assert!(sent
        .iter()
        .all(|o| o.stream_id == stream.id && o.total_fragments == 3));
    assert_eq!(
        sent.iter().map(|o| o.payload.len()).collect::<Vec<_>>(),
        vec![100, 100, 50]
    );
    assert_eq!(
        sent.iter().map(|o| o.fragment_id).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

#[test]
fn tcp_mode_opens_with_a_bare_stream_syn() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    open(&mut core, b"ignored", now);
    let sent = drain(&mut core, now);
    assert_eq!(kinds(&sent), vec![PACKET_STREAM_SYN]);
    assert!(sent[0].payload.is_empty());
}

#[test]
fn a_connected_result_is_acknowledged_and_releases_what_arrived_early() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Socks5, now);
    let mut stream = open(&mut core, b"x", now);
    drain(&mut core, now);

    // Data that beats the result is kept, not delivered.
    core.handle_reply(reply(PACKET_STREAM_DATA, stream.id, 0, b"early"), now);
    assert!(stream.from_core.try_recv().is_err());
    let acks = drain(&mut core, now);
    assert_eq!(
        kinds(&acks),
        vec![PACKET_STREAM_DATA_ACK],
        "data is acked even while paused"
    );

    core.handle_reply(reply(PACKET_SOCKS5_CONNECTED, stream.id, 0, b""), now);
    assert_eq!(stream.connected.try_recv().unwrap(), Ok(()));
    assert_eq!(stream.from_core.try_recv().unwrap(), b"early");
    assert_eq!(
        kinds(&drain(&mut core, now)),
        vec![PACKET_SOCKS5_CONNECTED_ACK]
    );
}

#[test]
fn data_is_delivered_in_order_and_each_packet_is_acknowledged() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    let mut stream = open(&mut core, b"", now);
    drain(&mut core, now);
    core.handle_reply(reply(PACKET_STREAM_CONNECTED, stream.id, 0, b""), now);
    drain(&mut core, now);

    // Seq 1 arrives first: held back, acknowledged. Seq 0 then releases both.
    core.handle_reply(reply(PACKET_STREAM_DATA, stream.id, 1, b"world"), now);
    assert!(stream.from_core.try_recv().is_err());
    core.handle_reply(reply(PACKET_STREAM_DATA, stream.id, 0, b"hello "), now);
    assert_eq!(stream.from_core.try_recv().unwrap(), b"hello world");
    let acks = drain(&mut core, now);
    assert!(
        acks.iter()
            .filter(|o| o.packet_type == PACKET_STREAM_DATA_ACK)
            .count()
            >= 2
    );
}

#[test]
fn a_failed_connect_ends_the_stream_with_the_servers_reason() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Socks5, now);
    let mut stream = open(&mut core, b"x", now);
    drain(&mut core, now);
    core.handle_reply(
        reply(PACKET_SOCKS5_CONNECTION_REFUSED, stream.id, 0, b""),
        now,
    );
    let error = stream.connected.try_recv().unwrap().unwrap_err();
    assert!(error.to_string().contains("refused"), "{error}");
    assert_eq!(core.stream_count(), 0);
}

#[test]
fn bytes_from_the_owner_become_numbered_data_packets_until_the_window_is_full() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    let stream = open(&mut core, b"", now);
    drain(&mut core, now);
    core.handle_reply(reply(PACKET_STREAM_CONNECTED, stream.id, 0, b""), now);
    drain(&mut core, now);
    assert_eq!(core.send(stream.id, b"one", now), Ok(true));
    assert_eq!(core.send(stream.id, b"two", now), Ok(true));
    let sent = drain(&mut core, now);
    assert_eq!(kinds(&sent), vec![PACKET_STREAM_DATA; 2]);
    assert_eq!(sent.iter().map(|o| o.seq).collect::<Vec<_>>(), vec![0, 1]);
    // An ack frees a slot and is not answered.
    core.handle_reply(reply(PACKET_STREAM_DATA_ACK, stream.id, 0, b""), now);
    assert!(drain(&mut core, now).is_empty());
}

#[test]
fn unacknowledged_data_is_sent_again_after_its_timeout() {
    let start = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, start);
    let stream = open(&mut core, b"", start);
    drain(&mut core, start);
    // The setup packet is acknowledged, so only the data can be overdue.
    core.handle_reply(reply(PACKET_STREAM_SYN_ACK, stream.id, 0, b""), start);
    core.handle_reply(reply(PACKET_STREAM_CONNECTED, stream.id, 0, b""), start);
    drain(&mut core, start);
    core.send(stream.id, b"lost", start).unwrap();
    assert_eq!(drain(&mut core, start).len(), 1);

    // Nothing is due before the retransmit timeout…
    // (A keep-alive ping is due by then; the data packet is not.)
    core.tick(start + Duration::from_millis(500));
    let early = drain(&mut core, start + Duration::from_millis(500));
    assert!(
        early.iter().all(|o| o.packet_type == PACKET_PING),
        "{:?}",
        kinds(&early)
    );
    // …and the packet goes again once it has passed.
    let later = start + Duration::from_secs(3);
    core.tick(later);
    let again = drain(&mut core, later);
    assert!(
        again.iter().any(
            |o| matches!(o.packet_type, PACKET_STREAM_DATA | PACKET_STREAM_RESEND) && o.seq == 0
        ),
        "no retransmit: {:?}",
        kinds(&again)
    );
}

#[test]
fn a_server_close_ends_the_owners_read_side_but_not_the_stream() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    let mut stream = open(&mut core, b"", now);
    drain(&mut core, now);
    core.handle_reply(reply(PACKET_STREAM_CONNECTED, stream.id, 0, b""), now);
    core.handle_reply(reply(PACKET_STREAM_DATA, stream.id, 0, b"last words"), now);
    core.handle_reply(reply(PACKET_STREAM_CLOSE_READ, stream.id, 0, b""), now);
    assert_eq!(stream.from_core.try_recv().unwrap(), b"last words");
    // The channel is closed: the owner reads an EOF after the data.
    assert!(matches!(
        stream.from_core.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    ));
    // The close is acknowledged, and the stream stays until the owner is done.
    assert!(kinds(&drain(&mut core, now)).contains(&PACKET_STREAM_CLOSE_READ_ACK));
    assert_eq!(core.stream_count(), 1);
}

#[test]
fn the_owner_finishing_sends_a_close_once_everything_is_acknowledged() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    let stream = open(&mut core, b"", now);
    drain(&mut core, now);
    core.handle_reply(reply(PACKET_STREAM_CONNECTED, stream.id, 0, b""), now);
    drain(&mut core, now);
    core.send(stream.id, b"bye", now).unwrap();
    core.finish(stream.id, now);
    // Drain first: the close waits for the data to be acknowledged.
    let sent = drain(&mut core, now);
    assert_eq!(kinds(&sent), vec![PACKET_STREAM_DATA]);
    core.handle_reply(reply(PACKET_STREAM_DATA_ACK, stream.id, 0, b""), now);
    core.tick(now + Duration::from_millis(50));
    let closing = drain(&mut core, now + Duration::from_millis(50));
    assert!(
        kinds(&closing).contains(&PACKET_STREAM_CLOSE_READ),
        "no close after the drain: {:?}",
        kinds(&closing)
    );
}

#[test]
fn a_packet_for_an_unknown_stream_is_reset_once_a_second_not_every_time() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    core.handle_reply(reply(PACKET_STREAM_DATA, 9, 0, b"?"), now);
    core.handle_reply(
        reply(PACKET_STREAM_DATA, 9, 1, b"?"),
        now + Duration::from_millis(10),
    );
    let sent = drain(&mut core, now);
    assert_eq!(kinds(&sent), vec![PACKET_STREAM_RST]);
    core.handle_reply(
        reply(PACKET_STREAM_DATA, 9, 2, b"?"),
        now + Duration::from_secs(2),
    );
    assert_eq!(kinds(&drain(&mut core, now)), vec![PACKET_STREAM_RST]);
    // Acks and nacks for a dead stream need no answer.
    core.handle_reply(reply(PACKET_STREAM_DATA_ACK, 9, 0, b""), now);
    assert!(drain(&mut core, now).is_empty());
}

#[test]
fn a_keepalive_ping_is_queued_when_one_is_due_and_not_before() {
    let start = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, start);
    core.tick(start + Duration::from_millis(30));
    assert!(drain(&mut core, start).is_empty(), "no ping this soon");
    let later = start + Duration::from_millis(400);
    core.tick(later);
    let sent = drain(&mut core, later);
    assert_eq!(kinds(&sent), vec![PACKET_PING]);
    assert_eq!(sent[0].stream_id, 0);
    // One at a time: a second tick does not stack another behind it.
    core.tick(later + Duration::from_millis(30));
    core.tick(later + Duration::from_millis(60));
    assert!(drain(&mut core, later).len() <= 1);
}

#[test]
fn a_dropped_session_ends_the_tunnel_and_new_streams_are_refused() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    core.handle_reply(reply(PACKET_ERROR_DROP, 0, 0, b""), now);
    assert_eq!(core.dead, Some(Error::SessionLost));
    let (to_user, _) = mpsc::unbounded_channel();
    let (connect, _) = oneshot::channel();
    let error = core
        .open(
            b"",
            StreamPorts {
                to_user,
                connect,
                waker: Arc::new(Notify::new()),
            },
            now,
        )
        .unwrap_err();
    assert_eq!(error, Error::SessionLost);
}

#[test]
fn stream_ids_are_not_reused_while_a_stream_is_open() {
    let now = Instant::now();
    let mut core = Core::new(tuning(), Mode::Tcp, now);
    let a = open(&mut core, b"", now).id;
    let b = open(&mut core, b"", now).id;
    assert_ne!(a, b);
    assert_ne!(a, 0);
}
