//! End-to-end: a simulated Iranian failure must reach the planner as the right
//! evidence and produce the right move on the ladder.
//!
//! The observatory's own tests prove the ladder logic in isolation; the evasion
//! crate's simulation proves the countermeasures work against a concrete
//! censor. What neither covers is the join between them — that a real socket
//! error, classified by the runtime, carries the distinction the ladder depends
//! on. A censor that resets and a censor that blackholes need opposite
//! remedies, so collapsing them into one failure kind would make every later
//! decision arbitrary no matter how good the ladder is.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zero_core::{Failure, FailureKind, Stage};
use zero_observatory::{AccessClass, ConnectionPlanner, PathStrategy, Transition};
use zero_runtime::relay::classify_error;

/// Accept, then reset without answering.
async fn resetting_peer() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let mut stream = stream;
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await;
            // Closing while the receive buffer still holds unread data makes
            // the kernel emit RST rather than FIN, which is what a censor's
            // injected teardown looks like to the peer.
            drop(stream);
        }
    });
    Ok(address)
}

/// Accept and then say nothing at all.
async fn silent_peer() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    Ok(address)
}

/// Drive a real socket against `peer` and return the error text the runtime
/// would classify.
async fn provoke(peer: SocketAddr, stage: Stage) -> FailureKind {
    let attempt = async {
        let mut stream = TcpStream::connect(peer).await?;
        stream.set_nodelay(true)?;
        // Write enough that a reset is observed on this side rather than being
        // swallowed by the socket buffer.
        for _ in 0..64 {
            stream.write_all(&[0x5a; 4096]).await?;
            stream.flush().await?;
        }
        let mut sink = [0u8; 64];
        stream.read_exact(&mut sink).await?;
        Ok::<(), io::Error>(())
    };
    match tokio::time::timeout(Duration::from_millis(400), attempt).await {
        Err(_) => classify_error("operation timed out", stage),
        Ok(Ok(())) => panic!("the peer was expected to fail the flow"),
        Ok(Err(error)) => classify_error(&error.to_string(), stage),
    }
}

#[tokio::test]
async fn a_reset_and_a_blackhole_are_not_the_same_evidence() {
    let reset = provoke(resetting_peer().await.unwrap(), Stage::PayloadTransferred).await;
    let silent = provoke(silent_peer().await.unwrap(), Stage::TlsStarted).await;

    assert_eq!(reset, FailureKind::TcpReset);
    assert_eq!(silent, FailureKind::TlsTimeout);
    // The whole taxonomy rests on these being distinguishable.
    assert_ne!(reset, silent);
}

#[tokio::test]
async fn a_reset_after_payload_climbs_to_fragmentation() {
    let kind = provoke(resetting_peer().await.unwrap(), Stage::PayloadTransferred).await;
    let mut planner = ConnectionPlanner::new(b"simulated-iranian-isp");
    let transition = planner
        .record_failure(&Failure::new(kind, Stage::PayloadTransferred).with_bytes(64 * 4096));
    assert_eq!(
        transition,
        Transition::Climb {
            to: PathStrategy::ClientHelloFragment
        }
    );
    // Still the same access class: the server is reachable, the disguise is not
    // good enough. Changing class here would abandon a working endpoint.
    assert_eq!(planner.current_class(), AccessClass::DirectReality);
}

#[tokio::test]
async fn a_blackholed_handshake_changes_access_class() {
    let kind = provoke(silent_peer().await.unwrap(), Stage::TlsStarted).await;
    let mut planner = ConnectionPlanner::new(b"simulated-iranian-isp");
    let transition = planner.record_failure(&Failure::new(kind, Stage::TlsStarted));
    assert_eq!(
        transition,
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

#[tokio::test]
async fn a_blocked_address_exhausts_its_class_before_moving_on() {
    // Nothing is listening: connect fails outright, which indicts the address
    // rather than the disguise.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let mut planner = ConnectionPlanner::new(b"simulated-iranian-isp");
    let mut transitions = Vec::new();
    for _ in 0..3 {
        let kind = provoke(dead, Stage::SocketConnected).await;
        assert_eq!(kind, FailureKind::TcpRefused);
        transitions.push(planner.record_failure(&Failure::new(kind, Stage::SocketConnected)));
    }
    // The first two are ordinary noise; only sustained failure is a verdict on
    // the class.
    assert_eq!(transitions[0], Transition::Hold);
    assert_eq!(transitions[1], Transition::Hold);
    assert_eq!(
        transitions[2],
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

#[tokio::test]
async fn recovery_descends_the_ladder_again() {
    let mut planner = ConnectionPlanner::new(b"simulated-iranian-isp");
    // Climb under a blocking event.
    planner.record_failure(&Failure::new(FailureKind::TlsTimeout, Stage::TlsStarted));
    assert_eq!(planner.current(), PathStrategy::CdnWebSocket);

    // The event ends and the expensive rung now works consistently.
    for _ in 0..32 {
        planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(40));
    }
    let candidate = planner
        .schedule_downgrade_probe()
        .expect("sustained success should earn a cheaper probe");
    assert!(candidate < PathStrategy::CdnWebSocket);
    assert!(planner.record_probe(candidate, true));
    assert_eq!(planner.current(), candidate);
}
