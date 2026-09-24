//! Plumbing shared by the carriers that bridge an application duplex to a
//! transport running in a background task.

use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Drive both directions of a carrier bridge to completion.
///
/// A clean finish of one direction is a half-close: the other keeps running
/// until it finishes too. An error in either direction ends the bridge at
/// once. Both futures (and whatever halves of the application duplex they
/// own) are dropped, so the application sees EOF or a broken pipe instead of
/// a stream that silently never produces another byte.
pub(crate) async fn drive_both<U, D>(label: &'static str, uplink: U, downlink: D)
where
    U: Future<Output = Result<(), String>>,
    D: Future<Output = Result<(), String>>,
{
    tokio::pin!(uplink);
    tokio::pin!(downlink);
    let mut uplink_done = false;
    let mut downlink_done = false;
    while !(uplink_done && downlink_done) {
        tokio::select! {
            result = &mut uplink, if !uplink_done => {
                uplink_done = true;
                if let Err(error) = result {
                    tracing::debug!(%error, carrier = label, "uplink ended");
                    return;
                }
            }
            result = &mut downlink, if !downlink_done => {
                downlink_done = true;
                if let Err(error) = result {
                    tracing::debug!(%error, carrier = label, "downlink ended");
                    return;
                }
            }
        }
    }
}

/// Copy `reader` into `writer` until EOF, then shut the writer down.
///
/// `tokio::io::copy` stops at EOF without propagating it; on a bridge that
/// leaves the far side waiting for bytes that will never come, which is how a
/// finished download used to hang the whole logical stream.
pub(crate) async fn copy_then_shutdown<R, W>(mut reader: R, mut writer: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(&mut reader, &mut writer)
        .await
        .map_err(|error| error.to_string())?;
    writer.shutdown().await.map_err(|error| error.to_string())
}

/// Send `data` on an h2 stream as flow-control credit allows.
pub(crate) async fn send_with_capacity(
    send_stream: &mut h2::SendStream<bytes::Bytes>,
    mut data: bytes::Bytes,
) -> Result<(), String> {
    while !data.is_empty() {
        send_stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send_stream.poll_capacity(cx))
            .await
            .ok_or_else(|| "stream closed".to_string())?
            .map_err(|error| format!("capacity: {error}"))?;
        if capacity == 0 {
            continue;
        }
        let take = capacity.min(data.len());
        send_stream
            .send_data(data.split_to(take), false)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Bytes read from the application per QUIC stream write.
const QUIC_WRITE_CHUNK: usize = 32 * 1024;
/// Largest chunk taken from a QUIC receive stream at once.
const QUIC_READ_CHUNK: usize = 64 * 1024;
/// How long a finished uplink waits for the peer to acknowledge its tail.
const QUIC_FINISH_GRACE: Duration = Duration::from_secs(5);

/// Bridge an application duplex to one bidirectional QUIC stream.
///
/// Data moves as `Bytes` in both directions (`read_chunk` / `write_chunk`),
/// so neither side copies through an intermediate stack buffer. The end of
/// the peer's stream is passed on as EOF, and a finished uplink waits (for a
/// bounded time) until the peer has acknowledged every byte, so a caller that
/// closes the connection afterwards does not cut off the tail of the upload.
pub(crate) async fn bridge_quic_stream(
    app: tokio::io::DuplexStream,
    mut send: h3_quinn::quinn::SendStream,
    mut recv: h3_quinn::quinn::RecvStream,
    label: &'static str,
) {
    use tokio::io::AsyncReadExt;
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let uplink = async {
        let mut buffer = bytes::BytesMut::with_capacity(QUIC_WRITE_CHUNK);
        loop {
            buffer.reserve(QUIC_WRITE_CHUNK);
            let n = app_read
                .read_buf(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            if n == 0 {
                send.finish().map_err(|error| error.to_string())?;
                let _ = tokio::time::timeout(QUIC_FINISH_GRACE, send.stopped()).await;
                return Ok(());
            }
            send.write_chunk(buffer.split().freeze())
                .await
                .map_err(|error| error.to_string())?;
        }
    };
    let downlink = async {
        while let Some(chunk) = recv
            .read_chunk(QUIC_READ_CHUNK, true)
            .await
            .map_err(|error| error.to_string())?
        {
            app_write
                .write_all(&chunk.bytes)
                .await
                .map_err(|error| error.to_string())?;
        }
        app_write
            .shutdown()
            .await
            .map_err(|error| error.to_string())
    };
    drive_both(label, uplink, downlink).await;
}

/// Build a QUIC client endpoint on a socket the host has already been allowed
/// to protect.
///
/// `Endpoint::client` binds its own socket, which leaves no moment at which a
/// mobile host could exempt it from the tunnel it is serving — and an
/// unprotected QUIC socket there does not degrade, it loops back into the
/// proxy (`zero_core::platform`).
pub(crate) fn protected_client_endpoint(
    bind: std::net::SocketAddr,
) -> std::io::Result<h3_quinn::quinn::Endpoint> {
    let socket = zero_core::platform::bind_protected_udp(bind)?;
    h3_quinn::quinn::Endpoint::new(
        h3_quinn::quinn::EndpointConfig::default(),
        None,
        socket,
        std::sync::Arc::new(h3_quinn::quinn::TokioRuntime),
    )
}

/// Per-stream QUIC receive window. quinn's default (1.25 MB) is sized for
/// 100 Mbit/s at 100 ms; on the long, lossy paths these carriers exist for it
/// caps a single stream well below the link. This matches the Hysteria2
/// reference client's stream window.
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
/// Connection-wide QUIC receive window, shared by every stream.
const QUIC_CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;

/// Transport parameters for the QUIC carriers.
///
/// `keep_alive` keeps NAT bindings and the peer's idle timer alive while a
/// proxied connection is quiet; without it quinn's default 30 s idle timeout
/// silently kills an idle SSH session or long poll.
pub(crate) fn quic_transport(
    idle_timeout: Duration,
    keep_alive: Option<Duration>,
) -> h3_quinn::quinn::TransportConfig {
    let mut config = h3_quinn::quinn::TransportConfig::default();
    config.max_idle_timeout(idle_timeout.try_into().ok());
    config.keep_alive_interval(keep_alive);
    config.stream_receive_window(QUIC_STREAM_RECEIVE_WINDOW.into());
    config.receive_window(QUIC_CONNECTION_RECEIVE_WINDOW.into());
    config.send_window(u64::from(QUIC_CONNECTION_RECEIVE_WINDOW));
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn drive_both_waits_for_a_clean_half_close() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = finished.clone();
        drive_both(
            "test",
            async move {
                rx.await.ok();
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            async move {
                tx.send(()).ok();
                Ok(())
            },
        )
        .await;
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn drive_both_stops_on_the_first_error() {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            drive_both(
                "test",
                std::future::pending::<Result<(), String>>(),
                async { Err::<(), String>("boom".into()) },
            ),
        )
        .await;
        assert!(result.is_ok(), "an error must not wait for the other side");
    }

    #[tokio::test]
    async fn copy_then_shutdown_propagates_eof() {
        let (mut source, source_peer) = tokio::io::duplex(64);
        let (sink, mut sink_peer) = tokio::io::duplex(64);
        let task = tokio::spawn(copy_then_shutdown(source_peer, sink));
        source.write_all(b"abc").await.unwrap();
        drop(source);
        let mut got = Vec::new();
        sink_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abc");
        task.await.unwrap().unwrap();
    }
}
