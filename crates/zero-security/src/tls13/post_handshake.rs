//! Learns what a camouflage site sends straight after a TLS 1.3 handshake.
//!
//! How this works: a real TLS 1.3 server does not go quiet once the handshake
//! is done. It sends session tickets, and an HTTP/2 server its settings, each
//! as an encrypted record of a size typical for that site. A REALITY server
//! that sends nothing there can be told apart from the site it borrows its
//! name from by anyone who compares the two. [`observe`] connects to the site
//! the way a browser would, sends nothing after its Finished, and notes the
//! size of every record that arrives in the next few seconds. The server then
//! sends empty records of those sizes after each handshake it accepts
//! ([`super::server::PostHandshakeShapes`]).
//!
//! The rule it keeps: only sizes are learned. Nothing the site sent is kept,
//! replayed or decrypted for use, and the connection is closed afterwards.
//!
//! The surprise: the boundary between "handshake" and "after it" is not
//! marked on the wire, since both sides' records look like application data
//! by then. The client's own first encrypted record is its Finished, and the
//! server's whole handshake flight has to arrive before a client can send
//! that, so every record that arrives after it is post-handshake.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use zero_core::Failure;

use super::record::CONTENT_APPDATA;
use crate::fingerprint::FingerprintProfile;
use crate::tls::TlsParams;

/// How long to keep listening after the handshake. Tickets arrive at once;
/// the rest of the time is for a server that sends its HTTP/2 settings late.
pub const LISTEN: Duration = Duration::from_secs(3);
/// The most records remembered. Sites send two to four; the client side of
/// this stack refuses a long run of empty records, so the list stays short.
pub const MAX_RECORDS: usize = 8;

/// Finds record boundaries in a TLS byte stream that arrives in arbitrary
/// pieces, without keeping any of the bytes.
#[derive(Default)]
struct RecordWalker {
    header: [u8; 5],
    have: usize,
    body_left: usize,
}

impl RecordWalker {
    /// Feed the next bytes of the stream; `record` is called with the type
    /// and whole wire length of each record whose header completes in them.
    fn feed(&mut self, mut data: &[u8], mut record: impl FnMut(u8, usize)) {
        while !data.is_empty() {
            if self.body_left > 0 {
                let skip = self.body_left.min(data.len());
                self.body_left -= skip;
                data = &data[skip..];
                continue;
            }
            let take = (5 - self.have).min(data.len());
            self.header[self.have..self.have + take].copy_from_slice(&data[..take]);
            self.have += take;
            data = &data[take..];
            if self.have == 5 {
                self.have = 0;
                self.body_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                record(self.header[0], 5 + self.body_left);
            }
        }
    }
}

/// Sits under the TLS client and watches record headers go by in both
/// directions.
pub(super) struct Tap<S> {
    inner: S,
    sent: RecordWalker,
    received: RecordWalker,
    /// The client's Finished has gone out, so what arrives now is
    /// post-handshake.
    finished_sent: bool,
    sizes: Arc<Mutex<Vec<u16>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let finished_sent = this.finished_sent;
        let sizes = &this.sizes;
        this.received
            .feed(&buf.filled()[before..], |content_type, wire_len| {
                if finished_sent && content_type == CONTENT_APPDATA {
                    let mut sizes = sizes.lock().unwrap_or_else(|p| p.into_inner());
                    if sizes.len() < MAX_RECORDS {
                        sizes.push(wire_len as u16);
                    }
                }
            });
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            let finished_sent = &mut this.finished_sent;
            this.sent.feed(&buf[..written], |content_type, _| {
                *finished_sent |= content_type == CONTENT_APPDATA;
            });
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Put a tap on `io`, and get the list its post-handshake record sizes are
/// collected in.
pub(super) fn tap<S>(io: S) -> (Tap<S>, Arc<Mutex<Vec<u16>>>) {
    let sizes = Arc::new(Mutex::new(Vec::new()));
    let tap = Tap {
        inner: io,
        sent: RecordWalker::default(),
        received: RecordWalker::default(),
        finished_sent: false,
        sizes: Arc::clone(&sizes),
    };
    (tap, sizes)
}

/// Handshake with the site behind `io` as a browser asking for `server_name`
/// and return the wire sizes of the records it sends afterwards, in order.
///
/// An empty list is a real answer (the site sends nothing); an error means
/// the handshake did not complete and nothing was learned.
pub async fn observe<S>(io: S, server_name: &str) -> Result<Vec<u16>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (tap, sizes) = tap(io);
    let params = TlsParams::new(server_name)
        .with_alpn(&["h2", "http/1.1"])
        .with_profile(FingerprintProfile::Chrome);
    let mut stream = crate::tls::connect(tap, &params).await?;
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(LISTEN, async {
        // Whatever the site says is read only so its records keep arriving.
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
    let sizes = sizes.lock().unwrap_or_else(|p| p.into_inner()).clone();
    Ok(sizes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(content_type: u8, body: usize) -> Vec<u8> {
        let mut out = vec![content_type, 3, 3, (body >> 8) as u8, body as u8];
        out.resize(5 + body, 0);
        out
    }

    #[test]
    fn records_are_found_however_the_stream_is_cut() {
        let mut stream = record(0x16, 90);
        stream.extend(record(0x17, 250));
        stream.extend(record(0x17, 0));
        stream.extend(record(0x17, 64));
        for chunk in [1, 2, 5, 7, 300, stream.len()] {
            let mut walker = RecordWalker::default();
            let mut seen = Vec::new();
            for piece in stream.chunks(chunk) {
                walker.feed(piece, |kind, len| seen.push((kind, len)));
            }
            assert_eq!(
                seen,
                [(0x16, 95), (0x17, 255), (0x17, 5), (0x17, 69)],
                "cut every {chunk} bytes"
            );
        }
    }

    /// Against a real site, named in `ZRAY_LIVE_TLS_HOST`. Run with
    /// `cargo test -p zero-security live_site -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "connects to the site named in ZRAY_LIVE_TLS_HOST"]
    async fn a_live_site_reports_its_post_handshake_records() {
        let host = std::env::var("ZRAY_LIVE_TLS_HOST").expect("set ZRAY_LIVE_TLS_HOST");
        let tcp = tokio::net::TcpStream::connect((host.as_str(), 443))
            .await
            .unwrap();
        let sizes = observe(tcp, &host).await.unwrap();
        eprintln!("{host}: {sizes:?}");
        assert!(sizes.len() <= MAX_RECORDS);
    }

    /// Only what arrives after the client's first encrypted record counts,
    /// and only application-data records.
    #[tokio::test]
    async fn only_records_after_the_clients_finished_are_noted() {
        use tokio::io::AsyncWriteExt;
        let (near, mut far) = tokio::io::duplex(4096);
        let (mut tap, sizes) = tap(near);
        let mut sink = [0u8; 4096];

        // The server's handshake flight, then a compatibility CCS from us.
        far.write_all(&record(0x17, 1200)).await.unwrap();
        tap.read_exact(&mut sink[..1205]).await.unwrap();
        tap.write_all(&record(0x14, 1)).await.unwrap();
        assert!(sizes.lock().unwrap().is_empty());

        tap.write_all(&record(0x17, 53)).await.unwrap();
        far.write_all(&record(0x17, 250)).await.unwrap();
        far.write_all(&record(0x15, 19)).await.unwrap();
        far.write_all(&record(0x17, 64)).await.unwrap();
        let mut got = 0;
        while got < 255 + 24 + 69 {
            got += tap.read(&mut sink).await.unwrap();
        }
        assert_eq!(*sizes.lock().unwrap(), [255, 69]);
    }
}
