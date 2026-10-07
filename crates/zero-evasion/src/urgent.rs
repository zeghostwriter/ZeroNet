//! Hiding the server name behind one byte of TCP urgent data.
//!
//! TCP lets a sender mark a byte as "urgent". A receiving system takes that
//! byte out of the ordinary stream and keeps it aside (unless the program
//! asked otherwise, and TLS servers do not). A filter on the path that puts
//! the stream back together without honouring the mark keeps the byte in.
//!
//! So the ClientHello is sent in two parts, cut in the middle of the server
//! name, with one extra byte marked urgent at the end of the first part:
//!
//! ```text
//! what is sent     ... www.exa X mple.com ...     (X is urgent)
//! the server reads ... www.example.com ...        (X taken out)
//! the filter reads ... www.exaXmple.com ...       (a name it does not know)
//! ```
//!
//! It costs one byte and no delay, and it needs nothing from the kernel
//! beyond ordinary sockets, which is why it is the method for phones whose
//! kernel cannot send a decoy ([`crate::decoy`]).
//!
//! Measured 2026-10-07 from Tehran (Zi-Tel), with an HTTP request after the
//! handshake: `www.bbc.com` and `www.reddit.com` on Fastly 8 of 8,
//! `*.pages.dev` and `api.cloudflareclient.com` on Cloudflare 8 of 8, all
//! reset as they are; `engage.cloudflareclient.com` 0 of 4, where the decoy
//! got through. So it is one of the ways to try, not the only one.
//!
//! The rule this module keeps: the urgent byte is only ever an *extra* byte.
//! If the kernel takes less than the whole first part, a byte of the real
//! hello would carry the mark and be lost at the server, so that connection
//! is failed instead of sent on damaged.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Whether this system can send the urgent byte the way this module needs.
pub fn supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

/// A TCP stream whose first write, when it is a TLS ClientHello with a
/// server name, goes out with an urgent byte in the middle of the name (see
/// the module text). Every other write and every read passes straight
/// through, and so does a first write that is not such a hello.
pub struct UrgentStream<S> {
    inner: S,
    first: bool,
}

impl<S> UrgentStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, first: true }
    }
}

/// Send `head` followed by one urgent byte. `Ok(true)` when all of it went,
/// `Ok(false)` when nothing did (the caller sends the plain way), and an
/// error when only part did, which cannot be repaired.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_with_urgent_byte(fd: std::os::fd::RawFd, head: &[u8]) -> io::Result<bool> {
    use rand::Rng;
    let mut part = Vec::with_capacity(head.len() + 1);
    part.extend_from_slice(head);
    // A letter, so the name the filter reads still looks like a name.
    part.push(rand::thread_rng().gen_range(b'a'..=b'z'));
    // SAFETY: `part` is live for the call and its length is passed with it.
    let sent = unsafe {
        libc::send(
            fd,
            part.as_ptr().cast(),
            part.len(),
            libc::MSG_OOB | libc::MSG_NOSIGNAL,
        )
    };
    match usize::try_from(sent) {
        Ok(sent) if sent == part.len() => Ok(true),
        Err(_) => Ok(false),
        Ok(_) => Err(io::Error::other(
            "the urgent byte could not be sent whole; the connection is dropped",
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl<S: AsyncWrite + Unpin + std::os::fd::AsRawFd> AsyncWrite for UrgentStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if std::mem::take(&mut this.first) {
            if let Some(name) = crate::decoy::server_name_range(buf) {
                let cut = name.start + name.len() / 2;
                if send_with_urgent_byte(this.inner.as_raw_fd(), &buf[..cut])? {
                    // The caller writes the rest as ordinary data.
                    return Poll::Ready(Ok(cut));
                }
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl<S: AsyncWrite + Unpin> AsyncWrite for UrgentStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.first = false;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UrgentStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

/// Accept one connection on `listener` and read `wanted` bytes from it with
/// blocking calls, the way that is safe across an urgent mark: every call
/// asks the kernel again, so the read that stopped at the mark is followed by
/// one that carries on past it. For this crate's tests and for the check the
/// apps run. Empty when the bytes do not come in time.
pub fn read_past_the_mark(listener: &std::net::TcpListener, wanted: usize) -> Vec<u8> {
    use std::io::Read;
    let mut seen = vec![0u8; wanted];
    let read = listener.accept().and_then(|(mut peer, _)| {
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        peer.read_exact(&mut seen)
    });
    if read.is_err() {
        seen.clear();
    }
    seen
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The receiving kernel takes the urgent byte out, so a peer that reads
    /// the ordinary way gets the hello exactly as it was written, and what
    /// follows it too.
    ///
    /// The peer here reads with plain blocking calls, as a server written in
    /// Go or C does. A read stops at the urgent mark even when more has
    /// arrived, and tokio takes a short read to mean the socket is empty and
    /// waits for news that never comes, so a tokio reader can stall on this:
    /// see [`read_past_the_mark`] for what a reader has to do.
    #[tokio::test]
    async fn the_peer_reads_the_hello_without_the_urgent_byte() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let record = crate::build_fake_client_hello("blocked.example.com").unwrap();
        let mut stream = UrgentStream::new(client);
        stream.write_all(&record).await.unwrap();
        stream.write_all(b"after").await.unwrap();
        let wanted = record.len() + 5;
        let seen = tokio::task::spawn_blocking(move || read_past_the_mark(&listener, wanted))
            .await
            .unwrap();
        assert_eq!(seen[..record.len()], record[..]);
        assert_eq!(&seen[record.len()..], b"after");
    }

    /// Anything that is not a ClientHello with a name is sent untouched.
    #[tokio::test]
    async fn other_first_writes_pass_through() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut stream = UrgentStream::new(client);
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut seen = [0u8; 18];
        server.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"GET / HTTP/1.1\r\n\r\n");
    }
}
