//! A decoy ClientHello without root.
//!
//! [`crate::sni_desync`] injects a fake hello with a raw socket, which needs
//! `CAP_NET_RAW`: no use on a phone that is not rooted. This module gets the
//! same effect from an ordinary TCP socket, with three calls any process may
//! make.
//!
//! How it works, in the order it happens:
//!
//! 1. The real ClientHello is copied into a page of memory of our own, and
//!    the server name in the copy is replaced with a harmless one of the same
//!    length. That copy is the decoy.
//! 2. The page is handed to the kernel with `vmsplice` and `splice`, which
//!    send it *without copying it*: the socket's send queue points at our
//!    page. The segment also carries a TCP MD5 option (`TCP_MD5SIG`), which a
//!    filter on the path ignores and the server drops the segment for, since
//!    it never agreed on a key.
//! 3. Once the decoy has left, the page is overwritten with the real hello
//!    and the MD5 option is switched off. The server never acknowledged the
//!    decoy, so the kernel sends that part of the stream again, reads the
//!    page again, and this time sends the real hello.
//!
//! The filter saw an allowed name first; the server only ever saw the real
//! one. The price is one retransmission timeout per connection, measured at
//! 0.7 to 1.5 seconds, so this is something to turn on where it is needed and
//! not a default.
//!
//! Measured 2026-10-07 from Tehran (Zi-Tel) against Cloudflare's edge, 2 tries
//! each: `x.pages.dev` 0 as is and 2 this way, `engage.cloudflareclient.com`
//! 0 and 2, `api.cloudflareclient.com` 0 and 1.
//!
//! Two rules the measurements gave:
//!
//! * The decoy must be exactly as long as the real hello. A shorter one
//!   padded with zeros got every connection dropped, which is why the decoy
//!   is a copy of the real hello and not a hello of its own.
//! * The MD5 option is what keeps the decoy from the server. A low TTL does
//!   it too, but only when the hop count is guessed right, and a guess that
//!   is too high makes the server answer the decoy. When the kernel has no
//!   `TCP_MD5SIG` nothing is sent this way at all ([`supported`]).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Whether this kernel can send a decoy: Linux or Android with TCP MD5
/// signatures built in. Asked once; the answer cannot change while running.
pub fn supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SUPPORTED.get_or_init(sys::probe)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

/// Whether a decoy can be sent by any means: from the socket itself
/// ([`supported`]) or with a raw socket ([`crate::has_raw_socket_capability`]).
/// What a caller asks before it spends a probe on the decoy.
///
/// False while the user has the decoy switched off ([`set_enabled`]), so
/// everything that decides by itself (the planner, the CDN check, the server
/// test, auto mode's variants) leaves it alone.
pub fn available() -> bool {
    enabled() && (supported() || crate::has_raw_socket_capability())
}

/// Whether the name can be hidden by any method at all, the decoy or the
/// urgent byte ([`crate::urgent`]), and the user has not switched it off.
pub fn any_available() -> bool {
    enabled() && (crate::urgent::supported() || supported() || crate::has_raw_socket_capability())
}

/// Whether the user has left name hiding on ([`set_enabled`]). Shared with
/// [`crate::urgent`], the other way of hiding a name: one switch for both.
pub fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// The user's switch for the decoy: off stops every automatic use of it. A
/// configuration that names a decoy itself (`sniSpoof`) still gets one.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Where the server name sits in `record`, a TLS record holding one whole
/// ClientHello: the byte range of the host name itself.
///
/// `None` for anything else, including a hello that is cut short or has no
/// name, so the caller sends such bytes as they are.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn server_name_range(record: &[u8]) -> Option<std::ops::Range<usize>> {
    let u16_at = |at: usize| {
        Some(usize::from(u16::from_be_bytes([
            *record.get(at)?,
            *record.get(at + 1)?,
        ])))
    };
    // Record header (5), handshake header (4), version (2), random (32).
    if record.len() < 43 || record[0] != 0x16 || record[5] != 0x01 {
        return None;
    }
    if 5 + u16_at(3)? != record.len() {
        return None;
    }
    let mut at = 43;
    at += 1 + usize::from(*record.get(at)?); // session id
    at += 2 + u16_at(at)?; // cipher suites
    at += 1 + usize::from(*record.get(at)?); // compression methods
    let end = at + 2 + u16_at(at)?;
    at += 2;
    if end > record.len() {
        return None;
    }
    while at + 4 <= end {
        let (kind, length) = (u16_at(at)?, u16_at(at + 2)?);
        at += 4;
        if kind == 0 {
            // List length (2), name type (1), name length (2), then the name.
            let name_len = u16_at(at + 3)?;
            let start = at + 5;
            return (*record.get(at + 2)? == 0 && start + name_len <= at + length && name_len > 0)
                .then_some(start..start + name_len);
        }
        at += length;
    }
    None
}

/// A name exactly `len` bytes long for the decoy, built on `base` (a name the
/// filter lets through): `base` itself when it fits, a random label in front
/// of it when there is room, and a random `.com` name when `base` is too long.
/// The random part differs on every connection, so the decoys share no fixed
/// string to match on.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn decoy_name(base: &str, len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut label = |n: usize| -> Vec<u8> { (0..n).map(|_| rng.gen_range(b'a'..=b'z')).collect() };
    let mut name = match len.checked_sub(base.len()) {
        Some(0) => Vec::new(),
        Some(gap) if gap >= 2 => {
            let mut name = label(gap - 1);
            name.push(b'.');
            name
        }
        _ if len >= 6 => {
            let mut name = label(len - 4);
            name.extend_from_slice(b".com");
            return name;
        }
        _ => return label(len),
    };
    name.extend_from_slice(base.as_bytes());
    name
}

/// A TCP stream whose first write, when it is a TLS ClientHello, goes out
/// behind a decoy naming `base` (see the module text). Every other write and
/// every read passes straight through.
///
/// Anything that stops the decoy (not a ClientHello, no name in it, the
/// kernel refusing a call) falls back to sending the bytes as they are: the
/// decoy is an extra, and a connection is never lost for want of it.
pub struct DecoyStream<S> {
    inner: S,
    base: Box<str>,
    state: State,
}

enum State {
    /// Nothing written yet.
    First,
    /// The decoy has been handed to the kernel and is on its way out.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Leaving(sys::Leaving),
    /// The first write is over; the stream is an ordinary one from here.
    Plain,
}

impl<S> DecoyStream<S> {
    pub fn new(inner: S, base: &str) -> Self {
        Self {
            inner,
            base: base.into(),
            state: State::First,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl<S: AsyncWrite + Unpin + std::os::fd::AsRawFd> AsyncWrite for DecoyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if matches!(this.state, State::First) {
            this.state = server_name_range(buf)
                .and_then(|name| {
                    let decoy = decoy_name(&this.base, name.len());
                    // Only the head of the hello, up to the end of the name,
                    // goes out as a decoy; the caller writes the rest as
                    // ordinary data straight after. The server then holds the
                    // tail with a hole in front of it and says so, and the
                    // kernel fills the hole at once instead of waiting out a
                    // whole retransmission timeout.
                    sys::Leaving::start(this.inner.as_raw_fd(), &buf[..name.end], name, &decoy)
                })
                .map_or(State::Plain, State::Leaving);
        }
        match &mut this.state {
            State::Leaving(leaving) => {
                let sent = std::task::ready!(leaving.poll_finish(cx));
                this.state = State::Plain;
                Poll::Ready(Ok(sent))
            }
            _ => Pin::new(&mut this.inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl<S: AsyncWrite + Unpin> AsyncWrite for DecoyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let _ = &this.base;
        this.state = State::Plain;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DecoyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    //! The system calls. Everything unsafe in the module is here.

    use std::future::Future;
    use std::os::fd::RawFd;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    /// `TCP_MD5SIG` and its argument. Written out here because `libc` does
    /// not carry the struct for every target this builds for.
    const TCP_MD5SIG: libc::c_int = 14;
    #[repr(C)]
    struct Md5Sig {
        addr: libc::sockaddr_storage,
        flags: u8,
        prefix_len: u8,
        key_len: u16,
        if_index: libc::c_int,
        key: [u8; 80],
    }
    /// Any length will do: the key is never checked by anyone, the option
    /// only has to be there.
    const KEY_LEN: u16 = 5;
    /// `ioctl` for the bytes queued on a socket that have not been sent yet.
    const SIOCOUTQNSD: libc::c_ulong = 0x894B;
    /// How often, and how many times, to look whether the decoy has left.
    const LOOK_EVERY: Duration = Duration::from_millis(1);
    const LOOKS: u8 = 40;

    /// Turn the MD5 option on (`key_len > 0`) or off for the peer `fd` is
    /// connected to, or for `peer` when given.
    fn md5(fd: RawFd, key_len: u16, peer: Option<libc::sockaddr_storage>) -> bool {
        // SAFETY: `Md5Sig` is plain bytes, valid when zeroed; the kernel is
        // given its exact size and only reads it.
        unsafe {
            let mut sig: Md5Sig = std::mem::zeroed();
            match peer {
                Some(peer) => sig.addr = peer,
                None => {
                    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    if libc::getpeername(fd, std::ptr::addr_of_mut!(sig.addr).cast(), &mut len) != 0
                    {
                        return false;
                    }
                }
            }
            sig.key_len = key_len;
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_MD5SIG,
                std::ptr::addr_of!(sig).cast(),
                std::mem::size_of::<Md5Sig>() as libc::socklen_t,
            ) == 0
        }
    }

    /// Whether the kernel takes `TCP_MD5SIG` at all, tried on a socket that
    /// is never connected.
    pub(super) fn probe() -> bool {
        // SAFETY: a socket is opened, used for one `setsockopt` and closed.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return false;
            }
            let mut peer: libc::sockaddr_storage = std::mem::zeroed();
            let v4 = std::ptr::addr_of_mut!(peer).cast::<libc::sockaddr_in>();
            (*v4).sin_family = libc::AF_INET as libc::sa_family_t;
            (*v4).sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let ok = md5(fd, KEY_LEN, Some(peer));
            libc::close(fd);
            ok
        }
    }

    /// Memory of our own that the kernel sends from. It is private and
    /// anonymous, so unmapping it early is safe: the kernel keeps the page
    /// for as long as the socket still refers to it.
    struct Page {
        at: *mut u8,
        len: usize,
    }

    // SAFETY: the mapping belongs to this value alone and is only touched
    // through `&mut self`.
    unsafe impl Send for Page {}

    impl Page {
        fn holding(bytes: &[u8]) -> Option<Self> {
            // SAFETY: a fresh anonymous mapping of at least `bytes.len()`
            // bytes, written within its length.
            unsafe {
                let at = libc::mmap(
                    std::ptr::null_mut(),
                    bytes.len(),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if at == libc::MAP_FAILED {
                    return None;
                }
                let mut page = Self {
                    at: at.cast(),
                    len: bytes.len(),
                };
                page.write(0, bytes);
                Some(page)
            }
        }

        /// Copy `bytes` in at `offset`; anything past the end is left out.
        fn write(&mut self, offset: usize, bytes: &[u8]) {
            let room = self.len.saturating_sub(offset).min(bytes.len());
            // SAFETY: `offset + room` is within the mapping, and `bytes`
            // cannot overlap memory only this value points at.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.at.add(offset), room) }
        }
    }

    impl Drop for Page {
        fn drop(&mut self) {
            // SAFETY: the mapping made in `holding`, unmapped once.
            unsafe { libc::munmap(self.at.cast(), self.len) };
        }
    }

    /// A decoy that has been handed to the kernel, until it has left and the
    /// real bytes have taken its place.
    pub(super) struct Leaving {
        fd: RawFd,
        page: Page,
        /// The real bytes the decoy stood in for; exactly as many as the
        /// kernel took.
        real: Vec<u8>,
        looks_left: u8,
        sleep: Pin<Box<tokio::time::Sleep>>,
    }

    impl Leaving {
        /// Send `hello` (the head of one, ending with the name) with the
        /// name at `name` replaced by `decoy`, from a page of our own. `None` when any step is refused, in which case
        /// nothing was sent and the socket is as it was.
        pub(super) fn start(
            fd: RawFd,
            hello: &[u8],
            name: std::ops::Range<usize>,
            decoy: &[u8],
        ) -> Option<Self> {
            let mut page = Page::holding(hello)?;
            page.write(name.start, decoy);
            let mut pipe = [0; 2];
            // SAFETY: `pipe` is two descriptors wide, as `pipe2` wants.
            if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
                return None;
            }
            let sent = md5(fd, KEY_LEN, None).then(|| {
                let piece = libc::iovec {
                    iov_base: page.at.cast(),
                    iov_len: page.len,
                };
                // SAFETY: `piece` describes the live mapping; the pipe and the
                // socket are open. Gifting the page is what lets the kernel
                // send from it without a copy.
                unsafe {
                    let queued = libc::vmsplice(pipe[1], &piece, 1, libc::SPLICE_F_GIFT);
                    if queued <= 0 {
                        return 0;
                    }
                    libc::splice(
                        pipe[0],
                        std::ptr::null_mut(),
                        fd,
                        std::ptr::null_mut(),
                        queued as usize,
                        libc::SPLICE_F_NONBLOCK,
                    )
                }
            });
            // SAFETY: both ends were opened above and are closed once.
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            match sent {
                Some(sent) if sent > 0 => Some(Self {
                    fd,
                    page,
                    real: hello[..sent as usize].to_vec(),
                    looks_left: LOOKS,
                    sleep: Box::pin(tokio::time::sleep(LOOK_EVERY)),
                }),
                // Nothing went out. The option may have been set, so it is
                // taken off again before the hello is sent the plain way.
                _ => {
                    md5(fd, 0, None);
                    None
                }
            }
        }

        /// Wait for the decoy to leave, then put the real bytes in its place
        /// and take the MD5 option off. Returns how many of the caller's
        /// bytes this accounts for.
        ///
        /// The wait is bounded: if the kernel still reports unsent bytes
        /// after [`LOOKS`], the swap happens anyway, because holding the
        /// connection would cost more than a decoy that did not get out.
        pub(super) fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<usize> {
            while self.looks_left > 0 && self.unsent() {
                std::task::ready!(self.sleep.as_mut().poll(cx));
                self.looks_left -= 1;
                self.sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + LOOK_EVERY);
            }
            self.page.write(0, &self.real);
            md5(self.fd, 0, None);
            Poll::Ready(self.real.len())
        }

        fn unsent(&self) -> bool {
            let mut queued: libc::c_int = 0;
            // SAFETY: the ioctl writes one int.
            let ok = unsafe { libc::ioctl(self.fd, SIOCOUTQNSD as _, &mut queued) } == 0;
            ok && queued > 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello record naming `name`, with one extension either side of
    /// the name so the walk has something to step over.
    fn hello(name: &str) -> Vec<u8> {
        let mut extensions = vec![0xff, 0x01, 0, 1, 0]; // renegotiation_info
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&(name.len() as u16 + 5).to_be_bytes());
        extensions.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(name.as_bytes());
        extensions.extend_from_slice(&[0, 0x17, 0, 0]); // extended_master_secret
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[4, 1, 2, 3, 4]); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&(body.len() as u16 + 4).to_be_bytes());
        record.extend_from_slice(&[1, 0]);
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn the_name_is_found_where_it_is_and_nowhere_else() {
        let record = hello("blocked.example.com");
        let range = server_name_range(&record).expect("a name");
        assert_eq!(&record[range], b"blocked.example.com");
        // Cut short anywhere, it is not a whole hello and is left alone.
        for cut in 0..record.len() {
            assert!(server_name_range(&record[..cut]).is_none(), "cut at {cut}");
        }
        // Not a handshake record, and a handshake that is not a ClientHello.
        let mut other = record.clone();
        other[0] = 0x17;
        assert!(server_name_range(&other).is_none());
        let mut server_hello = record.clone();
        server_hello[5] = 2;
        assert!(server_name_range(&server_hello).is_none());
        // Bytes after the record (a second write glued on) are not a hello
        // this can stand in for.
        let mut longer = record;
        longer.push(0);
        assert!(server_name_range(&longer).is_none());
    }

    #[test]
    fn the_decoy_name_is_always_exactly_as_long_as_the_real_one() {
        let base = "www.speedtest.net";
        for len in 1..80 {
            let name = decoy_name(base, len);
            assert_eq!(name.len(), len);
            assert!(name
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || *byte == b'.'));
        }
        assert_eq!(decoy_name(base, base.len()), base.as_bytes());
        assert!(decoy_name(base, base.len() + 6).ends_with(b".www.speedtest.net"));
        assert!(decoy_name(base, 10).ends_with(b".com"));
    }

    /// Over the loopback nothing is lost, so what the peer reads is the
    /// decoy's fate decided by the kernel alone: the MD5 option makes the
    /// receiver drop it, and the retransmission brings the real hello.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn the_peer_only_ever_reads_the_real_hello() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if !supported() {
            eprintln!("skipped: this kernel has no TCP_MD5SIG");
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let record = hello("blocked.example.com");
        let mut stream = DecoyStream::new(client, "www.speedtest.net");
        stream.write_all(&record).await.unwrap();
        // A later write is an ordinary one.
        stream.write_all(b"after").await.unwrap();
        let mut seen = vec![0u8; record.len() + 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server.read_exact(&mut seen),
        )
        .await
        .expect("the real hello arrives by retransmission")
        .unwrap();
        assert_eq!(seen[..record.len()], record[..]);
        assert_eq!(&seen[record.len()..], b"after");
    }
}
