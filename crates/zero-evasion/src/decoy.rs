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
//! one. The price is the resend: the kernel only sends the real hello once
//! the server has said it is missing, about one round trip more per
//! connection (0.3 s from Tehran, where the whole plain handshake takes
//! 0.35 s). So this is something to use where it is needed, not a default:
//! `crate::choice` keeps it for the servers that need it.
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
//! * The decoy has to be stopped before the server. The MD5 option does that
//!   on a kernel built with it ([`Fooling::Md5`]). Where it is compiled out,
//!   as on many phones, a TTL low enough to expire between the filter and the
//!   server does the same job with an ordinary `setsockopt`
//!   ([`Fooling::Ttl`]).
//!
//! The TTL has to be guessed for the path: too low and the filter never sees
//! the decoy, too high and the server answers it and the handshake fails.
//! That is why it is never chosen silently. A policy asks for it by naming a
//! hop count ([`DecoyPolicy::ttl`]), and the app's auto mode sends it as a
//! variant of its own that the balancer keeps only if its probes get through.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Whether this kernel can send the MD5 decoy: Linux or Android with TCP MD5
/// signatures built in. Asked once; the answer cannot change while running.
pub fn supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        sys::kernel().md5
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

/// Whether this kernel can send the TTL decoy ([`Fooling::Ttl`]): Linux or
/// Android, where any socket may set its own hop limit.
pub fn ttl_supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        sys::kernel().ttl
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

/// Whether the TTL decoy is worth offering as a way of its own: the user has
/// name hiding on, this kernel can set a hop limit, and it has no MD5 option
/// (where it has, the MD5 decoy does the same job with no guess at the path).
pub fn ttl_available() -> bool {
    enabled() && ttl_supported() && !supported()
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
///
/// `?`, `#` and `*` in `base` are drawn once per connection
/// ([`draw_wildcards`]), so the decoys a single process sends share no fixed
/// string to match on. The random label and the random `.com` name are
/// lowercase letters.
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
    let at = name.len();
    name.extend_from_slice(base.as_bytes());
    // Only the bytes that came from `base` are wildcards; the label in front
    // is already random. Each wildcard stays one byte, so the length holds.
    draw_wildcards(&mut name[at..]);
    name
}

/// Draw the wildcards in a decoy name, in place: `?` becomes a lowercase
/// letter, `#` a digit and `*` either. Every other byte is left alone and
/// the length never changes, so `"www.???.com"` turns into something like
/// `"www.kqz.com"`, a fresh one on each call.
pub(crate) fn draw_wildcards(name: &mut [u8]) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for byte in name {
        let letter = match *byte {
            b'?' => true,
            b'#' => false,
            b'*' => rng.gen(),
            _ => continue,
        };
        *byte = if letter {
            rng.gen_range(b'a'..=b'z')
        } else {
            rng.gen_range(b'0'..=b'9')
        };
    }
}

/// How many segments the rest of the hello is sent in, after the decoy.
///
/// The server drops the decoy, so everything after it arrives with a hole in
/// front, and each piece makes the server say so (a SACK). Linux waits a
/// quarter of a round trip after the first such report in case the hole is
/// only reordering, but marks the hole lost at once from the third report on
/// (its reordering threshold). Three pieces take that wait off every decoy
/// connection: about 40 ms in a trace from Tehran, where a round trip is
/// about 170 ms.
#[cfg(any(target_os = "linux", target_os = "android"))]
const TAIL_PIECES: u8 = 3;

/// What keeps the decoy segment from the server it is addressed to. The
/// filter must read the decoy and the server must not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Fooling {
    /// The MD5 option where the kernel has it, otherwise the TTL when the
    /// policy names a hop count, otherwise no decoy.
    #[default]
    Auto,
    /// A TCP MD5 signature option in the segment. A server that never agreed
    /// on a key with this peer drops the whole segment, whatever else it
    /// carries. Needs `CONFIG_TCP_MD5SIG` in the sending kernel.
    Md5,
    /// A hop limit low enough that the segment expires between the filter and
    /// the server. Needs no kernel feature and no privilege, only a guess at
    /// how far away the server is, so it is only used with a hop count.
    Ttl,
}

/// What a decoy stream hides a name behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyPolicy {
    /// A name the filter lets through. `?` draws a lowercase letter, `#` a
    /// digit and `*` either, once per connection, so two decoys from this
    /// process never spell the same name. Whatever is left of the length is
    /// filled with a random label in front of it.
    pub name: Box<str>,
    /// How the decoy is kept from the server.
    pub fooling: Fooling,
    /// The hop limit for a decoy stopped by expiry. Zero means none is
    /// known, and then no TTL decoy is sent: one at the kernel's default
    /// would reach the server, which is worse than no decoy at all.
    /// [`DEFAULT_TTL`] is the usual guess.
    pub ttl: u8,
}

/// The hop limit a TTL decoy is sent with when nothing better is known. The
/// number the other userspace tools ship: enough for a path whose filter
/// sits within a few hops of the server.
pub const DEFAULT_TTL: u8 = 8;

impl Default for DecoyPolicy {
    fn default() -> Self {
        Self {
            // The same allow-listed name the REALITY masker, the clean-IP
            // scanner and the HTTP/2 SNI default use: it resolves on many
            // networks, nobody throttles it, and a censor that probes it
            // finds a real site.
            name: "www.speedtest.net".into(),
            fooling: Fooling::Auto,
            // No hop count is known, so no TTL decoy: the MD5 one or none.
            ttl: 0,
        }
    }
}

impl DecoyPolicy {
    /// Whether this kernel can send the decoy this policy asks for, so a
    /// caller can pick another way before it opens a stream with no decoy.
    pub fn sendable(&self) -> bool {
        self.fooled(supported(), ttl_supported()).is_some()
    }

    /// The way the decoy is stopped, given what the kernel has: `None` when
    /// this policy cannot be met on it.
    fn fooled(&self, md5: bool, ttl: bool) -> Option<Fooled> {
        let by_ttl = (ttl && self.ttl > 0).then_some(Fooled::Ttl(self.ttl));
        match self.fooling {
            Fooling::Md5 => md5.then_some(Fooled::Md5Sig),
            Fooling::Ttl => by_ttl,
            Fooling::Auto if md5 => Some(Fooled::Md5Sig),
            Fooling::Auto => by_ttl,
        }
    }
}

/// [`Fooling`] resolved for one connection: what is set on the socket while
/// the decoy leaves, and taken off again after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fooled {
    Md5Sig,
    Ttl(u8),
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
    policy: DecoyPolicy,
    state: State,
}

enum State {
    /// Nothing written yet.
    First,
    /// The decoy has been handed to the kernel and is on its way out.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Leaving(sys::Leaving),
    /// The decoy is out; the rest of the hello goes in this many separate
    /// writes (see [`TAIL_PIECES`]).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Tail(u8),
    /// The first write is over; the stream is an ordinary one from here.
    Plain,
}

impl<S> DecoyStream<S> {
    pub fn new(inner: S, policy: DecoyPolicy) -> Self {
        Self {
            inner,
            policy,
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
                    let decoy = decoy_name(&this.policy.name, name.len());
                    // Only the head of the hello, up to the end of the name,
                    // goes out as a decoy; the caller writes the rest as
                    // ordinary data straight after. The server then holds the
                    // tail with a hole in front of it and says so, and the
                    // kernel fills the hole at once instead of waiting out a
                    // whole retransmission timeout.
                    let kernel = sys::kernel();
                    let fooled = this.policy.fooled(kernel.md5, kernel.ttl)?;
                    sys::Leaving::start(
                        this.inner.as_raw_fd(),
                        &buf[..name.end],
                        name,
                        &decoy,
                        fooled,
                    )
                })
                .map_or(State::Plain, State::Leaving);
        }
        match &mut this.state {
            State::Leaving(leaving) => {
                let sent = std::task::ready!(leaving.poll_finish(cx));
                this.state = State::Tail(TAIL_PIECES);
                Poll::Ready(Ok(sent))
            }
            State::Tail(left) => {
                // An even share of what is left; the caller comes back for
                // the rest, and each call is its own segment (the socket has
                // no Nagle delay).
                let share = buf.len().div_ceil(usize::from(*left)).max(1);
                let written = std::task::ready!(
                    Pin::new(&mut this.inner).poll_write(cx, &buf[..share.min(buf.len())])
                );
                if written.is_ok() {
                    this.state = match *left {
                        0..=1 => State::Plain,
                        more => State::Tail(more - 1),
                    };
                }
                Poll::Ready(written)
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
        let _ = &this.policy;
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

    use super::Fooled;
    use std::future::Future;
    use std::os::fd::RawFd;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    /// `TCP_MD5SIG` and its argument. Written out here because `libc` does
    /// not carry the struct for every target this builds for.
    const TCP_MD5SIG: libc::c_int = 14;
    /// How either family spells "the kernel default" for `IP_TTL` and
    /// `IPV6_UNICAST_HOPS`. It is how the option is put back once the decoy
    /// has left, so a stream that hid a name and one that did not behave the
    /// same on the wire afterwards. Not zero: Linux refuses `IP_TTL` 0 and
    /// takes `IPV6_UNICAST_HOPS` 0 literally, and either way every later
    /// segment would expire before the server.
    const DEFAULT_TTL: libc::c_int = -1;
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

    /// Stamp `hops` on every segment this socket sends from now on. Both
    /// families are set, because only the one in use has any effect and a
    /// dual-stack socket may carry either. [`DEFAULT_TTL`] takes the stamp
    /// back off. True when at least one family took it.
    fn set_ttl(fd: RawFd, hops: libc::c_int) -> bool {
        // SAFETY: one small int in, nothing out.
        unsafe {
            let ok4 = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                (&hops as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0;
            let ok6 = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                (&hops as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0;
            ok4 || ok6
        }
    }

    /// What this kernel can stop a decoy with.
    #[derive(Clone, Copy)]
    pub(super) struct Kernel {
        pub(super) md5: bool,
        pub(super) ttl: bool,
    }

    /// Ask the kernel once which of the two options it takes, on a socket
    /// that is never connected. The answer cannot change while the process
    /// runs, and the probe is a socket and a few `setsockopt` calls, too much
    /// to spend on every connection.
    pub(super) fn kernel() -> Kernel {
        static KERNEL: std::sync::OnceLock<Kernel> = std::sync::OnceLock::new();
        *KERNEL.get_or_init(|| {
            // SAFETY: a socket is opened, used for setsockopt and closed.
            unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                if fd < 0 {
                    return Kernel {
                        md5: false,
                        ttl: false,
                    };
                }
                let mut peer: libc::sockaddr_storage = std::mem::zeroed();
                let v4 = std::ptr::addr_of_mut!(peer).cast::<libc::sockaddr_in>();
                (*v4).sin_family = libc::AF_INET as libc::sa_family_t;
                (*v4).sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                let md5 = md5(fd, KEY_LEN, Some(peer));
                let ttl = set_ttl(fd, 1);
                libc::close(fd);
                Kernel { md5, ttl }
            }
        })
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
        /// What stops the decoy before the server, and what has to be undone
        /// once it has left.
        fooled: Fooled,
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
            fooled: Fooled,
        ) -> Option<Self> {
            let mut page = Page::holding(hello)?;
            page.write(name.start, decoy);
            let mut pipe = [0; 2];
            // SAFETY: `pipe` is two descriptors wide, as `pipe2` wants.
            if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
                return None;
            }
            let stopped = match fooled {
                Fooled::Md5Sig => md5(fd, KEY_LEN, None),
                Fooled::Ttl(hops) => set_ttl(fd, libc::c_int::from(hops)),
            };
            let sent = stopped.then(|| {
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
                    fooled,
                    looks_left: LOOKS,
                    sleep: Box::pin(tokio::time::sleep(LOOK_EVERY)),
                }),
                // Nothing went out. The option may have been set, so it is
                // taken off again before the hello is sent the plain way.
                _ => {
                    undo(fd, fooled);
                    None
                }
            }
        }

        /// Wait for the decoy to leave, then put the real bytes in its place
        /// and take the stopping option off. Returns how many of the caller's
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
            undo(self.fd, self.fooled);
            Poll::Ready(self.real.len())
        }

        fn unsent(&self) -> bool {
            let mut queued: libc::c_int = 0;
            // SAFETY: the ioctl writes one int.
            let ok = unsafe { libc::ioctl(self.fd, SIOCOUTQNSD as _, &mut queued) } == 0;
            ok && queued > 0
        }
    }

    /// Take whatever was stopping the decoy back off `fd`, so the real
    /// traffic that follows leaves the socket exactly as it would have.
    fn undo(fd: RawFd, fooled: Fooled) {
        match fooled {
            Fooled::Md5Sig => {
                md5(fd, 0, None);
            }
            Fooled::Ttl(_) => {
                set_ttl(fd, DEFAULT_TTL);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hops(fd: RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: one int out, its size passed in.
            let ok = unsafe {
                libc::getsockopt(
                    fd,
                    level,
                    name,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            assert_eq!(ok, 0);
            value
        }

        /// After a TTL decoy the socket must be back at the kernel's default
        /// hop count, or the real hello and everything after it would expire
        /// on the way just as the decoy did.
        #[test]
        fn a_ttl_decoy_leaves_the_default_hop_count_behind() {
            let cases = [
                (libc::AF_INET, libc::IPPROTO_IP, libc::IP_TTL),
                (libc::AF_INET6, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            ];
            for (family, level, name) in cases {
                // SAFETY: a socket is opened, used for setsockopt and closed.
                let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
                if fd < 0 {
                    continue; // no IPv6 on this machine
                }
                let default = hops(fd, level, name);
                assert!(set_ttl(fd, 8));
                assert_eq!(hops(fd, level, name), 8);
                undo(fd, Fooled::Ttl(8));
                assert_eq!(hops(fd, level, name), default, "family {family}");
                // SAFETY: closing the socket opened above.
                unsafe { libc::close(fd) };
            }
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

    /// A `?`, `#` or `*` in the name is drawn per call and never changes the
    /// length, so a rotating decoy stays a decoy the same size.
    #[test]
    fn wildcards_are_drawn_and_keep_the_length() {
        let base = "www.?????.net";
        let mut seen = Vec::new();
        for _ in 0..64 {
            let name = decoy_name(base, base.len());
            assert_eq!(name.len(), base.len(), "the length must not move");
            let text = String::from_utf8(name).unwrap();
            assert!(text.starts_with("www."), "{text}");
            assert!(text.ends_with(".net"), "{text}");
            seen.push(text);
        }
        // With five letters drawn each time, 64 draws are the same string
        // only if nothing is being drawn.
        assert!(seen.iter().collect::<std::collections::HashSet<_>>().len() > 1);
    }

    /// Whatever is drawn stays a letter or a digit: the decoy has to look
    /// like a name to whatever reads it.
    #[test]
    fn a_drawn_name_is_always_letters_and_digits() {
        let base = "*#*#*#*.example.com";
        for _ in 0..32 {
            let name = decoy_name(base, base.len());
            assert!(name
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'.'));
        }
    }

    /// The default decoy names a speed test host, the same allow-listed name
    /// the REALITY masker and the clean-IP scanner use, and guesses no hop
    /// count.
    #[test]
    fn the_default_policy_names_an_allow_listed_host() {
        let policy = DecoyPolicy::default();
        assert_eq!(&*policy.name, "www.speedtest.net");
        assert_eq!(policy.fooling, Fooling::Auto);
        assert_eq!(policy.ttl, 0, "a TTL decoy is never sent unasked");
    }

    /// The TTL is only ever used with a hop count, and the MD5 option is
    /// preferred wherever the kernel has it.
    #[test]
    fn fooling_is_resolved_by_what_the_kernel_has() {
        let policy = |fooling, ttl| DecoyPolicy {
            fooling,
            ttl,
            ..DecoyPolicy::default()
        };
        // Auto: MD5 when there, TTL only with a hop count.
        assert_eq!(
            policy(Fooling::Auto, 8).fooled(true, true),
            Some(Fooled::Md5Sig)
        );
        assert_eq!(
            policy(Fooling::Auto, 8).fooled(false, true),
            Some(Fooled::Ttl(8))
        );
        assert_eq!(policy(Fooling::Auto, 0).fooled(false, true), None);
        // Asked for by name, each is used or nothing is.
        assert_eq!(policy(Fooling::Md5, 8).fooled(false, true), None);
        assert_eq!(
            policy(Fooling::Ttl, 6).fooled(true, true),
            Some(Fooled::Ttl(6))
        );
        assert_eq!(policy(Fooling::Ttl, 0).fooled(true, true), None);
        assert_eq!(policy(Fooling::Ttl, 6).fooled(true, false), None);
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
        let mut stream = DecoyStream::new(client, DecoyPolicy::default());
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

    /// The TTL decoy over the loopback: the hello and what follows arrive
    /// intact, and the socket is back at the kernel's own hop count after.
    ///
    /// What the loopback cannot show is the decoy itself. There the receiver
    /// is handed the sender's own page instead of a copy, so by the time it
    /// reads, the page already holds the real hello again. Whether the decoy
    /// expires on the way is a property of a real path, and is checked on one.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn a_ttl_decoy_goes_out_and_the_socket_is_put_back() {
        use std::os::fd::AsRawFd;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if !ttl_supported() {
            eprintln!("skipped: this kernel takes no IP_TTL");
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let hops = |fd| {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: one int out, its size passed in.
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_TTL,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            value
        };
        let fd = client.as_raw_fd();
        let before = hops(fd);
        let record = hello("blocked.example.com");
        let policy = DecoyPolicy {
            name: "decoyname.example".into(),
            fooling: Fooling::Ttl,
            ttl: 3,
        };
        let mut stream = DecoyStream::new(client, policy);
        stream.write_all(&record).await.unwrap();
        stream.write_all(b"after").await.unwrap();
        let mut seen = vec![0u8; record.len() + 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server.read_exact(&mut seen),
        )
        .await
        .expect("the hello arrives")
        .unwrap();
        assert_eq!(seen[..record.len()], record[..]);
        assert_eq!(&seen[record.len()..], b"after");
        assert_eq!(hops(fd), before, "the hop count is the kernel's again");
    }
}
