use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// First and last delay of the backoff used when the *local* host is out of
/// sockets (fd limit, kernel buffers, ephemeral ports).
const LOCAL_BACKOFF_START: Duration = Duration::from_millis(5);
const LOCAL_BACKOFF_MAX: Duration = Duration::from_millis(200);

/// Errors that say nothing about the remote address: this host is out of
/// file descriptors, socket buffers or ephemeral ports. Reporting them as a
/// failed probe would mark live IPs dead whenever the scan outruns the fd
/// limit, so they are retried with backoff instead.
fn is_local_exhaustion(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EMFILE)
            | Some(libc::ENFILE)
            | Some(libc::ENOBUFS)
            | Some(libc::ENOMEM)
            | Some(libc::EADDRNOTAVAIL)
    )
}

fn open_socket(ip: IpAddr, timeout: Duration) -> io::Result<Socket> {
    let domain = match ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_nodelay(true);
    // RST on close instead of FIN: a scan opens tens of thousands of short
    // connections and TIME_WAIT would otherwise pin the ephemeral port range.
    let _ = socket.set_linger(Some(Duration::ZERO));
    // Inside a mobile VPN process an unprotected socket is routed back into
    // the tunnel, so the scan would measure the proxy instead of the edge.
    // A no-op unless the host installed a protector.
    zero_core::platform::protect_socket(&socket)?;

    #[cfg(target_os = "linux")]
    {
        // Fail connections that stop acknowledging data instead of letting
        // the kernel retransmit for minutes.
        let _ = socket.set_tcp_user_timeout(Some(timeout.min(Duration::from_secs(5))));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = timeout;

    Ok(socket)
}

/// Connects to `ip:port`, returning the stream and the TCP handshake time.
///
/// The returned duration covers only `connect()` up to the socket becoming
/// writable (one SYN/SYN-ACK round trip); socket setup and any wait for a
/// free file descriptor are excluded. `timeout` bounds the handshake itself.
pub async fn connect_tcp(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<(TcpStream, Duration), io::Error> {
    let target = SocketAddr::new(ip, port);
    let backoff_deadline = Instant::now() + timeout;
    let mut backoff = LOCAL_BACKOFF_START;

    loop {
        match try_connect(ip, target, timeout).await {
            Err(e) if is_local_exhaustion(&e) && Instant::now() + backoff < backoff_deadline => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(LOCAL_BACKOFF_MAX);
            }
            other => return other,
        }
    }
}

async fn try_connect(
    ip: IpAddr,
    target: SocketAddr,
    timeout: Duration,
) -> Result<(TcpStream, Duration), io::Error> {
    let socket = open_socket(ip, timeout)?;

    let start = Instant::now();
    match socket.connect(&target.into()) {
        Ok(()) => {}
        // Unix reports a pending non-blocking connect as EINPROGRESS,
        // Windows as WSAEWOULDBLOCK.
        Err(ref err)
            if err.raw_os_error() == Some(libc::EINPROGRESS)
                || err.kind() == io::ErrorKind::WouldBlock => {}
        Err(err) => return Err(err),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let tokio_stream = TcpStream::from_std(std_stream)?;

    let wait = async {
        tokio_stream.writable().await?;
        // A failed asynchronous connect reports writable too; the real
        // outcome is in SO_ERROR.
        if let Some(err) = tokio_stream.take_error()? {
            return Err(err);
        }
        Ok(())
    };

    match tokio::time::timeout(timeout, wait).await {
        Ok(Ok(())) => {
            let elapsed = start.elapsed();
            Ok((tokio_stream, elapsed))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP connect timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_and_measures_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let (_stream, rtt) =
            connect_tcp("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2))
                .await
                .unwrap();
        assert!(rtt < Duration::from_secs(2));
        accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn refused_connection_is_an_error_not_a_hang() {
        // Bind then drop to get a port that is (almost certainly) closed.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let res = connect_tcp("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)).await;
        assert!(res.is_err());
    }

    #[test]
    fn fd_exhaustion_is_classified_as_local() {
        assert!(is_local_exhaustion(&io::Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(is_local_exhaustion(&io::Error::from_raw_os_error(
            libc::ENFILE
        )));
        assert!(!is_local_exhaustion(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
        assert!(!is_local_exhaustion(&io::Error::new(
            io::ErrorKind::TimedOut,
            "x"
        )));
    }
}
