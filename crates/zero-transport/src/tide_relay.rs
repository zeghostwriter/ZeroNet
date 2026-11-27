//! A Tide relay: the address clients see, forwarding to an egress they never
//! touch.
//!
//! How this works. A relay is an HTTP/2 server that answers every request
//! that is not a Tide request with the decoy site, and passes every Tide
//! request (`POST <path>/<session>/open`, `POST .../u/<n>`, `GET .../d/<n>`)
//! on to one fixed upstream, the *egress*, and passes the answer back. The
//! bodies are still sealed end to end between the client and the egress; the
//! relay holds no key, reads no user, and cannot tell a stream's destination
//! from its length.
//!
//! Why: the address a censor sees a client talk to is the relay's, which can
//! be a cheap, replaceable machine (or a CDN-fronted function); the egress,
//! which opens connections to the real destinations and so builds up the
//! reputation of a busy server, is never the address the client dials. A
//! single address that both accepts clients and dials out to the world is
//! detectable from the connection graph alone; this splits the two roles.
//!
//! The rules it keeps:
//!  * it forwards only requests shaped like Tide's, only to the one upstream
//!    it was given, never to an address taken from a request: it is not an
//!    open proxy;
//!  * nothing that identifies the client (its address, its headers) is
//!    passed on, so the egress knows only the relay;
//!  * it keeps no state per session: any relay with the same upstream can
//!    carry any session, so relays can be many and can come and go;
//!  * when the upstream cannot be reached it answers as a reverse proxy does
//!    with its backend down (a 502 page), which clients retry on; the 404 is
//!    kept for what the egress itself says about a session it does not know,
//!    and clients give a session up on that and nothing else.
//!
//! The surprise: the relay's own connection to the egress is an ordinary
//! HTTP/2 connection it keeps and reuses for every client, so the egress sees
//! one busy connection from one address, not one per client.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use zero_core::BoxStream;

use crate::tide::{
    answer_bad_gateway, answer_decoy, other, request, send_all, Carrier, Decoy, Dialer, Tuning,
    H2_WINDOW,
};

pub struct RelayConfig {
    /// The path prefix Tide requests live under; must match the egress's.
    pub path: String,
    /// The egress's site name, for the `:authority` of what is forwarded.
    pub host: String,
    pub decoy: Decoy,
}

pub struct Relay {
    config: RelayConfig,
    upstream: Arc<Carrier>,
}

/// Response headers worth passing back; everything else is the egress's own.
const PASSED_BACK: [&str; 5] = [
    "date",
    "content-type",
    "content-length",
    "cache-control",
    "x-accel-buffering",
];

/// The most a forwarded query string may be: Tide's is a short proof.
const QUERY_MAX: usize = 128;

impl Relay {
    /// `dial` reaches the egress (TLS done, `h2` negotiated).
    pub fn new(config: RelayConfig, dial: Dialer) -> Arc<Self> {
        let upstream = Carrier::new(dial, config.host.clone(), None, &Tuning::default());
        Arc::new(Self { config, upstream })
    }

    /// Serve one client connection until it closes.
    pub async fn serve_connection(self: &Arc<Self>, io: BoxStream) -> io::Result<()> {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(H2_WINDOW)
            .initial_connection_window_size(H2_WINDOW)
            .max_concurrent_streams(256)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(other)?;
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = accepted.map_err(other)?;
            let relay = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(error) = relay.handle(request, respond).await {
                    tracing::debug!(%error, "tide relay request ended with an error");
                }
            });
        }
        Ok(())
    }

    /// Whether a request is one Tide would make: `open` by POST, `u/<n>` by
    /// POST, `d/<n>` by GET, on a 32-hex-digit session name.
    fn is_tide(&self, method: &Method, path: &str) -> bool {
        let Some((name, action)) = path
            .strip_prefix(self.config.path.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split_once('/'))
        else {
            return false;
        };
        let number = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        name.len() == 32
            && name.bytes().all(|b| b.is_ascii_hexdigit())
            && match (method, action) {
                (&Method::POST, "open") => true,
                (&Method::POST, a) => a.strip_prefix("u/").is_some_and(number),
                (&Method::GET, a) => a.strip_prefix("d/").is_some_and(number),
                _ => false,
            }
    }

    async fn handle(
        self: &Arc<Self>,
        request: Request<h2::RecvStream>,
        respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        let path = request.uri().path().to_string();
        let query = request.uri().query().unwrap_or("").to_string();
        let method = request.method().clone();
        if !self.is_tide(&method, &path) || query.len() > QUERY_MAX {
            return answer_decoy(&self.config.decoy.page, &method, &path, respond).await;
        }
        let target = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };
        let mut epoch = 0;
        let sent = match self.send_upstream(&method, &target, &mut epoch).await {
            Ok(sent) => sent,
            Err(error) => {
                tracing::debug!(%error, "tide relay could not reach its upstream");
                self.upstream.invalidate(epoch).await;
                return answer_bad_gateway(respond).await;
            }
        };
        self.pass_through(sent, epoch, request.into_body(), respond)
            .await
    }

    /// Start the same request upstream. A GET has no body; a POST's is
    /// passed on by [`Self::pass_through`]. `epoch` is set to the upstream
    /// connection used, so a failure blames that one and not a newer one.
    async fn send_upstream(
        &self,
        method: &Method,
        target: &str,
        epoch: &mut u64,
    ) -> io::Result<Upstream> {
        let lease = self.upstream.get().await?;
        *epoch = lease.epoch;
        let mut sender = lease.sender.clone().ready().await.map_err(other)?;
        let mut upstream = request(method.clone(), &self.config.host, target);
        if method == Method::POST {
            upstream.headers_mut().insert(
                "content-type",
                "application/octet-stream"
                    .parse()
                    .expect("a fixed header value"),
            );
        }
        let (response, body) = sender
            .send_request(upstream, method == Method::GET)
            .map_err(other)?;
        Ok(Upstream {
            response,
            body: (method == Method::POST).then_some(body),
        })
    }

    /// Carry the client's request body up and the egress's answer back, both
    /// at once: a POST's answer only comes after its body, but a GET's
    /// answer is the long part.
    async fn pass_through(
        &self,
        sent: Upstream,
        epoch: u64,
        mut client_body: h2::RecvStream,
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        let Upstream { response, body } = sent;
        let up = async {
            let Some(mut up) = body else { return Ok(()) };
            let result = async {
                while let Some(data) = client_body.data().await {
                    let data = data.map_err(other)?;
                    let size = data.len();
                    send_all(&mut up, data).await?;
                    let _ = client_body.flow_control().release_capacity(size);
                }
                up.send_data(Bytes::new(), true).map_err(other)
            }
            .await;
            if result.is_err() {
                up.send_reset(h2::Reason::CANCEL);
            }
            result
        };
        let (up, response) = tokio::join!(up, response);
        let response = match (up, response) {
            (Ok(()), Ok(response)) => response,
            _ => {
                self.upstream.invalidate(epoch).await;
                return answer_bad_gateway(respond).await;
            }
        };
        let mut builder = Response::builder().status(response.status());
        for name in PASSED_BACK {
            if let Some(value) = response.headers().get(name) {
                builder = builder.header(name, value);
            }
        }
        let status = response.status();
        let mut down = response.into_body();
        let reply = builder.body(()).map_err(other)?;
        let mut out = respond
            .send_response(reply, status == StatusCode::NO_CONTENT)
            .map_err(other)?;
        while let Some(data) = down.data().await {
            let data = data.map_err(other)?;
            let size = data.len();
            send_all(&mut out, data).await?;
            let _ = down.flow_control().release_capacity(size);
        }
        out.send_data(Bytes::new(), true).map_err(other)
    }
}

/// A request that has been sent upstream.
struct Upstream {
    response: h2::client::ResponseFuture,
    /// The body half, when the client's body still has to be copied into it.
    body: Option<h2::SendStream<Bytes>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tide::{Client, ClientConfig, Server, ServerConfig};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::RwLock;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zero_core::{boxed, Address, Destination};
    use zero_protocol::tide;

    struct Rig {
        client: Arc<Client>,
        /// Connections the relay made to the egress.
        egress_dials: Arc<AtomicUsize>,
        relay: Arc<Relay>,
        /// Cut every connection of one hop: client to relay, relay to egress.
        cut_front: Arc<tokio::sync::Notify>,
        cut_back: Arc<tokio::sync::Notify>,
    }

    /// client -> relay -> egress (an echo server), all in memory. The relay
    /// is built from the egress's public details only.
    fn rig(known_user: bool) -> Rig {
        rig_rotating(known_user, None)
    }

    fn rig_rotating(known_user: bool, rotation: Option<crate::tide::Rotation>) -> Rig {
        let (secret, public) = tide::generate_keypair();
        let user = [4u8; 16];
        let users = Arc::new(RwLock::new(HashMap::new()));
        if known_user {
            users.write().unwrap().insert(user, "t".to_string());
        }
        let (egress, mut streams) = Server::new(ServerConfig {
            path: "/static/app".into(),
            admin: None,
            secret,
            users,
            decoy: Decoy::default(),
            shape: tide::ShapeLevel::Off,
        });
        tokio::spawn(async move {
            while let Some((_, _, mut stream)) = streams.recv().await {
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 16 * 1024];
                    while let Ok(n @ 1..) = stream.read(&mut buffer).await {
                        if stream.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        let egress_dials = Arc::new(AtomicUsize::new(0));
        let cut_front = Arc::new(tokio::sync::Notify::new());
        let cut_back = Arc::new(tokio::sync::Notify::new());
        let to_egress: Dialer = {
            let (dials, cut) = (egress_dials.clone(), cut_back.clone());
            Arc::new(move || {
                let (egress, dials, cut) = (egress.clone(), dials.clone(), cut.clone());
                Box::pin(async move {
                    dials.fetch_add(1, Ordering::SeqCst);
                    let (near, far) = tokio::io::duplex(256 * 1024);
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = egress.serve_connection(boxed(far)) => {}
                            () = cut.notified() => {}
                        }
                    });
                    Ok(boxed(near))
                })
            })
        };
        let relay = Relay::new(
            RelayConfig {
                path: "/static/app".into(),
                host: "egress.test".into(),
                decoy: Decoy::default(),
            },
            to_egress,
        );
        let to_relay: Dialer = {
            let (relay, cut) = (relay.clone(), cut_front.clone());
            Arc::new(move || {
                let (relay, cut) = (relay.clone(), cut.clone());
                Box::pin(async move {
                    let (near, far) = tokio::io::duplex(256 * 1024);
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = relay.serve_connection(boxed(far)) => {}
                            () = cut.notified() => {}
                        }
                    });
                    Ok(boxed(near))
                })
            })
        };
        let client = Client::new(
            ClientConfig {
                host: "relay.test".into(),
                path: "/static/app".into(),
                server_public: public,
                user,
                split: true,
                linger: Duration::from_millis(100),
                lane: false,
                rotation,
                tuning: Default::default(),
            },
            to_relay,
        );
        Rig {
            client,
            egress_dials,
            relay,
            cut_front,
            cut_back,
        }
    }

    fn target() -> Destination {
        Destination::tcp(Address::domain("example.com"), 443)
    }

    async fn round_trip(stream: &mut tide::TideStream, payload: &[u8]) {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let send = async {
            writer.write_all(payload).await.unwrap();
            writer.flush().await.unwrap();
        };
        let receive = async {
            let mut got = vec![0u8; payload.len()];
            reader.read_exact(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(send, receive);
        assert!(got == payload, "payload came back altered");
    }

    /// A client reaches the egress through the relay and its streams work,
    /// large and small, several at once; the relay uses one connection to
    /// the egress for all of it.
    #[tokio::test]
    async fn streams_work_through_a_relay_over_one_upstream_connection() {
        let rig = rig(true);
        let mut first = rig.client.open(target()).await.unwrap();
        round_trip(&mut first, b"hello").await;
        let big: Vec<u8> = (0..900_000).map(|i| (i % 251) as u8).collect();
        round_trip(&mut first, &big).await;
        let mut second = rig.client.open(target()).await.unwrap();
        round_trip(&mut second, &big[..40_000]).await;
        assert_eq!(rig.egress_dials.load(Ordering::SeqCst), 1);
    }

    /// The relay needs no key to be useful, and a user the egress does not
    /// know gets what an unknown user gets directly.
    #[tokio::test]
    async fn an_unknown_user_is_refused_by_the_egress_not_the_relay() {
        let rig = rig(false);
        let error = rig.client.open(target()).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// Only Tide-shaped requests are forwarded.
    #[tokio::test]
    async fn only_requests_shaped_like_tides_are_forwarded() {
        let rig = rig(true);
        let name = "0123456789abcdef0123456789abcdef";
        let tide = |method: &Method, path: String| rig.relay.is_tide(method, &path);
        assert!(tide(&Method::POST, format!("/static/app/{name}/open")));
        assert!(tide(&Method::POST, format!("/static/app/{name}/u/12")));
        assert!(tide(&Method::GET, format!("/static/app/{name}/d/3")));
        for (method, path) in [
            (&Method::GET, format!("/static/app/{name}/open")),
            (&Method::POST, format!("/static/app/{name}/d/3")),
            (&Method::POST, format!("/static/app/{name}/u/x")),
            (&Method::POST, format!("/static/app/{name}/u/")),
            (&Method::POST, format!("/static/app/{name}/other")),
            (&Method::POST, "/static/app/short/open".to_string()),
            (&Method::POST, format!("/elsewhere/{name}/open")),
            (&Method::GET, "/".to_string()),
            (&Method::POST, format!("/static/app/{name}/open/../../x")),
        ] {
            assert!(!tide(method, path.clone()), "{method} {path}");
        }
    }

    /// A visitor to the relay sees a site, and garbage sent to a Tide path
    /// gets the same answer as the egress gives directly.
    #[tokio::test]
    async fn the_relay_shows_the_decoy_and_the_egress_answer_for_garbage() {
        let rig = rig(true);
        let (near, far) = tokio::io::duplex(64 * 1024);
        let relay = rig.relay.clone();
        tokio::spawn(async move { relay.serve_connection(boxed(far)).await });
        let (sender, connection) = h2::client::handshake(near).await.unwrap();
        tokio::spawn(connection);
        async fn fetch(
            sender: &h2::client::SendRequest<Bytes>,
            method: Method,
            path: &str,
            body: &[u8],
        ) -> (StatusCode, Vec<u8>) {
            let mut sender = sender.clone().ready().await.unwrap();
            let (response, mut send) = sender
                .send_request(request(method, "relay.test", path), false)
                .unwrap();
            send.send_data(Bytes::copy_from_slice(body), true).unwrap();
            let response = response.await.unwrap();
            let status = response.status();
            let mut body = response.into_body();
            let mut got = Vec::new();
            while let Some(data) = body.data().await {
                got.extend_from_slice(&data.unwrap());
            }
            (status, got)
        }
        let (status, page) = fetch(&sender, Method::GET, "/", b"").await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.starts_with(b"<!doctype html>"));
        let (missing, missing_body) = fetch(&sender, Method::GET, "/nothing", b"").await;
        assert_eq!(missing, StatusCode::NOT_FOUND);
        let name = "0123456789abcdef0123456789abcdef";
        let (garbage, garbage_body) = fetch(
            &sender,
            Method::POST,
            &format!("/static/app/{name}/open"),
            &[7u8; 90],
        )
        .await;
        assert_eq!(garbage, missing);
        assert_eq!(garbage_body, missing_body);
    }

    /// Connection rotation and the relay together: the client's connections
    /// to the relay are replaced while a stream is open, the reset of an old
    /// download reaches the egress through the relay, and nothing is lost.
    #[tokio::test]
    async fn rotation_works_through_a_relay() {
        let age = Duration::from_millis(400);
        let rig = rig_rotating(
            true,
            Some(crate::tide::Rotation {
                min_age: age,
                max_age: age,
                max_bytes: u64::MAX,
            }),
        );
        let mut stream = rig.client.open(target()).await.unwrap();
        for round in 0..20u8 {
            let payload: Vec<u8> = (0..30_000).map(|i| (i % 251) as u8 ^ round).collect();
            round_trip(&mut stream, &payload).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The relay's own connection to the egress was not churned by it.
        assert_eq!(rig.egress_dials.load(Ordering::SeqCst), 1);
    }

    /// Trouble on both hops at once: connections to the relay and from the
    /// relay to the egress are cut at random while several streams move data
    /// and the client's connections are being replaced. Nothing is lost.
    #[tokio::test]
    async fn a_relayed_session_survives_cuts_on_both_hops() {
        let age = Duration::from_millis(500);
        let rig = rig_rotating(
            true,
            Some(crate::tide::Rotation {
                min_age: age,
                max_age: age,
                max_bytes: 500_000,
            }),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let chaos = tokio::spawn({
            let (front, back, stop) = (rig.cut_front.clone(), rig.cut_back.clone(), stop.clone());
            async move {
                let mut front_turn = true;
                while !stop.load(Ordering::SeqCst) {
                    let wait = rand::Rng::gen_range(&mut rand::thread_rng(), 300..800);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    if front_turn {
                        front.notify_waiters();
                    } else {
                        back.notify_waiters();
                    }
                    front_turn = !front_turn;
                }
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let mut flows = Vec::new();
        for flow in 0..4u8 {
            let client = rig.client.clone();
            flows.push(tokio::spawn(async move {
                let mut stream = client.open(target()).await.unwrap();
                let mut rounds = 0u32;
                while std::time::Instant::now() < deadline {
                    let size = rand::Rng::gen_range(&mut rand::thread_rng(), 1_000..150_000);
                    let payload: Vec<u8> = (0..size)
                        .map(|i| ((i as u32).wrapping_mul(17) as u8) ^ flow ^ rounds as u8)
                        .collect();
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        round_trip(&mut stream, &payload),
                    )
                    .await
                    .expect("a round trip stalled for 30 s");
                    rounds += 1;
                }
                rounds
            }));
        }
        let mut total = 0;
        for flow in flows {
            total += flow.await.unwrap();
        }
        stop.store(true, Ordering::SeqCst);
        chaos.await.unwrap();
        assert!(total >= 8, "only {total} round trips in 6 s of trouble");
        assert!(
            rig.egress_dials.load(Ordering::SeqCst) > 1,
            "the back hop was never cut"
        );
    }

    /// With the egress unreachable the client gets an error, quickly, and the
    /// relay says 502, as any proxy with its backend down does: not the 404
    /// that tells a client its session is gone.
    #[tokio::test]
    async fn an_unreachable_egress_looks_like_a_proxy_with_its_backend_down() {
        let (_, public) = tide::generate_keypair();
        let down: Dialer =
            Arc::new(|| Box::pin(async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) }));
        let relay = Relay::new(
            RelayConfig {
                path: "/static/app".into(),
                host: "egress.test".into(),
                decoy: Decoy::default(),
            },
            down,
        );
        let to_relay: Dialer = {
            let relay = relay.clone();
            Arc::new(move || {
                let relay = relay.clone();
                Box::pin(async move {
                    let (near, far) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(async move { relay.serve_connection(boxed(far)).await });
                    Ok(boxed(near))
                })
            })
        };
        let client = Client::new(
            ClientConfig {
                host: "relay.test".into(),
                path: "/static/app".into(),
                server_public: public,
                user: [4u8; 16],
                split: true,
                linger: Duration::ZERO,
                lane: false,
                rotation: None,
                tuning: Default::default(),
            },
            to_relay,
        );
        let result = tokio::time::timeout(Duration::from_secs(5), client.open(target()))
            .await
            .expect("the client waited for ever");
        let error = result.err().expect("there is no egress to reach");
        assert_eq!(
            error.kind(),
            io::ErrorKind::ConnectionRefused,
            "a down backend must read as unavailable, not as a refusal: {error}"
        );
    }
}
