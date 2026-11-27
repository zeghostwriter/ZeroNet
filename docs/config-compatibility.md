# Known divergences from Xray

Everything here is a place where Zray's behaviour is deliberately, knowably
different from the pinned Xray oracle (`v26.7.28`, commit `5ca6f4b`). Each entry
names the test that holds the divergence in place, because an undocumented
divergence and an unnoticed regression look identical from the outside.

## Fingerprint profiles that cannot carry REALITY

Profiles with no X25519 key share — the Android/okhttp shape, the 360 shapes,
several archived Chrome/Firefox/iOS versions — cannot carry a REALITY tag,
because REALITY derives its authentication key from the hello's own ephemeral
X25519 secret. These are refused at config-compile time rather than at connect
time, since a REALITY failure is a *silent* relay to the decoy site.

**Pinned by.** `zero-security/src/reality_compat.rs` and the cross-crate parity
test `zero-runtime/tests/reality_compatibility.rs`, which compares the config
compiler's independent copy of the rule against the wire corpus for every
profile in it.

## ClientHellos that are not browser-shaped

The uTLS profile is applied to TCP TLS hellos only. Three kinds of hello leave
as rustls writes them:

- **QUIC** (Hysteria2, TUIC, Juicity, XHTTP over HTTP/3, the WARP MASQUE HTTP/3
  leg, DoH3/DoQ). The shaping hook returns no plan when the connection is QUIC
  (`BrowserClientHelloCustomizer`), because a browser's QUIC hello carries
  `quic_transport_parameters` and a different extension set from its TCP one,
  and the TCP profile data is not that.
- **ECH.** With an ECH config list the shape is skipped (see
  `build_client_config`), because the hook cannot tell the outer hello from the
  inner one and reshaping broke Cloudflare ECH.
- **DoT** (port 853), which has no browser equivalent to copy.

Every other plain client (config and asset fetches, subscriptions, the update
check, WARP registration, the clean-IP probe, DoH over HTTP/2, the WARP MASQUE
HTTP/2 leg) uses the Chrome profile; the HTTP/1.1-only ones offer `http/1.1`
as their only ALPN because that is all they speak.

**Pinned by.** `zero-security` `the_https_helper_wears_chrome_and_offers_only_what_it_speaks`,
`zero-transport` `the_http2_leg_wears_a_browser_hello_and_offers_h2`, and
`zero-dns` `doh_is_browser_shaped_and_dot_is_not`.

## ECH GREASE payload length

uTLS draws the ECH GREASE payload length from four candidates per connection;
Zray pins the first. Recorded in `utls_profiles.rs` alongside the constant.
Unpinning it requires a fixture per candidate so the shape guard can accept any
of the four.

## Encrypted resolvers behind a private CA

`dns.certificates` accepts the same `usage: "verify"` entries an outbound's
`tlsSettings.certificates` does, and adds them to the trust store every
encrypted resolver transport shares (DoT, DoH, DoH3 and DoQ).

Xray has no equivalent: its DoQ nameserver builds a TLS config with no way to
name a trust anchor, so reaching a self-hosted resolver there means changing
the system store or the process environment. That is a divergence in Zray's
favour and it is deliberate — the alternative operators reach for is disabling
verification, and an anti-sanction or enterprise resolver behind a private CA
is a normal thing to have (PLAN-02 §3.5).

Anchors are additive: naming one never removes the public roots, and never
makes verification optional. An unusable anchor is logged and skipped rather
than taking DNS down for a typo.

**Pinned by.** `zero-runtime/tests/dns_oracle.rs`, which reaches a DoQ server
presenting the test CA, and would fail closed without the anchor.

## SOCKS5 outbound is TCP only

**What differs.** Xray's `socks` outbound can relay UDP through UDP ASSOCIATE.
Zray's speaks CONNECT only, so a UDP destination routed to it is refused.

**Why.** The point of this outbound is to put a local Tor, Orbot or Psiphon
client in the path, and Tor carries no UDP at all. A UDP flow that reaches it
fails at once instead of silently going nowhere.

**Accepted shapes.** `settings.servers[0]` with `users[0]` (`user`, `pass`), and
the flat form `settings.address/port/user/pass`. Names are sent to the upstream
unresolved (`socks5h` behaviour), so the upstream does the lookup.

**Pinned by.** `zero-protocol/src/socks.rs` (client handshake against RFC 1928
and 1929), `zero-config` (both JSON shapes, `socks://`, `socks5://`,
`socks5h://`) and `zero-runtime/tests/socks_upstream.rs` (a runtime through an
independent SOCKS5 server, including that a name that resolves nowhere still
arrives).

## The `tor` outbound has no Xray counterpart

`{"protocol": "tor"}` is Zray's own. It runs Arti inside the process and needs
a build with the `tor` cargo feature (`zero-runtime/tor`, or `--features tor`
on `zray` and `zeronet-tui`); without it the outbound parses, then every
connection fails with a message saying the build has no Tor.

`settings` are all optional: `bridges` (bridge lines), `transports`
(`{"obfs4": "/usr/bin/lyrebird"}`), `dataDir`, `memoryMiB` (default 64, minimum
32). A bridge that names a transport with no program set is rejected when the
config is read.

Limits worth knowing: TCP only, and desktop only for now (the Android library
is not built with the feature). Pluggable-transport programs (lyrebird,
snowflake-client) are separate processes that this build does not include; their
sockets are the program's own and are not exempted from a VPN. Tor's own
connections to relays and bridges are exempted through the same socket hook
every other outbound uses.

**Pinned by.** `zero-config` (settings and bridge/transport validation),
`zero-tor` (Arti configuration and the memory cap) and
`zero-runtime/tests/tor_outbound.rs` (the no-Tor-build message, UDP refusal,
and an ignored live check that needs the real Tor network: it opens a circuit to
check.torproject.org and reads the answer back). Arti buffers writes until they
are flushed, so a caller that writes and then only reads must flush first.

## Hysteria 2: Salamander, and certificate checks

A Hysteria 2 link reads `obfs=salamander&obfs-password=…` (the password also
as `obfs_password`). Every UDP datagram of the connection is then wrapped the
way the Hysteria 2 server does it: an 8-byte salt in front, the payload XORed
with `BLAKE2b-256(password || salt)`. The password must be at least 4 bytes;
another `obfs` type is refused, not ignored, because connecting without the
obfuscation to a server that wants it only looks like a dead server. sing-box
configs carry it as `"obfs": {"type": "salamander", "password": …}`, which the
subscription import turns into the same link. Verified against the
`apernet/hysteria` server: the right password carries traffic, a wrong or
missing one does not.

The Hysteria 2 *server* side of ZeroNet (the inbound) does not take a
Salamander password yet.

`insecure=1` (Hysteria 2), `allow_insecure=1` (TUIC, Juicity) and
`allowInsecure=1` (the TCP carriers) skip the certificate check for that one
link. Without them the certificate is verified, so a self-signed server needs
the flag or a trusted certificate. Skipping the check lets anyone on the path
pose as the server.

## The `juicity` outbound has no Xray counterpart

`{"protocol": "juicity"}` and the `juicity://<uuid>:<password>@host:port` link
are Zray's own, matching the `daeuniverse` reference and the `juicity` server.
Like TUIC it rides one authenticated QUIC connection per server (ALPN `h3`),
but each request is a trojan-style stream — `[network][addr][port]` then the
bytes — so a UDP flow is carried over a stream too, not a QUIC datagram.

**Certificate verification is mandatory.** Juicity deployments often front a
self-signed certificate pinned by `pinned_certchain_sha256`, and some share
links carry `allow_insecure`. Zray accepts both fields and honours neither: the
model refuses to disable verification for any outbound, and this client has no
pin-by-hash trust path, so it verifies the ordinary certificate chain. A
Juicity server must therefore present a chain Zray can verify (a public CA, or
one named through `tlsSettings.certificates`); a self-signed server that only a
hash would admit is refused at connect time rather than trusted blindly.

**Pinned by.** `zero-config` (the `juicity://` link and `{"protocol":
"juicity"}` JSON, uuid/password and the secure-by-default TLS block) and
`zero-transport/src/juicity.rs` (the trojan address framing and the
authentication command) and `zero-runtime/tests/juicity_loopback.rs` (the whole
client through a Juicity server written in the test from the reference's wire
contract: TCP, a destination sent as a name, twelve streams on one authenticated
connection, UDP over a stream, and a wrong password refused). That server is not
the reference binary, so interoperability with a real Juicity server is checked
against the reference source, not run.

## Plain WireGuard rides the AmneziaWG path

A plain WireGuard link (`wireguard://`, `wg://`) or `{"protocol": "wireguard"}`
config with no AmneziaWG obfuscation fields parses straight through the
AmneziaWG outbound with every junk and header-rewrite knob left at zero (and
`h1..h4` at the standard WireGuard message types `1..4`), which is byte-for-byte
plain WireGuard on the wire. There is no separate plain-WireGuard code path, and
none is needed.

**Pinned by.** `zero-config` (the `wireguard`/`wg` link schemes and the
`wireguard`/`amnezia-wg`/`amneziawg` JSON protocols both reaching
`parse_amnezia_wireguard`).

## ShadowTLS v3 is a `streamSettings.security`, not a separate outbound

sing-box models ShadowTLS as its own outbound that another outbound detours
through: a Shadowsocks outbound with `"detour": "shadowtls-out"`, and a
`{"type": "shadowtls"}` outbound carrying the password, version and decoy `tls`
block. Zray has no detour chain, so the two collapse into one outbound — a
Shadowsocks outbound whose `streamSettings.security` is `shadowtls`:

```json
{
  "protocol": "shadowsocks",
  "settings": {
    "servers": [{
      "address": "relay.example", "port": 443,
      "method": "2022-blake3-aes-128-gcm", "password": "<inner shadowsocks key>"
    }]
  },
  "streamSettings": {
    "network": "raw",
    "security": "shadowtls",
    "shadowtlsSettings": {
      "version": 3,
      "password": "<shadowtls password>",
      "tls": { "serverName": "www.microsoft.com", "alpn": ["h2", "http/1.1"] }
    }
  }
}
```

The mapping from a sing-box pair is direct: the Shadowsocks `method`/`password`
become the `servers[0]` entry, the ShadowTLS outbound's `password` and `version`
become `shadowtlsSettings.password`/`version`, and its `tls.server_name` /
`tls.alpn` become `shadowtlsSettings.tls.serverName` / `tls.alpn`. The relay
host and port are the Shadowsocks `address`/`port` (in sing-box they sit on the
ShadowTLS outbound; here the single outbound owns them). `alpn` defaults to
`["h2", "http/1.1"]` when omitted; it is camouflage carried in the decoy
ClientHello only and never changes which protocol rides inside.

**Only version 3.** `version` other than `3` is rejected at parse time rather
than silently downgraded — v1/v2 are a different wire contract this client does
not speak. The carrier must be `raw`: there is no ClientHello fragmentation,
TCP finalmask or raw-HTTP camouflage underneath, because splitting or reshaping
the hello would break the relay's frame extraction and the data-stream HMAC.

**No share link.** There is no standard `shadowtls://` scheme — reference
clients configure it through sing-box JSON, Surge, or the CLI — so inventing one
would interoperate with nothing. ShadowTLS comes in through JSON only.

**Simplified client, still fails closed.** The client sends a genuine,
browser-shaped ClientHello carrying the keyed HMAC the relay checks, reads the
ServerHello for its random, and then speaks the HMAC-framed data stream; it does
not run a full TLS handshake with the decoy the way a stock client does, because
the relay switches to the real backend on the first client data frame whose HMAC
matches and never requires the decoy handshake to finish. A wrong password means
the relay never switches, so the first real frame fails its HMAC check and the
stream errors out — it does not fall back to an unauthenticated tunnel.

**Pinned by.** `zero-config` (the `shadowtls` security in `parse_stream` and the
`Security::ShadowTls` model with its Shadowsocks-only, raw-carrier validation)
and `zero-transport/src/shadowtls.rs` (the ClientHello HMAC, the ServerHello
random, and the data-stream framing), and `zero-runtime/tests/singbox_oracle.rs`,
which runs the client against a real sing-box ShadowTLS v3 relay (a megabyte
echoed intact, six concurrent streams, and a wrong password refused). That test
is opt-in (`--ignored`) and needs a `sing-box` binary.

## `tlssni` is a second fragment mode

`fragment.packets` also takes `tlssni`, next to `tlshello` and a write range. It
re-frames the first ClientHello into two valid TLS records with the cut inside
the server name (the middle of its second-level label), for a filter that puts
TCP segments back together but reads the name out of one TLS record. With no
delay set both records go in one write. Xray has no such mode, so a config using
it is Zray-only; a server sees an ordinary hello split across two records.

**Pinned by.** `zero-evasion/src/fragment.rs` (the cut lands inside the name, the
records rebuild the hello, anything that is not a ClientHello with a name passes
through) and `zero-runtime/tests/xray_oracle.rs`
(`vless_over_tls_with_a_hello_split_inside_the_name_matches_the_oracle`, an
Xray server accepting the split hello and carrying traffic; opt-in, needs `xray`).

## `dns.leakPolicy` is Zray's own key, and only a server can use it

**What differs.** Xray has no such key. Zray's DNS is strict by default: it
refuses to fall back to the operating system's resolver, because on a client
that resolver would answer outside the tunnel. A server is the opposite case:
the machine's own resolver is the one that is always reachable from its own
network, so the installer writes `"leakPolicy": "fallback"` into the server
configuration it generates.

**Guard.** `fallback` is honoured only when every outbound of the configuration
exits directly (`freedom` or `blackhole`). A configuration with any proxy
outbound is a client, and the key is ignored there, so a configuration or
subscription from outside cannot make a client leak its DNS. Any other value
means strict.

**Pinned by.** `zero-config` (`the_dns_leak_policy_is_strict_unless_a_server_says_otherwise`)
and the preset test that a built preset cannot produce `fallback`.

## The server installer (`zero-provision`)

The apps' "My server" page and `zray-setup` set up a stranger's VPS over SSH and
write a server configuration of the shape the engine itself reads:

- `VLESS + REALITY` (Vision, TCP) on `reality-in`, and optionally
  `VLESS + XHTTP + REALITY` on `xhttp-in` (own port, a random request path, no
  flow). Both use one key pair, short id and user list, and the first block of
  the configuration sends private networks (loopback, LAN, link-local, cloud
  metadata) to a black hole so a client cannot reach services that trust the
  server.
- `GET /usage` on the loopback management API reports, per inbound, sessions,
  distinct devices now and in the last five minutes, and byte totals. Devices
  are counted from a per-process salted hash that never leaves memory; no
  address or key is stored, logged or returned.

**Pinned by.** `zero-provision` (the generated configuration compiles in the
engine, the links parse with the apps' own parser), `zero-runtime`
(`usage_reports_counts_and_no_address`), and an installation checked end to end
against an Ubuntu 24.04 container with systemd: both inbounds installed, a
client connected through each link, usage counted on the right inbound, and
removal left the machine clean.
