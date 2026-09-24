# Zero-Core / Zray — consolidated engineering blueprint

After all of the research passes, the project has become much clearer.

The most important conclusion is that **Zray should not be a line-by-line Rust translation of Xray-core**. That would inherit Xray's historical architecture, tightly couple unrelated systems, and make every new Xray behavior expensive to track.

The better structure is:

> **Zero-Core = generic Rust networking/proxy runtime**  
> **Zray = Xray-compatible implementation built on Zero-Core**

This lets Zero-Core eventually power protocols that have nothing to do with Xray while Zray remains highly compatible with Xray's VLESS, REALITY, Vision, XHTTP, DNS, routing and configuration behavior.

---

# 1. What the research actually discovered

The research fell into four major areas:

| Area | Main conclusion |
|---|---|
| Cloudflare DNS/Rust | Separate protocol logic from networking I/O; compile/cache compact immutable data |
| Rust Xray implementations | A native Rust implementation is realistic, but REALITY/TLS fidelity is the hardest boundary |
| Modern Xray | Compatibility is **versioned behavior**, not just “implement VLESS” |
| Iran | Never hard-code assumptions; continuously measure network capabilities |

Together they imply this architecture:

```text
                         ZRAY
       Xray config / links / CLI / API compatibility
                           │
                           ▼
                    Config Compiler
                           │
                           ▼
                 Immutable Runtime Graph
                           │
                           ▼
                       ZERO-CORE

Inbound
   │
   ▼
Session
   │
   ▼
Sniffing
   │
   ▼
Router
   │
   ▼
Connection Planner
   │
   ├─────────────── Zero-DNS
   │
   ├─────────────── Network Observatory
   │
   ▼
Protocol
   │
   ▼
Security
   │
   ▼
Transport
   │
   ▼
Socket / TUN
   │
   ▼
Operating System
```

That should be the foundation.

---

# 2. Cloudflare's Rust DNS work: what matters to us

There were actually **three separate Cloudflare findings**.

## Big Pineapple

Cloudflare's newer DNS platform, **Big Pineapple**, gradually replaced significant resolver functionality with Rust and Tokio.

The architectural feature that matters most is this concept:

```rust
async fn resolve(
    request: Request,
    exchanger: impl Exchanger,
) -> Result<Response>
```

The resolver contains the DNS logic, but **doesn't directly perform network I/O**. Networking is supplied through an abstraction.

Cloudflare explicitly says this made the recursive resolver easier to test and made complicated DNS/DNSSEC logic more readable. They also normalize UDP/TCP/HTTP requests into higher-level “frames” instead of letting transport details contaminate DNS processing. 

This should become a fundamental Zero-Core design principle.

### Bad architecture

```text
VLESS
 └─ opens socket
     └─ resolves DNS
         └─ starts TLS
             └─ configures REALITY
                 └─ chooses route
```

Everything knows everything.

### Zero-Core architecture

```text
VLESS
 │
 ▼
Protocol intent
 │
 ▼
Connection planner
 ├─ DNS resolver
 ├─ route
 ├─ security
 ├─ transport
 └─ socket provider
```

VLESS should not know *how* DNS works.

DNS should not know whether the user came from SOCKS or TUN.

REALITY should not know whether the physical socket came from IPv4 or IPv6.

This separation is perhaps the single most valuable thing to copy from Cloudflare.

---

# 3. Cloudflare's August 2026 DNS cache work

This gave us several Rust-specific optimization ideas.

Cloudflare said Big Pineapple holds **more than 250 billion DNS cache entries**. Its August 2026 redesign reduced benchmarked memory per entry from **953 bytes to 420 bytes**, cut allocations from roughly 1.1 KB to 461 bytes, increased insertion throughput from 625k to 893k entries/sec, and reduced lookup latency from 828 ns to 670 ns. Cloudflare estimated roughly **100 TB of memory was saved fleet-wide**. 

The important lesson isn't Cloudflare's scale.

It is their data-layout strategy.

Once configuration/cache data becomes immutable, don't retain mutable containers unnecessarily.

Instead of keeping:

```rust
String
Vec<T>
Vec<Record>
Vec<Record>
Vec<Record>
```

forever, consider compact immutable representations where appropriate:

```rust
Box<str>
Box<[T]>
```

or one contiguous region:

```text
all_records[]
answer_end
authority_end
```

rather than three separate allocations.

Zero-Core should therefore distinguish very aggressively between:

```text
configuration/build-time representation
```

and:

```text
runtime/hot-path representation
```

---

# 4. Configuration compilation should be mandatory

Do **not** let Serde JSON objects become Zero-Core's internal runtime configuration.

Instead:

```text
Xray JSON
     │
     ▼
Deserialize
     │
     ▼
Schema validation
     │
     ▼
Semantic validation
     │
     ▼
Reference resolution
     │
     ▼
Protocol compatibility validation
     │
     ▼
Compile domain/IP matchers
     │
     ▼
Compile outbound graph
     │
     ▼
Compile DNS plans
     │
     ▼
Compile compatibility profile
     │
     ▼
RuntimeGeneration
```

That compiled generation should contain small IDs and immutable structures.

For example, instead of storing:

```rust
struct Session {
    inbound_tag: String,
    outbound_tag: String,
    domain: String,
}
```

everywhere, prefer something conceptually like:

```rust
struct Session {
    generation: GenerationId,
    inbound: InboundId,
    source: SocketAddr,
    destination: Destination,
    route: Option<RouteId>,
    flags: SessionFlags,
}
```

The actual strings live once in the immutable configuration generation.

---

# 5. Hot reload should replace the whole runtime graph

Current `xray-rust` already supports things such as atomic routing/geodata replacement, health-aware selectors, DNS caching, FakeDNS, DoT/DoH/DoQ and a fairly sophisticated routing/DNS subsystem.

However, its documentation explicitly notes that **full configuration/outbound topology replacement still requires creating a new Core**. 

Zero-Core can improve on that.

Use generations:

```text
RuntimeGeneration 41
├── routing
├── outbound graph
├── DNS configuration
├── balancers
├── protocol settings
├── compatibility settings
├── observatory settings
└── static resources
```

When configuration changes:

```text
new JSON
   │
   ▼
compile completely
   │
   ▼
RuntimeGeneration 42
   │
   ▼
atomic pointer swap
```

Then:

```text
existing connections → Generation 41
new connections      → Generation 42
```

No giant global lock.

No partially updated configuration.

`arc-swap` would be a natural implementation candidate.

---

# 6. Don't make everything `dyn Trait`

A clean architecture doesn't mean:

```rust
Box<dyn Protocol>
Box<dyn Transport>
Box<dyn Security>
Box<dyn Router>
```

on every packet.

That would introduce unnecessary allocation, indirection and optimizer blindness.

Use flexible abstractions at configuration/setup boundaries but compile common cases into enums.

For example:

```rust
enum CompiledOutbound {
    Freedom(FreedomOutbound),
    Vless(VlessOutbound),
    Trojan(TrojanOutbound),
    Shadowsocks(ShadowsocksOutbound),
}
```

and:

```rust
enum CompiledTransport {
    Raw(RawTransport),
    XHttp(XHttpTransport),
    WebSocket(WebSocketTransport),
    Grpc(GrpcTransport),
    Quic(QuicTransport),
}
```

Traits make sense where substitution is fundamental.

The DNS exchanger is one.

The platform socket provider is another.

The hot packet path generally should not be an elaborate object graph.

---

# 7. Cloudflare's PQ DNS work

Cloudflare enabled **ML-DSA-44 DNSSEC validation** on 1.1.1.1 in September 2026.

The notable consequence is signature size: approximately **2,420 bytes**. 

This reinforces an important Zero-DNS requirement:

DNS responses cannot be assumed to fit comfortably into tiny UDP packets.

Zero-DNS therefore needs correct handling of:

```text
UDP DNS
   │
   ├─ valid answer
   │
   └─ TC=1
        │
        ▼
    same resolver over TCP
```

and separately:

```text
DoT
DoH2
DoH3
DoQ
```

The logical DNS query must be independent of the carrier.

---

# 8. Important clarification: there are TWO different post-quantum things

Don't combine them.

Cloudflare DNSSEC currently concerns:

```text
ML-DSA-44
```

Xray REALITY currently has optional support for:

```text
ML-DSA-65
```

for an additional post-quantum signature in REALITY's temporary certificate mechanism. Current Xray documentation states that enabling this can significantly increase the certificate size and requires an adequately large target certificate to avoid creating an obvious difference. 

They solve different problems.

Zero-DNS eventually may care about ML-DSA-44 DNSSEC.

`zero-security/reality` will need ML-DSA-65 support for modern Xray compatibility.

---

# 9. Do NOT build a recursive DNS resolver first

Big Pineapple is an inspiration, not our product requirement.

Zero-DNS initially needs to be an excellent **proxy/stub DNS engine**, not 1.1.1.1.

Build:

```text
UDP
TCP
DoT
DoH2
DoH3
DoQ

split DNS
routing through outbounds
bootstrap resolution
FakeDNS
TTL cache
negative cache
single-flight
stale service
DNS leak policies
A/AAAA policies
IPv4/IPv6 awareness
```

Do not initially implement:

```text
root recursion
full authoritative traversal
large-scale recursive DNSSEC
root hints
full resolver infrastructure
```

That would consume months while contributing little to the initial proxy engine.

---

# 10. Rust Xray implementations: what we learned

Several implementations prove this project is feasible.

## `xray-rust`

Current `xray-rust` supports a substantial client subset:

```text
SOCKS5
HTTP CONNECT
TUN

Freedom
VLESS

TLS
REALITY
Vision

VLESS UDP
XUDP

XHTTP-related functionality

routing
geoip/geosite
balancing
health checks

DoT
DoH
DoQ
FakeDNS
DNS cache
```

It still deliberately doesn't attempt complete Xray parity. 

This is evidence that we should implement Xray incrementally.

---

# 11. Leaf

Leaf proves a Rust proxy core can support:

```text
SOCKS
Shadowsocks
Trojan
VMess
VLESS
TLS
WebSocket
QUIC
REALITY
proxy chains
failover
TUN
```

and its TUN support can use `lwIP` or `smoltcp`. 

The architectural lesson is normalization.

Incoming traffic should become a common session description, regardless of whether it originated from:

```text
SOCKS
HTTP CONNECT
TUN
transparent proxying
future API
```

---

# 12. Shoes

`shoes` demonstrates even broader Rust protocol coverage.

It currently advertises implementations including VLESS, VMess AEAD, Shadowsocks, Trojan, Hysteria2, TUIC v5, AnyTLS, NaiveProxy, REALITY, Vision and TUN support. 

This proves that implementing these protocols in Rust is not the core uncertainty.

The hard part is:

> **being exactly compatible with modern Xray semantics.**

That is what Zray should specialize in.

---

# 13. REALITY is the hardest subsystem

This conclusion became stronger after every research pass.

Official REALITY is not simply:

```text
TLS + X25519
```

It depends on modifications around the TLS handshake, session ID/authentication behavior, X25519-derived secrets, certificate verification behavior and browser-shaped ClientHellos.

The official REALITY project itself is based on a modified TLS implementation. 

Rust experiments reinforce the same point.

`rustls-reality` explicitly forks/modifies Rustls to expose internal handshake state and add REALITY behavior. Its own README warns not to use the modified library for ordinary TLS. 

`xray-lite` also exists as a Rust VLESS/REALITY/XHTTP implementation and includes its own REALITY-related Rustls work. 

Therefore:

## Do not merge REALITY into the generic TLS subsystem.

Use something like:

```text
zero-security/
│
├── tls/
│   ├── rustls_backend
│   └── native_profile
│
├── fingerprint/
│   ├── chrome
│   ├── firefox
│   ├── safari
│   └── edge
│
├── reality/
│   ├── crypto
│   ├── client
│   ├── server
│   ├── handshake
│   ├── authentication
│   ├── certificate
│   ├── compatibility
│   └── pq
│
└── vision/
```

A Rustls upgrade should not require rewriting VLESS.

A REALITY protocol change should not destabilize generic TLS.

---

# 14. TLS fingerprinting also needs to be independent

A standard Rustls ClientHello is not automatically equivalent to Chrome, Firefox, Safari or Xray's expected uTLS profile.

Details can differ in:

```text
cipher suites
extension ordering
supported groups
key shares
signature schemes
ALPN
GREASE
TLS versions
padding
ECH-related behavior
```

Current `xray-rust` explicitly implements uTLS-shaped ClientHellos and even documents that some fingerprint profiles cannot be used with REALITY because they don't contain the X25519 key-share shape REALITY needs. 

Therefore Zero-Core should have:

```text
TlsBackend
```

and separately:

```text
TlsFingerprintProfile
```

not assume they're the same concept.

---

# 15. REALITY compatibility is now VERSIONED

This was one of the biggest findings from the later research.

Current Xray REALITY configuration includes:

```text
minClientVer
maxClientVer
```

and current Xray source still exposes these fields. 

More importantly, in July 2026 Xray committed a change setting REALITY's default:

```text
minClientVer = 26.3.27
```

unless changed. 

There have also been real interoperability reports involving clients that worked against older Xray releases and failed against newer REALITY releases. Those issue reports don't prove a universal Xray bug, but they prove that version-sensitive interoperability is real. 

Therefore Zray needs:

```text
zero-security/reality/compatibility/
```

with something conceptually like:

```rust
struct RealityCompatibility {
    protocol_generation: RealityGeneration,
    reported_client_version: ClientVersion,
    fingerprint_profile: FingerprintProfile,
    supports_mldsa65: bool,
}
```

Do not scatter:

```rust
if xray_version >= ...
```

through the codebase.

---

# 16. Xray itself must become a differential-test oracle

You cannot test REALITY by checking:

```text
"the connection succeeded once"
```

Every supported protocol combination should be tested against known Xray releases.

Build CI around:

```text
Zray client ───────► Xray server
Xray client ───────► Zray server
Zray client ───────► Zray server
```

across several pinned Xray versions.

For example:

```text
Xray 26.6.x
Xray 26.7.x
current stable
current main/nightly test
```

Then you can determine:

```text
Zray regression

versus

Xray behavior changed
```

This will save an enormous amount of debugging time.

---

# 17. Capture binary REALITY fixtures

For REALITY specifically, create deterministic interoperability fixtures for:

```text
ClientHello
SessionID
shortId
SNI/serverName
X25519 keys
derived secret
sealed authentication state
certificate
certificate verification
client version
ML-DSA state
successful handshake
rejected handshake
fallback handshake
```

Ideally compare exact bytes where deterministic.

Then dependency upgrades cannot silently change compatibility.

---

# 18. REALITY failure classification needs to be detailed

Do not return:

```text
REALITY_FAILED
```

for everything.

Internally support classifications such as:

```text
REALITY_KEY_REJECTED
REALITY_SHORT_ID_REJECTED
REALITY_SERVER_NAME_REJECTED

REALITY_CLIENT_VERSION_REJECTED
REALITY_PROTOCOL_VERSION_MISMATCH

REALITY_CLIENTHELLO_INCOMPATIBLE
REALITY_FINGERPRINT_INCOMPATIBLE

REALITY_CERTIFICATE_FAILURE
REALITY_CRYPTO_FAILURE

REALITY_TIMEOUT
REALITY_FALLBACK
REALITY_UNKNOWN
```

Not every failure can be observed perfectly.

Therefore each diagnosis can optionally contain:

```text
Confirmed
Likely
Unknown
```

That becomes extremely useful for automatic fallback and debugging.

---

# 19. Protocol composition is NOT arbitrary

Originally it was tempting to model:

```text
Protocol × Transport × Security × Flow
```

as freely interchangeable.

Research showed that is wrong.

Current Xray documentation says REALITY can be combined with:

```text
RAW
XHTTP
gRPC
```

rather than every transport. 

There are also more subtle constraints involving Vision and wrapped streams.

Current `xray-rust` compatibility documentation explains that direct Vision assumptions differ depending on whether it receives the appropriate TLS/REALITY connection shape, and specifically documents different behavior for XHTTP unless the required protected VLESS layer is present. 

So implement:

```rust
struct CarrierCapabilities {
    supports_tcp: bool,
    supports_udp: bool,

    preserves_direct_stream: bool,
    preserves_tls_connection: bool,

    supports_reality: bool,
    supports_vision_direct: bool,
    supports_vision_encrypted: bool,

    supports_xudp: bool,
    supports_mux: bool,
}
```

Then configuration compilation evaluates compatibility.

Invalid combinations should fail during startup.

Not after a connection already reaches the network.

---

# 20. XHTTP deserves high priority

Modern Xray increasingly relies on XHTTP.

Therefore Zray shouldn't spend its first year implementing every historical transport before XHTTP.

Initial XHTTP support should focus on:

```text
HTTP/2
REALITY + XHTTP
TLS + XHTTP
upload/download streams
packet-up
stream-up
stream-one
session identification
padding
XMUX behavior
```

Then add H3.

Current `xray-rust` documentation notes the following transport choices in the compatibility behavior it targets:

```text
TLS + ["http/1.1"] → HTTP/1.1
TLS + ["h3"]       → HTTP/3
other TLS ALPN     → HTTP/2
REALITY            → HTTP/2
```

and warns this isn't automatically an H3→H2→H1 fallback ladder. 

That distinction matters.

---

# 21. Iran fundamentally changes how the network layer should work

This was probably the most important non-Xray conclusion.

**There is no single “Iran Internet behavior.”**

It varies with:

```text
ISP
mobile/fixed
geographical area
IPv4/IPv6
date
political conditions
destination
protocol
time of day
```

OONI has documented periods in Iran where QUIC/HTTP3 dropped almost to zero, encrypted DNS was interfered with, and IPv6 was disrupted. 

The 2026 shutdowns made the distinction even clearer.

Cloudflare observed a **98.5% reduction in announced Iranian IPv6 address space** shortly before the January 8 shutdown. Several hours later overall Internet traffic effectively dropped to zero. 

During the February shutdown, overall traffic dropped to **well under 1%** of previous levels even though IPv4 route announcements remained relatively stable, which strongly indicates that BGP reachability alone was not enough to describe actual Internet access. Cloudflare attributes the observations to mechanisms such as filtering/whitelisting rather than broad IPv4 route withdrawal. 

IPv6 also remained heavily impacted during the later partial restoration. 

So this would be a major design mistake:

```rust
if country == Iran {
    disable_ipv6();
    disable_quic();
    use_tcp();
}
```

Don't do that.

---

# 22. Zero-Core should measure capabilities

Instead:

```text
Network interface appears
        │
        ▼
Create NetworkGeneration
        │
        ▼
Observe behavior
        │
        ├── IPv4
        ├── IPv6
        ├── TCP
        ├── UDP
        ├── TLS
        ├── H2
        ├── QUIC
        ├── H3
        ├── DNS
        ├── DoT
        ├── DoH
        └── DoQ
```

And capabilities shouldn't just be booleans.

Use:

```rust
enum CapabilityState {
    Unknown,
    Available,
    Degraded,
    Unavailable,
}
```

plus observations:

```rust
struct CapabilityObservation {
    state: CapabilityState,
    confidence: Confidence,
    observed_at: Instant,
    expires_at: Instant,
    evidence: Evidence,
}
```

Possible evidence:

```text
Passive observation
Active probe
Successful real flow
Failed real flow
```

---

# 23. Why `Degraded` matters

Consider:

```text
IPv6 route exists
        ↓
AAAA DNS works
        ↓
TCP handshake works
        ↓
TLS repeatedly stalls
```

A normal program might say:

```text
IPv6 supported = true
```

Zray should say:

```text
IPv6:
    routing = AVAILABLE
    TCP = AVAILABLE
    TLS application path = DEGRADED
```

That is far more useful.

---

# 24. Separate observation from policy

This was another major architectural improvement from the later research.

Don't let:

```text
Network Observatory
```

choose the transport.

It should only collect facts.

For example:

```text
IPv4 H2:
    connect success 99%
    TLS success     99%
    payload success 98%
    median RTT      83ms

IPv6 H2:
    connect success 91%
    TLS success     72%
    payload success 65%
    median RTT      64ms

IPv4 QUIC:
    handshake       18%
    payload success 11%
```

Then a completely separate:

```text
Connection Planner
```

consumes those observations and decides what to do.

This distinction is critical.

---

# 25. The Connection Planner

The planner takes:

```text
Network observations
+
Server capabilities
+
Protocol requirements
+
Privacy policy
+
User policy
+
Historical flow success
+
Probe cost
```

and produces:

```text
ConnectionPlan
```

For example:

```text
PRIMARY
IPv4
TCP
REALITY
XHTTP/H2

FALLBACK
IPv6
TCP
REALITY
XHTTP/H2

OPPORTUNISTIC TEST
IPv4
QUIC/H3
```

The planner can evolve independently from measurements.

---

# 26. Don't aggressively race everything

Don't create:

```text
IPv4 TCP
IPv6 TCP
IPv4 QUIC
IPv6 QUIC
DoH2
DoH3
DoQ
```

for every connection.

That wastes traffic, battery, sockets and server resources.

Instead use:

```text
Unknown network
      │
      ▼
safe baseline
      │
      ▼
collect evidence
      │
      ▼
cache observations briefly
      │
      ▼
prefer successful path
      │
      ▼
probe alternatives occasionally
```

This is roughly Happy Eyeballs generalized beyond IP families.

---

# 27. Detect “ghost connectivity”

This is particularly important for heavily filtered networks.

A successful:

```text
TCP SYN
SYN/ACK
ACK
```

doesn't mean Internet access works.

Neither does:

```text
ping success
```

nor even necessarily:

```text
TLS connected
```

Your success stages should include:

```text
SOCKET_CONNECTED

TLS_STARTED
TLS_COMPLETED

REQUEST_SENT

UPLOAD_CONFIRMED

FIRST_BYTE_RECEIVED

PAYLOAD_TRANSFERRED

BIDIRECTIONAL_FLOW_CONFIRMED
```

A path should only receive high confidence after useful data moves successfully.

---

# 28. Failure taxonomy is central

Don't reduce everything to:

```rust
std::io::Error
```

Internally classify:

```text
DNS_TIMEOUT
DNS_NXDOMAIN
DNS_NODATA
DNS_MALFORMED
DNS_SUSPECTED_INTERFERENCE

TCP_TIMEOUT
TCP_RST
TCP_UNREACHABLE

TLS_TIMEOUT
TLS_ALERT
TLS_CERTIFICATE_FAILURE

HTTP_403
HTTP_421
HTTP_5XX

H2_PROTOCOL_ERROR

UDP_TIMEOUT
UDP_BLACKHOLE

QUIC_HANDSHAKE_TIMEOUT
QUIC_TRANSPORT_ERROR

REALITY_AUTH_FAILURE
REALITY_VERSION_FAILURE

SERVER_REJECTED

NETWORK_CHANGED
```

This gives the planner actual information.

Otherwise fallback becomes blind trial-and-error.

---

# 29. Distinguish NETWORK health from SERVER health

This is subtle but very important.

These two things are not equivalent:

```text
Irancell currently disrupts QUIC
```

and:

```text
Server #4's QUIC endpoint is dead
```

Therefore:

```text
zero-net/observation
```

measures the network itself.

While:

```text
zero-observatory
```

measures server/outbound health.

They should not share the same state.

---

# 30. Zero-DNS architecture

DNS deserves its own subsystem:

```text
DNS request
    │
    ▼
DNS policy
    │
    ▼
DNS planner
    │
    ├── hosts
    ├── FakeDNS
    ├── split rules
    └── resolver candidates
           │
      ┌────┼────┬────┬────┐
      ▼    ▼    ▼    ▼    ▼
     UDP  TCP  DoT  DoH  DoQ
      │    │    │    │    │
      └────┴────┴────┴────┘
                │
                ▼
              Cache
```

It should have explicit privacy policies.

For example:

```text
STRICT

encrypted/tunneled resolver fails
→ resolution fails
```

versus:

```text
FALLBACK

encrypted resolver fails
→ system DNS may be allowed
```

Zray must never silently leak DNS because a preferred resolver failed.

---

# 31. Implement DNS single-flight

If:

```text
200 connections
```

all request:

```text
example.com
```

simultaneously, do not create 200 DNS queries.

Create one:

```text
example.com lookup
        │
        ├── waiter 1
        ├── waiter 2
        ├── waiter 3
        ...
        └── waiter 200
```

Current `xray-rust` implements this kind of managed single-flight behavior, which validates the design. 

---

# 32. DNS cache requirements

Initial Zero-DNS cache should support:

```text
positive TTL caching
negative caching
single-flight
bounded capacity
LRU-like eviction
stale-while-revalidate
CNAME chains
A/AAAA
family policies
DNS server policy
cache bypass
```

Cache keys need policy isolation.

Something conceptually like:

```rust
struct DnsCacheKey {
    name: DomainId,
    qtype: QType,
    resolver_policy: ResolverPolicyId,
}
```

Otherwise two different split-DNS policies could incorrectly reuse each other's results.

---

# 33. QUIC/H3 in Iran should be opportunistic

OONI historically observed QUIC/HTTP3 traffic dropping almost to zero during Iranian censorship events. 

So don't make:

```text
H3 > H2
```

a universal preference.

Make:

```text
if H3 is proven healthy on this network generation:
    prefer/use according to policy
else:
    use H2/TCP
```

If the filtering environment changes, Zray automatically adapts.

No country-specific release needed.

---

# 34. Do the same for IPv6

Never:

```text
Iran → IPv6 off
```

Instead observe IPv6.

Use Happy Eyeballs-like behavior where appropriate.

The 2026 measurements demonstrate why static assumptions would age badly: IPv6 availability in Iran changed drastically around major shutdown events while IPv4 BGP visibility behaved very differently. 

---

# 35. TUN architecture

Keep platform details outside routing/protocol code.

Conceptually:

```text
zero-tun
│
├── linux
├── windows
├── android
├── macos
├── ios
└── netstack
```

Platforms:

```text
Linux   → kernel TUN
Windows → Wintun
Android → VpnService fd
Apple   → NetworkExtension / packet tunnel
```

The userspace TCP/IP stack, if used, should sit behind an abstraction:

```rust
trait NetStack {
    ...
}
```

Possible first backend:

```text
smoltcp
```

Leaf demonstrates that a Rust proxy core can support both lwIP and smoltcp approaches. 

---

# 36. Recommended workspace

I would now structure the project approximately like this:

```text
zero/
│
├── crates/
│
│   ├── zero-core/
│   │   ├── runtime
│   │   ├── generations
│   │   ├── session
│   │   ├── dispatcher
│   │   └── lifecycle
│
│   ├── zero-config/
│   │   ├── xray_json
│   │   ├── native
│   │   ├── share_links
│   │   ├── validation
│   │   └── compiler
│
│   ├── zero-net/
│   │   ├── socket
│   │   ├── interface
│   │   ├── generation
│   │   ├── observation
│   │   ├── capability
│   │   ├── planner
│   │   ├── happy_eyeballs
│   │   └── failure
│
│   ├── zero-dns/
│   │   ├── message
│   │   ├── planner
│   │   ├── cache
│   │   ├── singleflight
│   │   ├── hosts
│   │   ├── fakedns
│   │   ├── udp
│   │   ├── tcp
│   │   ├── dot
│   │   ├── doh
│   │   └── doq
│
│   ├── zero-router/
│   │   ├── rules
│   │   ├── domain
│   │   ├── cidr
│   │   ├── geoip
│   │   ├── geosite
│   │   ├── sniff
│   │   └── balancer
│
│   ├── zero-protocol/
│   │   ├── socks
│   │   ├── http
│   │   ├── vless
│   │   ├── vmess
│   │   ├── trojan
│   │   └── shadowsocks
│
│   ├── zero-security/
│   │   ├── tls
│   │   ├── fingerprint
│   │   ├── reality
│   │   └── vision
│
│   ├── zero-transport/
│   │   ├── raw
│   │   ├── xhttp
│   │   ├── websocket
│   │   ├── httpupgrade
│   │   ├── grpc
│   │   └── quic
│
│   ├── zero-tun/
│   │   ├── platform
│   │   └── netstack
│
│   ├── zero-observatory/
│   │   ├── health
│   │   ├── latency
│   │   └── accounting
│
│   └── zero-platform/
│       ├── linux
│       ├── windows
│       ├── android
│       └── apple
│
└── apps/
    └── zray/
```

---

# 37. Core session object

Everything should normalize to something similar to:

```rust
SessionContext {
    generation,
    source,
    destination,
    original_destination,
    network,
    inbound,
    sniffed_domain,
    process_metadata,
    routing_metadata,
    network_generation,
}
```

Then:

```text
Inbound
   │
   ▼
SessionContext
   │
   ▼
Sniffer
   │
   ▼
Router
   │
   ▼
ConnectionPlan
   │
   ▼
Outbound
```

This normalization is extremely important.

---

# 38. Rust stack

The current likely foundation is:

| Component | Candidate |
|---|---|
| async runtime | Tokio |
| byte buffers | `bytes` |
| normal TLS | rustls |
| crypto backend | aws-lc-rs / selected RustCrypto crates |
| HTTP | hyper |
| H2 | hyper/h2 |
| QUIC | quinn |
| H3 | Rust h3 ecosystem |
| DNS parsing | carefully scoped Hickory components |
| CIDR | ipnet |
| config swap | arc-swap |
| pattern matching | aho-corasick / regex-automata |
| serialization | serde |
| errors | thiserror |
| telemetry | tracing |
| flags | bitflags |
| low-level sockets | socket2 |

For REALITY, assume from day one that ordinary Rustls APIs may not be enough for perfect server/client compatibility.

Keep the backend swappable.

---

# 39. The implementation order

This is the sequence I would use now.

1. **Create the Zero workspace and `zero-core`.** Implement runtime generations, session model, lifecycle, dispatcher, structured errors and socket abstraction.

2. **Implement SOCKS5 + HTTP CONNECT + Freedom.** This proves that the dispatcher and socket engine actually work before any Xray-specific complexity appears.

3. **Implement Zero-DNS.** Start with UDP/TCP, caching, single-flight, hosts, A/AAAA, strict leak policy and resolver routing. Add DoT/DoH2 shortly afterward.

4. **Implement routing.** Domain rules, CIDRs, inbound tag, network, ports, geoip/geosite, sniffing and compiled rule structures.

5. **Implement VLESS RAW without REALITY.** TCP first, then UDP/XUDP.

6. **Build the TLS fingerprint subsystem.** Do not hide it inside VLESS.

7. **Implement REALITY client.** Create exact interoperability fixtures immediately.

8. **Create the Xray compatibility CI matrix.** Test Zray against several pinned Xray versions before calling REALITY stable.

9. **Implement Vision.** Make flow capability explicit.

10. **Implement XHTTP/H2.** This should happen before chasing every historical transport.

11. **Implement TUN + FakeDNS.** Keep platform adapters isolated.

12. **Implement Network Observatory + Connection Planner.** This is where the Iran-focused adaptive behavior starts becoming distinctive.

13. **Implement DoH3/DoQ/XHTTP H3 and QUIC capability detection.** These are optional paths, not universal defaults.

14. **Implement Zray server mode.** VLESS inbound + REALITY server + fallback semantics.

15. **Add legacy/ecosystem protocols.** VMess AEAD, Trojan, Shadowsocks, WebSocket, HTTPUpgrade, gRPC compatibility.

16. **Expand Xray JSON parity and management APIs.** Don't make exhaustive config compatibility block the networking engine.

---

# 40. What you should NOT implement first

Do not start with VMess.

Do not start with a full recursive DNS server.

Do not start with every Xray JSON field.

Do not start with every historical transport.

Do not start with eBPF/XDP optimization.

Do not start with sophisticated GUI/API management.

Do not optimize tiny allocation differences before the architecture works.

Do not fork Rustls throughout the whole program.

Do not hard-code Iranian ISPs or censorship rules.

And most importantly:

> **Do not build REALITY until the surrounding TLS/fingerprint/test architecture exists.**

Otherwise REALITY will infect the entire codebase with compatibility hacks.

---

# 41. Build an Iran network simulator

This is worth making part of Zero's CI.

It should simulate conditions like:

```text
UDP completely dropped

QUIC packets dropped
but TCP works

IPv6 route exists
but payload stalls

TCP handshake succeeds
then application traffic is dropped

TLS ClientHello leaves
ServerHello never returns

DNS UDP succeeds
DoH TLS is reset

DoH2 succeeds
DoH3 fails

DNS response is poisoned

MTU unexpectedly low

upload works
download fails

download works
upload fails

connection reset after N bytes

network interface changes mid-session
```

Then test that the planner responds correctly.

This gives you a repeatable laboratory for Iran-specific resilience rather than depending on the actual Iranian network being in a particular state during development.

---

# 42. Implement shadow testing like Cloudflare

Cloudflare used shadow processing when introducing new recursive resolver behavior: run the new system against real examples and compare outcomes without allowing it to control production responses. 

Zero-Core can copy this idea.

For example:

```text
normal route decision
        │
        ├──────────────► actual connection
        │
        └──────────────► experimental planner
                           │
                           ▼
                      record decision
```

Then compare:

```text
current planner chose H2
new planner would choose H3
```

without risking user traffic.

This is an excellent way to improve Iran adaptation algorithms.

---

# 43. Privacy must be designed in

The adaptive engine does **not** need a centralized database containing browsing activity.

Keep capability measurements locally keyed to an opaque network identity/generation.

Something conceptually like:

```text
NetworkProfile
├── opaque identifier
├── capability observations
├── quality measurements
├── timestamps
└── expiry
```

Not:

```text
domain history
sites visited
full DNS history
connection destinations
```

The planner needs network characteristics, not browsing history.

---

# 44. The project's differentiator

At this point, merely saying:

> “Zray is Xray written in Rust”

would understate the project.

The real concept should become:

> **Zray is an Xray-compatible client/server built on Zero-Core, a Rust networking runtime designed around compiled immutable configurations, strict protocol interoperability, detailed failure classification, privacy-preserving network observation and adaptive connection planning.**

Its Iran advantage is not:

```text
IranMode = true
```

Its Iran advantage is that it can determine:

```text
on THIS network
at THIS moment

IPv4 works
IPv6 partially works
UDP is unreliable
QUIC is unavailable
H2 works
DoH2 works
DoQ fails
REALITY/H2 works

→ choose the path that actually works
```

And thirty minutes later:

```text
QUIC returned
IPv6 became healthy

→ adapt automatically
```

That architecture is much harder to obsolete.

---

# 45. Final architecture

The system I would now commit to is:

```text
┌────────────────────────────────────────────────────┐
│                      ZRAY                          │
│                                                    │
│ Xray JSON │ links │ API │ CLI │ compatibility      │
└─────────────────────────┬──────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────┐
│                ZERO-CONFIG                         │
│                                                    │
│ parse → validate → normalize → compile             │
│                                                    │
│              RuntimeGeneration N                   │
└─────────────────────────┬──────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────┐
│                  ZERO-CORE                         │
│                                                    │
│ Inbound                                            │
│    ↓                                               │
│ Session                                            │
│    ↓                                               │
│ Sniffing                                           │
│    ↓                                               │
│ Router                                             │
│    ↓                                               │
│ Connection Planner ◄──────── Network Observatory   │
│    │                                               │
│    ├──────────────► Zero-DNS                       │
│    │                                               │
│    ▼                                               │
│ Protocol                                           │
│    ↓                                               │
│ Security                                           │
│ TLS / REALITY / Vision                             │
│    ↓                                               │
│ Transport                                          │
│ RAW / XHTTP / WS / gRPC / QUIC                     │
│    ↓                                               │
│ Socket Engine                                      │
└─────────────────────────┬──────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────┐
│                PLATFORM LAYER                      │
│                                                    │
│ Linux │ Windows │ Android │ macOS │ iOS            │
│                                                    │
│ TUN │ Wintun │ VpnService │ NetworkExtension       │
└────────────────────────────────────────────────────┘
```

And there are four principles I would now treat as **non-negotiable**:

**Protocol logic must not own networking I/O.**

**Configuration must be compiled into immutable runtime generations.**

**Xray compatibility must be tested against versions, not assumed from protocol names.**

**Iran-specific resilience must come from observation and adaptation, not hard-coded censorship assumptions.**

If those four decisions are established correctly at the beginning, the rest of Zray—VLESS, REALITY, Vision, XHTTP, TUN, DNS and eventually VMess/Trojan/Shadowsocks—can be added incrementally without turning Zero-Core into another monolithic proxy codebase.