# Zray-Core — implementation plan from the inspected corpus

Companion to `RESEARCH-01.md`. That document decided *what architecture to build*.
This one decides *what to build it out of*, having actually read the code.

All fourteen reference repositories are cloned under `reference/`. Every claim below
is from reading those trees, not from their marketing.

---

# 1. The corpus, measured

| Repo | License | Rust LOC | Role |
|---|---|---|---|
| `aimalygin/xray-rust` | **MPL-2.0** | 187,882 | Mature **client**. 12 crates. XHTTP H1/H2/H3, REALITY client, uTLS, DNS, TUN, routing |
| `cfal/shoes` | **MIT** | 70,809 | Broad **server**. Own TLS1.3+REALITY stack. VLESS/Vision/VMess/Trojan/SS/Hysteria2/TUIC/AnyTLS/Snell/ShadowTLS |
| `shadowsocks/shadowsocks-rust` | **MIT** | 102,288 | Best-in-class socket/UDP-relay/TUN hygiene |
| `MFSGA/Chimera_Client` | **Apache-2.0** | 83,119 | `clash-rs` fork, Persian README, Iran-oriented. Clash/Mihomo config, netstack, FakeIP, hot reload |
| `eycorsican/leaf` | **Apache-2.0** | 43,168 | TUN (lwIP + smoltcp), chain/failover/select/tryall, amux |
| `hickory-dns/hickory-dns` | MIT/Apache-2.0 | 132,364 | DNS message/proto crates |
| `undead-undead/xray-lite` | **MIT** | 6k src (+45k vendored) | Small **server**. REALITY server, XHTTP h2/gRPC, eBPF/XDP firewall |
| `undead-undead/rustls-reality` | Apache/MIT/ISC | 45,329 | rustls 0.22 fork; REALITY core is only **89 LOC** |
| `therealaleph/sni-spoofing-rust` | **MIT** | 5,720 | Iranian DPI-desync technique (fake ClientHello, bad TCP seq) |
| `XTLS/Xray-core` | MPL-2.0 | 151,400 Go | **Normative oracle** |
| `XTLS/REALITY` | MPL-2.0 | 15,866 Go | **Normative oracle** for REALITY |
| `Qv2ray/v2ray-rust` | **AGPL-3.0** | 10,396 | ⛔ **Quarantined** |
| `SagerNet/sing-box` | **AGPL-3.0** | 190,525 Go | ⛔ **Quarantined** |
| `Qv2ray/Qv2ray` | GPL-3.0 | — (C++) | ⛔ Quarantined; archived GUI, no core value |

## 1.1 Capability matrix

| | xray-rust | shoes | xray-lite | leaf | Chimera | ss-rust |
|---|---|---|---|---|---|---|
| Client | ●●● | ●● | ○ | ●● | ●● | ●●● |
| **Server inbound** | **○** | **●●●** | ●● | ●● | ●● | ●●● |
| REALITY client | ●●● (ML-DSA-65) | ●● | ○ | ● | ●● | ○ |
| **REALITY server** | **○** | **●●●** | ●● | ○ | ○ | ○ |
| Vision | ●● | ●●● | ○ | ○ | ● | ○ |
| **XHTTP** | **●●● (H1/H2/H3)** | ○ | ● | ○ | ● (prototype) | ○ |
| uTLS fingerprints | ●●● (4,585 LOC) | ● | ○ | ○ | ● | ○ |
| DNS (DoT/DoH/DoQ/FakeIP) | ●●● (7,060 LOC) | ● | ○ | ●● | ●● | ●● |
| TUN | ●● | ●● | ○ | ●●● | ●●● | ●●● |
| VMess/Trojan/SS | ○ | ●●● | ○ | ●● | ●● | ●●● |
| Hysteria2/TUIC/AnyTLS | ○ | ●●● | ○ | ○ | ● | ○ |

**The two cores are almost perfectly complementary.** xray-rust is a client with no
server and the only real XHTTP. shoes is a server with no XHTTP and the only
from-scratch REALITY that works in both directions.

---

# 2. Licensing is the binding constraint (RESEARCH-01 does not mention this)

This determines the plan more than any technical factor.

- **AGPL-3.0** — `v2ray-rust`, `sing-box`. Network-copyleft. Linking these into a
  proxy server forces the *entire* Zray source on every user who connects to a
  Zray server. **Never copy. Never link.** Read only to understand behavior, and
  even then prefer the Go `Xray-core` oracle for the same answer.
- **MPL-2.0** — `xray-rust`, `Xray-core`, `REALITY`. **File-level** copyleft: a file
  containing MPL code stays MPL and must be published, but it may sit in the same
  binary as MIT/Apache/proprietary files. Entirely workable — *if* MPL-derived code
  is quarantined into known crates rather than smeared across the tree.
- **MIT / Apache-2.0** — everything else. Free to use with attribution.

## Decision 1 — Zray-Core ships as MPL-2.0

It is the only license that lets the most valuable asset (xray-rust's XHTTP + DNS +
uTLS, 188k LOC) be used at all, while still accepting MIT and Apache code inbound.
It also matches Xray-core itself, which matters politically in this ecosystem.

**Enforcement, from commit one:**
- `crates/*/PROVENANCE.md` per crate: upstream repo, commit SHA, license, what was taken.
- CI job fails the build if a file in an `mpl-clean` crate imports from an MPL-derived crate in the wrong direction, and if any path matches the AGPL quarantine list.
- `cargo-deny` with an explicit allow-list; AGPL/GPL in the dependency graph is a hard error.

---

# 3. Four decisions that sharpen RESEARCH-01

## Decision 2 — Own the TLS 1.3 stack for REALITY. Do not fork rustls.

This is the most consequential technical call, and the corpus settles it.

Three strategies exist in the wild:

| Strategy | Who | Verdict |
|---|---|---|
| Fork rustls, expose handshake internals | xray-rust (`shaped-rustls`), xray-lite (`rustls-reality`) | **Reject** |
| Implement the TLS 1.3 subset REALITY needs | **shoes** (`src/reality/`, 7,900 LOC) | **Adopt** |
| Use stock rustls | — | Impossible; REALITY needs ServerHello.random and session-id control |

Why reject the fork:

1. xray-rust's own `docs/status.md` flags it as a liability: REALITY shaping "depends
   on a full, immutable Git revision of the maintainer's public `shaped-rustls` fork
   rather than the crates.io `rustls` release... consumers should include that fork in
   dependency and security reviews." A personal rustls fork is a supply-chain risk and
   a permanent rebase tax.
2. `rustls-reality` shows how thin the fork's value is: the REALITY core is **89 lines**,
   and it is wired incorrectly — `rustls::reality::verify_client` computes
   `HMAC(private_key, client_random)`, which is not REALITY. xray-lite only works
   because it does the real verification itself in `server_rustls.rs:159` and then
   hands the derived `auth_key` to the fork with `verify_client = false`. The fork's
   own auth path and `xray-lite/src/transport/reality/auth.rs` are dead, wrong code.
3. **REALITY requires emitting exact ClientHello bytes.** Owning the stack makes uTLS
   shaping a serialization problem instead of a fight with someone else's state machine.
   xray-rust spends 4,585 LOC in `utls_profiles.rs` + 949 in `utls_shaping.rs` +
   889 in `reality_rustls.rs` partly *because* rustls wants to own that buffer.
4. It is the only strategy in the corpus that gives **client and server from one
   codebase**, which Zray needs and xray-rust does not have.

**But keep rustls for ordinary TLS.** Two backends behind one trait, exactly as
RESEARCH-01 §13 asks:

```
zero-security/
├── tls/           # rustls — ordinary TLS, cert verification, DoT/DoH/H2/H3
├── tls13-core/    # owned minimal TLS1.3 — records, AEAD, key schedule, messages
├── fingerprint/   # ClientHello byte emission; consumed by BOTH backends
├── reality/       # built on tls13-core; client + server + compatibility + pq
└── vision/
```

`tls13-core` is a *REALITY substrate*, not a general TLS library. It must never be
offered for ordinary TLS — that is the mistake `rustls-reality`'s README warns about.

## Decision 3 — Client from xray-rust, server from shoes, joined at a new core

Neither is the base. Both are donors into the `zero-*` workspace from RESEARCH-01 §36.

## Decision 4 — Refactor on intake; do not vendor monoliths

xray-rust's substance sits in files that cannot be maintained as-is:

| File | LOC |
|---|---|
| `xray-core-rs/src/outbound.rs` | 7,973 |
| `xray-core-rs/src/tun.rs` | 7,939 |
| `xray-transport/src/dns.rs` | 7,060 |
| `xray-core-rs/src/tun_dns.rs` | 6,576 |
| `xray-transport/src/utls_profiles.rs` | 4,585 |
| `xray-transport/src/stream/xhttp/transport.rs` | 3,531 |

Intake rule: **no file over 1,500 LOC enters the tree.** Port by behavior with the
tests, not by copy-paste. This is also what keeps MPL provenance legible.

## Decision 5 — Xray-core and REALITY are test oracles, not reading material

Per RESEARCH-01 §16. Pin the same revision xray-rust pins so its interop evidence
transfers: **Xray-core `v26.7.28`, commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.**

---

# 4. Component sourcing

| Zray crate | Primary donor | License in | Notes |
|---|---|---|---|
| `zero-core` | new | MPL | Generations, session, dispatcher, lifecycle |
| `zero-config` | xray-rust `xray-config` (19,341 LOC) | MPL | Add the compiler stage RESEARCH-01 §4 requires; xray-rust stops at parse |
| `zero-net/socket` | **shadowsocks-rust** | MIT | Best socket options, fwmark, bind-to-device, UDP relay |
| `zero-net/happy_eyeballs` | xray-rust `happy_eyeballs.rs` (714) | MPL | Already correct: races TCP only, one handshake on the winner |
| `zero-net/observation`,`planner` | **new** | MPL | The differentiator. Nothing in the corpus has this |
| `zero-dns` | xray-rust `dns.rs` (7,060+3,048) + `hickory-proto` | MPL+MIT | Split into message/planner/cache/singleflight/transports |
| `zero-router` | xray-rust `xray-routing` + Chimera rules | MPL+Apache | Aho-Corasick domain sets, compiled CIDR |
| `zero-protocol/vless` | **shoes** `vless/` | MIT | Has client **and** server; xray-rust has client only |
| `zero-protocol/{vmess,trojan,ss}` | **shoes** + shadowsocks-rust | MIT | Do not write from scratch |
| `zero-protocol/{hysteria2,tuic,anytls}` | **shoes** | MIT | Free breadth, later phase |
| `zero-security/tls13-core` | **shoes** `reality/` | MIT | 7,900 LOC, client+server |
| `zero-security/reality` | shoes + `XTLS/REALITY` oracle | MIT | Add versioning + ML-DSA-65 from xray-rust |
| `zero-security/fingerprint` | xray-rust `utls_profiles.rs` | MPL | Largest fingerprint corpus in Rust |
| `zero-security/vision` | **shoes** `vless/vision_*` | MIT | 4 files; cleanest Vision in Rust |
| `zero-transport/xhttp` | xray-rust `stream/xhttp/` (~8k) | MPL | **Only real XHTTP in Rust.** Irreplaceable |
| `zero-transport/{ws,grpc,httpupgrade}` | xray-rust `stream/` | MPL | gRPC divergences already documented |
| `zero-tun/netstack` | **leaf** + Chimera `clash-netstack` | Apache | smoltcp first, lwIP later |
| `zero-tun/platform` | xray-rust + shadowsocks-rust | MPL+MIT | Android/Apple adapters already exist |
| `zero-evasion` | **sni-spoofing-rust** + Xray `freedom` | MIT+MPL | See §5 |
| `zero-observatory` | xray-rust `health.rs`,`startup_probe.rs` | MPL | Server health only — never network health |

**Irreplaceable assets (build order follows these):** xray-rust's XHTTP and uTLS
profiles; shoes' TLS1.3/REALITY/Vision. Everything else has two or more donors.

---

# 5. The Iran layer — where Zray actually differentiates

RESEARCH-01 §21–34 is right that hard-coding `if country == Iran` is wrong. But
observation-and-adaptation alone is *defensive*. The corpus contains active techniques
none of the cores combine.

## 5.1 Active evasion (`zero-evasion`) — new, nothing in the corpus has all of it

| Technique | Source | Status in Rust cores |
|---|---|---|
| TCP-segment fragmentation of ClientHello | Xray `freedom.fragment` | partial (xray-rust, shoes, xray-lite) |
| UDP `noises` before real payload | Xray `freedom.noises` (`config.proto:30,63`) | **absent everywhere** |
| **Fake ClientHello with out-of-window TCP seq** | `sni-spoofing-rust` (846★) | **absent from every core** |
| TLS record-layer splitting | — | absent |

The SNI-desync technique is the notable one: inject a fake ClientHello carrying a
whitelisted SNI with a deliberately wrong sequence number. Passive DPI sees the fake
SNI and whitelists the flow; the real server discards the segment as out-of-window.
It needs `CAP_NET_RAW` (Linux) / WinDivert (Windows), so it must be an **optional,
capability-gated** layer that degrades cleanly to fragmentation when raw sockets are
unavailable — which is always the case on unrooted Android and iOS.

Design constraint: evasion is a property of a *path*, selected by the Connection
Planner from measured evidence, never a global config flag. `zero-evasion` exposes
strategies; the planner decides when one is worth its cost.

## 5.2 Observation feeds evasion, not just transport choice

Extend RESEARCH-01 §27's success ladder so the planner can attribute failures:

```
SOCKET_CONNECTED → TLS_STARTED → TLS_COMPLETED → REQUEST_SENT
→ UPLOAD_CONFIRMED → FIRST_BYTE → PAYLOAD_TRANSFERRED → BIDIRECTIONAL_CONFIRMED
```

Add the Iran-specific discriminator RESEARCH-01 misses: **when a path dies, does it
die at a byte threshold or a time threshold?** Reset-after-N-bytes indicates
throughput-based DPI and argues for fragmentation/padding. Reset-after-T-seconds with
clean handshake indicates flow-timeout policy and argues for keepalive shaping. Same
`CONNECTION_RESET`, opposite remedies. Record `bytes_at_failure` and
`elapsed_at_failure` on every terminal failure.

## 5.3 Privacy floor

Per RESEARCH-01 §43: `NetworkProfile` is keyed by an opaque local identity
(hash of gateway MAC + SSID + interface), holds capability observations only, never
domains or destinations, and never leaves the device. No telemetry endpoint ships.

---

# 6. Efficiency — beyond the Cloudflare notes

RESEARCH-01 §3 correctly extracts the data-layout lesson. Concretely:

1. **Compiled config uses `Box<str>` / `Box<[T]>`, never `String`/`Vec`.** Strings live
   once in `RuntimeGeneration`; sessions carry `u32` IDs (RESEARCH-01 §4).
2. **DNS cache entries in one contiguous region** with `answer_end`/`authority_end`
   offsets rather than three `Vec<Record>`. Cloudflare's 953→420 bytes/entry came from
   exactly this.
3. **`arc-swap` generations**, and — improving on xray-rust, whose `docs/architecture.md`
   admits "A core's full configuration is not hot-reloaded" and that changing outbounds
   "requires a new handle" — swap the *whole* graph, not just routing rules.
4. **Enums on the hot path, traits only at setup boundaries** (RESEARCH-01 §6). The
   DNS exchanger and platform socket provider stay `dyn`; nothing per-packet does.
5. **Fix the two throughput ceilings xray-rust documented.** Its H2 stream window is
   raised to 4 MiB but the connection window is pinned by `h2` at 65,535 and released
   only from the app read path — one stalled flow starves an entire outbound. Owning
   the H2 layer or patching credit release is a phase-10 requirement, not an
   optimization. Its `docs/transport-window-audit.md` has the measurements.
6. **Single-flight everywhere**, not just DNS: REALITY handshakes to the same endpoint,
   geodata loads, and certificate generation.

Efficiency work is gated on benchmarks, not intuition — xray-rust ships a comparison
harness (`xray-bench`, 20,810 LOC) against pinned Xray-core and sing-box. Port it early;
it is the only way to know whether a change helped.

---

# 7. Testing — the differential oracle

Non-negotiable per RESEARCH-01 §16–17.

```
Zray client → Xray server      Xray client → Zray server      Zray ↔ Zray
```

across pinned Xray `v26.7.28`, current stable, and a warning-only `main` smoke.
Zray having both client and server is what makes the middle column possible — xray-rust
cannot run it.

**Byte-exact REALITY fixtures** (RESEARCH-01 §17) captured from the Go `REALITY` oracle:
ClientHello, session-id sealing, `X25519` shared secret, HKDF `"REALITY"` expansion,
ServerHello.random HMAC injection, temporary-certificate HMAC-SHA512, ML-DSA-65 state,
and the reject/fallback paths. Any dependency bump that changes a byte fails CI.

**REALITY version compatibility** (RESEARCH-01 §15): Xray set default
`minClientVer = 26.3.27` in July 2026. Model this as
`RealityCompatibility { protocol_generation, reported_client_version, fingerprint_profile, supports_mldsa65 }`
in one module — never `if xray_version >=` scattered through the tree. Note also that
xray-rust documents fingerprint profiles that *cannot* be used with REALITY because
they lack the X25519 key-share shape; that constraint belongs in
`CarrierCapabilities` validation (RESEARCH-01 §19) and must fail at config-compile
time, not at connect time.

**Iran network simulator** (RESEARCH-01 §41) as a CI harness using `tc netem` +
nftables: UDP dropped, QUIC dropped/TCP fine, IPv6 routed but stalling, reset-after-N-bytes,
reset-after-T-seconds, DoH reset while UDP DNS passes, poisoned responses, low MTU,
asymmetric upload/download failure, mid-session interface change. Assert the *planner's
decision*, not just that traffic flowed.

---

# 8. Phased roadmap

Each phase has an exit gate. No phase starts before its predecessor's gate is green.

| # | Phase | Gate |
|---|---|---|
| 0 | Workspace, license enforcement, `PROVENANCE.md`, cargo-deny, pinned oracles | CI rejects an AGPL dep and a cross-license import |
| 1 | `zero-core`: generations, session, dispatcher, failure taxonomy, socket engine | Full-graph hot swap under load with zero dropped flows |
| 2 | SOCKS5 + HTTP CONNECT + Freedom (**+ server inbounds from day one**) | Throughput within 10% of Xray on loopback |
| 3 | `zero-config` compiler: parse → validate → compile → `RuntimeGeneration` | Invalid protocol/transport combos fail at compile, not connect |
| 4 | `zero-dns`: UDP/TCP, cache, single-flight, hosts, strict leak policy, DoT/DoH2 | Leak test passes under STRICT; contiguous-layout cache benchmarked |
| 5 | `zero-router`: domain/CIDR/geo/port/network, compiled matchers | Rule-match parity vs Xray on a generated corpus |
| 6 | VLESS RAW client **and server**, then UDP/XUDP | Both directions against pinned Xray |
| 7 | `zero-security/fingerprint` standalone | Byte-exact ClientHello per profile vs uTLS |
| 8 | `zero-security/tls13-core` + REALITY **client and server** | Byte-exact fixtures; full 3×3 interop matrix |
| 9 | Vision, with capability constraints enforced at compile | Vision over RAW/REALITY both directions |
| 10 | XHTTP H1/H2, all three modes, xmux; fix the H2 connection-window ceiling | Interop all modes; no single-flow starvation under 32 flows |
| 11 | TUN + FakeDNS, platform adapters isolated | Android + Linux full-tunnel soak |
| 12 | **Network Observatory + Connection Planner + `zero-evasion`** | Iran simulator: correct planner decision in all 13 scenarios |
| 13 | QUIC/H3, DoQ/DoH3 — opportunistic, never default | H3 used only when measured healthy |
| 14 | VMess/Trojan/Shadowsocks/Hysteria2/TUIC/AnyTLS via shoes | Interop per protocol |
| 15 | Config parity expansion, management API, share links | — |

Note the deliberate divergence from RESEARCH-01 §39: **server mode moves from step 14
to step 2.** Building client-only and retrofitting a server is exactly how xray-rust
ended up with no server after 188k LOC, and it forfeits the Xray-client→Zray-server
test column for the entire project lifetime.

---

# 9. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Owning TLS 1.3 introduces a crypto vulnerability | **High** | Scope to the REALITY substrate only; never expose for general TLS; fuzz records/handshake; audit before any server release |
| REALITY compatibility drifts with Xray releases | **High** | Byte fixtures + pinned 3-version CI matrix; versioned compatibility module |
| MPL provenance smears across the tree | Medium | Per-crate `PROVENANCE.md`; CI import-direction check; 1,500-LOC intake limit |
| AGPL contamination from reading `sing-box`/`v2ray-rust` | Medium | Quarantine list in CI; prefer the Go oracle for behavioral questions |
| Scope collapse — 1M LOC of donors invites endless porting | **High** | Phase gates; "irreplaceable assets" list drives order; breadth protocols last |
| `h2` crate limits XHTTP throughput | Medium | Measured in xray-rust's audit; budget a fork or patch in phase 10 |
| Evasion techniques need privileges mobile will never grant | Medium | Capability-gated with clean degradation; never a correctness dependency |

---

# 10. The one-sentence version

> Zray-Core is an MPL-2.0 Rust workspace that takes xray-rust's XHTTP, DNS and uTLS
> fingerprint corpus, shoes' from-scratch TLS 1.3 / REALITY / Vision stack with its
> client *and* server symmetry, leaf and Chimera's netstack, and shadowsocks-rust's
> socket hygiene — and adds the two things none of them have: a network observatory
> that measures what actually works on this network right now, and an active evasion
> layer the planner can deploy when it doesn't.
