# Zray-Core — Iran implementation plan

Companion to `RESEARCH-01.md` (architecture) and `PLAN-01.md` (what to build it from).
This one is derived from configs that **actually work in Iran right now**: a live
VLESS/REALITY/Vision config, and `bia-pain-bache/BPB-Worker-Panel` read in full
(9,152 LOC, cloned to `reference/BPB-Worker-Panel`).

> **Credential note.** The config shared for analysis is live. Its UUID, public key and
> shortId are deliberately **not** reproduced anywhere in this repo — only its shape.
> Anything committed here is public forever; a burned config is a blocked server.

---

# 1. Two config classes work in Iran, for opposite reasons

Everything that survives Iranian DPI falls into one of two families. They fail
differently, so a serious client must support both and move between them.

| | **Class A — Direct REALITY** | **Class B — CDN-fronted** |
|---|---|---|
| Example | the shared config | BPB Worker/Pages |
| Egress | your own VPS | Cloudflare edge |
| Looks like | real TLS to a major site | real CF traffic |
| Killed by | **VPS IP blocked** | CF IP ranges blocked / throttled |
| Latency | low (1 RTT, no detour) | higher (CF detour) |
| Throughput | full | worker limits (100k req/day) |
| Needs | a clean VPS IP | nothing — no server at all |
| UDP | yes | **no** (workers can't do UDP) |

**Class A is fast and fragile. Class B is slow and durable.** Neither is sufficient.
The Iranian user experience is dominated by the transition between them.

---

# 2. Why the shared config works, field by field

```
vless://<uuid>@<ip>:443
  ?security=reality
  &sni=www.googletagmanager.com
  &fp=chrome
  &pbk=<x25519-pub>&sid=<8-byte-hex>
  &flow=xtls-rprx-vision
  &type=tcp&headerType=none
  &encryption=none
```

| Field | Why it survives |
|---|---|
| `@<raw IPv4>` | No domain means **no DNS to poison**. Iranian DNS interception is the cheapest censorship layer; a literal IP skips it entirely |
| `security=reality` | The handshake is a *real* TLS session to a *real* site. Active probing of the IP gets a genuine `googletagmanager.com` certificate chain, because REALITY relays the probe to the real host |
| `sni=www.googletagmanager.com` | **Collateral-damage selection.** GTM is embedded in a large fraction of the commercial web, Iranian banking and e-commerce included. Blocking this SNI breaks the domestic internet, so it is politically expensive to block. This is the single most important choice in the config |
| `fp=chrome` | uTLS-shaped ClientHello. A stock Go/Rust TLS ClientHello is itself a fingerprint; Chrome's is the most common shape on the wire |
| `pbk` + `sid` | REALITY X25519 public key and shortId. The shortId is sealed inside the session-id, so passive DPI sees only a normal random session-id |
| `flow=xtls-rprx-vision` | **Defeats TLS-in-TLS detection.** Without Vision, tunneled TLS shows a distinctive record-size/timing signature — an inner handshake wrapped in an outer one. Vision splices inner records directly after the outer handshake so the pattern disappears |
| `type=tcp&headerType=none` | No WebSocket/XHTTP/gRPC wrapper. Every wrapper adds fingerprint surface; raw TCP has the least |
| `encryption=none` | Correct and not a weakness — VLESS is a bare multiplexing header; REALITY supplies all crypto |

**The load-bearing parts are `sni` choice, REALITY, and Vision.** Fingerprint and raw
TCP are hardening. The raw IP is what makes it fragile: nothing recovers it when the
IP is blocked.

---

# 3. What BPB does that no Rust core does

BPB is a Cloudflare Worker, so none of its code is reusable — but its **parameters are
field-tuned against Iranian ISPs**, and that tuning is the real asset.

## 3.1 TCP fragmentation — `finalmask.tcp`

`src/settings/settings.ts:218-225`, emitted at `src/cores/xray/outbounds.ts:447`.

```
packets  = 'tlshello'     # fragment ONLY the ClientHello
length   = 100-200        # bytes per fragment
delay    = 1-1            # ms between fragments
maxSplit = 0-0            # unlimited splits
```

Splitting the ClientHello across TCP segments means the SNI never appears contiguously
in one packet. Stateless DPI that string-matches SNI within a single segment fails to
reassemble. `packets` also accepts `1-1`, `1-2`, `1-3`, `1-5` to fragment the first N
packets rather than just the handshake.

Note `tlshello` over `1-N`: fragment only what must be hidden. Fragmenting everything
costs latency and is itself a timing signature.

## 3.2 UDP noise — `finalmask.udp`

```
reset = '30-60'
noise = [{ type:'rand', packet:'50-100', delay:'1-5', count:5 }]
```

Five random 50–100 byte datagrams, 1–5 ms apart, before the real payload. Types are
`rand` / `array` / `str` / `base64` / `hex`. Applied at `routing.ts:90` to UDP on
`443, 2053, 2083, 2087, 2096, 8443` — Cloudflare's HTTPS port set. **Absent from every
Rust core in the corpus.**

## 3.3 Knocker noise (QUIC masquerade)

```
knockerNoiseMode = 'quic'   # shape noise as QUIC initials
count = 10-15, size = 5-10, delay = 1-1
```

Rather than random bytes, emit packets shaped like QUIC handshakes so the flow is
classified as QUIC rather than unknown.

## 3.4 AmneziaWG — `src/cores/wireguard.ts:26-34`

```
Jc = 5            # junk packets before handshake
Jmin/Jmax = 50-100  # junk size range
S1 = 0, S2 = 0      # init/response packet junk
H1..H4 = 1,2,3,4    # header magic values — breaks WireGuard's fixed type bytes
MTU = 1280
```

Standard WireGuard is trivially fingerprinted: fixed 148-byte handshake, message type
in byte 0. `H1..H4` reassign those constants and `Jc/Jmin/Jmax` break the length
signature. This is a *protocol*, not a transport tweak, and Zray must implement it as
one.

## 3.5 Three-tier DNS — and the insight everyone misses

`src/cores/xray/dns.ts` + `geo-assets.ts:38-52`:

```
remoteDNS       = https://8.8.8.8/dns-query   # through the tunnel
localDNS        = 8.8.8.8                     # direct, for bypassed domains
antiSanctionDNS = 178.22.122.100              # Shecan
```

`178.22.122.100` is **Shecan**, an Iranian anti-sanction resolver. It exists because
**Iran has two opposite network problems**:

| | Censorship | Sanctions |
|---|---|---|
| Who blocks | Iranian ISPs / DPI | US companies (OpenAI, Docker, Adobe, Intel, Nvidia…) |
| Blocks what | outbound to the world | inbound from Iranian IPs |
| Direction | in → out | out → in |
| Fix | **tunnel out** | **stay Iranian**, resolve via Shecan |

These remedies are mutually exclusive. Tunneling `openai.com` through a foreign VPS
gets you blocked *harder* — datacenter IPs are banned more aggressively than residential
Iranian ones. So BPB routes sanctioned domains **direct, with Shecan DNS**, which
returns a domestic relay address.

BPB also pins the DoH host's own IP into `hosts` (`dns.ts:29-31`) so bootstrap
resolution cannot be poisoned — the classic chicken-and-egg leak.

**No Rust proxy core in the corpus models sanctions as a distinct routing class.**
This is the single biggest functional gap for Iranian users.

## 3.6 CDN mechanics (Class B only)

- **Clean IP / CDN address** (`cleanIPs: ['www.speedtest.net']`) — Iran blocks *some*
  Cloudflare ranges, not all. Users hunt for reachable edge IPs. BPB makes this manual.
- **HTTPS ports** `443, 8443, 2053, 2083, 2087, 2096` (HTTP: `80, 8080, 2052, 2082,
  2086, 2095, 8880`) — when 443 is throttled, alternates often survive.
- **Proxy IP / prefix** (`src/protocols/common.ts:33-53`) — a CF Worker cannot open a
  socket to a CF IP, so destinations behind Cloudflare need a relay. On direct-connect
  failure, retry through a proxy IP or a dynamically generated prefix.
- **Chain proxy** — pin the egress IP for services that geo-discriminate.
- **ECH** (`enableECH`, `echServerName`) — encrypts the SNI itself. Mutually exclusive
  with fragment in BPB (`outbounds.ts:111`), since there is no plaintext SNI left to split.

---

# 4. What this changes in `PLAN-01.md`

Five substantive additions.

## 4.1 Config *class* becomes a first-class routing concept

`PLAN-01` §5 treats evasion as per-path tuning. That is too small. The real failure
Iranian users hit is **the whole class dying** — the VPS IP gets blocked and every
Class A config is dead at once.

```rust
enum AccessClass {
    DirectReality { endpoint: SocketAddr },   // fast, fragile
    CdnFronted    { edge: CdnEdge },          // slow, durable
    WarpTunnel    { amnezia: AmneziaParams }, // last resort
}
```

The Connection Planner must fail over **across classes**, not just across servers
within a class. Success ladders and failure taxonomy are per-class. This is the feature
that turns a proxy into something that stays up through an Iranian blocking event.

## 4.2 `zero-evasion` gains a concrete, tuned scope

| Strategy | Parameters | Default (from BPB field tuning) |
|---|---|---|
| `TlsHelloFragment` | packets, length, delay, maxSplit | `tlshello`, 100-200 B, 1 ms, unlimited |
| `PacketFragment` | first N packets | `1-3` |
| `UdpNoise` | type, size, delay, count, reset | `rand`, 50-100 B, 1-5 ms, ×5, reset 30-60 |
| `QuicMasquerade` | count, size, delay | 10-15, 5-10 B, 1 ms |
| `SniDesync` | fake SNI, seq offset | from `sni-spoofing-rust`; needs `CAP_NET_RAW` |
| `Ech` | ech config list | mutually exclusive with fragment |

These are **defaults, not constants.** They ship as the starting point; the observatory
measures whether they help on *this* network and the planner adjusts. That is the
difference between Zray and every panel that hard-codes BPB's numbers.

## 4.3 Clean-IP discovery is a measurement problem, not a user chore

BPB and every panel make the user run an external IP scanner and paste results. That is
exactly what `zero-net/observation` exists for. Zray should continuously and cheaply
probe a bounded candidate set of CDN edges, rank by measured `PAYLOAD_TRANSFERRED`
success (not ping — ghost connectivity, `RESEARCH-01` §27), and keep the ranking in the
`NetworkProfile`. Same machinery, no new subsystem, and it removes the single most
common support burden for Iranian users.

## 4.4 Routing needs a third verdict

Current model is binary: `direct` or `proxy`. Iran needs three:

```rust
enum RouteVerdict {
    Direct,                                  // domestic
    Proxy   { outbound: OutboundId },        // censored
    DirectVia { resolver: ResolverId },      // sanctioned — direct, anti-sanction DNS
}
```

`DirectVia` is not expressible today and is why sanctioned services break for Iranian
users on every Rust core in the corpus. The `zero-dns` resolver-policy work in
`PLAN-01` §4 already has the machinery — the router just needs to be able to name a
resolver in a verdict.

## 4.5 AmneziaWG joins the protocol list

Add to `zero-protocol/`: WireGuard plus `Jc/Jmin/Jmax/S1/S2/H1-H4`. It is the fallback
when both TLS-based classes are dead, and `Chimera_Client` (Apache-2.0) plus the WG
ecosystem give a starting point. Lower priority than VLESS but higher than Hysteria2 /
TUIC for the Iranian user specifically.

---

# 5. Default strategy ladder

What Zray should try, in order, on an unknown Iranian network. Each rung costs more than
the last, so the planner climbs only on evidence.

```
0  REALITY + Vision + raw TCP, direct IP        ← fastest; the shared config
1  … + uTLS fingerprint rotation
2  … + TLS ClientHello fragmentation            ← costs ~1 RTT of latency
3  … + SNI desync                               ← needs CAP_NET_RAW; desktop only
4  REALITY + XHTTP/H2                           ← survives some flow-shape blocking
5  CDN-fronted WS/XHTTP on 443                  ← class change; VPS IP is gone
6  … + alternate CDN ports (2053/2083/2087/2096/8443)
7  … + clean-IP rotation
8  AmneziaWG with junk packets                  ← last resort; UDP must work
```

Two rules keep this from becoming blind trial-and-error:

- **Never skip rungs on a hunch.** Climb only when the failure taxonomy says the current
  rung failed in a way the next rung addresses. A `TCP_RST` after 4 KB argues for
  fragmentation; a clean `TLS_TIMEOUT` argues for a class change. Same symptom class,
  different remedy — this is why `PLAN-01` §5.2 records `bytes_at_failure` and
  `elapsed_at_failure`.
- **Descend too.** Blocking in Iran is often temporary and event-driven. A client stuck
  at rung 7 after a shutdown ends is wasting most of its throughput. Periodically
  re-probe lower rungs at low cost.

---

# 6. Roadmap changes

Against `PLAN-01` §8:

| Phase | Change |
|---|---|
| 3 `zero-config` | **Add:** parse `vless://` share links (this is how every Iranian user imports), `finalmask` fragment/noise schema, ECH fields |
| 5 `zero-router` | **Add:** `RouteVerdict::DirectVia`; anti-sanction geosite set |
| 4 `zero-dns` | **Add:** third resolver tier; pin DoH-host IP to defeat bootstrap poisoning |
| 8 REALITY | **Add:** SNI-selection guidance — collateral-damage domains, not obscure ones |
| **12 evasion** | **Split and promote.** `12a` fragment + UDP noise (cheap, huge payoff, no privileges) lands right after XHTTP; `12b` SNI desync + clean-IP discovery + class failover after the observatory |
| 14 protocols | **Add:** AmneziaWG, ahead of Hysteria2/TUIC |

The promotion of `12a` is the important one. Fragmentation and UDP noise are ~500 LOC,
need no privileges, work on mobile, and are the difference between "connects" and
"doesn't" on many Iranian ISPs today. They should not sit behind the observatory.

---

# 7. What to verify before building

Three things I could not establish from the corpus and that should be measured, not assumed:

1. **Is `finalmask` current Xray schema, or is `freedom.fragment` still canonical?**
   BPB emits `streamSettings.finalmask`; `Xray-core/proxy/freedom/config.proto:61,63`
   has `fragment` and `noises` on the freedom outbound. These may be different
   generations of the same feature. Resolve against the pinned oracle before designing
   the config surface — this is exactly the versioned-behavior trap of `RESEARCH-01` §15.
2. **Does Vision still matter with XHTTP?** Vision defeats TLS-in-TLS; XHTTP already
   restructures the stream. `xray-rust` documents that Vision is *refused* over XHTTP
   without VLESS encryption. The combination matrix needs pinning in
   `CarrierCapabilities`.
3. **Are BPB's fragment numbers still optimal?** They are field-tuned, but against ISP
   behavior at some past date. They are a starting prior for the observatory, not
   ground truth.

---

# 8. The one-sentence version

> Iranian resilience is not one technique but a **ladder of increasingly expensive
> disguises across two config classes**, plus the recognition that censorship and
> sanctions are opposite problems needing opposite routes — and Zray's advantage is
> that it climbs and descends that ladder from measured evidence, while every existing
> panel makes the user do it by hand.
