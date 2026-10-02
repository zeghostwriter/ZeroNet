"""What each core can do, and why a cell in the matrix is empty.

This module is the single place that decides whether a (core, scenario) pair is
attempted, skipped, or reported as a failure. Keeping it declarative and
separate from the runner is the point: a benchmark that quietly omits a
combination is worse than one that refuses to run it, because the omission
reads as "they were equal and it did not matter".

Two different things live here, and they must not be confused:

* `Core` describes what a core can be *configured* to do. It drives what the
  harness attempts.
* `FEATURES` describes what each project *documents* at a pinned version,
  across areas a loopback benchmark cannot exercise -- SSH, NaiveProxy,
  Snell, Tor, routed inbounds, Linux gateway features. It drives the published
  comparison table, and it is the only place the answer to "what does sing-box
  have that we do not" is written down.

Every claim names the version it describes. `PINS` records which. When a pin
moves, the capability data is re-checked rather than assumed.

`notes` are load-bearing rather than decorative: they are the reasons a core is
skipped, and they are copied verbatim into the report so a reader can tell a
structural boundary from a bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Version pins
# ---------------------------------------------------------------------------
#
# A benchmark result is only interpretable next to the exact binaries it came
# from. These are the versions the tables below describe; the runner records
# the version string and SHA-256 of whatever binary it actually used, so a
# mismatch between the two shows up in the report instead of going unnoticed.

#: The base core is Zray built from a ref rather than from the workspace, so it
#: has no version of its own. The pin exists so that every core in `ALL_CORES`
#: resolves, and its `note` is what says why.
BASE_ID = "zray-base"

PINS = {
    "xray": {
        "project": "Xray-core",
        "repo": "https://github.com/XTLS/Xray-core",
        "version": "v26.3.27",
        "note": "last release with full release notes; later tags are prereleases",
        "asset": "Xray-linux-64.zip",
    },
    "singbox": {
        "project": "sing-box",
        "repo": "https://github.com/SagerNet/sing-box",
        "version": "1.14.2",
        "note": "current stable line; a 1.15.0 alpha is in progress",
        "asset": "sing-box-1.14.2-linux-amd64.tar.gz",
    },
    "xray-rust": {
        "project": "xray-rust",
        "repo": "https://github.com/aimalygin/xray-rust",
        "version": "v0.7.0",
        "note": "source only; no prebuilt binaries are published",
        "asset": None,
    },
    "zray": {
        "project": "Zray (this workspace)",
        "repo": "https://github.com/zeghostwriter/ZeroNet",
        "version": "0.1.0",
        "note": "built from the checkout under test",
        "asset": None,
    },
    BASE_ID: {
        "project": "Zray (base commit)",
        "repo": "https://github.com/zeghostwriter/ZeroNet",
        "version": "from --base-ref",
        "note": "the same core built from the ref a change is measured against",
        "asset": None,
    },
}

# Transport names as they appear in a scenario. `raw` is Xray's current spelling
# of the transport that older configs call `tcp`.
RAW = "raw"

# Protocol names as they appear in a scenario, chosen to match the Xray
# `protocol` key where one exists, because the harness reads like the configs it
# generates.
PROTOCOLS = [
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "shadowsocks2022",
    "anytls",
    "hysteria2",
    "tuic",
]

TRANSPORTS = [RAW, "ws", "httpupgrade", "grpc", "xhttp-h1", "xhttp-h2", "xhttp-h3"]

SECURITIES = ["none", "tls", "reality"]


@dataclass(frozen=True)
class Core:
    """One proxy core the harness can drive."""

    id: str
    label: str
    language: str
    dialect: str
    """`xray` if this core reads Xray JSON verbatim, `singbox` otherwise."""
    cli: str
    """Which command line this core speaks. Not the same thing as the dialect:
    Xray-core and xray-rust both read Xray JSON and are invoked differently
    (`run -c` against `run -config`). Every core has to name one, because
    dispatching on the id means a new core fails at run time with "no run
    command known" instead of at start-up."""
    client_protocols: frozenset[str]
    server_protocols: frozenset[str]
    transports: frozenset[str]
    securities: frozenset[str]
    vision: bool
    mux: bool
    udp: bool
    """Whether the core can carry a SOCKS5 UDP ASSOCIATE through a proxy
    outbound. Distinct from whether it can *originate* UDP."""
    can_serve: bool
    """False when the core has no server-side listener at all."""
    version_arg: tuple[str, ...]
    client_ca: bool = True
    """Whether a TLS client can be given a private CA to trust.

    Separate from `securities` on purpose. Being able to speak TLS and being
    able to be told which certificate authority to trust are different
    abilities, and this harness's TLS fixtures are signed by a private CA, so a
    core without this cannot connect to any of them -- no matter how complete
    its TLS support otherwise is. Claiming the TLS layer and then failing every
    TLS cell is a wrong capability table, not a benchmark result.
    """
    notes: dict[str, str] = field(default_factory=dict)

    def why_not(self, protocol: str, transport: str, security: str) -> str | None:
        """Why this core cannot run the cell, or None when it can.

        The order matters: a reader wants the first reason, not the last check
        that happened to fail.
        """
        if protocol not in self.client_protocols:
            return f"no {protocol} client"
        if transport not in self.transports:
            return f"no {transport} transport"
        if security not in self.securities:
            return f"no {security} layer"
        if security == "tls" and not self.client_ca:
            return (
                "no way to trust a private CA, so it cannot connect to a "
                "certificate this harness generates"
            )
        return None

    def why_not_server(self, protocol: str, transport: str, security: str) -> str | None:
        """Why this core cannot *serve* the cell."""
        if not self.can_serve:
            return "no server-side listener in this core"
        if protocol not in self.server_protocols:
            return f"no {protocol} inbound"
        if transport not in self.transports:
            return f"no {transport} transport on an inbound"
        if security not in self.securities:
            return f"no {security} layer on an inbound"
        return None


# ---------------------------------------------------------------------------
# The cores
# ---------------------------------------------------------------------------

ZRAY = Core(
    id="zray",
    label="Zray (ZeroNet)",
    language="Rust",
    dialect="xray",
    cli="zray",
    client_protocols=frozenset(
        {
            "vless",
            "vmess",
            "trojan",
            "shadowsocks",
            "shadowsocks2022",
            "anytls",
            "hysteria2",
            "tuic",
            "freedom",
        }
    ),
    server_protocols=frozenset(
        {
            "vless",
            "vmess",
            "trojan",
            "shadowsocks",
            "shadowsocks2022",
            "anytls",
            "hysteria2",
            "tuic",
            "socks",
        }
    ),
    transports=frozenset(TRANSPORTS),
    securities=frozenset(SECURITIES),
    vision=True,
    # `mux.enabled` is VLESS-only, is refused together with Vision, and is not
    # Xray's `muxcool` with its XUDP concurrency settings.
    mux=True,
    udp=True,
    can_serve=True,
    version_arg=("version",),
    notes={
        "allowInsecure": (
            "`allowInsecure: true` is a parse error rather than a warning. A private "
            "CA is supplied with `tlsSettings.certificates` and `usage: \"verify\"`."
        ),
        "alterId": "`alterId != 0` is a parse error; VMess is AEAD only.",
        "muxcool": (
            "`mux.cool`, `xudpConcurrency` and `xudpProxyUDP443` are not parsed, so "
            "the `xudpProxyUDP443` values `allow` and `skip` cannot be selected."
        ),
        "transports": (
            "`kcp`/`mkcp` are not implemented, and `quic` and `h2` are not accepted "
            "as transports. HTTP/2 and HTTP/3 exist only as XHTTP carriers."
        ),
        "packetencoding": "`packetEncoding` (`none`/`packetaddr`/`xudp`) is not parsed.",
        "beyond_xray": (
            "Not in Xray-core: ECH client configuration, `mldsa65Verify` "
            "post-quantum REALITY, VLESS Encryption (ML-KEM-768 with X25519), "
            "`finalmask` TCP fragmentation and UDP noise, Hysteria 2 and TUIC "
            "inbounds, Cloudflare MASQUE, and AmneziaWG."
        ),
        "not_in_zray": (
            "Not implemented: `kcp`, `quic`, `h2` as standalone transports, "
            "`packetEncoding`, `muxcool`, SSH, ShadowTLS, Snell, NaiveProxy, Tor, "
            "SniffTLS, and the `gost`/`sudoku`/`xmux`/`xudp` variants that appear in "
            "some panel generators."
        ),
    },
)

XRAY = Core(
    id="xray",
    label="Xray-core",
    language="Go",
    dialect="xray",
    cli="xray",
    client_protocols=frozenset(
        {"vless", "vmess", "trojan", "shadowsocks", "shadowsocks2022", "freedom"}
    ),
    server_protocols=frozenset(
        {"vless", "vmess", "trojan", "shadowsocks", "shadowsocks2022", "socks"}
    ),
    transports=frozenset(
        # `kcp` exists upstream and is absent here on purpose: the matrix covers
        # the transports a current configuration is likely to name.
        {RAW, "ws", "httpupgrade", "grpc", "xhttp-h1", "xhttp-h2", "xhttp-h3"}
    ),
    securities=frozenset(SECURITIES),
    vision=True,
    mux=True,
    udp=True,
    can_serve=True,
    version_arg=("version",),
    notes={
        "transports": (
            "Current prereleases report `h2`/`http` and `quic` as removed features and "
            "deprecate `ws`, `httpupgrade` and `grpc` in favour of XHTTP. `kcp` still "
            "works and is not measured here."
        ),
        "protocols": (
            "No `anytls`, `ssh`, `tuic`, `shadowtls`, `naive`, `snell` or `tor` "
            "protocol in either direction."
        ),
        "reality": (
            "REALITY is accepted only on raw, XHTTP and gRPC. A REALITY server also "
            "rejects clients outside `minClientVer`/`maxClientVer`, and the default "
            "lower bound is the current Xray version; the generated fixture widens "
            "both bounds so the rows measure capability rather than version strings."
        ),
        "beyond_zray": (
            "Not in Zray: `kcp`, `packetEncoding` with `xudpProxyUDP443`, the "
            "`finalmask` UDP mask family (`sudoku`, `salamander`, `realm`, `xdns`, "
            "`xicmp`, `mkcp-legacy`), the XDRIVE transport, a MASQUE inbound and "
            "outbound, `xhttpSettings.sessionIDTable`, and "
            "`sockopt.trustedXForwardedFor`."
        ),
    },
)

SINGBOX = Core(
    id="singbox",
    label="sing-box",
    language="Go",
    dialect="singbox",
    cli="singbox",
    client_protocols=frozenset(
        {
            "vless",
            "vmess",
            "trojan",
            "shadowsocks",
            "shadowsocks2022",
            "anytls",
            "hysteria2",
            "tuic",
        }
    ),
    server_protocols=frozenset(
        {
            "vless",
            "vmess",
            "trojan",
            "shadowsocks",
            "shadowsocks2022",
            "anytls",
            "hysteria2",
            "tuic",
            "socks",
        }
    ),
    # `raw` is the absence of a transport block in sing-box, which is why plain
    # TCP is the one transport it can serve everywhere.
    transports=frozenset({RAW, "ws", "httpupgrade", "grpc"}),
    securities=frozenset(SECURITIES),
    vision=True,
    # h2mux / smux / yamux, plus Brutal, which no other core here offers.
    mux=True,
    udp=True,
    can_serve=True,
    version_arg=("version",),
    notes={
        "transports": (
            "Five v2ray transports only: ws, httpupgrade, grpc, http (h2) and a `quic` "
            "block with no options. There is no XHTTP and no mKCP."
        ),
        "reality": (
            "No `mldsa65`. Post-quantum is limited to the X25519MLKEM768 curve and the "
            "`chrome_pq*` uTLS fingerprints."
        ),
        "tls_trust": (
            "A sing-box client cannot be given a private CA, so the generated client "
            "uses `insecure: true` against a loopback-only certificate. Zray and "
            "Xray-core verify the chain instead, so the TLS rows compare everything "
            "except certificate verification."
        ),
        "multiplex": "`multiplex.brutal` has no equivalent in the other cores here.",
        "beyond_zray": (
            "Not in Zray: `ssh`, `shadowtls` v3, `snell`, `naive`, `tor`, `cloudflared`, "
            "`tailcat`, `openconnect`, `openvpn-client`, an HTTP/2 transport, a `quic` "
            "transport, multiplex protocol selection, multiplex Brutal, TLS ClientHello "
            "spoofing (`tls.spoof_method`), a TUN `stack` selection, a `redirect` and "
            "`tproxy` inbound, `bridge`, the gRPC API service and dashboard, network "
            "namespaces, and a MASQUE endpoint."
        ),
    },
)

XRAY_RUST = Core(
    id="xray-rust",
    label="xray-rust",
    language="Rust",
    dialect="xray",
    cli="xray-rust",
    client_protocols=frozenset({"vless", "hysteria2"}),
    # Its inbounds are socks, http and tun. There is no server mode, so it can
    # only ever be the client in this harness.
    server_protocols=frozenset(),
    transports=frozenset(
        {RAW, "ws", "httpupgrade", "grpc", "xhttp-h1", "xhttp-h2", "xhttp-h3"}
    ),
    securities=frozenset(SECURITIES),
    vision=True,
    # Mux is an unmerged pull request at the pinned version.
    mux=False,
    udp=True,
    can_serve=False,
    version_arg=("config", "check"),
    # Its TLS config has no `certificates` field: a client cannot be given a
    # trust anchor, so it rejects every TLS fixture this harness builds. Observed
    # on CI as `tlsSettings.certificates: unsupported field 'certificates'`.
    client_ca=False,
    notes={
        "server": (
            "No server mode exists. `InboundProtocol` is socks/http/tun and "
            "server-side VLESS is a stated non-goal, so this core is only ever "
            "measured as a client against another core's server."
        ),
        "protocols": (
            "VLESS, Hysteria 2 and a bounded WireGuard client at v0.7.0. No VMess, "
            "Trojan, Shadowsocks or Shadowsocks-2022: those are an unmerged pull "
            "request. The README scope table was not refreshed for v0.7 and still "
            "lists WireGuard as unsupported."
        ),
        "transports": (
            "HTTP/2 and QUIC exist only as XHTTP's wire engines, not as standalone "
            "`network: \"h2\"` or `\"quic\"` transports. mKCP is a stated non-goal."
        ),
        "mux": "`mux.enabled` is rejected; mux is not implemented at this version.",
        "trust": (
            "The TLS client config has no `certificates` field, so a client "
            "cannot be given a CA to trust and rejects every fixture signed by a "
            "private CA. REALITY does work, because REALITY authenticates the "
            "server with its own key pair rather than with a certificate chain."
        ),
        "build": (
            "Built from a pinned tag because no binaries are published. The build "
            "depends on a git-pinned `shaped-rustls` fork and a vendored quinn, "
            "smoltcp, blake3 and h3-quinn, so it needs more disk than a small runner "
            "has."
        ),
        "audit": (
            "No independent security audit, and every version below 1.0 is explicitly "
            "pre-1.0 in API and security maturity. Its own published parity report for "
            "v0.7 concludes the comparison is 'not established across all measured cases'."
        ),
    },
)

#: The same core built from a different commit. Present only when a run is asked
#: to build one, because the question a pull request asks is "did this change move
#: the number", and the only comparison that answers it is the same core from the
#: commit the change is measured against. A five-line diff to a buffer copy cannot
#: move a core-versus-core ratio in either direction, so a regression hides inside
#: the difference between two projects.
ZRAY_BASE = Core(
    id=BASE_ID,
    label="Zray (base commit)",
    language="Rust",
    dialect="xray",
    # The same command line as the candidate: the two binaries have to differ in
    # exactly one thing, and that thing is the commit.
    cli=ZRAY.cli,
    client_protocols=ZRAY.client_protocols,
    server_protocols=ZRAY.server_protocols,
    transports=ZRAY.transports,
    securities=ZRAY.securities,
    client_ca=ZRAY.client_ca,
    vision=ZRAY.vision,
    mux=ZRAY.mux,
    udp=ZRAY.udp,
    can_serve=True,
    version_arg=ZRAY.version_arg,
    notes={
        "purpose": (
            "The candidate's own baseline: the same core, the same profile and the "
            "same toolchain, built from the ref passed as `--base-ref`."
        ),
        "build": (
            "Built in a detached worktree with its own target directory. Sharing a "
            "target between two checkouts reuses same-package fingerprints when "
            "source timestamps precede a previous build, and then the \"base\" is "
            "the candidate."
        ),
    },
)

#: The command lines the harness knows how to drive. A `Core` outside this set
#: cannot be started or validated, and the self-test fails on that rather than a
#: run failing fifty cells later.
KNOWN_CLIS = ("zray", "xray", "xray-rust", "singbox")

ALL_CORES = {c.id: c for c in (ZRAY, XRAY, SINGBOX, XRAY_RUST, ZRAY_BASE)}
DEFAULT_CORES = ["zray", "xray", "singbox", "xray-rust"]
#: What a pull request run compares: its own build, then the four projects for
#: context, with the base first so it is the baseline every ratio is against.
PR_CORES = [BASE_ID, "zray", "xray", "singbox", "xray-rust"]


def get(core_id: str) -> Core:
    try:
        return ALL_CORES[core_id]
    except KeyError:
        raise SystemExit(
            f"unknown core {core_id!r}; known cores: {', '.join(sorted(ALL_CORES))}"
        ) from None


# ---------------------------------------------------------------------------
# The published comparison table
# ---------------------------------------------------------------------------
#
# `yes` / `no` / `partial` / `deprecated` / `removed` / `alpha` / `n-a`.
# These describe what each project can be *configured* to do at the pinned
# version, which is a different and much larger question than what a
# process-per-core loopback benchmark can exercise. The `note` column carries the
# citation or the reason, so a reader can check any single cell.

@dataclass(frozen=True)
class FeatureRow:
    area: str
    feature: str
    zray: str
    xray: str
    singbox: str
    xray_rust: str
    note: str = ""


FEATURES: list[FeatureRow] = [
    # -- proxy protocols, client side ---------------------------------------
    FeatureRow("Client protocol", "VLESS", "yes", "yes", "yes", "yes"),
    FeatureRow("Client protocol", "VLESS Encryption (ML-KEM-768 + X25519)", "yes", "yes", "no", "yes"),
    FeatureRow("Client protocol", "VMess (AEAD)", "yes", "yes", "yes", "no"),
    FeatureRow("Client protocol", "Trojan", "yes", "yes", "yes", "no"),
    FeatureRow("Client protocol", "Shadowsocks (AEAD)", "yes", "yes", "yes", "no"),
    FeatureRow("Client protocol", "Shadowsocks 2022 (SIP022)", "yes", "yes", "yes", "no"),
    FeatureRow("Client protocol", "Shadowsocks plugins (obfs, v2ray-plugin)", "no", "yes", "no", "no",
               "SS plugin support exists upstream in Xray-core; the other three have none"),
    FeatureRow("Client protocol", "AnyTLS", "yes", "no", "yes", "no"),
    FeatureRow("Client protocol", "Hysteria 2", "yes", "partial", "yes", "yes",
               "Xray-core carries Hysteria v1 and a Hysteria 2 transport; sing-box and Zray carry the protocol"),
    FeatureRow("Client protocol", "Hysteria v1", "no", "yes", "yes", "no"),
    FeatureRow("Client protocol", "TUIC v5", "yes", "no", "yes", "no"),
    FeatureRow("Client protocol", "SSH", "no", "no", "yes", "no"),
    FeatureRow("Client protocol", "ShadowTLS v3", "no", "no", "yes", "no"),
    FeatureRow("Client protocol", "NaiveProxy", "no", "no", "yes", "no"),
    FeatureRow("Client protocol", "Snell", "no", "no", "yes", "no"),
    FeatureRow("Client protocol", "Tor", "no", "no", "yes", "no"),
    FeatureRow("Client protocol", "Cloudflared", "no", "no", "yes", "no"),
    FeatureRow("Client protocol", "WireGuard", "yes (AmneziaWG)", "yes", "yes (endpoint)", "yes (bounded)"),
    FeatureRow("Client protocol", "MASQUE (CONNECT-IP)", "yes (WARP route)", "prerelease", "alpha", "no",
               "Xray-core's MASQUE inbound and outbound are on `main`, not in the pinned release"),
    FeatureRow("Client protocol", "SOCKS / HTTP proxy chain", "no", "yes", "yes", "no",
               "Zray resolves upstream proxies from the environment instead of the config"),
    # -- server side ---------------------------------------------------------
    FeatureRow("Server protocol", "SOCKS / mixed inbound", "yes", "yes", "yes", "yes (socks)"),
    FeatureRow("Server protocol", "HTTP inbound", "yes", "yes", "yes", "yes"),
    FeatureRow("Server protocol", "Dokodemo-door", "yes", "yes", "no", "no",
               "sing-box uses `redirect` and `tproxy` inbound types instead"),
    FeatureRow("Server protocol", "redirect / tproxy inbound", "no", "no", "yes", "no",
               "Xray does transparent proxying with dokodemo-door plus `sockopt.tproxy`"),
    FeatureRow("Server protocol", "TUN inbound", "yes", "yes", "yes", "yes (fd)"),
    FeatureRow("Server protocol", "VLESS inbound", "yes", "yes", "yes", "no"),
    FeatureRow("Server protocol", "Trojan / VMess / SS inbound", "yes", "yes", "yes", "no"),
    FeatureRow("Server protocol", "AnyTLS inbound", "yes", "no", "yes", "no"),
    FeatureRow("Server protocol", "Hysteria 2 inbound", "yes", "partial", "yes", "no"),
    FeatureRow("Server protocol", "TUIC inbound", "yes", "no", "yes", "no"),
    FeatureRow("Server protocol", "Reverse proxy / bridge", "no", "yes", "yes (bridge)", "no"),
    # -- transports ----------------------------------------------------------
    FeatureRow("Transport", "raw (tcp)", "yes", "yes", "yes", "yes"),
    FeatureRow("Transport", "WebSocket", "yes", "deprecated", "yes", "yes",
               "Xray-core deprecates ws in favour of XHTTP over H2 and H3"),
    FeatureRow("Transport", "HTTPUpgrade", "yes", "deprecated", "yes", "yes"),
    FeatureRow("Transport", "gRPC", "yes", "deprecated", "yes", "yes"),
    FeatureRow("Transport", "XHTTP over HTTP/1.1", "yes", "yes", "no", "yes"),
    FeatureRow("Transport", "XHTTP over HTTP/2", "yes", "yes", "no", "yes"),
    FeatureRow("Transport", "XHTTP over HTTP/3", "yes", "yes", "no", "yes"),
    FeatureRow("Transport", "HTTP/2 as a transport", "no", "removed", "yes (`http`)", "no",
               "Xray-core reports `h2`/`http` as a removed feature"),
    FeatureRow("Transport", "QUIC as a transport", "no", "removed", "empty block", "no"),
    FeatureRow("Transport", "mKCP", "no", "yes", "no", "no"),
    FeatureRow("Transport", "XDRIVE", "no", "prerelease", "no", "no"),
    # -- security ------------------------------------------------------------
    FeatureRow("Security", "none / TLS", "yes", "yes", "yes", "yes"),
    FeatureRow("Security", "REALITY", "yes", "yes (raw/xhttp/grpc)", "yes", "yes"),
    FeatureRow("Security", "REALITY ML-DSA-65 signatures", "yes", "yes", "no", "yes"),
    FeatureRow("Security", "ML-KEM-768 hybrid key exchange", "yes", "yes", "yes", "yes"),
    FeatureRow("Security", "XTLS Vision", "yes", "yes", "yes", "yes"),
    FeatureRow("Security", "ECH", "yes (client)", "yes", "yes (no PQ sigs)", "yes"),
    FeatureRow("Security", "Client certificate pinning by SHA-256", "no", "yes", "yes", "yes",
               "Zray's pinning is a private CA in `tlsSettings.certificates`, not a pin"),
    FeatureRow("Security", "ClientHello fragmentation", "yes (`finalmask`)", "yes (`finalmask`)", "yes (`tls.fragment`)", "no"),
    FeatureRow("Security", "ClientHello spoofing", "no", "no", "yes", "no",
               "sing-box 1.14 `tls.spoof_method`: wrong-sequence, wrong-checksum, wrong-ack, wrong-md5"),
    FeatureRow("Security", "Private CA for a client", "yes", "yes", "no", "no",
               "sing-box has no client CA option; the harness uses `insecure` there"),
    # -- proxy features ------------------------------------------------------
    FeatureRow("Proxy feature", "Mux", "yes (not `muxcool`)", "yes (XUDP)", "yes (h2mux/smux/yamux)", "no"),
    FeatureRow("Proxy feature", "Mux Brutal", "no", "no", "yes", "no"),
    FeatureRow("Proxy feature", "`packetEncoding`", "no", "yes", "n-a", "n-a"),
    FeatureRow("Proxy feature", "`xudpProxyUDP443`", "no", "yes", "n-a", "n-a"),
    FeatureRow("Proxy feature", "SOCKS5 UDP ASSOCIATE through a proxy", "yes", "yes", "yes", "yes"),
    FeatureRow("Proxy feature", "Outbound chaining (`dialerProxy` / `detour`)", "yes (dialerProxy)", "yes (dialerProxy)", "yes (detour)", "partial (TCP only)"),
    FeatureRow("Proxy feature", "Health checking / balancer", "yes", "yes (observatory)", "yes (urltest)", "partial"),
    # -- platform ------------------------------------------------------------
    FeatureRow("Platform", "Routing rules", "yes", "yes", "yes (rule-set)", "yes"),
    FeatureRow("Platform", "Geodata (`.dat`)", "yes", "yes", "no (`.srs`)", "yes"),
    FeatureRow("Platform", "FakeDNS", "yes", "yes", "yes", "yes"),
    FeatureRow("Platform", "Sniffing", "yes", "yes", "yes", "partial"),
    FeatureRow("Platform", "TUN stack selection", "no (fixed smoltcp)", "yes", "yes (deprecated 1.15)", "no"),
    FeatureRow("Platform", "Management API", "yes (HTTP)", "yes (gRPC)", "yes (gRPC + HTTP)", "yes (C ABI)"),
    FeatureRow("Platform", "Independent security audit", "yes (in this repository)", "no stated", "no stated", "no"),
]


def feature_value(row: FeatureRow, core_id: str) -> str:
    return {
        "zray": row.zray,
        "xray": row.xray,
        "singbox": row.singbox,
        "xray-rust": row.xray_rust,
    }[core_id]


#: How a cell is drawn in the comparison charts. The order is the order of
#: severity, so a reader scanning the legend learns the scale.
SCALE = [
    ("yes", 1.00),
    ("partial", 0.72),
    ("deprecated", 0.55),
    ("alpha", 0.45),
    ("prerelease", 0.38),
    ("removed", 0.16),
    ("empty block", 0.10),
    ("no", 0.0),
]


#: Phrases that mean "the answer is not stated", which is not the same as "no".
#: They get their own value because charting an unstated answer at zero asserts
#: the absence of the feature -- the markdown table says only that nothing was
#: written down.
UNSTATED = 0.06


def scale_value(text: str) -> float:
    """A phrase to its position on the capability scale.

    The phrase is matched whole. Splitting on the first space turned "empty block"
    into "empty", which is not on the scale, and the fallback is zero -- so a stub
    was charted as absent, and "no stated" was charted as "no".
    """
    head = text.split("(")[0].strip().lower()
    for name, value in SCALE:
        if head == name:
            return value
    if "n/a" in head or head in ("n-a", "unknown", "-"):
        return UNSTATED
    if head.startswith("no stated") or head.startswith("not stated"):
        return UNSTATED
    # Anything unrecognised is unstated rather than zero, for the same reason.
    return UNSTATED


def project_cores() -> list[str]:
    """The four separate projects.

    `zray-base` is excluded: it is a build of this project from another commit,
    not a project, so it has no capability of its own to tabulate. Its support
    for a connection type is the candidate's, and the run's own coverage table
    shows that.
    """
    return [c for c in DEFAULT_CORES if c in ALL_CORES]


def feature_areas() -> list[str]:
    seen: list[str] = []
    for row in FEATURES:
        if row.area not in seen:
            seen.append(row.area)
    return seen
