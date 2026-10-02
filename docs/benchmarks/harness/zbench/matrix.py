"""The scenarios: what gets measured, and in which suite.

A scenario is a link (protocol / transport / security) crossed with a workload
(direction, concurrency, size) and a size on the clock. Suites are named bundles
that a command line can name, so "what will this run cost me" is answerable from
the docs.

Every `note` below describes what the row varies. None of them says what the
result should be, or which core ought to win it: the numbers are the argument,
and a note that argues for one is a note that will be quoted out of context.

The sizes are the second most-argued-about part of a loopback benchmark, so the
reasoning is written down rather than left inside a number:

* **A transfer has to outlast the ramp.** One gibibyte crosses loopback in well
  under a second on a fast machine, which is short enough for TCP window growth
  and CPU frequency scaling to weigh on the rate. The default is sized so one
  sample takes about a second, and `--bytes` overrides it.
* **Latency needs hundreds of iterations.** A freshly started core serves its
  first flow tens of milliseconds into process life, so a short run measures the
  start-up transient. The default is 1000 measured iterations after a warmup.
* **Concurrency has to reach past the scheduler.** One flow does not exercise
  how a core shards work, and 256 is where per-flow overhead stops falling off.
  Eight is the count a browser makes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .configs import Link

SMOKE = "smoke"
STANDARD = "standard"
FULL = "full"
SUITES = [SMOKE, STANDARD, FULL]

DOWN = "down"
UP = "up"
DUPLEX = "duplex"
LATENCY = "latency"
CHURN = "churn"
HOLD = "hold"
UDP = "udp-down"

#: Report order. Groups appear in this sequence everywhere.
GROUPS = [
    "baseline",
    "security",
    "transport",
    "protocol",
    "setup",
    "memory",
    "udp",
    "user",
]

_SUITE_ALL = (STANDARD, FULL)


@dataclass(frozen=True)
class Scenario:
    id: str
    link: Link
    workload: str
    group: str
    suites: tuple[str, ...]
    streams: int = 1
    bytes: int | None = None
    iterations: int | None = None
    hold_ms: int | None = None
    payload: int | None = None
    ramp_us: int | None = None
    note: str = ""

    def default_bytes(self, override: int | None) -> int:
        return override or self.bytes or 512 * 1024 * 1024

    def default_iterations(self, override: int | None) -> int:
        return override or self.iterations or 1000

    def default_payload(self) -> int:
        return self.payload or (8 if self.workload == CHURN else 1024)

    def describe(self) -> str:
        shape = {
            DOWN: f"download, {self.streams} flow(s)",
            UP: f"upload, {self.streams} flow(s)",
            DUPLEX: f"duplex, {self.streams} flow(s)",
            LATENCY: f"latency, {self.streams} flow(s)",
            CHURN: f"connect and close, {self.iterations or 1000} times",
            HOLD: f"{self.streams} flows held open",
            UDP: "UDP echo through SOCKS5 UDP ASSOCIATE",
        }[self.workload]
        return f"{self.link.describe()} - {shape}"


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


def _stream_ladder(sec: str, suites: tuple[str, ...]) -> list[Scenario]:
    """One link, four concurrency levels.

    Kept as a ladder rather than as four unrelated rows because the shape of the
    curve between the levels is the measurement: a core that is flat from 8 to
    64 flows and one that falls off are different from a core that is flat
    throughout, and a single row at one concurrency cannot tell them apart.
    """
    link = Link("vless", "raw", sec)
    levels = [
        (1, (SMOKE,) + _SUITE_ALL),
        (8, (SMOKE,) + _SUITE_ALL),
        (64, _SUITE_ALL),
        (256, (FULL,)),
    ]
    return [
        Scenario(
            f"vless-raw-{sec}-down-{n}",
            link,
            DOWN,
            "baseline",
            suite,
            streams=n,
            note=f"concurrent flows: {n}",
        )
        for n, suite in levels
    ]


def _baseline(sec: str) -> list[Scenario]:
    out = _stream_ladder(sec, _SUITE_ALL)
    link = Link("vless", "raw", sec)
    out.append(
        Scenario(
            f"vless-raw-{sec}-up-1",
            link,
            UP,
            "baseline",
            _SUITE_ALL,
            streams=1,
            note="one flow pushing; the read path is not on the critical path",
        )
    )
    out.append(
        Scenario(
            f"vless-raw-{sec}-duplex-8",
            link,
            DUPLEX,
            "baseline",
            _SUITE_ALL,
            streams=8,
            note="both directions on the same carriers at once",
        )
    )
    out.append(
        Scenario(
            f"vless-raw-{sec}-latency-1",
            link,
            LATENCY,
            "setup",
            ((SMOKE,) + _SUITE_ALL) if sec == "tls" else _SUITE_ALL,
            streams=1,
            note="1000 validated round trips after a 50-iteration warmup",
        )
    )
    out.append(
        Scenario(
            f"vless-raw-{sec}-churn",
            link,
            CHURN,
            "setup",
            _SUITE_ALL,
            iterations=2000,
            note="2000 connect-and-close cycles with an 8-byte payload",
        )
    )
    return out


def _transports() -> list[Scenario]:
    """Every transport over TLS, at eight flows.

    `raw` is deliberately absent: it is the same link, the same flow count and
    the same workload as `vless-raw-tls-down-8` in the baseline group, and two
    rows for one measurement is one row too many.
    """
    rows = [
        ("ws", "a CDN front that speaks WebSocket"),
        ("httpupgrade", "a CDN front that will not do WebSocket"),
        ("grpc", "the shape some panel generators emit"),
        ("xhttp-h1", "XHTTP over HTTP/1.1"),
        ("xhttp-h2", "XHTTP over HTTP/2 with a separate upload stream"),
        ("xhttp-h3", "XHTTP over HTTP/3"),
    ]
    return [
        Scenario(
            f"vless-{transport}-tls-down-8",
            Link("vless", transport, "tls"),
            DOWN,
            "transport",
            ((SMOKE,) if transport == "ws" else ()) + _SUITE_ALL,
            streams=8,
            note=note,
        )
        for transport, note in rows
    ]


def _protocols() -> list[Scenario]:
    """Every protocol that can carry a TCP stream to a loopback sink.

    The VLESS rows this would duplicate are the baseline group's, so the group
    holds one new measurement per protocol rather than a second copy of the
    reference.
    """
    out: list[Scenario] = []
    # VLESS over TLS at eight flows is the baseline group's
    # `vless-raw-tls-down-8`; it is not repeated here.
    for protocol, sec, note in [
        ("vmess", "tls", "AEAD; `alterId` is 0"),
        ("trojan", "tls", "password, no client identity"),
        ("shadowsocks", "tls", "AEAD ciphers"),
        ("shadowsocks2022", "tls", "SIP022 with a blake3 key derivation"),
        ("anytls", "tls", "not an Xray-core protocol"),
    ]:
        out.append(
            Scenario(
                f"{protocol}-raw-{sec}-down-8",
                Link(protocol, "raw", sec),
                DOWN,
                "protocol",
                _SUITE_ALL,
                streams=8,
                note=note,
            )
        )
    # VLESS with no security layer is the baseline group's
    # `vless-raw-none-down-8`; only the other two are new measurements.
    for protocol in ("vmess", "shadowsocks"):
        out.append(
            Scenario(
                f"{protocol}-raw-none-down-8",
                Link(protocol, "raw", "none"),
                DOWN,
                "protocol",
                _SUITE_ALL,
                streams=8,
                note="no security layer: the carrier without a cipher",
            )
        )
    return out


def _security() -> list[Scenario]:
    """Rows that differ from their baseline in exactly one setting.

    `vless-raw-reality-down-8` is not here: the baseline group already measures
    it, and a row that appears in two groups is a measurement charged twice.
    """
    return [
        # uTLS synthesises the ClientHello, and the synthesis is a per-fingerprint
        # code path with a per-fingerprint cost. Chrome is the baseline; these are
        # the ones a stack is most often tuned against.
        Scenario(
            "vless-raw-tls-firefox-down-8",
            Link("vless", "raw", "tls", fingerprint="firefox"),
            DOWN,
            "security",
            (FULL,),
            streams=8,
            note="uTLS firefox ClientHello; the comparable row is vless-raw-tls-down-8",
        ),
        Scenario(
            "vless-raw-tls-safari-down-8",
            Link("vless", "raw", "tls", fingerprint="safari"),
            DOWN,
            "security",
            (FULL,),
            streams=8,
            note="uTLS safari ClientHello; the comparable row is vless-raw-tls-down-8",
        ),
        Scenario(
            "vless-raw-reality-firefox-down-8",
            Link("vless", "raw", "reality", fingerprint="firefox"),
            DOWN,
            "security",
            (FULL,),
            streams=8,
            note="REALITY over a firefox ClientHello; the comparable row is vless-raw-reality-down-8",
        ),
        Scenario(
            "vless-raw-tls-vision-down-8",
            Link("vless", "raw", "tls", vision=True),
            DOWN,
            "security",
            (SMOKE,) + _SUITE_ALL,
            streams=8,
            note="XTLS Vision on; the comparable row is vless-raw-tls-down-8",
        ),
        Scenario(
            "vless-raw-reality-vision-down-8",
            Link("vless", "raw", "reality", vision=True),
            DOWN,
            "security",
            (SMOKE,) + _SUITE_ALL,
            streams=8,
            note="REALITY and Vision together",
        ),
        Scenario(
            "vless-raw-reality-mldsa65-down-8",
            Link("vless", "raw", "reality", mldsa=True),
            DOWN,
            "security",
            (FULL,),
            streams=8,
            note=(
                "REALITY with an ML-DSA-65 signature; the fixture key needs OpenSSL "
                "3.5 or newer and the row reports its own absence"
            ),
        ),
        Scenario(
            "vless-raw-tls-mux-down-8",
            Link("vless", "raw", "tls", mux=True),
            DOWN,
            "security",
            _SUITE_ALL,
            streams=8,
            note="eight sessions over one carrier",
        ),
    ]


def _memory() -> list[Scenario]:
    """Idle is recorded for every cell. These add the slope."""
    return [
        Scenario(
            "hold-100-flows",
            Link("vless", "raw", "tls"),
            HOLD,
            "memory",
            _SUITE_ALL,
            streams=100,
            hold_ms=5000,
            ramp_us=2000,
            note="100 flows opened, then held with no payload",
        ),
        Scenario(
            "hold-1000-flows",
            Link("vless", "raw", "tls"),
            HOLD,
            "memory",
            (SMOKE,) + _SUITE_ALL,
            streams=1000,
            hold_ms=8000,
            ramp_us=2000,
            note="1000 flows opened over a 2 s ramp, then held",
        ),
        Scenario(
            "hold-5000-flows",
            Link("vless", "raw", "tls"),
            HOLD,
            "memory",
            (FULL,),
            streams=5000,
            hold_ms=10000,
            ramp_us=2000,
            note="5000 flows; per-flow state is visible at this scale",
        ),
    ]


def _udp() -> list[Scenario]:
    return [
        Scenario(
            "vless-raw-tls-udp-latency",
            Link("vless", "raw", "tls"),
            UDP,
            "udp",
            (FULL,),
            iterations=500,
            note="SOCKS5 UDP ASSOCIATE carried over VLESS",
        ),
        Scenario(
            "vmess-raw-tls-udp-latency",
            Link("vmess", "raw", "tls"),
            UDP,
            "udp",
            (FULL,),
            iterations=500,
            note="SOCKS5 UDP ASSOCIATE carried over VMess",
        ),
    ]


def all_scenarios() -> list[Scenario]:
    out: list[Scenario] = []
    out += _baseline("none")
    out += _baseline("tls")
    out += _baseline("reality")
    out += _transports()
    out += _protocols()
    out += _security()
    out += _memory()
    out += _udp()
    return out


def select(
    suite: str = STANDARD,
    *,
    only: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Scenario]:
    if suite not in SUITES:
        raise SystemExit(f"unknown suite {suite!r}; choose one of {', '.join(SUITES)}")
    chosen = [s for s in all_scenarios() if suite in s.suites]
    if only:
        chosen = [s for s in chosen if any(p in s.id for p in only)]
    if exclude:
        chosen = [s for s in chosen if not any(p in s.id for p in exclude)]
    # Stable order: grouping by link afterwards depends on it, and a matrix that
    # reorders itself between runs is impossible to diff.
    return sorted(chosen, key=lambda s: (s.link.name(), s.id))


def links_in(scenarios: list[Scenario]) -> list[Link]:
    """The distinct links, in first-seen order.

    Grouping by link is what lets one server process serve every core's samples
    for the same connection type, which is what keeps the client the only thing
    that varies.
    """
    seen: list[Link] = []
    for scenario in scenarios:
        if scenario.link not in seen:
            seen.append(scenario.link)
    return seen
