"""What a proxy benchmark is expected to cover, and where this one falls short.

Published proxy-core benchmarks exist, and reading them is how the list below was
compiled: cross-engine throughput over the transport matrix, validated payloads,
process-level CPU and RSS, paired ratio intervals, TUN and DNS workloads, geodata
routing, multiple TLS fingerprints, shaped paths, and absolute budgets for
internal work.

The entries are data rather than prose so that `test_harness.py` can hold them
against the code. A row that drifts from the matrix is a failing test rather than
a sentence nobody re-reads, and a gap that stops being a gap has to be marked as
covered before the table will pass.
"""

from __future__ import annotations

#: What a benchmark of this kind is expected to measure, and where this one stands.
#:
#: `status` is one of:
#:   `covered`      -- measured here, same idea
#:   `partial`      -- measured here, narrower than theirs
#:   `capability`   -- named and probed as a config the core can be given
#:   `not_covered`  -- not measured here, and why
XRAY_RUST_SUITE = (
    {
        "item": "VLESS over raw TCP, TLS, REALITY, Vision",
        "builds": (("vless", "raw"), ("vless", "ws"), ("vless", "grpc")),
        "suite": "standard",
        "status": "covered",
        "ours": "raw/tls/reality/vision scenarios in all three suites",
    },
    {
        "item": "WebSocket, HTTPUpgrade, gRPC, XHTTP h1/h2/h3",
        "builds": (("vless", "ws"), ("vless", "httpupgrade"), ("vless", "grpc"), ("vless", "xhttp-h1"), ("vless", "xhttp-h2"), ("vless", "xhttp-h3")),
        "suite": "standard",
        "status": "covered",
        "ours": "each transport has a config-generated scenario per security layer",
    },
    {
        "item": "Payload validated against a deterministic byte pattern",
        "suite": "standard",
        "status": "covered",
        "builds": (),
        "ours": "every byte the sink returns is checked against the keystream",
    },
    {
        "item": "Peak RSS and CPU per payload, from outside the process",
        "suite": "standard",
        "status": "covered",
        "builds": (),
        "ours": "rss_peak_mb, rss_idle_mb, cpu_s, cpu_s_per_GB, and the server's",
    },
    {
        "item": "Paired bootstrap ratio intervals",
        "suite": "extended",
        "status": "covered",
        "builds": (),
        "ours": "same construction, 4000 resamples, fixed seed",
    },
    {
        "item": "Multiple uTLS fingerprints across TLS and REALITY",
        "builds": (("vless", "raw"),),
        "suite": "extended",
        "status": "covered",
        "ours": "chrome as the baseline, plus firefox and safari rows",
    },
    {
        "item": "Hysteria2 as a client protocol",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": (
            "one core accepts a Hysteria 2 client config and the capability table "
            "records it, but no core here serves the protocol, so a transfer has "
            "no destination. A row would measure a connection that cannot complete"
        ),
    },
    {
        "item": "TUIC as a client protocol",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": (
            "a core accepts a TUIC client config and the capability table records "
            "it, but no core here serves the protocol, so a transfer has no "
            "destination -- the same position as Hysteria 2"
        ),
    },
    {
        "item": "WireGuard as a client protocol",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": (
            "the implementation available is a userspace stack whose peer must be "
            "a real WireGuard endpoint, so the same applies: nothing here can be "
            "its peer"
        ),
    },
    {
        "item": "TUN inbound workloads",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": "every scenario here drives a socks inbound; TUN needs a tun device",
    },
    {
        "item": "DNS and FakeDNS policy workloads",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": (
            "no DNS fixture and no resolver under test; the traffic is proxied "
            "TCP and UDP, so resolver selection and cache behaviour are not measured"
        ),
    },
    {
        "item": "Geodata routing latency",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": (
            "no generated config carries geodata rules, so a routing decision "
            "here never consults a dataset and its cost is not measured"
        ),
    },
    {
        "item": "A shaped WAN: bounded delay, bandwidth and loss",
        "builds": (("vless", "raw"),),
        "suite": "extended",
        "status": "partial",
        "ours": (
            "loopback only, so nothing here measures loss or round trip. A relay "
            "was built and measured in isolation -- 20 ms of configured round trip "
            "read back as 25 ms -- but under concurrent flows it throttled to a "
            "tenth of its configured rate, so it was removed rather than shipped "
            "half-right"
        ),
    },
    {
        "item": "Absolute budgets in nanoseconds for route and selector work",
        "builds": (),
        "suite": "extended",
        "status": "not_covered",
        "ours": (
            "process-level sampling cannot see inside the router's own work, so a "
            "nanosecond budget for route selection is not something this harness "
            "can state either way"
        ),
    },
)

#: What this harness measures that their suite does not.
SUPERSETS = (
    {
        "item": "A measured generator ceiling, per flow count",
        "theirs": "only relative ratios; no published generator ceiling",
    },
    {
        "item": "The baseline measured against itself",
        "theirs": "no noise floor beside each ratio",
    },
    {
        "item": "A gate against the change's own base, on every pull request",
        "theirs": "no benchmark run on a pull request",
    },
    {
        "item": "Four cores measured in one run, including this project's own",
        "theirs": "usually two or three, with this project as one of them",
    },
    {
        "item": "A capability surface: what each core cannot be configured to do",
        "theirs": "left to each config being rejected",
    },
    {
        "item": "A coverage grid drawn per link, with missing cells hatched",
        "theirs": "not present",
    },
    {
        "item": "Benchmarking a configuration supplied from outside the repo",
        "theirs": "not present",
    },
    {
        "item": "A validator that re-derives every aggregate from the raw cells",
        "theirs": "reuses the same statistics helpers it is checking",
    },
)

#: What the published evidence supports, as opposed to what it claims.
READINGS = (
    {
        "claim": (
            "a parity verdict of 'not established across all measured cases', "
            "with a third of the retained point differences outside a 3% allowance"
        ),
        "ours": (
            "consistent with what we measure, where 34 of 35 comparisons resolve "
            "to within noise at three repeats"
        ),
    },
    {
        "claim": (
            "a project's own scope table can be behind the code at the tag it "
            "documents"
        ),
        "ours": (
            "which is why support here is read from each core's own config "
            "checker rather than from its documentation -- it is how this harness "
            "found a Hysteria 2 client that the scope table did not list"
        ),
    },
    {
        "claim": "heap allocation counts are out of reach for both",
        "ours": "agreed: process-level sampling cannot compare Go and Rust allocation",
    },
)


def by_status(status: str) -> list[str]:
    return [row["item"] for row in XRAY_RUST_SUITE if row["status"] == status]


def not_covered_items() -> list[str]:
    return by_status("not_covered")
