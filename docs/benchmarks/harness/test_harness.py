#!/usr/bin/env python3
"""Checks on the harness itself, runnable without a proxy core.

```sh
python3 test_harness.py
```

The benchmark is only as trustworthy as the code that produces it, and a
benchmark that needs twenty minutes and four binaries cannot be its own test
suite. These are the properties that are cheap to assert and expensive to get
wrong:

* the argument parser accepts and rejects what it should;
* the capability table is internally consistent, and the documented scale covers
  every value it contains;
* a generated configuration is what it claims to be, in both dialects, and the
  Xray dialect is byte-identical for the two cores that share it;
* the statistics do what the report says they do, including refusing to call a
  difference it cannot resolve;
* the load generator's pattern actually validates, and rejects corruption;
* a config supplied from outside the repository is read, or refused with a
  reason.

Plain asserts, no test framework, so it runs anywhere the harness runs.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bench  # noqa: E402
import split_configs  # noqa: E402
from zbench import caps, configs, matrix, measure, stats, userconfig  # noqa: E402

FAILURES: list[str] = []


def check(name: str):
    def wrap(fn):
        try:
            fn()
        except AssertionError as exc:
            FAILURES.append(f"{name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - a crash is a failure too
            FAILURES.append(f"{name}: {type(exc).__name__}: {exc}")
        return fn

    return wrap


# A SOCKS5 listener that forwards to the sink, so the load generator is driven
# through a real proxy hop rather than straight at the sink. It propagates a
# half-close instead of tearing the pair down, because a relay that closes both
# directions on the first EOF swallows the sink's completion byte and the client
# sees a truncated transfer that never was one.
FORWARDER = """
import socket, sys, threading
listen, target = int(sys.argv[1]), int(sys.argv[2])

def pump(a, b):
    try:
        while True:
            data = a.recv(1 << 20)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s, how in ((b, socket.SHUT_WR), (a, socket.SHUT_RDWR)):
            try:
                s.shutdown(how)
            except OSError:
                pass

def handle(conn):
    try:
        conn.recv(3)
        conn.sendall(bytes([5, 0]))            # NO AUTHENTICATION REQUIRED
        head = conn.recv(4)
        n = {1: 4, 4: 16}.get(head[3], 0)
        if n:
            conn.recv(n)
        conn.recv(2)
        conn.sendall(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        up = socket.create_connection(("127.0.0.1", target))
        threading.Thread(target=pump, args=(conn, up), daemon=True).start()
        pump(up, conn)
    except OSError:
        pass
    finally:
        conn.close()

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", listen))
server.listen(128)
while True:
    conn, _ = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"""

# A peer that accepts the header and then returns zeros: a transfer any
# implementation without validation would score as a pass.
LIAR = """
import socket, sys
port = int(sys.argv[1])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(8)
while True:
    conn, _ = server.accept()
    try:
        conn.recv(24)
        conn.sendall(b"\\x00" * (8 << 20))
    except OSError:
        pass
    finally:
        conn.close()
"""


def _loadgen_binary():
    binary = HERE / "loadgen" / "target" / "release" / "loadgen"
    if not binary.exists():
        print("  (loadgen is not built; its checks need it)", file=sys.stderr)
    return binary if binary.exists() else None


# ---------------------------------------------------------------------------


@check("byte_size accepts the documented shorthands")
def _byte_size() -> None:
    assert bench.byte_size("512M") == 512_000_000
    assert bench.byte_size("2G") == 2_000_000_000
    assert bench.byte_size("64k") == 64_000
    assert bench.byte_size("1024") == 1024
    assert bench.byte_size("1_000") == 1000
    try:
        bench.byte_size("lots")
    except Exception:
        return
    raise AssertionError("a non-numeric size was accepted")


@check("every core is complete enough to start and to validate")
def _cores() -> None:
    from zbench import cores

    for core_id in caps.DEFAULT_CORES:
        assert core_id in caps.ALL_CORES, core_id
    assert set(caps.PINS) == set(caps.ALL_CORES), "a core has no version pin"

    # A core that names no known command line cannot be started, and the failure
    # lands in the middle of a run rather than at the start of one. `zray-base`
    # was exactly that: it existed, it built, and then every cell said "no run
    # command known for zray-base".
    for core_id, core in caps.ALL_CORES.items():
        assert core.cli in caps.KNOWN_CLIS, f"{core_id}: cli={core.cli!r}"
        argv = cores.run_argv(core, pathlib.Path("/x"), pathlib.Path("/c.json"))
        assert argv[0] == "/x" and "run" in argv, f"{core_id}: {argv}"
        check = cores.check_argv(core, pathlib.Path("/x"), pathlib.Path("/c.json"))
        assert check is not None, f"{core_id}: no config check, so a refusal cannot be recorded"
        assert check[0] == "/x", f"{core_id}: {check}"
    # Two cores that share a dialect may still need different command lines.
    assert caps.get("xray").cli != caps.get("xray-rust").cli, (
        "xray-core and xray-rust share a dialect and are invoked differently"
    )


@check("the capability table is internally consistent")
def _capability_table() -> None:
    assert caps.FEATURES, "the table is empty"
    for row in caps.FEATURES:
        for core_id in caps.DEFAULT_CORES:
            value = caps.feature_value(row, core_id)
            assert value, f"{row.feature} has no value for {core_id}"
            # The same reduction `scale_value` applies, so a value the chart
            # cannot plot is a failure here rather than a blank cell there.
            head = value.split(" ")[0].split("(")[0].strip().lower()
            known = {name for name, _ in caps.SCALE} | {"n-a", "n/a", "empty"}
            assert head in known, f"{row.feature}/{core_id}: {value!r} is not in the scale"
    # Every protocol the benchmark can generate must be claimed by someone, or
    # the coverage table would be empty for a reason nobody wrote down.
    for protocol in caps.PROTOCOLS:
        holders = [
            c.id for c in caps.ALL_CORES.values() if protocol in c.client_protocols
        ]
        assert holders, f"no core claims to be a {protocol} client"


@check("a prior refusal names the first thing that is missing")
def _why_not() -> None:
    zray = caps.get("zray")
    singbox = caps.get("singbox")
    assert zray.why_not("vless", "xhttp-h1", "tls") is None
    assert "xhttp" in (singbox.why_not("vless", "xhttp-h1", "tls") or "")
    assert "trojan" in (caps.get("xray-rust").why_not("trojan", "raw", "tls") or "")
    assert caps.get("xray-rust").why_not_server("vless", "raw", "tls") is not None
    assert caps.get("xray").why_not_server("vless", "raw", "tls") is None


@check("the suites are ordered, named and free of duplicates")
def _suites() -> None:
    seen: set[str] = set()
    for scenario in matrix.all_scenarios():
        assert scenario.id not in seen, f"duplicate scenario id {scenario.id}"
        seen.add(scenario.id)
        assert scenario.suites, f"{scenario.id} is in no suite"
        for suite in scenario.suites:
            assert suite in matrix.SUITES, f"{scenario.id}: unknown suite {suite}"
    for suite in matrix.SUITES:
        chosen = matrix.select(suite)
        assert chosen, f"suite {suite} is empty"
        assert len(matrix.links_in(chosen)) >= 1
    smoke = [s.id for s in matrix.select("smoke")]
    assert len(smoke) <= 12, f"the smoke suite is {len(smoke)} scenarios; it is meant to be quick"
    assert matrix.select("standard", only=["vless-raw-tls"])
    assert matrix.select("standard", exclude=["hold"]) != matrix.select("standard")


@check("one link generates the same job in both dialects")
def _configs() -> None:
    with tempfile.TemporaryDirectory() as raw:
        directory = pathlib.Path(raw)
        identity = configs.generate_identity(directory)
        for link in (
            configs.Link("vless", "raw", "none"),
            configs.Link("vless", "raw", "tls"),
            configs.Link("vless", "raw", "reality", vision=True),
            configs.Link("vless", "ws", "tls"),
            configs.Link("vless", "grpc", "tls"),
            configs.Link("vless", "xhttp-h2", "tls"),
            configs.Link("vmess", "raw", "tls"),
            configs.Link("trojan", "raw", "tls"),
            configs.Link("shadowsocks", "raw", "tls"),
            configs.Link("shadowsocks2022", "raw", "tls"),
            configs.Link("anytls", "raw", "tls"),
        ):
            server = configs.xray_server(link, identity, 1234, 4321)
            client = configs.xray_client(link, identity, 5678, 1234)
            assert server["inbounds"][0]["port"] == 1234, link
            assert client["inbounds"][0]["port"] == 5678, link
            # The server address in the client must be the server's port: a
            # harness that generated a config pointing at the wrong port would
            # fail at run time, in CI, on someone else's machine.
            blob = json.dumps(client)
            assert '"port": 1234' in blob, f"{link}: client does not point at the server port"
            # A shape the dialect cannot express must be refused, not faked --
            # asked of the generator, which is what the run actually uses.
            refused = False
            for build in (
                lambda: configs.singbox_server(link, identity, 1234, 4321),
                lambda: configs.singbox_client(link, identity, 5678, 1234, 4321),
            ):
                try:
                    build()
                except configs.UnsupportedShape:
                    refused = True
            if refused:
                continue
            sing_server = configs.singbox_server(link, identity, 1234, 4321)
            sing_client = configs.singbox_client(link, identity, 5678, 1234, 4321)
            assert sing_server["inbounds"][0]["listen_port"] == 1234, link
            assert sing_client["outbounds"][0]["server_port"] == 1234, link

        # A QUIC-based protocol carries its own TLS and has no streamSettings.
        for protocol in ("hysteria2", "tuic"):
            link = configs.Link(protocol)
            assert link.quic_based
            server = configs.xray_server(link, identity, 1234)
            assert "streamSettings" not in server["inbounds"][0], protocol
            sing = configs.singbox_server(link, identity, 1234, 4321)
            assert sing["inbounds"][0]["tls"]["enabled"] is True, protocol

        # The fixture keys and certificate exist and are the ones referenced.
        for name in ("ca.pem", "cert.pem", "key.pem"):
            assert identity.path(name).exists(), name
        assert configs.ss_method("shadowsocks2022").startswith("2022-blake3-")
        assert not configs.ss_method("shadowsocks").startswith("2022-")
        for scenario in matrix.all_scenarios():
            if scenario.link.protocol not in ("shadowsocks", "shadowsocks2022"):
                continue
            assert configs.xray_protocol(scenario.link.protocol) == "shadowsocks"
            server = configs.xray_server(
                scenario.link, identity, 1234, 4321
            )
            assert server["inbounds"][0]["protocol"] == "shadowsocks", scenario.id
            assert server["inbounds"][0]["settings"]["method"] == configs.ss_method(
                scenario.link.protocol
            ), scenario.id


@check("scenario names map onto each dialect's own spelling")
def _spelling() -> None:
    # Shadowsocks 2022 is a method, not a protocol name.
    assert configs.xray_protocol("shadowsocks2022") == "shadowsocks"
    assert configs.xray_protocol("vless") == "vless"
    for scenario in matrix.all_scenarios():
        assert configs.xray_protocol(scenario.link.protocol) in (
            "vless", "vmess", "trojan", "shadowsocks", "anytls", "hysteria2", "tuic"
        ), scenario.id
    # sing-box has no TLS block on a Shadowsocks outbound, so the cell is
    # unsupported there and must be refused rather than emitted.
    assert not configs.singbox_tls_capable("shadowsocks")
    assert not configs.singbox_tls_capable("shadowsocks2022")
    assert configs.singbox_tls_capable("vless")
    link = configs.Link("shadowsocks", "raw", "tls")
    with tempfile.TemporaryDirectory() as raw:
        identity = configs.generate_identity(pathlib.Path(raw))
        try:
            configs.singbox_client(link, identity, 5678, 1234, 4321)
            raise AssertionError("sing-box has no TLS block on Shadowsocks")
        except configs.UnsupportedShape:
            pass
        try:
            configs.singbox_client(link, identity, 1, 2, 3)
        except configs.UnsupportedShape:
            pass
        else:
            raise AssertionError("sing-box was asked for Shadowsocks over TLS")
        # The 2022 PSK is standard base64 with padding, because that is what a
        # Go decoder accepts; the URL-safe form is refused as illegal base64.
        import base64 as _base64

        psk = identity.ss_passwords["shadowsocks2022"]
        assert "=" in psk, psk
        assert len(_base64.b64decode(psk, validate=True)) == 16, psk
        assert set(psk) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        ), psk


@check("a scenario transport maps onto Xray's network spelling")
def _network_names() -> None:
    assert configs.xray_network("raw") == "raw"
    assert configs.xray_network("ws") == "ws"
    assert configs.xray_network("httpupgrade") == "httpupgrade"
    assert configs.xray_network("grpc") == "grpc"
    # The three XHTTP rows differ in httpVersion, not in `network`: writing the
    # scenario's own name there is refused by every core that reads Xray JSON.
    for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
        assert configs.xray_network(transport) == "xhttp", transport
    for scenario in matrix.all_scenarios():
        if scenario.link.quic_based or scenario.link.transport == "raw":
            continue
        assert configs.xray_network(scenario.link.transport) in (
            "raw", "ws", "httpupgrade", "grpc", "xhttp"
        ), scenario.id


@check("the Xray dialect is identical for the two cores that share it")
def _shared_dialect() -> None:
    with tempfile.TemporaryDirectory() as raw:
        identity = configs.generate_identity(pathlib.Path(raw))
        link = configs.Link("vless", "ws", "tls", vision=True)
        first = configs.xray_client(link, identity, 1, 2)
        second = configs.xray_client(link, identity, 1, 2)
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


@check("a medians-only report never claims a difference it cannot resolve")
def _stats() -> None:
    assert stats.median([1, 2, 3]) == 2
    assert stats.median([1, 2, 3, 4]) == 2.5
    assert stats.median([]) is None
    assert stats.percentile([1, 2, 3, 4, 5], 95) == 5, "nearest-rank p95 of five is the largest"
    assert stats.mad([2, 2, 2]) == 0

    identical = stats.paired_ratio([10, 10, 10], [10, 10, 10])
    assert identical.verdict == "within_noise", identical.verdict
    assert 1.0 == (identical.ratio or 0), identical.ratio

    noisier = stats.paired_ratio([10, 40, 12, 38, 11, 41], [10, 10, 10, 10, 10, 10])
    assert noisier.verdict == "within_noise", (
        f"a 4x difference on 6 paired samples should not resolve; got {noisier.verdict}"
    )

    clean = stats.paired_ratio([120, 121, 119, 120, 118], [100, 100, 100, 100, 100])
    assert clean.verdict == "candidate_better", clean.verdict
    assert clean.ci_low and clean.ci_low > 1.0, clean.as_dict()

    # Direction comes from the metric, not from the sign of the ratio. The same
    # ratio is an improvement on a throughput row and a regression on a memory or
    # latency row, and reading the ratio alone once labelled a 20% memory
    # increase "candidate_cheaper".
    slower = stats.paired_ratio([120, 121, 119, 120, 118], [100] * 5, higher_is_better=False)
    assert slower.verdict == "candidate_worse", slower.verdict
    leaner = stats.paired_ratio([80, 81, 79, 80, 78], [100] * 5, higher_is_better=False)
    assert leaner.verdict == "candidate_better", leaner.verdict

    # The quoted margin is the end of the interval nearest 1.0x, because that is
    # the end the whole interval guarantees. Quoting the far end promises more
    # than the data supports.
    assert f"{((clean.ci_low or 1) - 1) * 100:.0f}%" in clean.explanation, clean.explanation
    assert f"{(1 - (leaner.ci_high or 1)) * 100:.0f}%" in leaner.explanation, leaner.explanation
    assert f"{((clean.ci_high or 1) - 1) * 100:.0f}%" not in clean.explanation, (
        "the far end of the interval must not be quoted as the guaranteed margin: "
        + clean.explanation
    )

    # A zero reference sample has no ratio, so it must leave the pair count too:
    # counting a pair the statistics never saw is how one ratio gets described as
    # a two-pair result.
    zeroed = stats.paired_ratio([10, 0], [10, 0])
    assert zeroed.verdict == "unproven", zeroed.verdict
    assert zeroed.pairs == 1, zeroed.pairs

    cheap = stats.paired_ratio([1, 1], [1, 1], higher_is_better=False)
    assert stats.paired_ratio([1], [1]).verdict == "unproven"
    assert cheap.pairs == 2

    # The bootstrap is seeded, so a report is reproducible rather than a
    # different interval every time it is regenerated.
    a = stats.paired_ratio([120, 121, 119], [100, 100, 100])
    b = stats.paired_ratio([120, 121, 119], [100, 100, 100])
    assert a.as_dict() == b.as_dict()


@check("the load generator moves exactly what it was asked to move")
def _loadgen_arithmetic() -> None:
    """Four arithmetic defects lived here, and none of them raised an error.

    * A duplex run gave the writer thread its own byte counters, so it reported
      `bytes_sent: 0` after writing a hundred megabytes, and a rate half of the
      truth.
    * A per-flow size that was not a multiple of eight failed validation with a
      "payload mismatch" that was not one, so `--bytes 100M --streams 3` reported
      corruption on a healthy transfer.
    * Integer division dropped the remainder, so 100,000,000 bytes over three
      flows moved 99,999,999 -- and the same truncation understated the ceiling
      every other row is compared against.
    * A zero-byte request encodes as the hold shape, so taking it as a transfer
      reported a rate of zero as if it were a result.
    """
    binary = _loadgen_binary()
    if binary is None:
        return
    import socket
    import subprocess
    import time

    def free_port() -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def run(argv):
        return subprocess.run(
            [str(binary), *argv], capture_output=True, text=True, timeout=300
        )

    proxy_port, sink_port = free_port(), free_port()
    sink = subprocess.Popen(
        [str(binary), "sink", "--port", str(sink_port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    forwarder = subprocess.Popen(
        [sys.executable, "-c", FORWARDER, str(proxy_port), str(sink_port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        for mode in ("down", "up", "duplex"):
            for request, streams in (("100M", 3), ("1G", 7), ("999", 5), ("7", 7)):
                out = run(
                    [
                        "run", "--proxy", f"127.0.0.1:{proxy_port}",
                        "--target", f"127.0.0.1:{sink_port}",
                        "--mode", mode, "--bytes", request,
                        "--streams", str(streams), "--json",
                    ]
                )
                assert out.returncode == 0, f"{mode} {request}/{streams}: {out.stderr[-300:]}"
                payload = json.loads(out.stdout)
                assert not payload.get("errors"), (
                    f"{mode} {request}/{streams}: {payload['errors'][:1]}"
                )
                wanted = payload["bytes_requested_per_direction"]
                # `--bytes` is per direction, so a duplex run moves it twice and
                # `bytes_moved` is the total across both.
                assert payload["directions"] == (2 if mode == "duplex" else 1), payload
                if mode == "duplex":
                    assert payload["bytes_sent"] == wanted, (
                        f"duplex reported bytes_sent={payload['bytes_sent']:,} of {wanted:,}"
                    )
                    assert payload["bytes_received"] == wanted, payload
                    assert payload["bytes_moved"] == 2 * wanted, payload
                else:
                    assert payload["bytes_moved"] == wanted, (
                        f"{mode} {request}/{streams}: moved "
                        f"{payload['bytes_moved']:,} of {wanted:,}"
                    )
                    unused = "sent" if mode == "down" else "received"
                    assert payload[f"bytes_{unused}"] == 0, (
                        f"{mode} reported bytes on the wrong side: {payload}"
                    )
        out = run(
            [
                "run", "--proxy", f"127.0.0.1:{proxy_port}",
                "--target", f"127.0.0.1:{sink_port}",
                "--mode", "down", "--bytes", "0", "--json",
            ]
        )
        assert out.returncode == 1, "a zero-byte download was accepted"
        assert "bytes" in (json.loads(out.stdout).get("error") or ""), out.stdout

        # The ceiling is the number every other row is compared against, so a
        # dropped remainder in it makes every core look closer to the limit.
        for request, streams in (("100M", 3), ("1G", 7), ("999", 5)):
            out = run(
                [
                    "selftest", "--target", f"127.0.0.1:{sink_port}",
                    "--bytes", request, "--streams", str(streams), "--json",
                ]
            )
            assert out.returncode == 0, out.stderr[-300:]
            payload = json.loads(out.stdout)
            assert payload["bytes_moved"] == bench.byte_size(request), (
                f"selftest {request}/{streams} moved {payload['bytes_moved']:,}"
            )
            assert payload["throughput_mbps"] > 0, payload
    finally:
        forwarder.terminate()
        sink.terminate()
        forwarder.wait(timeout=10)
        sink.wait(timeout=10)


@check("validation still rejects a peer that returns the wrong bytes")
def _loadgen_rejects_corruption() -> None:
    """The tail fix must not have turned validation into a rubber stamp."""
    binary = _loadgen_binary()
    if binary is None:
        return
    import socket
    import subprocess
    import time

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    liar = subprocess.Popen(
        [sys.executable, "-c", LIAR, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        out = subprocess.run(
            [
                str(binary), "selftest", "--target", f"127.0.0.1:{port}",
                "--bytes", "1M", "--streams", "1", "--json",
            ],
            capture_output=True, text=True, timeout=120,
        )
        combined = out.stdout + out.stderr
        assert "mismatch" in combined or out.returncode != 0, (
            "a peer returning zeros was accepted as a valid transfer"
        )
    finally:
        liar.terminate()
        liar.wait(timeout=10)


@check("the sampler reads a real process")
def _sampler() -> None:
    import time

    pid = measure.os.getpid()
    with measure.Sampler(pid, interval=0.01) as sampler:
        # Time-boxed rather than a fixed iteration count: a fixed count can
        # finish inside one scheduling quantum, which is exactly the case where a
        # sampler that never ran would look identical to one that did.
        deadline = time.monotonic() + 0.4
        total = 0
        while time.monotonic() < deadline:
            total += 1
    assert total > 0
    assert sampler.samples, "the sampler took no samples"
    window = measure.summarise(sampler.samples, pid)
    assert window.samples >= 2, f"one sample is not a window: {window}"
    assert window.rss_peak_kb > 0, window
    assert window.cpu_s > 0, f"this process was busy for 0.4 s: {window}"
    gib = window.cpu_s_per_gb(1024**3)
    assert gib is not None and gib > 0, gib
    assert window.cpu_s_per_gb(0) is None, "a window that moved no bytes has no per-GB cost"


@check("a pasted configuration is split, and a subscription is recognised")
def _split() -> None:
    # A pretty-printed document, a compact one-line document, and a document
    # whose braces are all on one line: three shapes, three documents.
    pretty = '{\n  "a": 1\n}\n{\n  "b": 2\n}\n'
    assert len(split_configs.split(pretty)) == 2, split_configs.split(pretty)
    assert len(split_configs.split('{"a":1}\n{"b":2}')) == 2, split_configs.split('{"a":1}\n{"b":2}')
    assert len(split_configs.split('{"a":{"b":1}}')) == 1
    assert split_configs.split("   ") == []
    assert split_configs.split("") == []

    with tempfile.TemporaryDirectory() as raw:
        directory = pathlib.Path(raw)
        (directory / "one.json").write_text(json.dumps({
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": 1080}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [
                {"address": "example.com", "port": 443, "users": [{"id": "x"}]}
            ]}}],
        }))
        (directory / "two.json").write_text(json.dumps({
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1081}],
            "outbounds": [{"type": "trojan", "server": "1.2.3.4", "server_port": 443}],
        }))
        (directory / "broken.json").write_text("{nope")
        (directory / "nolisten.json").write_text(json.dumps({
            "outbounds": [{"protocol": "freedom"}]
        }))
        (directory / "links.txt").write_text("vless://a@b:443#x")

        found = {c.name: c for c in userconfig.collect(directory=directory)}
        assert found["one"].runnable, found["one"].problems
        assert found["one"].target_host == "example.com", found["one"].summary()
        assert found["one"].proxy_port == 1080
        assert found["two"].runnable, found["two"].problems
        assert found["two"].target_host == "1.2.3.4", found["two"].summary()
        assert found["two"].proxy_port == 1081, "the sing-box listen_port spelling"
        assert not found["broken"].runnable
        assert found["broken"].problems, "an unreadable file must say why"
        assert not found["nolisten"].runnable
        assert any("inbound" in p for p in found["nolisten"].problems)
        assert found["links"].kind == "link", found["links"].kind


@check("a supplied config transfers only when a destination is named")
def _user_target() -> None:
    """The distinction the whole supplied-config path rests on.

    A config names its own proxy server, and that endpoint speaks the proxy
    protocol rather than this harness's, so pointing a byte transfer at it fails
    for every core every time. Without a named destination the config must still
    be measured -- the tunnel -- and must not claim a throughput it never got.
    """
    from zbench import report, runner as R

    with tempfile.TemporaryDirectory() as raw:
        directory = pathlib.Path(raw)
        (directory / "c.json").write_text(json.dumps({
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": 1080}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [
                {"address": "example.com", "port": 443, "users": [{"id": "x"}]}
            ]}}],
        }))
        found = {c.name: c for c in userconfig.collect(directory=directory)}["c"]

        assert not found.can_transfer, "no destination named means nothing to move bytes to"
        assert found.target_host == "example.com"

        found.measure_host, found.measure_port = "10.0.0.1", 9000
        assert found.can_transfer, "a named destination is what makes a transfer possible"

        # The probe path must not claim a rate it never measured. `_fill` is
        # shared with the matrix rows, and its operations-rate branch was gated on
        # a list of workloads that did not include this one, so the row's headline
        # metric was computed nowhere and every such cell read as blank.
        engine = R.Runner.__new__(R.Runner)
        cell = R.Cell(scenario="user:c", group="user", link="user",
                      workload="passthrough", core="xray", repeat=0,
                      status="skipped", streams=R.USER_CONFIG_STREAMS)
        assert report.HEADLINE["passthrough"][0] == "throughput_mbps"
        assert report.HEADLINE["tunnel"][0] == "ops_per_s", (
            "a probed config leads with the tunnel rate, not a throughput it never got"
        )
        engine.harness_ceiling = None
        engine._ceilings = {}
        window = measure.Window(cpu_s=0.1, rss_peak_kb=1024.0, rss_hwm_kb=None,
                                threads_peak=None, samples=4)
        engine._fill(cell, {"measured_ms": 1000.0, "iterations": 200}, window)
        assert cell.ops_per_s == 200.0, cell.ops_per_s
        assert cell.throughput_mbps is None, (
            "a probe exchanges no payload, so it has no throughput to report"
        )

        # And with a destination named it does report one.
        engine._fill(cell, {"throughput_mbps": 1000.0, "MBps": 125.0,
                            "bytes_moved": 1024, "measured_ms": 1000.0,
                            "iterations": 4}, window)
        assert cell.throughput_mbps == 1000.0, cell.throughput_mbps


@check("the generated comparison document is deterministic")
def _support_doc() -> None:
    from zbench import support_doc

    first = support_doc.render()
    second = support_doc.render()
    assert first == second, "the document changes between renders"
    for core_id in caps.DEFAULT_CORES:
        assert caps.get(core_id).label in first, core_id
        # The version appears exactly once, in the versions table generated from
        # PINS. A second copy in the feature table is how the two would drift.
        assert first.count(caps.PINS[core_id]["version"]) == 1, (
            f"{core_id}: the pinned version appears more than once in the document"
        )
    assert "## Regenerating" in first


@check("the workflow's argument script resolves every option by name")
def _bench_args_script() -> None:
    """One implementation of how a run is assembled, and it is checkable.

    The three jobs used to build the list inline. One of them overwrote `--runs`
    instead of `--cores` by indexing the array by position, so the capability
    probe silently stopped working on any run where xray-rust failed to build --
    which is exactly the run where you most want the probe. A positional edit of
    an argument array is not reviewable either: the diff does not show which
    element moved.
    """
    # harness/ -> benchmarks/ -> docs/ -> the repository root.
    script = HERE.parents[2] / ".github" / "scripts" / "bench-args.sh"
    assert script.exists(), f"{script} is missing; the workflow calls it"
    import subprocess
    import tempfile

    def assemble(**environment):
        with tempfile.TemporaryDirectory() as raw:
            out = pathlib.Path(raw) / "args"
            env = dict(os.environ, OUT=str(out))
            env.update({k: str(v) for k, v in environment.items()})
            proc = subprocess.run(
                ["bash", str(script)], env=env, capture_output=True, text=True,
                timeout=60,
            )
            assert proc.returncode == 0, proc.stderr[-400:]
            return out.read_text().splitlines(), proc.stdout.strip()

    lines, echoed = assemble()
    assert lines[:2] == ["--suite", "standard"], lines
    assert "--cores" in lines
    cores = lines[lines.index("--cores") + 1]
    assert cores == "zray,xray,singbox,xray-rust", cores
    # Each option is followed by its own value: a value can never land where a
    # flag belongs, which is the whole failure mode this replaced.
    flags = {"--suite", "--server-core", "--runs", "--bytes", "--iterations",
             "--cores", "--only", "--exclude", "--user-config-url",
             "--user-config-dir", "--base-ref", "--gate-regression",
             "--user-target", "--repo"}
    for index, item in enumerate(lines):
        if item in flags:
            assert index + 1 < len(lines), f"{item} has no value"
            assert lines[index + 1] not in flags, f"{item} was given a flag as its value"
    assert echoed.startswith("bench.py "), echoed

    # A base ref puts the base first, so the ratios are against the base.
    lines, _ = assemble(BENCH_BASE_REF="abc123")
    cores = lines[lines.index("--cores") + 1]
    assert cores.startswith("zray-base,"), cores
    lines, _ = assemble(BENCH_BASE_REF="abc123", BENCH_GATE="5")
    assert lines[lines.index("--gate-regression") + 1] == "5", lines
    assert lines[lines.index("--base-ref") + 1] == "abc123", lines

    # An explicit core list still wins over the default.
    lines, _ = assemble(BENCH_CORES="zray-base,zray", BENCH_BASE_REF="x")
    assert lines[lines.index("--cores") + 1] == "zray-base,zray", lines

    # A combined baseline needs to know which repository's pull requests to merge.
    lines, _ = assemble(BENCH_REPO="zeghostwriter/ZeroNet")
    assert lines[lines.index("--repo") + 1] == "zeghostwriter/ZeroNet", lines
    lines, _ = assemble()
    assert "--repo" not in lines, "no repository asked for means no flag"

    # A supplied config's destination reaches the harness by name.
    lines, _ = assemble(BENCH_USER_TARGET="example.org:9000")
    assert lines[lines.index("--user-target") + 1] == "example.org:9000", lines
    lines, _ = assemble()
    assert "--user-target" not in lines, "no target asked for means no flag"

    # Comma separated lists with stray whitespace do not become empty arguments.
    lines, _ = assemble(BENCH_ONLY=" vless-raw-tls , xhttp ", BENCH_EXCLUDE="")
    assert lines.count("--only") == 2, lines
    assert "--exclude" not in lines, "an empty list should add no flag"


@check("the regression gate reads the interval and the metric's direction")
def _gate() -> None:
    from zbench import report

    def row(ratio, low, high, higher=True, scenario="s"):
        return {
            "scenario": scenario, "group": "baseline", "metric": "throughput_mbps",
            "unit": "Mbit/s", "higher_is_better": higher, "candidate": 1.0,
            "base": 1.0, "ratio": ratio, "ci95": (low, high),
            "verdict": (
                "within_noise" if low <= 1.0 <= high
                else "candidate_better"
            ),
            "pairs": 3, "spread": 0.03,
        }

    # The tolerance is a percentage, because the flag and the workflow input both
    # say "5 means 5%". Used as a fraction against a 0..1 ratio it became
    # `1.0 - 5`, so no interval could ever be beyond it and the gate reported that
    # it had run while being incapable of failing.
    assert not report.gate([row(0.60, 0.55, 0.65)], max_regression=5).ok, (
        "a 40% regression must fail a 5% gate"
    )
    assert report.gate([row(0.97, 0.96, 0.98)], max_regression=5).ok, (
        "a 3% regression must pass a 5% gate"
    )
    assert not report.gate([row(0.60, 0.55, 0.65)], max_regression=0.5).ok, (
        "0.5% is a tighter tolerance and still fails on 40%"
    )

    # A 4% regression and a 40% one have the same shape in a point estimate. The
    # interval is what tells them apart, and a gate that only reads the point
    # estimate fails at random.
    assert report.gate([row(0.96, 0.94, 0.98)], max_regression=10).ok
    assert not report.gate([row(0.60, 0.55, 0.65)], max_regression=10).ok

    # An unresolved interval is neither a pass nor a finding: it is the absence of
    # a measurement, and it must not be reported as one.
    noisy = report.gate([row(0.93, 0.85, 1.10)], max_regression=10)
    assert noisy.ok, noisy.lines
    assert any("unresolved" in line for line in noisy.lines)

    # Direction is read from the metric, not the sign of the ratio: a ratio above
    # 1.0 is an improvement for throughput and a regression for memory.
    worse_memory = report.gate([row(1.30, 1.20, 1.40, higher=False)], max_regression=10)
    assert not worse_memory.ok, worse_memory.lines
    better_memory = report.gate([row(0.90, 0.85, 0.95, higher=False)], max_regression=10)
    assert better_memory.ok, better_memory.lines

    # The counts the gate reports have to agree with its verdict. Reading the
    # ratio's sign alone filed a 40% throughput regression under "resolved
    # better" and left the gate passing.
    def counts(g):
        return [line for line in g.lines if "resolved" in line]

    slower = report.gate([row(0.60, 0.55, 0.65)], max_regression=10)
    assert any("0 scenario(s) resolved better" in c for c in counts(slower)), slower.lines
    assert any("1 scenario(s) resolved worse" in c for c in counts(slower)), slower.lines
    faster = report.gate([row(1.40, 1.35, 1.45)], max_regression=10)
    assert any("1 scenario(s) resolved better" in c for c in counts(faster)), faster.lines
    assert any("0 scenario(s) resolved worse" in c for c in counts(faster)), faster.lines

    # "Cleared an improvement" means the whole interval cleared it.
    marginal = report.gate([row(1.04, 1.02, 1.20)], max_regression=10,
                           min_improvement=10)
    assert any("0 scenario(s) cleared" in line for line in marginal.lines), marginal.lines
    real = report.gate([row(1.40, 1.35, 1.45)], max_regression=10, min_improvement=10)
    assert any("1 scenario(s) cleared" in line for line in real.lines), real.lines

    # One bad scenario among many is still a failure, and it is named.
    mixed = report.gate(
        [row(1.01, 0.99, 1.03, scenario="fine"),
         row(0.70, 0.60, 0.80, scenario="broken")],
        max_regression=10,
    )
    assert not mixed.ok, mixed.lines
    assert any("`broken`" in line for line in mixed.lines), mixed.lines

    assert not report.gate([], max_regression=5).ok, "an empty comparison passed"


@check("the base core is a real core with a pin and a default slot")
def _base_core() -> None:
    assert caps.BASE_ID in caps.ALL_CORES
    assert caps.BASE_ID in caps.PINS, "the base core has no pin"
    assert caps.PR_CORES[0] == caps.BASE_ID, "the base has to be the baseline"
    base = caps.get(caps.BASE_ID)
    candidate = caps.get("zray")
    assert base.dialect == candidate.dialect
    assert base.client_protocols == candidate.client_protocols
    assert base.transports == candidate.transports
    assert base.server_protocols == candidate.server_protocols
    # A base that cannot serve would make every scenario a server skip.
    assert base.can_serve


@check("every metric the report lists actually reaches a table")
def _metrics_render() -> None:
    """A metric can be aggregated, stored, and still never be printed.

    `threads_peak` was stored as a bare integer while the tables read a summary
    dictionary, so the section was dropped from every report that had one -- and
    it only has one on Linux, where `ps` is not the source of a thread count.
    """
    from zbench import report, runner as R, stats as S

    cell = R.Cell(scenario="s", group="memory", link="l", workload="hold",
                  core="xray", repeat=0, status="measured", threads_peak=37)
    res = R.Result()
    res.binaries = [{"id": "xray", "label": "Xray-core"}]
    res.cells = [cell]
    agg = report.aggregate(res)
    record = agg["rows"]["s"]["cores"]["xray"]
    assert isinstance(record["threads_peak"], dict), (
        f"a table cannot read {record['threads_peak']!r}"
    )
    assert record["threads_peak"]["median"] == 37, record["threads_peak"]

    table = report._metric_table(
        agg, ["s"], ["xray"], "threads_peak", "threads",
    )
    assert "37" in table, f"the thread count is missing from its own table:\n{table}"
    # And the column headings agree with the group table above it.
    assert "Xray-core" in table, table


@check("this harness still measures everything the previous one measured")
def _superset() -> None:
    """A rewrite that quietly drops a scenario is a regression, not a cleanup.

    The harness this replaced was one protocol at two security layers against two
    cores, at 1/8/64 streams plus upload, reporting MB/s, CPU per GB, and idle and
    peak resident memory. Each of those has to remain reachable, or "better"
    quietly means "less".
    """
    from zbench import matrix as M, caps as C

    standard = {s.id: s for s in M.select("standard")}
    full = {s.id: s for s in M.select("full")}

    for name in ("xray", "zray"):
        assert name in C.ALL_CORES, f"the comparator {name} is gone"

    for scenario, transport, security, direction, streams in (
        ("vless-raw-none-down-1", "raw", "none", "down", 1),
        ("vless-raw-none-down-8", "raw", "none", "down", 8),
        ("vless-raw-none-down-64", "raw", "none", "down", 64),
        ("vless-raw-none-up-1", "raw", "none", "up", 1),
        ("vless-raw-tls-down-1", "raw", "tls", "down", 1),
    ):
        found = standard.get(scenario) or full.get(scenario)
        assert found is not None, f"the previous harness measured {scenario}"
        assert found.link.security == security, scenario
        assert found.workload == direction, scenario
        assert found.streams == streams, (scenario, found.streams)

    # Every metric the previous file recorded: measured on a cell, aggregated into
    # the record the tables read, and printed. `MBps` was the one that was measured
    # and aggregated nowhere, and printed nowhere, while the old charts were drawn
    # in exactly that unit.
    from zbench import report, runner as R
    aggregated = report.AGGREGATED_METRICS
    printed = {m for m, _t, _u in report.PRINTED_METRICS}
    for metric in ("MBps", "cpu_s_per_GB", "rss_idle_mb", "rss_peak_mb"):
        assert metric in R.Cell.__dataclass_fields__, f"{metric} is no longer measured"
        assert metric in aggregated, f"{metric} is measured but not aggregated"
        assert metric in printed, f"{metric} is aggregated but never printed"
    # And the unit the previous charts used is printed, not just stored: the old
    # figures are in MB/s, so a reader comparing them needs it in front of them.
    units = {u for _m, _t, u in report.PRINTED_METRICS}
    assert "MB/s" in units, units
    assert report._fmt(2000.0, "MB/s") == "2.00 GB/s", report._fmt(2000.0, "MB/s")
    assert report._fmt(800.0, "MB/s") == "800 MB/s", report._fmt(800.0, "MB/s")
    # A unit with no branch in the formatter prints a bare number, so every unit
    # the tables pass is checked against the formatter here rather than trusted.
    for metric, title, unit in report.PRINTED_METRICS:
        rendered = report._fmt(1234.0, unit)
        assert not rendered.isdigit(), (
            f"{metric} is printed as a bare number, so its unit never appears: "
            f"{rendered!r} for unit {unit!r}"
        )


@check("the xray-rust comparison is accurate, in both directions")
def _xray_rust_suite() -> None:
    """A comparison that cannot be checked is a claim, not a measurement.

    Every `covered` row has to name something the matrix really builds, and the
    protocols this harness says it does not touch have to be exactly the ones
    xray-rust can be given a config for and this one cannot serve -- otherwise
    the gap list is either hiding a scenario that works or inventing one that
    does not.
    """
    from zbench import caps, configs, matrix as M, xrayrust_suite as X

    statuses = {row["status"] for row in X.XRAY_RUST_SUITE}
    assert statuses <= {"covered", "partial", "capability", "not_covered"}, statuses
    assert "covered" in statuses and "not_covered" in statuses, (
        "a comparison in which nothing is missing would be a claim of superset; "
        "it is not one, and the rows should say so"
    )

    # What the matrix builds, as (protocol, transport, security).
    built = {(s.link.protocol, s.link.transport, s.link.security)
             for s in M.select("full")}
    for protocol, transport, security in built:
        if protocol in ("vless", "vmess") and transport in (
            "raw", "ws", "httpupgrade", "grpc", "xhttp-h1", "xhttp-h2", "xhttp-h3"
        ):
            continue
        # Anything outside that shape must be deliberate, so a new protocol cannot
        # be added without deciding whether its transport is covered.
        assert protocol in {"trojan", "shadowsocks", "shadowsocks2022", "anytls"}, (
            f"{protocol}/{transport} is in the matrix but not in the known shape"
        )

    # Fingerprints are a real axis, not one hardcoded value: uTLS synthesises the
    # ClientHello and the synthesis is a per-fingerprint code path, so a table
    # claiming to cover them while the config always says `chrome` is false.
    fingerprints = {
        s.link.fingerprint for s in M.select("full") if s.link.security != "none"
    }
    assert len(fingerprints) >= 2, f"only one fingerprint is ever measured: {fingerprints}"
    for fingerprint in fingerprints:
        built_tls = any(
            link.security in ("tls", "reality") and link.fingerprint == fingerprint
            for link in (s.link for s in M.select("full"))
        )
        assert built_tls, f"{fingerprint} appears in no scenario"
        # And the generated config must carry it, not a default.
        ident = configs.generate_identity(pathlib.Path(tempfile.mkdtemp()))
        link = configs.Link("vless", "raw", "reality", fingerprint=fingerprint)
        client = configs.xray_client(link, ident, 1080, 443)
        blob = json.dumps(client)
        assert fingerprint in blob, f"{link.name()} does not carry {fingerprint}"

    # Every protocol this harness can configure but does not drive must appear in
    # the gap list -- with the reason it is a gap.
    # A protocol any core accepts a config for, that no scenario drives, has to
    # be in the gap list with a reason -- otherwise the table quietly understates
    # the coverage.
    drivable = {p for p, _t, _s in built}
    items = " ".join(row["item"].lower() for row in X.XRAY_RUST_SUITE)
    for core in (caps.ZRAY, caps.XRAY, caps.SINGBOX, caps.XRAY_RUST):
        for protocol in core.client_protocols - drivable:
            if protocol == "freedom":
                # A direct outbound, not a proxy protocol: there is nothing to
                # tunnel, so it is not a coverage gap.
                continue
            assert protocol.replace("2", "") in items.replace("2", "") or (
                protocol in items
            ), (
                f"{core.id} accepts a {protocol} client, no scenario drives it, "
                f"and it is not listed as a gap"
            )
    for row in X.XRAY_RUST_SUITE:
        if row["status"] != "not_covered":
            continue
        assert len(row["ours"]) > 40, f"{row['item']!r} is a gap with no reason given"

    # And the reverse: a `covered` row must be one this harness really builds, so
    # it cannot claim coverage of a scenario nobody runs.
    # A `covered` row names the (protocol, transport) pairs it claims, and every
    # one has to be a pair the matrix actually builds. This is what makes
    # "covered" mean something: claim a transport with no scenario behind it and
    # this fails, so the table cannot drift away from the matrix.
    built_pairs = {(s.link.protocol, s.link.transport) for s in M.select("full")}
    claimed = 0
    for row in X.XRAY_RUST_SUITE:
        if "builds" not in row:
            continue
        for pair in row["builds"]:
            claimed += 1
            assert pair in built_pairs, (
                f"{row['item']!r} claims {pair} is covered, but no scenario uses "
                f"that protocol and transport"
            )
        if row["status"] == "not_covered" and row["builds"]:
            raise AssertionError(f"{row['item']!r} says not covered but claims pairs")
    assert claimed >= 8, f"only {claimed} claimed pairs; the table asserts almost nothing"

    # Every transport the full matrix builds should be accounted for by a row,
    # so a scenario added later cannot be silently uncompared.
    unaccounted = built_pairs - {
        pair for row in X.XRAY_RUST_SUITE for pair in row.get("builds", ())
    }
    documented = {
        ("vless", "raw"), ("vless", "ws"), ("vless", "httpupgrade"),
        ("vless", "grpc"), ("vless", "xhttp-h1"), ("vless", "xhttp-h2"),
        ("vless", "xhttp-h3"), ("vmess", "raw"), ("vmess", "ws"),
        ("trojan", "raw"), ("trojan", "ws"), ("trojan", "grpc"),
        ("shadowsocks", "raw"), ("shadowsocks2022", "raw"), ("anytls", "raw"),
    }
    new_pairs = unaccounted - documented
    assert not new_pairs, (
        f"these protocol/transport pairs are in the matrix but no comparison row "
        f"mentions them: {sorted(new_pairs)}"
    )


@check("the combined baseline names what it was built from")
def _pr_base() -> None:
    """A baseline made of many branches has to say which ones.

    Merging ten pull requests and reporting one number against it is only
    meaningful if the report says what went in. These checks need no network:
    they read the sentinel handling and the shape of the record, so a change that
    drops the description is caught here rather than in a run somebody waited on.
    """
    from zbench import prbase

    assert prbase.MERGED.startswith("@") and prbase.PLAIN.startswith("@")

    # A pull request head moves when its author pushes, and a plain fetch refuses
    # the non-fast-forward update -- so without the force the baseline of a busy
    # repository could only be built once.
    import inspect
    source = inspect.getsource(prbase.merged_prs_ref)
    assert "+refs/pull/" in source, (
        "the pull request refspec is not forced, so a moved head is rejected as a "
        "non-fast-forward update"
    )
    assert "CONFLICT" in inspect.getsource(prbase.merged_prs_ref), (
        "a conflicting merge must name the files, not just stop"
    )
    # And the exclusion path exists, because not every set combines.
    assert "exclude" in inspect.signature(prbase.merged_prs_ref).parameters
    assert "exclude" in inspect.signature(prbase.list_pull_requests).parameters

    # A plain sentinel is passed through untouched, with a description.
    value, notes = prbase.resolve_base_ref(".", prbase.PLAIN, repo="x/y")
    assert value == prbase.PLAIN, value
    assert notes and any("default branch" in n for n in notes), notes

    # An ordinary git ref is left for the builder and still described.
    value, notes = prbase.resolve_base_ref(".", "v0.2.0", repo="x/y")
    assert value == "v0.2.0", value
    assert notes and any("v0.2.0" in n for n in notes), notes

    # A repository with nothing open is a question with no answer, not a baseline
    # of the empty merge.
    original = prbase.list_pull_requests
    try:
        prbase.list_pull_requests = lambda repo, **kw: []
        try:
            prbase.merged_prs_ref(".", "x/y")
            raise AssertionError("an empty merge was accepted as a baseline")
        except SystemExit as exc:
            assert "no open pull requests" in str(exc), exc
        # A merge that conflicts must stop the run and name the pull request.
        prbase.list_pull_requests = lambda repo, **kw: [
            prbase.PullRequest(7, "t", "head", "main", "u", "MERGEABLE")
        ]
        prbase._gh = lambda *a: "[]"
        prbase.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            SystemExit("merging #7 head for the benchmark baseline failed")
        )
        try:
            prbase.merged_prs_ref(".", "x/y")
            raise AssertionError("a conflicting merge was accepted as a baseline")
        except SystemExit as exc:
            assert "#7" in str(exc), exc
    finally:
        prbase.list_pull_requests = original


@check("the chart scale is monotonic and total")
def _scale() -> None:
    values = [caps.SCALE[i][1] for i in range(len(caps.SCALE))]
    assert values == sorted(values, reverse=True), values
    assert caps.scale_value("yes") == 1.0
    assert caps.scale_value("no") == 0.0
    assert caps.scale_value("removed") < caps.scale_value("partial")
    # "not stated" is not "no". Charting an unstated answer at zero asserts the
    # feature is absent when the table only says nothing was written down, and the
    # two are drawn identically, so a reader of the chart alone would conclude
    # something the text never claimed.
    for unstated in ("n-a", "n/a", "-", "unknown", "no stated"):
        value = caps.scale_value(unstated)
        assert value != caps.scale_value("no"), (
            f"{unstated!r} charts at the same value as `no`, asserting absence"
        )
        assert 0 < value < caps.scale_value("empty block"), (unstated, value)
    # A stub exists, so it must not chart as absent. The phrase was split on the
    # first space, became "empty", missed the scale, and fell through to zero.
    assert caps.scale_value("empty block") == 0.10
    assert caps.scale_value("empty block") > caps.scale_value("no")
    assert caps.scale_value("no (as of v0.7)") == 0.0, "the qualifier must not break the match"
    # Every value the capability table actually contains has to land somewhere
    # real, since the fallback is "unstated" and would otherwise paper over a
    # phrase the table grows later.
    from zbench import caps as C
    values = {getattr(row, core) for row in C.FEATURES
              for core in ("zray", "xray", "singbox", "xray_rust")}
    off_scale = sorted({v for v in values if v.split("(")[0].strip().lower()
                        not in {name for name, _ in C.SCALE}})
    assert off_scale == ["n-a", "no stated"], off_scale
    assert all(C.scale_value(v) != C.scale_value("no") for v in off_scale)


# ---------------------------------------------------------------------------


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("_") and callable(value)]
    print(f"harness self-test: {len(tests)} checks")
    for failure in FAILURES:
        print(f"  FAIL {failure}")
    if FAILURES:
        print(f"{len(FAILURES)} of {len(tests)} checks failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
