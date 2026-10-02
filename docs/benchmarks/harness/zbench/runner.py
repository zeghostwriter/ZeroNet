"""The runner: what actually gets executed, in what order, and what is recorded.

The loop is built around one rule. Within a repeat, every core is measured for
the same scenario back to back, and the order is rotated and then reversed on
alternate repeats. Two reasons, and the second is the one that gets forgotten:

* A core measured first on a cold machine looks slower than the same core
  measured after the machine has warmed up.
* Repeating a fixed order would make "the second core in the list" a permanent
  confound, so a difference would look like a core difference.

Because every core sees the same repeat, the per-repeat values pair up, which is
what lets `stats.paired_ratio` bootstrap a comparison that survives the
run-to-run noise of a shared runner.

Everything a reader needs to distrust or reproduce a number is written to
`results.json`: the binaries and their digests, the exact configs, the host, the
invocation, and a status per cell that distinguishes "measured", "this core does
not support it", "this core claims not to and its own config checker agreed",
and "it was supposed to work and did not".
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import caps, configs, cores, matrix, measure, userconfig
from .configs import Link

STATUS_MEASURED = "measured"
STATUS_ACCEPTED = "accepted"
"""The config was accepted and nothing was measured. Its own status, because
calling it `measured` would put a row of numbers in a report that has none, and
would make a coverage probe look like a performance result."""
STATUS_UNSUPPORTED = "unsupported"
STATUS_UNSUPPORTED_CONFIRMED = "unsupported_confirmed"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"
STATUS_TIMEOUT = "timeout"

#: Flows a supplied configuration is measured with. One number for every such
#: run, so a ceiling measured at it can be compared across configs and cores.
USER_CONFIG_STREAMS = 4


def log(message: str) -> None:
    stamp = time.strftime("%H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


class TlsDest:
    """A TLS listener that exists to hand out a certificate and nothing else.

    A REALITY server proxies the client's ClientHello to `dest` and serves the
    certificate it gets back, so `dest` must complete a TLS handshake. It never
    carries payload: the tunnel's own destination is the sink, and only the
    certificate travels this way. So this completes the handshake and closes,
    which is all a REALITY server asks of it.
    """

    def __init__(self, cert_pem: str, key_pem: str, *, workdir: Path):
        import ssl
        import threading

        self._ssl = ssl
        self._threading = threading
        self._workdir = workdir
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert = workdir / "reality-dest.crt"
        key = workdir / "reality-dest.key"
        cert.write_text(cert_pem)
        key.write_text(key_pem)
        key.chmod(0o600)
        context.load_cert_chain(cert, key)
        self._context = context
        self._stop = threading.Event()
        self._port = 0

    def start(self) -> int:
        import socket

        from .cores import free_port

        self._port = free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self._port))
        listener.listen(128)
        listener.settimeout(0.5)
        self._threading.Thread(
            target=self._serve, args=(listener,), daemon=True
        ).start()
        log(f"reality dest: TLS listener on 127.0.0.1:{self._port}")
        return self._port

    def _serve(self, listener) -> None:
        while not self._stop.is_set():
            try:
                sock, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            self._threading.Thread(target=self._handshake, args=(sock,), daemon=True).start()

    def _handshake(self, sock) -> None:
        # Every failure here is routine: the listener is probed by clients that
        # are not REALITY clients at all, and a rejected handshake is the correct
        # answer for them.
        try:
            with self._context.wrap_socket(sock, server_side=True):
                pass
        except Exception:
            try:
                sock.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()


@dataclass
class Cell:
    scenario: str
    group: str
    link: str
    workload: str
    core: str
    repeat: int
    status: str
    reason: str = ""
    diagnostic: str = ""
    # loadgen output
    throughput_mbps: float | None = None
    MBps: float | None = None
    bytes_moved: int | None = None
    transfer_ms: float | None = None
    total_ms: float | None = None
    connect_us_median: float | None = None
    tcp_connect_us_median: float | None = None
    socks_connect_us_median: float | None = None
    latency_us_median: float | None = None
    latency_us_p95: float | None = None
    flows_opened: int | None = None
    open_ms: float | None = None
    ops_per_s: float | None = None
    """Connections or round trips completed per second, for the setup rows."""
    # process measurement
    cpu_s: float | None = None
    cpu_s_per_GB: float | None = None
    rss_idle_mb: float | None = None
    rss_peak_mb: float | None = None
    rss_peak_reported_mb: float | None = None
    threads_peak: int | None = None
    server_cpu_s: float | None = None
    server_rss_peak_mb: float | None = None
    streams: int = 0
    """How many flows this cell opened. The ceiling is per flow count, so the
    report needs this to pair a row with the ceiling that belongs to it."""
    notes: str = ""
    """Why this cell's numbers are thinner than the others, in one sentence."""
    harness_ceiling_mbps: float | None = None
    """The generator's own ceiling at *this cell's* stream count.

    Not the run's single summary number: the ceiling is a property of the loop,
    and the loop differs at one flow and at sixty-four. Measured on this host the
    same generator reached 78 Gbit/s at 1 stream, 86 at 8 and 5.7 at 64, so one
    number for the whole run would mark 64-flow rows as unbounded when they are
    in fact the ones the generator itself is holding back.
    """
    samples: int = 0


@dataclass
class Result:
    schema: str = "zray-bench/3"
    started: str = ""
    finished: str = ""
    host: dict = field(default_factory=dict)
    invocation: list[str] = field(default_factory=list)
    binaries: list[dict] = field(default_factory=list)
    server_core: str = ""
    base_ref: str = ""
    base_revision: str = ""
    candidate_revision: str = ""
    probe_only: bool = False
    """True when the run asked each core whether it accepts a config and stopped
    there. A probe run produces no performance numbers, and every consumer has
    to know that from the file rather than by noticing empty columns."""
    identity: dict = field(default_factory=dict)
    harness_ceiling_mbps: float | None = None
    harness_ceilings: dict[str, float] = field(default_factory=dict)
    """Stream count -> measured ceiling in Mbit/s, one per stream count used."""
    ceiling_note: str = ""
    cells: list[Cell] = field(default_factory=list)
    user_configs: list[dict] = field(default_factory=list)
    unavailable: list[dict] = field(default_factory=list)
    """Cores that were asked for and could not be had, with the reason."""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        out = asdict(self)
        out["cells"] = [asdict(c) for c in self.cells]
        return out


# ---------------------------------------------------------------------------
# Host description
# ---------------------------------------------------------------------------


def describe_host() -> dict:
    info = {
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "loadgen_ceiling_note": (
            "loopback numbers show how much work each core does per byte; they "
            "are not what a real link will deliver"
        ),
    }
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        info["cpu"] = platform.processor() or "unknown"
    try:
        info["load_average"] = os.getloadavg()
    except (OSError, AttributeError):
        pass
    return info


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


class Runner:
    def __init__(
        self,
        *,
        root: Path,
        workdir: Path,
        binaries: dict[str, cores.CoreBinary],
        server_core: str,
        runs: int,
        bytes_override: int | None,
        iterations_override: int | None,
        timeout: float,
        harness_ceiling: float | None,
        sink_port: int,
        probe_only: bool = False,
        unavailable: list | None = None,
        base_ref: str = "",
        candidate_revision: str = "",
    ):
        self.root = root
        self.workdir = workdir
        self.binaries = binaries
        self.server_core = server_core
        self.runs = runs
        self.bytes_override = bytes_override
        self.iterations_override = iterations_override
        self.timeout = timeout
        self.harness_ceiling = harness_ceiling
        self.sink_port = sink_port
        self._loadgen_fault: str = ""
        self._reality_dest_port: int | None = None
        self._reality_dest: "TlsDest | None" = None
        self.probe_only = probe_only
        self.loadgen = self._find_loadgen()
        self.identity = configs.generate_identity(
            workdir / "fixture", with_mldsa=True
        )
        self.result = Result(
            started=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            host=describe_host(),
            invocation=list(sys_argv()),
            binaries=[b.summary() for b in binaries.values()],
            server_core=server_core,
            base_ref=base_ref,
            candidate_revision=candidate_revision,
            probe_only=probe_only,
            identity=self.identity.summary(),
            harness_ceiling_mbps=harness_ceiling,
        )
        for entry in unavailable or []:
            self.result.unavailable.append(
                entry.as_dict() if hasattr(entry, "as_dict") else dict(entry)
            )
        if probe_only:
            self.result.ceiling_note = (
                "not measured: a capability probe moves no traffic, so there is "
                "nothing for the ceiling to bound"
            )
        for entry in self.result.unavailable:
            self.result.notes.append(
                f"{entry['core']} was not measured: {entry['reason']}"
            )
        base = self.binaries.get(caps.BASE_ID)
        if base is not None:
            self.result.base_ref = base.source_ref or base_ref
            self.result.base_revision = base.source_revision
            if base_ref:
                # A caller-supplied base binary carries no revision, so the ref is
                # resolved separately. When the harness built the binary itself
                # the two have to agree: a base binary from one commit wearing
                # another's name is the worst combination available here, because
                # the ratio is real and the caption is wrong.
                resolved = cores.git(root, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
                if not self.result.base_revision:
                    self.result.base_revision = resolved
                elif resolved and resolved != self.result.base_revision:
                    self.result.notes.append(
                        f"the base binary reports commit {self.result.base_revision} "
                        f"but {base_ref} resolves to {resolved}; the comparison is "
                        f"against the binary, and the ref is recorded as given"
                    )
        if candidate_revision:
            self.result.candidate_revision = candidate_revision
            candidate = self.binaries.get("zray")
            if candidate is not None and candidate.source_revision and (
                not candidate.source_revision.startswith(candidate_revision[:12])
            ):
                self.result.notes.append(
                    f"the candidate binary reports commit "
                    f"{candidate.source_revision} but the checkout is at "
                    f"{candidate_revision}; the numbers are from the binary and the "
                    f"revision names the checkout"
                )
        if not self.identity.mldsa_seed:
            self.result.notes.append(
                "OpenSSL 3.5 or newer was not available, so the ML-DSA-65 REALITY "
                "scenario was not generated. Every other row is unaffected."
            )
        self._sinks: list[subprocess.Popen] = []
        self._ceilings: dict[int, float | None] = {}
        self._server: cores.CoreProcess | None = None

    # -- setup ---------------------------------------------------------------

    def _find_loadgen(self) -> Path:
        given = os.environ.get("LOADGEN")
        candidates = [
            Path(given) if given else None,
            self.root / "docs" / "benchmarks" / "harness" / "loadgen" / "target" / "release" / "loadgen",
        ]
        for path in candidates:
            if path and path.exists():
                return path
        log("building loadgen")
        cores.run(
            ["cargo", "build", "--release"],
            cwd=self.root / "docs" / "benchmarks" / "harness" / "loadgen",
            timeout=900,
        )
        built = self.root / "docs" / "benchmarks" / "harness" / "loadgen" / "target" / "release" / "loadgen"
        if not built.exists():
            raise SystemExit(f"loadgen was not produced at {built}")
        return built

    def start_sink(self) -> None:
        tcp = subprocess.Popen(
            [str(self.loadgen), "sink", "--port", str(self.sink_port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        udp = subprocess.Popen(
            [str(self.loadgen), "sink-udp", "--port", str(self.sink_port + 1)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cores.CHILDREN.add(tcp)
        cores.CHILDREN.add(udp)
        self._sinks = [tcp, udp]
        if not cores.wait_for_port(self.sink_port, tcp, timeout=10):
            raise SystemExit("the data sink did not start")

    def stop_sink(self) -> None:
        if self._reality_dest_port is not None:
            self._reality_dest.stop()
            self._reality_dest_port = None
        for proc in getattr(self, "_sinks", []):
            cores._terminate(proc)
            cores.CHILDREN.discard(proc)

    def ceiling_for(self, streams: int) -> float | None:
        """What the harness alone can do, for this stream count.

        Measured per stream count rather than once, because the ceiling is a
        property of the loop and the loop is different at one flow and at
        sixty-four. A core that reaches this number is limited by the generator,
        and the report says so rather than implying the core could go faster.
        """
        if streams in self._ceilings:
            return self._ceilings[streams]
        if self.harness_ceiling:
            # An operator-supplied ceiling applies to every stream count: it is
            # a statement about the host, not a measurement.
            self._ceilings[streams] = self.harness_ceiling
            return self.harness_ceiling
        out = self._loadgen(
            ["selftest", "--target", f"127.0.0.1:{self.sink_port}",
             "--bytes", "1G", "--streams", str(streams), "--json"],
            timeout=self.timeout,
        )
        value = (out or {}).get("throughput_mbps")
        self._ceilings[streams] = value
        if value:
            self.result.harness_ceilings[str(streams)] = round(value, 3)
            # A summary, not the value any row is judged on: each row uses the
            # ceiling measured at its own stream count.
            if self.result.harness_ceiling_mbps is None:
                self.result.harness_ceiling_mbps = value
                self.result.ceiling_note = (
                    f"measured with the same validated loop and no core in the "
                    f"path, on this host, at {streams} stream(s); every stream "
                    f"count a scenario uses is measured separately, and each row "
                    f"is compared against the ceiling at its own stream count"
                )
            log(f"harness ceiling at {streams} stream(s): {value / 1000:.1f} Gbps")
        else:
            self.result.notes.append(
                f"the harness ceiling was not measured at {streams} stream(s); "
                f"rows at that stream count are unbounded by any ceiling"
            )
            if self.result.harness_ceiling_mbps is None:
                self.result.ceiling_note = (
                    f"not measured at {streams} stream(s): the load generator did "
                    f"not return a rate, so the rows are unbounded by any ceiling"
                )
        return value

    # -- loadgen -------------------------------------------------------------

    def _loadgen(self, args: list[str], *, timeout: float) -> dict | None:
        """Run the generator and parse its JSON.

        Three outcomes are deliberately kept apart. Only the first is a timeout;
        a generator that exits non-zero or prints malformed JSON has crashed or
        misbehaved, and the caller used to be told it had run out of time -- which
        sends a reader looking at a core that was never the problem. The reason is
        returned alongside so `run_cell` can report which one happened.
        """
        self._loadgen_fault = ""
        try:
            proc = subprocess.run(
                [str(self.loadgen), *args], capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            self._loadgen_fault = f"the load generator did not finish within {timeout:.0f}s"
            return None
        text = proc.stdout.strip()
        if proc.returncode != 0:
            # The generator prints its whole JSON report, and the part that
            # explains the failure is the `errors` array at the end. Leading with
            # the preamble meant a 300-character reason filled with schema and
            # byte counts and cut off before the first error, so a failing cell
            # said nothing about why it failed.
            detail = _first_errors(text) or (proc.stderr or "").strip()
            self._loadgen_fault = (
                f"the load generator exited {proc.returncode}: "
                f"{detail[:300] or 'no output'}"
            )
            return None
        if not text:
            self._loadgen_fault = "the load generator printed nothing"
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            self._loadgen_fault = (
                f"the load generator printed output that is not JSON ({exc.msg} at "
                f"position {exc.pos}): {text[:200]!r}"
            )
            return None

    # -- server --------------------------------------------------------------

    def reality_dest_port(self) -> int:
        """A port serving TLS, for the links whose server needs one.

        REALITY does not terminate TLS itself: the server proxies the client's
        ClientHello to `dest` and presents the certificate that comes back, which
        is what makes an unauthenticated prober see a real website. So `dest`
        has to answer a TLS handshake, and the traffic sink cannot, because it
        speaks a length-prefixed keystream rather than TLS. Pointing `dest` at
        the sink made every REALITY handshake fail on every core -- the server
        logged the dial failing and closed the connection.

        The listener only completes the handshake and closes. That is enough:
        the certificate is all the server takes from it.
        """
        if self._reality_dest_port is None:
            self._reality_dest = TlsDest(
                self.identity.cert_pem, self.identity.key_pem, workdir=self.workdir
            )
            self._reality_dest_port = self._reality_dest.start()
        return self._reality_dest_port

    def start_server(self, link: Link) -> tuple[cores.CoreProcess | None, int, str]:
        """Start the single server every client in this link's cells talks to."""
        binary = self.binaries[self.server_core]
        reason = binary.core.why_not_server(
            link.protocol, link.transport, link.security
        )
        if reason:
            return None, 0, reason
        port = cores.free_port()
        try:
            handshake_port = (
                self.reality_dest_port() if link.security == "reality" else self.sink_port
            )
            config = configs.server_config(
                binary.core.dialect, link, self.identity, port, handshake_port
            )
        except configs.UnsupportedShape as exc:
            return None, 0, str(exc)
        path = configs.write_config(
            self.workdir / "configs" / f"server-{link.name()}.json", config
        )
        check = cores.check_config(binary.core, binary.path, path)
        if not check.ok:
            return None, 0, f"server config rejected: {check.diagnostic}"
        proc = cores.start(
            binary, path, self.workdir / "logs" / f"server-{link.name()}.log"
        )
        # A QUIC-based protocol and XHTTP over HTTP/3 both listen on UDP, so a
        # TCP probe can never succeed for them. For those, staying up past a
        # short settle is the only evidence available, and the report records
        # that the readiness check was the weaker one.
        ready = False
        if link.quic_based or link.transport == "xhttp-h3":
            time.sleep(1.5)
            ready = proc.proc.poll() is None
        else:
            ready = cores.wait_for_port(port, proc.proc, timeout=20)
        if not ready:
            detail = proc.log_tail(300) if proc.proc.poll() is not None else "never listened"
            proc.stop()
            return None, 0, f"server did not start listening ({detail})"
        self._server = proc
        return proc, port, ""

    # -- one cell ------------------------------------------------------------

    def run_cell(
        self,
        scenario: matrix.Scenario,
        core_id: str,
        repeat: int,
        server_port: int,
        server_link_id: str,
    ) -> Cell:
        binary = self.binaries[core_id]
        cell = Cell(
            scenario=scenario.id,
            group=scenario.group,
            link=server_link_id,
            workload=scenario.workload,
            core=core_id,
            repeat=repeat,
            status=STATUS_SKIPPED,
            streams=scenario.streams,
        )

        prior = binary.core.why_not(
            scenario.link.protocol, scenario.link.transport, scenario.link.security
        )

        # The capability probe: generate the config even when the prior says the
        # core cannot run it, and let the core's own config checker decide. A
        # prior is a claim; this is the evidence. Without it, every negative in
        # the matrix would be a belief about someone else's parser.
        try:
            config = configs.client_config(
                binary.core.dialect,
                scenario.link,
                self.identity,
                cores.free_port(),
                server_port,
                self.sink_port,
            )
        except configs.UnsupportedShape as exc:
            # The harness cannot write this combination in this core's dialect.
            # That is a different fact from the core not supporting it, and the
            # two are kept apart in the report.
            cell.status = STATUS_UNSUPPORTED
            cell.reason = (
                f"the harness has no {binary.core.dialect} spelling for "
                f"{scenario.link.name()}: {exc}"
            )
            return cell

        proxy_port = config["inbounds"][0].get("port") or config["inbounds"][0].get(
            "listen_port"
        )
        path = configs.write_config(
            self.workdir / "configs" / f"client-{scenario.id}-{core_id}.json", config
        )
        check = cores.check_config(binary.core, binary.path, path)
        if not check.ok:
            cell.diagnostic = check.diagnostic
            if prior:
                cell.status = STATUS_UNSUPPORTED_CONFIRMED
                cell.reason = prior
            else:
                cell.status = STATUS_ERROR
                cell.reason = "config rejected despite the capability table claiming support"
            return cell
        if prior:
            # The prior said no, the core's own checker said yes. Believe the
            # checker, and say that the table was wrong.
            cell.status = STATUS_MEASURED
            self.result.notes.append(
                f"{binary.core.label} accepted {scenario.id}, which the capability "
                f"table listed as unsupported ({prior}). The table is out of date."
            )
        if self.probe_only:
            cell.status = STATUS_ACCEPTED
            cell.reason = "config accepted by the core's own validator; no traffic"
            return cell

        proc = cores.start(
            binary, path, self.workdir / "logs" / f"client-{scenario.id}-{core_id}.log"
        )
        server_proc = self._server
        server_sampler = (
            measure.Sampler(server_proc.pid) if server_proc is not None else None
        )
        try:
            if not cores.wait_for_port(int(proxy_port), proc.proc, timeout=25):
                cell.status = STATUS_ERROR
                cell.reason = "the client's local proxy port never accepted a connection"
                cell.diagnostic = proc.log_tail(400)
                return cell

            # Idle memory is read before any traffic, with a settle pause: a core
            # that is still finishing its own start-up work would otherwise look
            # like a core that needs more memory.
            time.sleep(0.7)
            cell.rss_idle_mb = _mb(measure.read_rss_kb(proc.pid))
            cell.rss_peak_reported_mb = _mb(measure.read_hwm_kb(proc.pid))

            # The server is sampled inside the client's window, not from the
            # moment the client process was launched. Started alongside the
            # process, its window also covered the client's port wait and settle
            # sleep, so a column labelled "CPU used by the server during this
            # scenario" was measuring a longer period than the client's, and its
            # peak memory could only be inflated by that extra time.
            if server_sampler is not None:
                server_sampler.__enter__()
            try:
                with measure.Sampler(proc.pid) as sampler:
                    output = self._run_workload(scenario, int(proxy_port))
                    window = measure.summarise(sampler.samples, proc.pid)
                    if server_sampler is not None:
                        server_window = measure.summarise(server_sampler.samples, server_proc.pid)
                        cell.server_cpu_s = server_window.cpu_s
                        cell.server_rss_peak_mb = server_window.rss_peak_mb
            finally:
                if server_sampler is not None:
                    server_sampler.__exit__(None, None, None)
            cell.samples = window.samples
            if window.missing:
                # Too few readings to have measured a difference. Recorded so the
                # report can say so rather than print the zero the window carries
                # for want of anything to compute.
                cell.notes = (
                    f"{window.samples} sample(s) were taken, which is too few to "
                    f"measure a difference, so its CPU and memory read as unmeasured"
                )
            if sampler.error:
                cell.diagnostic = sampler.error
            if output is None:
                # Whether this was a hang or a crash changes what it means, and
                # only the generator knows which.
                fault = self._loadgen_fault or f"the load generator failed within {self.timeout:.0f}s"
                cell.status = (
                    STATUS_TIMEOUT if fault.startswith("did not finish") else STATUS_ERROR
                )
                cell.reason = fault
                cell.diagnostic = proc.log_tail(400)
                return cell
            if output.get("errors"):
                errors = [str(e) for e in output["errors"]]
                # EAGAIN on a timed socket is the deadline expiring, not a
                # shortage: a stalled core reads differently from a refused one.
                stalled = all("temporarily unavailable" in e for e in errors)
                cell.status = STATUS_TIMEOUT if stalled else STATUS_ERROR
                cell.reason = (
                    f"the core stopped sending for longer than the transfer's "
                    f"deadline ({len(errors)} of "
                    f"{len(errors)} flows); {errors[0][:300]}"
                    if stalled
                    else "; ".join(errors[:3])[:400]
                )
                cell.diagnostic = proc.log_tail(400)
                return cell

            self._fill(cell, output, window)
            cell.status = STATUS_MEASURED
        finally:
            proc.stop()
        return cell

    def _run_workload(self, scenario: matrix.Scenario, proxy_port: int) -> dict | None:
        target = f"127.0.0.1:{self.sink_port}"
        base = [
            "run",
            "--proxy", f"127.0.0.1:{proxy_port}",
            "--target", target,
            "--handshake-timeout-ms", "15000",
        ]
        if scenario.workload == matrix.LATENCY:
            return self._loadgen(
                base + [
                    "--mode", "latency",
                    "--iterations", str(scenario.default_iterations(self.iterations_override)),
                    "--warmup", "50",
                    "--json",
                ],
                timeout=self.timeout,
            )
        if scenario.workload == matrix.UDP:
            return self._loadgen(
                base + [
                    "--mode", "udp-latency",
                    "--iterations", str(scenario.default_iterations(self.iterations_override)),
                    "--warmup", "20",
                    "--json",
                ],
                timeout=self.timeout,
            )
        if scenario.workload == matrix.CHURN:
            # An 8-byte payload keeps the row about connection setup: any
            # transfer that happens is one RTT's worth of framing.
            return self._loadgen(
                base + [
                    "--mode", "latency",
                    "--payload", str(scenario.default_payload()),
                    "--iterations", str(scenario.default_iterations(self.iterations_override)),
                    "--warmup", "50",
                    "--json",
                ],
                timeout=self.timeout,
            )
        if scenario.workload == matrix.HOLD:
            args = [
                "--mode", "hold",
                "--streams", str(scenario.streams),
                "--hold-ms", str(scenario.hold_ms or 5000),
            ]
            if scenario.ramp_us:
                # Opening every flow in the same millisecond would measure the
                # listen backlog rather than the core.
                args += ["--ramp-us", str(scenario.ramp_us)]
            return self._loadgen(base + args + ["--json"], timeout=self.timeout)
        return self._loadgen(
            base + [
                "--mode", scenario.workload,
                "--bytes", str(scenario.default_bytes(self.bytes_override)),
                "--streams", str(scenario.streams),
                "--json",
            ],
            timeout=self.timeout,
        )

    def _fill(self, cell: Cell, output: dict, window: measure.Window) -> None:
        cell.throughput_mbps = output.get("throughput_mbps")
        cell.MBps = output.get("MBps")
        cell.bytes_moved = output.get("bytes_moved")
        cell.transfer_ms = output.get("transfer_ms")
        cell.total_ms = output.get("total_ms")
        latency = output.get("latency_us") or {}
        cell.latency_us_median = latency.get("median")
        cell.latency_us_p95 = latency.get("p95")
        cell.flows_opened = output.get("flows_opened")
        cell.open_ms = output.get("open_ms")
        wall_ms = output.get("wall_ms") or output.get("total_ms") or 0.0
        if cell.workload in (matrix.LATENCY, matrix.CHURN, matrix.UDP, "passthrough"):
            # `iterations` is already the number the generator recorded; the warmup
            # iterations are never counted in it. Subtracting them again dropped
            # the numerator, and dividing by a window that includes the warmup
            # dropped it again -- together, a 5% low reading on every setup row.
            # The generator reports the measured window separately for this.
            measured_ms = output.get("measured_ms")
            iterations = output.get("iterations") or 0
            if iterations > 0 and measured_ms:
                cell.ops_per_s = round(iterations / (measured_ms / 1000.0), 1)
            elif iterations > 0 and wall_ms:
                cell.ops_per_s = round(iterations / (wall_ms / 1000.0), 1)
        connect = output.get("connect_us")
        if isinstance(connect, dict):
            total = connect.get("total")
            if isinstance(total, dict):
                cell.connect_us_median = total.get("median")
            else:
                cell.connect_us_median = connect.get("median")
            stages = connect.get("stages")
            if isinstance(stages, dict):
                for stage, key in (
                    ("tcp_connect", "tcp_connect_us_median"),
                    ("socks_connect", "socks_connect_us_median"),
                ):
                    value = stages.get(stage)
                    if isinstance(value, dict):
                        setattr(cell, key, value.get("median"))
        cell.cpu_s = window.cpu_s
        cell.cpu_s_per_GB = window.cpu_s_per_gb(cell.bytes_moved or 0)
        cell.rss_peak_mb = window.rss_peak_mb
        if window.rss_hwm_kb:
            cell.rss_peak_reported_mb = window.rss_hwm_kb / 1024.0
        cell.threads_peak = window.threads_peak
        cell.harness_ceiling_mbps = self._ceilings.get(cell.streams)

    # -- the loop ------------------------------------------------------------

    def order_for_repeat(self, core_ids: list[str], repeat: int) -> list[str]:
        """Rotate, then reverse on alternate repeats.

        Rotation means no core keeps the coldest slot; reversal means no core
        keeps the position that follows another core's burst of work. Both are
        needed: rotation alone leaves "second" systematically warm, and reversal
        alone leaves "first" systematically cold.
        """
        if not core_ids:
            return []
        offset = repeat % len(core_ids)
        rotated = core_ids[offset:] + core_ids[:offset]
        if repeat % 2 == 1:
            rotated.reverse()
        return rotated

    def run_matrix(self, scenarios: list[matrix.Scenario]) -> None:
        core_ids = list(self.binaries)
        links = matrix.links_in(scenarios)
        log(f"{len(scenarios)} scenarios, {len(links)} links, {len(core_ids)} cores, {self.runs} repeats")

        for link in links:
            group = [s for s in scenarios if s.link == link]
            server, server_port, why = self.start_server(link)
            if server is None:
                for scenario in group:
                    for core_id in core_ids:
                        cell = Cell(
                            scenario=scenario.id,
                            group=scenario.group,
                            link=link.name(),
                            workload=scenario.workload,
                            core=core_id,
                            repeat=0,
                            status=STATUS_UNSUPPORTED,
                            reason=f"the {self.server_core} server cannot serve this link: {why}",
                        )
                        self.result.cells.append(cell)
                log(f"skip {link.name()}: {why}")
                continue
            try:
                self._run_group(group, link, server_port, core_ids)
            finally:
                server.stop()
                self._server = None
            log(f"done {link.name()}")

    def _run_group(
        self,
        group: list[matrix.Scenario],
        link: Link,
        server_port: int,
        core_ids: list[str],
    ) -> None:
        for scenario in group:
            if scenario.workload in (matrix.DOWN, matrix.UP, matrix.DUPLEX):
                self.ceiling_for(scenario.streams)
            for repeat in range(self.runs):
                for core_id in self.order_for_repeat(core_ids, repeat):
                    cell = self.run_cell(scenario, core_id, repeat, server_port, link.name())
                    self.result.cells.append(cell)
                    log(
                        f"  {scenario.id} [{core_id}] rep{repeat}: "
                        + describe_cell(cell)
                    )

    # -- user configs --------------------------------------------------------

    def materialise(self, config: userconfig.UserConfig) -> userconfig.UserConfig:
        """Turn a share link or a subscription into a configuration, once.

        Almost nobody has a JSON configuration to hand; almost everybody has a
        link. Translating a link per core would compare the four link parsers
        instead of the four transports, and a mistranslation would be reported
        as a missing feature. So the link is converted once, with Zray's own
        parser, and the resulting file is what every core is given. The report
        states that this happened, because a reader comparing two rows knows
        whether the transport or the parser was under test.
        """
        if config.kind not in ("link", "subscription"):
            return config
        zray = self.binaries.get("zray")
        if zray is None:
            config.problems = [
                "a share link needs Zray's `preset` to become a configuration, and "
                "Zray was not among the cores for this run"
            ]
            return config
        target = self.workdir / "user-configs" / f"{config.name}-from-link.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [str(zray.path), "preset", "iran", str(config.path),
             "--no-assets", "-o", str(target)],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0 or not target.exists():
            detail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-300:]
            config.problems = [f"`zray preset` could not read it: {detail}"]
            return config
        produced = userconfig.load_file(target)
        produced.name = config.name
        produced.source = (
            f"{config.source or config.path} -> generated by `zray preset iran`"
        )
        return produced

    def run_user_config(self, config: userconfig.UserConfig, core_id: str) -> Cell:
        """Measure a supplied config in place, under one core."""
        binary = self.binaries[core_id]
        cell = Cell(
            scenario=f"user:{config.name}",
            group="user",
            link="user",
            workload="passthrough",
            core=core_id,
            repeat=0,
            status=STATUS_SKIPPED,
            streams=USER_CONFIG_STREAMS,
        )
        if not config.runnable:
            cell.status = STATUS_SKIPPED
            cell.reason = "; ".join(config.problems)
            return cell
        check = cores.check_config(binary.core, binary.path, config.path)
        if not check.ok:
            cell.status = STATUS_UNSUPPORTED_CONFIRMED
            cell.reason = "the core's own config checker rejected this file"
            cell.diagnostic = check.diagnostic
            return cell

        proc = cores.start(
            binary, config.path, self.workdir / "logs" / f"user-{config.name}-{core_id}.log"
        )
        try:
            port = int(config.proxy_port)
            if not cores.wait_for_port(port, proc.proc, timeout=25):
                cell.status = STATUS_ERROR
                cell.reason = "the config's local proxy port never accepted a connection"
                cell.diagnostic = proc.log_tail(400)
                return cell
            time.sleep(0.7)
            cell.rss_idle_mb = _mb(measure.read_rss_kb(proc.pid))
            if config.can_transfer:
                # The cell says which measurement it is, so the row's headline
                # follows from the workload alone rather than from a guess made
                # later about what the cells happen to hold.
                cell.workload = "passthrough"
                target = f"{config.measure_host}:{config.measure_port}"
                args = [
                    "--target", target,
                    "--mode", "down",
                    "--bytes", str(self.bytes_override or 128 * 1024 * 1024),
                    "--streams", str(USER_CONFIG_STREAMS),
                ]
                ceiling = self.ceiling_for(USER_CONFIG_STREAMS)
            else:
                cell.workload = "tunnel"
                # With no destination named, the tunnel itself is what gets
                # measured: the only endpoint a config names is its own proxy
                # server, which does not speak the harness's protocol.
                target = f"{config.target_host}:{config.target_port}"
                args = [
                    "--target", target,
                    "--mode", "probe",
                    "--iterations", "200",
                    "--warmup", "10",
                ]
                ceiling = None
            with measure.Sampler(proc.pid) as sampler:
                output = self._loadgen(
                    [
                        "run",
                        "--proxy", f"127.0.0.1:{port}",
                        *args,
                        "--handshake-timeout-ms", "20000",
                        "--json",
                    ],
                    timeout=self.timeout,
                )
                window = measure.summarise(sampler.samples, proc.pid)
            if output is None:
                # Same distinction as the matrix: a hang and a crash are different
                # findings, and only the generator can say which one happened.
                fault = self._loadgen_fault or "the load generator failed"
                cell.status = (
                    STATUS_TIMEOUT if fault.startswith("did not finish") else STATUS_ERROR
                )
                cell.reason = fault
                return cell
            if output.get("errors"):
                errors = [str(e) for e in output["errors"]]
                # EAGAIN on a timed socket is the deadline expiring, not a
                # shortage: a stalled core reads differently from a refused one.
                stalled = all("temporarily unavailable" in e for e in errors)
                cell.status = STATUS_TIMEOUT if stalled else STATUS_ERROR
                cell.reason = (
                    f"the core stopped sending for longer than the transfer's "
                    f"deadline ({len(errors)} of "
                    f"{len(errors)} flows); {errors[0][:300]}"
                    if stalled
                    else "; ".join(errors[:3])[:400]
                )
                cell.diagnostic = proc.log_tail(400)
                return cell
            self._fill(cell, output, window)
            if not config.can_transfer:
                # The tunnel time is the measurement here, so it is read from the
                # probe's own distribution rather than left only in the raw output.
                tunnel = output.get("tunnel_us") or {}
                cell.latency_us_median = tunnel.get("median")
                cell.latency_us_p95 = tunnel.get("p95")
                cell.throughput_mbps = None
                if cell.harness_ceiling_mbps is not None and ceiling is None:
                    cell.harness_ceiling_mbps = None
            cell.status = STATUS_MEASURED
            cell.reason = (
                f"transferred to {config.measure_host}:{config.measure_port}"
                if config.can_transfer
                else f"tunnel to {config.target_host}:{config.target_port}; no "
                f"destination was supplied, so no bytes were moved"
            )
        finally:
            proc.stop()
        return cell

    def finish(self) -> None:
        self.stop_sink()
        self.result.finished = time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _first_errors(text: str) -> str:
    """The generator's own first error, if it printed a JSON report."""
    try:
        report = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return ""
    errors = report.get("errors") or ([report["error"]] if report.get("error") else [])
    return "; ".join(str(e) for e in errors[:3])


def _mb(kb: float | None) -> float | None:
    return None if kb is None else round(kb / 1024.0, 3)


def describe_cell(cell: Cell) -> str:
    """One line per cell, showing the number the row is actually about."""
    if cell.status != STATUS_MEASURED:
        return f"{cell.status}: {cell.reason or cell.diagnostic}"[:200]
    # A measured cell with no number is a capability probe, and its reason says
    # so; printing "no samples" there would read as a failed measurement.
    if cell.reason and cell.throughput_mbps is None and cell.rss_peak_mb is None:
        return cell.reason
    if cell.workload in (matrix.LATENCY, matrix.CHURN, matrix.UDP):
        median = cell.latency_us_median
        rtt = f"{median:,.0f} us" if median is not None else "no samples"
        rate = f", {cell.ops_per_s:,.0f}/s" if cell.ops_per_s else ""
        return f"{rtt}{rate}"
    if cell.workload == matrix.HOLD:
        opened = f"{cell.flows_opened} flows" if cell.flows_opened is not None else "flows"
        return f"{opened}, peak {cell.rss_peak_mb:.1f} MB" if cell.rss_peak_mb else opened
    if cell.throughput_mbps is None:
        return cell.reason or "no throughput recorded"
    parts = [f"{cell.throughput_mbps:,.0f} Mbit/s"]
    if cell.cpu_s_per_GB is not None:
        parts.append(f"{cell.cpu_s_per_GB:.2f} CPU-s/GB")
    if cell.rss_peak_mb:
        parts.append(f"peak {cell.rss_peak_mb:.0f} MB")
    return ", ".join(parts)


def sys_argv() -> list[str]:
    return ["python3", *os.sys.argv[1:]]
