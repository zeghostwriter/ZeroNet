"""Sampling a running core's memory and CPU while traffic flows.

The numbers that decide which core is cheaper are properties of a *process*, so
they are read from the OS rather than inferred from anything the core reports:

* resident set size, sampled;
* cumulative CPU time, differenced across the sample window;
* thread count, where the platform exposes it.

Two deliberate choices:

* **Peak is the maximum of the samples**, not `VmHWM`, so the number means the
  same thing on every platform this harness runs on. `VmHWM` is recorded
  separately on Linux because it is a better measurement, and the two are
  reported as different fields rather than silently merged.
* **CPU is a difference, not a total.** A process that was already busy before
  the sample started would otherwise be charged for work this benchmark did not
  ask for, which is exactly how a core with a busy background task looks
  faster than one without.

The server process is sampled too. It shares loopback CPU with the client even
though it is not the thing under test, and leaving that unstated is how a
loopback number ends up meaning "the pair, on this host".
"""

from __future__ import annotations

import os
import platform
import subprocess
import threading
import time
from dataclasses import dataclass

IS_LINUX = platform.system() == "Linux"
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024 if hasattr(os, "sysconf") else 4
CLOCK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

# Linux reports /proc/<pid>/stat times in clock ticks; macOS `ps time` is
# "D-HH:MM:SS.ss" or "MM:SS.ss". Sampling more finely than the tick would only
# produce repeated values.
DEFAULT_INTERVAL = 0.05 if IS_LINUX else 0.2

#: Consecutive failed reads before sampling gives up on a live process. One is
#: ordinary contention; a run of them means sampling is not working.
MISSES_BEFORE_GIVING_UP = 5


@dataclass
class Sample:
    at: float
    rss_kb: float
    cpu_s: float
    threads: int | None


def _read_linux(pid: int) -> tuple[float, int | None] | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    # The comm field can contain spaces and parentheses, so the fields after it
    # are located from the *last* ')'. Getting this wrong silently reports
    # another process's numbers.
    end = data.rfind(b")")
    if end < 0:
        return None
    fields = data[end + 2 :].split()
    if len(fields) < 19:
        return None
    utime = int(fields[11])
    stime = int(fields[12])
    return (utime + stime) / CLOCK_TCK, int(fields[17])


def _read_linux_rss(pid: int) -> float | None:
    try:
        with open(f"/proc/{pid}/statm", "rb") as fh:
            fields = fh.read().split()
    except OSError:
        return None
    if len(fields) < 2:
        return None
    return int(fields[1]) * PAGE_KB


def _read_linux_hwm(pid: int) -> float | None:
    try:
        with open(f"/proc/{pid}/status", "r") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return float(line.split()[1])
    except OSError:
        pass
    return None


def _ps_time_to_seconds(text: str) -> float | None:
    """Parse `ps -o time=` into seconds.

    The format grows a day field once a process has been alive long enough, and
    a benchmark session can easily cross that boundary on a slow runner.
    """
    text = text.strip()
    if not text:
        return None
    days = 0
    if "-" in text:
        day_part, text = text.split("-", 1)
        try:
            days = int(day_part)
        except ValueError:
            return None
    parts = text.split(":")
    try:
        if len(parts) == 3:
            hours, minutes, seconds = parts
        elif len(parts) == 2:
            hours, minutes, seconds = "0", parts[0], parts[1]
        else:
            return None
        return days * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    except ValueError:
        return None


def _read_darwin(pid: int) -> tuple[float, float, int | None] | None:
    try:
        proc = subprocess.run(
            ["ps", "-o", "rss=", "-o", "time=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    parts = proc.stdout.split()
    if len(parts) < 2:
        return None
    try:
        rss = float(parts[0])
    except ValueError:
        return None
    cpu = _ps_time_to_seconds(parts[1])
    if cpu is None:
        return None
    # `ps` does not report a thread count here, so this stays None rather than a
    # placeholder zero that a consumer would read as "measured, and it was none".
    return rss, cpu, None


def read_once(pid: int) -> Sample | None:
    if IS_LINUX:
        cpu = _read_linux(pid)
        if cpu is None:
            return None
        cpu_s, threads = cpu
        rss = _read_linux_rss(pid)
        if rss is None:
            return None
    else:
        values = _read_darwin(pid)
        if values is None:
            return None
        rss, cpu_s, threads = values
    # Timestamped after the read, not before: on macOS this is a `ps` fork, and a
    # timestamp taken first would understate when the counters were actually read.
    return Sample(at=time.monotonic(), rss_kb=rss, cpu_s=cpu_s, threads=threads)


def read_rss_kb(pid: int) -> float | None:
    sample = read_once(pid)
    return sample.rss_kb if sample else None


def read_hwm_kb(pid: int) -> float | None:
    return _read_linux_hwm(pid) if IS_LINUX else None


def pid_alive(pid: int) -> bool:
    """Whether the process still exists, which is not the same as readable.

    A failed read has two very different causes -- a dead process and a slow or
    contended one -- and only the first is a finding. This distinguishes them
    without depending on the sampling read succeeding.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class Sampler:
    """Polls one pid until stopped, then reports what it saw.

    A `with` block, because the failure mode of getting this wrong is a sampling
    thread that outlives the measurement and keeps a dead pid in a loop.
    """

    def __init__(self, pid: int, interval: float | None = None):
        self.pid = pid
        self.interval = interval or DEFAULT_INTERVAL
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.samples: list[Sample] = []
        self.error: str | None = None

    def __enter__(self) -> "Sampler":
        # The baseline is read here, synchronously, before the caller starts the
        # workload. Left to the thread, the first read races the workload it is
        # supposed to precede, and a transfer quicker than one sampling interval
        # produced a single sample -- no window at all, so a fast core reported
        # zero CPU rather than a small number it had not measured.
        baseline = read_once(self.pid)
        if baseline is not None:
            self.samples.append(baseline)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _loop(self) -> None:
        misses = 0
        while not self._stop.is_set():
            sample = read_once(self.pid)
            if sample is None:
                # A failed read is not the same as a dead process. On macOS this
                # is a `ps` fork per sample, and one slow fork was ending the
                # series and filing the cell as "process disappeared" while the
                # process was still running. Only the process actually being gone
                # is that finding, and `pid_alive` is the only thing that says so.
                misses += 1
                if not pid_alive(self.pid):
                    self.error = "process disappeared while sampling"
                    return
                if misses >= MISSES_BEFORE_GIVING_UP:
                    self.error = (
                        f"{misses} consecutive sample reads failed while the "
                        f"process was still running"
                    )
                    return
                self._stop.wait(self.interval)
                continue
            misses = 0
            self.samples.append(sample)
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        # One last read, so the CPU window ends at the workload rather than up to
        # one interval before it. The counters are cumulative, so the window is
        # `last - first`; without a closing read that difference silently omits
        # the tail of the transfer, which is a fixed cost and proportionally the
        # largest on the shortest cells.
        final = read_once(self.pid)
        if final is not None:
            self.samples.append(final)


@dataclass
class Window:
    """A difference between two samples, which is the only honest form of CPU."""

    cpu_s: float
    rss_peak_kb: float
    rss_hwm_kb: float | None
    threads_peak: int | None
    samples: int
    missing: bool = False
    """True when there were too few readings to measure a difference.

    A window with fewer than two samples has no delta to report, and returning
    zero for it says a core used no CPU -- which is the one reading a reader
    cannot tell apart from a real zero. The flag exists so the report can say
    "not observed" instead.
    """

    @property
    def rss_peak_mb(self) -> float:
        return self.rss_peak_kb / 1024.0

    def cpu_s_per_gb(self, bytes_moved: int) -> float | None:
        if bytes_moved <= 0:
            return None
        gib = bytes_moved / (1024**3)
        if gib <= 0:
            return None
        return self.cpu_s / gib


def summarise(samples: list[Sample], pid: int | None = None) -> Window:
    if not samples:
        return Window(0.0, 0.0, None, None, 0, missing=True)
    if len(samples) < 2:
        # One sample is a single reading, not a difference. Returning 0.0 for the
        # CPU delta of a lone sample reports "this core used no CPU" for a core
        # that was never observed twice, which is the one reading a reader cannot
        # distinguish from a real zero.
        return Window(0.0, samples[-1].rss_kb, None, None, len(samples), missing=True)
    peak = max(s.rss_kb for s in samples)
    threads = [s.threads for s in samples if s.threads]
    return Window(
        # First and last cumulative CPU, in that order: a difference of a
        # cumulative counter is the window's cost and nothing else.
        cpu_s=max(0.0, samples[-1].cpu_s - samples[0].cpu_s),
        rss_peak_kb=peak,
        rss_hwm_kb=read_hwm_kb(pid) if pid else None,
        threads_peak=max(threads) if threads else None,
        samples=len(samples),
    )
