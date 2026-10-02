"""Finding, building, starting and stopping each proxy core.

The measurement model is process-per-core: every cell of the matrix is a real
proxy process with a real config, started and killed by this module. Nothing is
in-process, because the things worth comparing -- resident memory, CPU time,
thread count, how long the first byte takes -- are properties of a process, not
of a library.

Two rules the rest of the harness relies on:

* **A core is identified by its binary.** The path, the version string and the
  SHA-256 go into every result. A benchmark that cannot name the binary it
  measured is not reproducible, and a caller-supplied binary is only ever
  pinned by its digest, never by a source revision, because a binary does not
  carry one.
* **Every child is reaped.** `CoreProcess` kills and waits in a `finally`, and
  also on interpreter exit, so a timeout or an exception cannot leave a proxy
  running and quietly steal CPU from the next cell.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import caps

# ---------------------------------------------------------------------------


def _now() -> float:
    return time.monotonic()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def host_platform() -> str:
    """(os, arch) in the spelling the release assets use."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    if arch is None:
        raise SystemExit(f"unsupported architecture {machine!r}")
    return system, arch


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict | None = None,
    timeout: float = 600,
    check: bool = True,
    quiet: bool = True,
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"{argv[0]} failed with {proc.returncode}\n"
            f"  cmd: {' '.join(argv)}\n"
            f"  out: {proc.stdout[-2000:]}\n  err: {proc.stderr[-2000:]}"
        )
    if not quiet and proc.returncode != 0:
        print(proc.stderr[-2000:], file=sys.stderr)
    return proc


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------


#: A release archive or a config is small. Anything larger than this is a
#: redirect loop, a captive portal, or somebody else's idea of a release.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024


def fetch_url(url: str, dest: Path) -> None:
    """Download over HTTPS, refusing anything that is not.

    `curl` is used in preference to urllib for two reasons: every runner that can
    build these cores has it, and it has a working trust store even on hosts
    whose Python was built without one. urllib stays as the fallback so the
    harness is not curl-only.

    The flags are the ones that matter for fetching something that a benchmark
    will then execute: TLS 1.2 floor, no protocol downgrade, no cross-protocol
    redirect, a retry, and a size cap.
    """
    if not url.startswith("https://"):
        raise SystemExit(f"refusing to fetch {url!r}: only https is allowed")
    dest.parent.mkdir(parents=True, exist_ok=True)
    curl = shutil.which("curl")
    if curl:
        proc = subprocess.run(
            [
                curl, "--fail", "--location", "--silent", "--show-error",
                "--proto", "=https", "--tlsv1.2", "--retry", "3",
                "--max-time", "300", "--max-filesize", str(MAX_DOWNLOAD_BYTES),
                "--user-agent", "zray-bench",
                "--output", str(dest), url,
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return
        detail = (proc.stderr or "").strip()[-300:]
    else:
        detail = "curl is not installed"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "zray-bench"})
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            body = resp.read(MAX_DOWNLOAD_BYTES + 1)
        if len(body) > MAX_DOWNLOAD_BYTES:
            raise SystemExit(f"{url} is larger than {MAX_DOWNLOAD_BYTES} bytes")
        dest.write_bytes(body)
        return
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit(f"could not fetch {url}: {detail or exc}") from exc


def _fetch(url: str, dest: Path) -> None:
    fetch_url(url, dest)


def _unzip_first(archive: Path, member_suffix: str, dest: Path) -> Path:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.filename.endswith(member_suffix) and not info.is_dir():
                target = dest / Path(info.filename).name
                with zf.open(info) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out)
                target.chmod(0o755)
                return target
    raise SystemExit(f"no {member_suffix} inside {archive}")


def _untar_first(archive: Path, member_suffix: str, dest: Path) -> Path:
    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            if member.name.endswith(member_suffix) and member.isfile():
                target = dest / Path(member.name).name
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src, target.open("wb") as out:
                    shutil.copyfileobj(src, out)
                target.chmod(0o755)
                return target
    raise SystemExit(f"no {member_suffix} inside {archive}")


XRAY_ASSETS = {
    ("linux", "amd64"): "Xray-linux-64.zip",
    ("linux", "arm64"): "Xray-linux-arm64-v8a.zip",
    ("darwin", "amd64"): "Xray-macOS-64.zip",
    ("darwin", "arm64"): "Xray-macOS-arm64-v8a.zip",
    ("windows", "amd64"): "Xray-windows-64.zip",
    ("windows", "arm64"): "Xray-windows-arm64-v8a.zip",
}

SINGBOX_ASSETS = {
    ("linux", "amd64"): "linux-amd64",
    ("linux", "arm64"): "linux-arm64",
    ("darwin", "amd64"): "darwin-amd64",
    ("darwin", "arm64"): "darwin-arm64",
    ("windows", "amd64"): "windows-amd64",
    ("windows", "arm64"): "windows-arm64",
}


# ---------------------------------------------------------------------------
# Core binaries
# ---------------------------------------------------------------------------


@dataclass
class CoreBinary:
    core: caps.Core
    path: Path
    version: str
    digest: str
    origin: str
    """`provided`, `built` or `downloaded`. Recorded so a reader knows whether
    the binary is the project's own artifact or something the caller supplied."""
    version_note: str = ""
    """Where `version` came from. Empty means the binary printed it, which is the
    only claim strong enough to compare against a release note."""
    build_command: str = ""
    source_revision: str = ""
    """The commit the binary was built from, when the harness knows it. Empty for a
    binary the caller supplied: a path and a digest identify an artifact, but
    nothing inside a binary states which commit produced it."""
    source_ref: str = ""

    def summary(self) -> dict:
        return {
            "id": self.core.id,
            "source_revision": self.source_revision or None,
            "source_ref": self.source_ref or None,
            "label": self.core.label,
            "language": self.core.language,
            "version": self.version,
            "version_source": self.version_note or "binary",
            "binary_sha256": self.digest,
            "binary_path": str(self.path),
            "origin": self.origin,
            "build_command": self.build_command,
            "pinned_version": caps.PINS[self.core.id]["version"],
            "repo": caps.PINS[self.core.id]["repo"],
        }


def _probe_version(core: caps.Core, path: Path) -> tuple[str, str]:
    """(version, where it came from) for a binary.

    A failure here is recorded, not raised: a core that cannot print a version is
    still measurable, and refusing to measure it would be a worse outcome than
    reporting the version as unknown. xray-rust has no version flag at all, so
    for it the pin is the only version there is -- and saying "unknown" for a
    binary the harness itself checked out at a named tag throws away the one
    piece of provenance that exists.
    """
    for argv in (list(core.version_arg), [core.version_arg[0]], ["-v"], ["--version"]):
        try:
            proc = subprocess.run(
                [str(path), *argv],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        text = (proc.stdout or "") + (proc.stderr or "")
        first = next((line.strip() for line in text.splitlines() if line.strip()), "")
        if proc.returncode == 0 and first:
            return first[:200], "binary"
    pinned = caps.PINS.get(core.id, {}).get("version", "unknown")
    if pinned and not str(pinned).startswith("from "):
        return pinned, "pin: the binary prints no version, so this is the version it was built from"
    return "unknown", "unknown"


def resolve_zray(root: Path, given: Path | None, allow_build: bool) -> CoreBinary:
    path = given
    origin = "provided"
    build_command = ""
    if path is None:
        env = os.environ.get("ZRAY_BIN")
        path = Path(env) if env else root / "target" / "release" / "zray"
        if not path.exists():
            if not allow_build:
                raise SystemExit(
                    f"zray binary not found at {path}; build it with "
                    f"`cargo build --release -p zray-cli` or pass --bin-zray"
                )
            run(["cargo", "build", "--release", "-p", "zray-cli"], cwd=root, timeout=3600)
            origin = "built"
            build_command = "cargo build --release -p zray-cli"
    if not path.exists():
        raise SystemExit(f"zray binary not found: {path}")
    version, note = _probe_version(caps.ZRAY, path)
    return CoreBinary(
        core=caps.ZRAY,
        path=path,
        version=version,
        version_note=note,
        digest=sha256(path),
        origin=origin,
        build_command=build_command,
    )


def resolve_xray(bin_dir: Path, given: Path | None, allow_download: bool) -> CoreBinary:
    version = caps.PINS["xray"]["version"]
    path = given or _from_env("XRAY_BIN") or (bin_dir / "xray")
    origin = "provided"
    build_command = ""
    if not path.exists():
        if not allow_download:
            raise SystemExit(
                f"xray binary not found at {path}; pass --bin-xray or allow downloads"
            )
        system, arch = host_platform()
        asset = XRAY_ASSETS.get((system, arch))
        if asset is None:
            raise SystemExit(f"no Xray release asset for {system}/{arch}")
        url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}"
        archive = bin_dir / asset
        _fetch(url, archive)
        path = _unzip_first(archive, "xray.exe" if system == "windows" else "xray", bin_dir)
        archive.unlink(missing_ok=True)
        origin = "downloaded"
        build_command = f"downloaded {url}"
    version, note = _probe_version(caps.XRAY, path)
    return CoreBinary(
        core=caps.XRAY,
        path=path,
        version=version,
        version_note=note,
        digest=sha256(path),
        origin=origin,
        build_command=build_command,
    )


def resolve_singbox(bin_dir: Path, given: Path | None, allow_download: bool) -> CoreBinary:
    version = caps.PINS["singbox"]["version"]
    path = given or _from_env("SINGBOX_BIN") or (bin_dir / "sing-box")
    origin = "provided"
    build_command = ""
    if not path.exists():
        if not allow_download:
            raise SystemExit(
                f"sing-box binary not found at {path}; pass --bin-singbox or allow downloads"
            )
        system, arch = host_platform()
        suffix = SINGBOX_ASSETS.get((system, arch))
        if suffix is None:
            raise SystemExit(f"no sing-box release asset for {system}/{arch}")
        asset = f"sing-box-{version}-{suffix}.tar.gz"
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{asset}"
        archive = bin_dir / asset
        _fetch(url, archive)
        path = _untar_first(archive, "sing-box.exe" if system == "windows" else "sing-box", bin_dir)
        archive.unlink(missing_ok=True)
        origin = "downloaded"
        build_command = f"downloaded {url}"
    version, note = _probe_version(caps.SINGBOX, path)
    return CoreBinary(
        core=caps.SINGBOX,
        path=path,
        version=version,
        version_note=note,
        digest=sha256(path),
        origin=origin,
        build_command=build_command,
    )


def resolve_xray_rust(
    bin_dir: Path,
    given: Path | None,
    allow_build: bool,
    timeout: float,
    toolchain: str | None = None,
) -> CoreBinary:
    path = given or _from_env("XRAY_RUST_BIN") or (bin_dir / "xray-rust")
    origin = "provided"
    build_command = ""
    if not path.exists():
        if not allow_build:
            raise SystemExit(
                f"xray-rust binary not found at {path}; pass --bin-xray-rust or "
                f"allow source builds (it publishes no prebuilt binaries)"
            )
        version = caps.PINS["xray-rust"]["version"]
        checkout = bin_dir / "xray-rust-src"
        if not checkout.exists():
            # A pinned tag rather than a branch: the capability table in
            # caps.py describes a specific version, and a moving branch would
            # quietly change what "xray-rust" means between two runs.
            run(
                [
                    "git", "clone", "--depth", "1", "--branch", version,
                    "https://github.com/aimalygin/xray-rust.git", str(checkout),
                ],
                timeout=timeout,
            )
        # The checkout pins a toolchain in rust-toolchain.toml. Honouring the pin
        # is what makes the comparator reproducible, but it also means rustup
        # downloads a second toolchain, which is a large ask of a small runner.
        # `toolchain` overrides it, and the value used is recorded.
        env = dict(os.environ)
        if toolchain:
            env["RUSTUP_TOOLCHAIN"] = toolchain
        run(
            ["cargo", "build", "--locked", "--release", "-p", "xray-cli"],
            cwd=checkout,
            env=env,
            timeout=timeout,
        )
        built = checkout / "target" / "release" / (
            "xray-rust.exe" if platform.system() == "Windows" else "xray-rust"
        )
        if not built.exists():
            raise SystemExit(f"xray-rust build produced no binary at {built}")
        shutil.copy2(built, path)
        path.chmod(0o755)
        origin = "built"
        build_command = (
            f"git clone --branch {version} && "
            f"cargo build --locked --release -p xray-cli"
            + (f"  (RUSTUP_TOOLCHAIN={toolchain})" if toolchain else "")
        )
    version, note = _probe_version(caps.XRAY_RUST, path)
    return CoreBinary(
        core=caps.XRAY_RUST,
        path=path,
        version=version,
        version_note=note,
        digest=sha256(path),
        origin=origin,
        build_command=build_command,
    )


def git(root: Path, *args: str, timeout: float = 300) -> str:
    return run(["git", *args], cwd=root, timeout=timeout).stdout.strip()


def resolve_zray_base(
    root: Path,
    ref: str | None,
    bin_dir: Path,
    timeout: float,
    toolchain: str | None = None,
    allow_build: bool = True,
    given: Path | None = None,
) -> CoreBinary:
    """Build Zray from `ref` in its own worktree, and register it as a core.

    Three things are pinned so the two binaries are comparable: the same
    `--release` profile, the same toolchain, and a target directory of their own.
    A shared target directory reuses same-package fingerprints when source
    timestamps precede a previous build, and then the "base" is the candidate --
    which is the one failure mode here that would produce a confident, wrong
    number rather than an obvious one.
    """
    # An explicit binary wins. The error below names `--bin-zray-base` as the way
    # to supply one, so accepting the flag and then rebuilding regardless made
    # that advice a lie -- and on a small runner, rebuilding is exactly the cost
    # the caller was trying to avoid.
    if given is not None:
        binary = Path(given)
        if not binary.exists():
            raise SystemExit(f"--bin-{caps.BASE_ID} is {binary}, which does not exist")
        version, note = _probe_version(caps.ZRAY_BASE, binary)
        return CoreBinary(
            core=caps.ZRAY_BASE,
            path=binary,
            version=version,
            version_note=note,
            digest=sha256(binary),
            origin="provided",
            source_revision=ref,
        )
    if not ref:
        raise SystemExit(
            f"{caps.BASE_ID} needs --base-ref: it is Zray built from a ref, and "
            f"there is nothing to build without one"
        )
    if not allow_build:
        raise SystemExit(
            f"building {caps.BASE_ID} from {ref} needs builds allowed, or an "
            f"explicit --bin-{caps.BASE_ID}"
        )
    # Resolved here rather than left to the builder, so a base that cannot be
    # found says which ref it could not find. A shallow checkout holds only the
    # tip commit, and `--base-ref` naming any ancestor then failed with a bare
    # "git failed with 128" -- the run carried on, measured the candidate alone,
    # and reported a comparison that was never made.
    try:
        revision = git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    except RuntimeError as exc:
        raise SystemExit(
            f"--base-ref {ref!r} is not in this checkout. A shallow checkout holds "
            f"only its tip commit; fetch the history, or pass a ref already "
            f"present.\n  {' '.join(str(exc).split())[:400]}"
        ) from exc
    checkout = bin_dir / "zray-base-src"
    target = bin_dir / "zray-base-target"

    def discard() -> None:
        run(["git", "worktree", "remove", "--force", str(checkout)],
            cwd=root, timeout=timeout, check=False)
        if checkout.is_dir():
            shutil.rmtree(checkout, ignore_errors=True)
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)

    discard()
    run(
        ["git", "worktree", "add", "--detach", str(checkout), revision],
        cwd=root,
        timeout=timeout,
    )
    env = dict(os.environ)
    if toolchain:
        env["RUSTUP_TOOLCHAIN"] = toolchain
    try:
        run(
            ["cargo", "build", "--release", "-p", "zray-cli", "--target-dir", str(target)],
            cwd=checkout,
            env=env,
            timeout=timeout,
        )
        built = target / "release" / (
            "zray.exe" if platform.system() == "Windows" else "zray"
        )
        if not built.exists():
            raise SystemExit(f"the base build produced no binary at {built}")
        binary = bin_dir / caps.BASE_ID
        shutil.copy2(built, binary)
        binary.chmod(0o755)
    finally:
        # The worktree has to go even when the build failed: a stray worktree
        # makes the next run's `git worktree add` fail, and the next run is the
        # one somebody is waiting on.
        discard()
    version, note = _probe_version(caps.ZRAY_BASE, binary)
    return CoreBinary(
        core=caps.ZRAY_BASE,
        path=binary,
        version=version,
        version_note=note,
        digest=sha256(binary),
        origin="built",
        build_command=(
            f"git worktree add --detach {revision} && cargo build --release "
            f"-p zray-cli --target-dir <isolated>"
            + (f"  (RUSTUP_TOOLCHAIN={toolchain})" if toolchain else "")
        ),
        source_revision=revision,
        source_ref=ref,
    )


def _from_env(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


@dataclass
class Unavailable:
    core_id: str
    reason: str

    def as_dict(self) -> dict:
        return {"core": self.core_id, "reason": self.reason}


def resolve_all(
    ids: list[str],
    *,
    root: Path,
    bin_dir: Path,
    given: dict[str, Path],
    allow_build: bool = True,
    allow_download: bool = True,
    timeout: float = 3600,
    toolchain: str | None = None,
    base_ref: str | None = None,
) -> tuple[dict[str, CoreBinary], list[Unavailable]]:
    """Resolve every requested core, and explain each one that cannot be had.

    A comparator that will not build is a fact about the run, not a reason to
    abandon it. Building xray-rust from source on a small runner can fail for
    want of disk; the useful response is to measure against the cores that are
    there and to say plainly in the report which one was missing and why.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, CoreBinary] = {}
    missing: list[Unavailable] = []
    for core_id in ids:
        given_path = given.get(core_id)
        try:
            if core_id == caps.BASE_ID:
                out[core_id] = resolve_zray_base(
                    root, base_ref, bin_dir, timeout, toolchain, allow_build,
                    given_path,
                )
            elif core_id == "zray":
                out[core_id] = resolve_zray(root, given_path, allow_build)
            elif core_id == "xray":
                out[core_id] = resolve_xray(bin_dir, given_path, allow_download)
            elif core_id == "singbox":
                out[core_id] = resolve_singbox(bin_dir, given_path, allow_download)
            elif core_id == "xray-rust":
                out[core_id] = resolve_xray_rust(
                    bin_dir, given_path, allow_build, timeout, toolchain
                )
            else:
                raise SystemExit(f"unknown core {core_id!r}")
        except SystemExit as exc:
            missing.append(Unavailable(core_id, str(exc)))
        except Exception as exc:  # a build or a download failing is not fatal
            # The useful half of a subprocess failure is on the second line: the
            # command and its stderr. `exc` is multi-line and the first line --
            # "git failed with 128" -- says nothing about why, so it was all that
            # ever reached the report. Collapsed to one line, command and git's
            # own message kept.
            detail = " ".join(str(exc).split())
            missing.append(Unavailable(core_id, f"{type(exc).__name__}: {detail[:400]}"))
    return out, missing


# ---------------------------------------------------------------------------
# Running a core
# ---------------------------------------------------------------------------


def run_argv(core: caps.Core, binary: Path, config: Path) -> list[str]:
    """The argv that runs a config, in the core's own command line.

    `zray` deliberately has no separate server mode: the same `run` subcommand
    serves whatever inbounds the config declares, which is why one adapter covers
    both roles. Dispatch is on `Core.cli` rather than on the id, so a core that
    is a variant of an existing one -- `zray-base` is Zray -- needs no new branch.
    """
    if core.cli in ("zray", "xray-rust"):
        return [str(binary), "run", "-config", str(config)]
    if core.cli in ("xray", "singbox"):
        return [str(binary), "run", "-c", str(config)]
    raise SystemExit(
        f"{core.id} names no known command line (cli={core.cli!r}); known: "
        f"{', '.join(caps.KNOWN_CLIS)}"
    )


def check_argv(core: caps.Core, binary: Path, config: Path) -> list[str] | None:
    """The argv that validates a config without opening a socket, when there is
    one.

    This matters more than it looks: a core that cannot parse a config says so
    in one line, and the matrix can record *why* a cell is empty instead of
    reporting a connection timeout thirty seconds later.
    """
    if core.cli == "zray":
        return [str(binary), "check", str(config)]
    if core.cli == "xray":
        return [str(binary), "run", "-test", "-c", str(config)]
    if core.cli == "singbox":
        return [str(binary), "check", "-c", str(config)]
    if core.cli == "xray-rust":
        return [str(binary), "config", "check", "--config", str(config)]
    return None


@dataclass
class CheckResult:
    ok: bool
    diagnostic: str = ""


def check_config(core: caps.Core, binary: Path, config: Path, timeout: float = 60) -> CheckResult:
    argv = check_argv(core, binary, config)
    if argv is None:
        return CheckResult(True)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return CheckResult(False, "config check timed out")
    except OSError as exc:
        return CheckResult(False, f"config check could not run: {exc}")
    if proc.returncode == 0:
        return CheckResult(True)
    text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    return CheckResult(False, _shorten(text))


def _shorten(text: str, limit: int = 400) -> str:
    """Keep the line that says what went wrong.

    Every one of these cores prints a banner and an informational line before it
    fails, so taking the first lines of the output shows the reader the version
    they already know and hides the reason. Lines that look like a failure win;
    the first few are only used when there is nothing better.
    """
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "(no diagnostic)"
    interesting = [
        line
        for line in lines
        if any(
            word in line.lower()
            for word in ("fail", "error", "not supported", "unsupported", "invalid", "unknown", "missing")
        )
    ]
    chosen = (interesting or lines)[:2]
    return " / ".join(chosen)[:limit]


# ---------------------------------------------------------------------------


class _Children:
    """Tracks every child so none of them outlives the harness."""

    def __init__(self) -> None:
        self._procs: set[subprocess.Popen] = set()

    def add(self, proc: subprocess.Popen) -> None:
        self._procs.add(proc)

    def discard(self, proc: subprocess.Popen) -> None:
        self._procs.discard(proc)

    def kill_all(self) -> None:
        for proc in list(self._procs):
            _terminate(proc)


CHILDREN = _Children()


def _terminate(proc: subprocess.Popen, grace: float = 5.0) -> None:
    """SIGTERM, then SIGKILL, then always wait.

    A proxy that ignores SIGTERM would otherwise hold a port the next cell
    needs, and a proxy that is never waited for becomes a zombie whose memory
    still counts against the machine.
    """
    if proc.poll() is not None:
        proc.wait()
        return
    try:
        proc.terminate()
    except OSError:
        pass
    deadline = _now() + grace
    while _now() < deadline:
        if proc.poll() is not None:
            proc.wait()
            return
        time.sleep(0.02)
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


@dataclass
class CoreProcess:
    binary: CoreBinary
    config: Path
    argv: list[str]
    proc: subprocess.Popen
    log: Path
    started: float = field(default_factory=_now)

    @property
    def pid(self) -> int:
        return self.proc.pid

    @property
    def core(self) -> caps.Core:
        return self.binary.core

    def log_tail(self, limit: int = 2000) -> str:
        try:
            return self.log.read_text(errors="replace")[-limit:]
        except OSError:
            return "(no log)"

    def stop(self) -> None:
        try:
            _terminate(self.proc)
        finally:
            CHILDREN.discard(self.proc)


def start(binary: CoreBinary, config: Path, log: Path) -> CoreProcess:
    argv = run_argv(binary.core, binary.path, config)
    log.parent.mkdir(parents=True, exist_ok=True)
    handle = log.open("ab")
    handle.write(f"$ {' '.join(argv)}\n".encode())
    handle.flush()
    proc = subprocess.Popen(
        argv,
        stdout=handle,
        stderr=subprocess.STDOUT,
        # A new process group so a timeout can take down a core that spawned
        # helpers, without touching the harness itself.
        start_new_session=True,
    )
    CHILDREN.add(proc)
    return CoreProcess(binary=binary, config=config, argv=argv, proc=proc, log=log)


def wait_for_port(port: int, proc: subprocess.Popen, timeout: float = 20.0) -> bool:
    """Block until `port` accepts a TCP connection, or the process dies.

    Polling a port beats sleeping a fixed interval: the fixed sleep is either
    too short on a loaded runner (and reports a spurious failure) or too long
    (and adds its own seconds to every one of a few hundred samples).
    """
    deadline = _now() + timeout
    while _now() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def free_port() -> int:
    """Ask the kernel for an unused port, then release it.

    There is an unavoidable race between releasing and rebinding. It is the
    standard race, it is narrow, and the alternative -- a fixed base port -- is
    a deterministic failure the moment two runs overlap.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def cleanup_at_exit() -> None:
    import atexit

    atexit.register(CHILDREN.kill_all)
