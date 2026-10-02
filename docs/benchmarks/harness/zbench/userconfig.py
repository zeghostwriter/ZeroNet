"""Running a configuration the user supplied, under every core that can read it.

This is the case the matrix cannot cover: a real subscription, a real link, a
real server. Two things follow from that, and both are stated in the report
rather than left for the reader to work out.

**A user config is measured in place, not against a fixture.** The loadgen is
pointed at the address the config itself names, so the number includes the real
network. A fast row here means "this core moved this config's traffic at this
rate on this host at this time", not "this core is faster".

**Cross-core rows are only comparable when every core reached the same
endpoint.** If one core silently failed to connect and reported a low number,
that is a compatibility result, not a performance one, and the report separates
the two: a config a core could not read is a support finding, a config a core
could read but that failed to carry traffic is a failure with the core's own
log attached.

Nothing here rewrites a user's config. Adding a SOCKS inbound would change what
is being measured, so a config without a local proxy listener is reported as not
runnable, with the reason. A caller who wants that trade made on purpose edits
the file; the harness will then measure the file as it stands.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .cores import fetch_url

#: Inbounds a loadgen can drive.
DRIVABLE_INBOUNDS = {"socks", "mixed", "http"}

_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|ssr|socks|http|hysteria2?|tuic|anytls)://", re.I)


@dataclass
class UserConfig:
    name: str
    path: Path
    raw: object
    dialect: str
    """Which config dialect the file is written in, decided by its own shape."""
    proxy_port: int | None
    target_host: str | None
    target_port: int | None
    """The proxy's own server address, from the first proxy outbound.

    This is where the tunnel goes, which makes it the right target for measuring
    whether the tunnel comes up and how fast -- and the wrong target for moving
    bytes, because that endpoint speaks the proxy protocol rather than the
    harness's. `measure_host`/`measure_port` is the destination to push bytes to.
    """
    measure_host: str | None = None
    measure_port: int | None = None
    problems: list[str] = field(default_factory=list)
    kind: str = "json"
    """`json`, `subscription` or `link`. The last two are share links that still
    have to become a configuration before any core can be pointed at them."""
    source: str = "file"
    link_count: int = 0

    @property
    def runnable(self) -> bool:
        return not self.problems

    @property
    def can_transfer(self) -> bool:
        """Whether a byte-moving measurement is possible for this config.

        Only when the caller named a destination. Without one the harness reports
        tunnel establishment and latency, which every config supports, rather than
        sending a payload to a port that cannot answer it.
        """
        return bool(self.measure_host and self.measure_port)

    def summary(self) -> dict:
        return {
            "name": self.name,
            "path": str(self.path),
            "kind": self.kind,
            "dialect": self.dialect,
            "source": self.source,
            "proxy_port": self.proxy_port,
            "target": (
                f"{self.target_host}:{self.target_port}"
                if self.target_host and self.target_port
                else None
            ),
            "runnable": self.runnable,
            "link_count": self.link_count,
            "problems": self.problems,
        }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _decode_base64_blob(text: str) -> str | None:
    """A subscription body: base64 of one link or config per line."""
    stripped = "".join(text.split())
    if len(stripped) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        return None
    padded = stripped.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", "replace")
    except Exception:
        return None
    return decoded if "://" in decoded or decoded.strip().startswith("{") else None


def load_file(path: Path) -> UserConfig:
    text = path.read_text(errors="replace")
    name = path.stem

    decoded = _decode_base64_blob(text)
    if decoded is not None:
        links = [l for l in decoded.splitlines() if _LINK_RE.match(l.strip())]
        if links and len(links) == len([l for l in decoded.splitlines() if l.strip()]):
            return UserConfig(
                name=name, path=path, raw=decoded, dialect="link",
                proxy_port=None, target_host=None, target_port=None,
                problems=[
                    f"a subscription of {len(links)} share link(s); only the first is "
                    f"measured, because one config is one destination"
                ],
                kind="subscription", link_count=len(links),
            )
        return _from_text(name, decoded, path, kind="json")

    return _from_text(name, text, path, kind="json")


def _from_text(name: str, text: str, path: Path, kind: str) -> UserConfig:
    """Turn a file's contents into a config, a link, or a problem."""
    stripped = text.strip()
    if not stripped:
        return UserConfig(
            name=name, path=path, raw=None, dialect="unknown",
            proxy_port=None, target_host=None, target_port=None,
            problems=["file is empty"], kind=kind,
        )

    if _LINK_RE.match(stripped):
        # A single share link. It is not translated here on purpose: each core
        # would need its own parser, and a mistranslated link would be reported
        # as a core incompatibility. `Runner.materialise` converts it once, with
        # Zray's own parser, and the report says that is what happened.
        return UserConfig(
            name=name, path=path, raw=stripped, dialect="link",
            proxy_port=None, target_host=None, target_port=None,
            problems=["a share link, not a configuration file"],
            kind="link", link_count=1,
        )

    if stripped.startswith("http://") or stripped.startswith("https://"):
        return UserConfig(
            name=name, path=path, raw=None, dialect="unknown",
            proxy_port=None, target_host=None, target_port=None,
            problems=[
                "a bare URL; pass it with --user-config-url so the bytes are "
                "fetched once and stored with the run"
            ],
            kind="url",
        )

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return UserConfig(
            name=name, path=path, raw=None, dialect="unknown",
            proxy_port=None, target_host=None, target_port=None,
            problems=[f"not JSON ({exc.msg} at line {exc.lineno})"], kind=kind,
        )

    return describe(name, parsed, path, kind=kind)


def describe(name: str, parsed: object, path: Path, kind: str = "json") -> UserConfig:
    """Work out the dialect, the local proxy port and the remote target."""
    problems: list[str] = []
    dialect = "xray"
    if isinstance(parsed, list):
        # A subscription array: the first element that has outbounds is the one
        # to describe, matching how every client in this space reads the file.
        elements = [e for e in parsed if isinstance(e, dict)]
        parsed = next(
            (e for e in elements if e.get("outbounds")), elements[0] if elements else {}
        )
    if not isinstance(parsed, dict):
        return UserConfig(
            name=name, path=path, raw=parsed, dialect="unknown",
            proxy_port=None, target_host=None, target_port=None,
            problems=["top level is not an object or an array of objects"],
            kind=kind,
        )

    if "outbounds" not in parsed:
        problems.append("no `outbounds` array, so there is nothing to proxy through")

    proxy_port = _find_proxy_port(parsed)
    if proxy_port is None:
        problems.append(
            "no local socks, mixed or http inbound, so there is no port for the "
            "load generator to connect to"
        )

    host, port = _find_target(parsed)
    if host is None:
        problems.append(
            "no server address found in the first proxy outbound, so there is no "
            "destination to measure"
        )

    return UserConfig(
        name=name,
        path=path,
        raw=parsed,
        dialect=dialect,
        proxy_port=proxy_port,
        target_host=host,
        target_port=port,
        problems=problems,
        kind=kind,
    )


def _find_proxy_port(config: dict) -> int | None:
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        proto = str(inbound.get("protocol") or inbound.get("type") or "").lower()
        if proto in DRIVABLE_INBOUNDS:
            port = inbound.get("port") or inbound.get("listen_port")
            try:
                return int(port)
            except (TypeError, ValueError):
                continue
    return None


def _find_target(config: dict) -> tuple[str | None, int | None]:
    """The remote endpoint the first proxy outbound points at.

    Only the first proxy outbound is considered. A routing config whose traffic
    goes out of the third outbound is measured against the wrong destination if
    this guesses, and the alternative -- asking which outbound to use -- is a
    question the caller cannot answer without reading the routing rules.
    """
    for outbound in config.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        proto = str(outbound.get("protocol") or outbound.get("type") or "").lower()
        if proto in ("freedom", "direct", "block", "blackhole", "dns", ""):
            continue
        # sing-box shape.
        if outbound.get("server"):
            port = outbound.get("server_port")
            return str(outbound["server"]), int(port) if port else None
        # Xray shape. The server list lives inside `settings`, which is the part
        # that is easy to get wrong: `outbound.vnext` does not exist, and a
        # lookup that stops at the outbound object finds nothing in any real
        # configuration.
        settings = outbound.get("settings")
        sources = [outbound]
        if isinstance(settings, dict):
            sources.insert(0, settings)
        for source in sources:
            for key in ("servers", "vnext"):
                for entry in source.get(key) or []:
                    if isinstance(entry, dict) and entry.get("address"):
                        port = entry.get("port")
                        return str(entry["address"]), int(port) if port else None
            if source.get("address"):
                port = source.get("port")
                return str(source["address"]), int(port) if port else None
    return None, None


#: A subscription body is very often a `.txt` and a panel's export is very often
#: a `.json`, so both are read. Anything else in the directory is left alone.
SUFFIXES = (".json", ".txt")


def _configs_in(directory: Path) -> list[Path]:
    found: list[Path] = []
    for suffix in SUFFIXES:
        found.extend(sorted(directory.glob(f"*{suffix}")))
    return sorted(set(found))


def collect(
    paths: list[Path] | None = None,
    directory: Path | None = None,
    urls: list[str] | None = None,
    workdir: Path | None = None,
) -> list[UserConfig]:
    """Gather every config to measure, from files, a directory and URLs.

    A URL is fetched once and written to the work directory, so the artifact
    uploaded with the results contains the exact bytes that were measured. A
    subscription that changes between two runs is otherwise impossible to
    reproduce, and a benchmark that cannot be reproduced is a rumour.
    """
    out: list[UserConfig] = []
    for path in paths or []:
        if path.is_dir():
            out.extend(load_file(p) for p in _configs_in(path))
        else:
            out.append(load_file(path))
    if directory:
        out.extend(load_file(p) for p in _configs_in(directory))
    for url in urls or []:
        out.append(_load_url(url, workdir))
    # A duplicated name would silently overwrite one result with another.
    seen: dict[str, int] = {}
    for config in out:
        if config.name in seen:
            seen[config.name] += 1
            config.name = f"{config.name}-{seen[config.name]}"
        else:
            seen[config.name] = 0
    return out


def _load_url(url: str, workdir: Path | None) -> UserConfig:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", url.split("?")[0].rstrip("/").split("/")[-1] or "remote")
    name = name or "remote"
    if not url.startswith("https://"):
        # A benchmark that fetches its input over cleartext is measuring a
        # different thing on every run, and a hostile network can rewrite it.
        return UserConfig(
            name=name, path=Path(name), raw=None, dialect="unknown",
            proxy_port=None, target_host=None, target_port=None,
            problems=["only https:// config URLs are fetched"],
            source=url,
        )
    try:
        fetch_url(url, workdir / "user-configs" / f"{name}.raw" if workdir else Path(f"{name}.raw"))
        fetched = (workdir / "user-configs" / f"{name}.raw") if workdir else Path(f"{name}.raw")
        body = fetched.read_text(errors="replace")
    except SystemExit as exc:
        return UserConfig(
            name=name, path=Path(name), raw=None, dialect="unknown",
            proxy_port=None, target_host=None, target_port=None,
            problems=[f"could not fetch: {exc}"],
            source=url,
        )
    path = (workdir / "user-configs" / f"{name}.json") if workdir else Path(f"{name}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    config = _from_text(name, body, path, kind="remote")
    config.source = url
    return config
