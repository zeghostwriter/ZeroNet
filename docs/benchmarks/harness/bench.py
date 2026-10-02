#!/usr/bin/env python3
"""Benchmark Zray against Xray-core, sing-box and xray-rust.

```sh
# the quick suite, every core, on this machine
python3 bench.py --suite smoke

# a scheduled full run
python3 bench.py --suite full --runs 5

# one connection type, to see whether a change moved it
python3 bench.py --only vless-raw-tls --suite standard

# configurations of your own, every core that can read them
python3 bench.py --user-config ~/mine.json --user-config-url https://host/sub
```

Every option that changes a number has a default chosen so that the default run
is a fair comparison; the ones that do not are named after what they turn off.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from zbench import caps, cores, matrix, prbase, report, runner, support_doc, userconfig  # noqa: E402

# harness/ -> benchmarks/ -> docs/ -> the repository root.
ROOT = HERE.parents[2]

#: Where the pull-request list is read from when the caller does not say. The
#: harness lives in this repository, so that is the repository whose pull
#: requests a combined baseline is made of.
DEFAULT_REPO = "TheGorgeousIvorChival/ZeroNet"


def byte_size(text: str) -> int:
    """Accept `512M` and `2G` as well as a plain integer.

    The same shorthand the load generator takes, so a size is written the same
    way in a shell, in the docs and in the command the harness ends up running.
    """
    cleaned = text.strip().replace("_", "")
    digits = cleaned.rstrip("kKmMgG")
    if not digits.isdigit():
        raise argparse.ArgumentTypeError(f"not a byte count: {text!r}")
    base = int(digits)
    suffix = cleaned[len(digits) :].lower()
    return base * {"": 1, "k": 1_000, "m": 1_000_000, "g": 1_000_000_000}[suffix]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--suite",
        default=matrix.STANDARD,
        choices=matrix.SUITES,
        help="which bundle of scenarios to run (default: %(default)s)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="SUBSTRING",
        help="run only scenarios whose id contains this; repeatable",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="SUBSTRING",
        help="skip scenarios whose id contains this; repeatable",
    )
    parser.add_argument(
        "--cores",
        default=None,
        help=(
            "comma-separated cores to compare. The first is the baseline every other "
            "core is compared against. The default is the four projects, or those "
            f"plus {caps.BASE_ID} first when --base-ref is given"
        ),
    )
    parser.add_argument(
        "--list-prs",
        action="store_true",
        help=(
            "print the open pull requests --base-ref would merge, and exit. Use it "
            "to see what a combined baseline is made of before measuring against it"
        ),
    )
    parser.add_argument(
        "--exclude-prs",
        default="",
        metavar="NUMBERS",
        help=(
            "pull request numbers to leave out of a @merged-prs baseline, comma "
            "separated. Two open pull requests that edit the same file often do "
            "not combine, and then there is no single merged state to measure"
        ),
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        metavar="OWNER/NAME",
        help=(
            f"the repository --list-prs and --base-ref {prbase.MERGED} work "
            f"against. Defaults to the project this harness lives in"
        ),
    )
    parser.add_argument(
        "--base-ref",
        default=os.environ.get("BENCH_BASE_REF") or None,
        help=(
            "build Zray from this git ref as a second core and make it the baseline. "
            "This is the comparison a change needs: the same core, the same profile "
            "and the same toolchain, from the commit the change is measured against"
        ),
    )
    parser.add_argument(
        "--gate-regression",
        type=float,
        default=None,
        metavar="PCT",
        help=(
            "exit non-zero when the candidate is worse than the base by more than "
            "PCT on any scenario whose interval excludes the tolerance, e.g. 5 for 5%%"
        ),
    )
    parser.add_argument(
        "--gate-improvement",
        type=float,
        default=None,
        metavar="PCT",
        help="report the scenarios that clear this improvement; not a failure condition",
    )
    parser.add_argument(
        "--server-core",
        default="xray",
        choices=sorted(caps.ALL_CORES),
        help=(
            "the core that serves the proxy side of every cell. One server core per "
            "run, so the client is the only thing that changes (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="repeats per cell. Three is the minimum worth reading (default: %(default)s)",
    )
    parser.add_argument(
        "--bytes",
        type=byte_size,
        default=None,
        help="bytes per transfer sample; the default is sized per scenario",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="round trips per latency sample; the default is 1000",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="seconds any one load generator sample may take (default: %(default)s)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=HERE / "results" / "latest",
        help="where results, the report and the charts are written (default: %(default)s)",
    )
    parser.add_argument(
        "--work",
        type=Path,
        default=None,
        help="where configs, logs and fixture keys go (default: <out>/run)",
    )
    parser.add_argument(
        "--sink-port",
        type=int,
        default=0,
        help="the data sink's TCP port; 0 asks the kernel for a free one",
    )
    parser.add_argument(
        "--harness-ceiling-mbps",
        type=float,
        default=None,
        help="skip measuring the harness ceiling and use this value instead",
    )
    parser.add_argument(
        "--probe-only",
        action="store_true",
        help=(
            "only ask each core whether it accepts the config. No traffic, no cores "
            "started: this is the fast way to produce the coverage matrix"
        ),
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="fail instead of downloading Xray-core and sing-box",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="fail instead of building Zray or xray-rust from source",
    )
    for core_id in sorted(caps.ALL_CORES):
        parser.add_argument(
            f"--bin-{core_id}",
            type=Path,
            default=None,
            help=f"path to the {core_id} binary, instead of building or downloading it",
        )
    parser.add_argument(
        "--user-config",
        action="append",
        type=Path,
        default=[],
        metavar="PATH",
        help="a configuration file to measure in place; repeatable, a directory works too",
    )
    parser.add_argument(
        "--user-config-dir",
        type=Path,
        default=None,
        help="a directory of configuration files to measure",
    )
    parser.add_argument(
        "--user-config-url",
        action="append",
        default=[],
        metavar="URL",
        help="an https:// configuration or subscription to fetch and measure; repeatable",
    )
    parser.add_argument(
        "--user-target",
        default=None,
        metavar="HOST:PORT",
        help=(
            "a destination that speaks this harness's protocol, for the supplied "
            "configurations to be measured moving bytes against -- typically a "
            "sink the caller runs. Without it a supplied config is still tested, "
            "but only for whether its tunnel comes up and how fast, because the "
            "only endpoint such a config names is its own proxy server"
        ),
    )
    parser.add_argument(
        "--only-user-configs",
        action="store_true",
        help="skip the scenario matrix and measure only the supplied configurations",
    )
    parser.add_argument(
        "--allow-single-core",
        action="store_true",
        help=(
            "run even if only one core could be resolved. A comparison needs two, "
            "so this is for probing a single core's own numbers"
        ),
    )
    parser.add_argument(
        "--xray-rust-toolchain",
        default=os.environ.get("XRAY_RUST_TOOLCHAIN"),
        help=(
            "override the toolchain used to build xray-rust, which otherwise "
            "follows the pin in that project's rust-toolchain.toml and downloads a "
            "second toolchain"
        ),
    )
    parser.add_argument(
        "--emit-support-doc",
        action="store_true",
        help=(
            "regenerate docs/benchmarks/protocol-support.md from the capability "
            "data and exit. With --check, exit non-zero if the file on disk differs"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="with --emit-support-doc, verify instead of writing",
    )
    parser.add_argument(
        "--print-report",
        action="store_true",
        help="print the finished report to stdout as well as writing it",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.emit_support_doc:
        return _support_doc(args)

    if args.list_prs:
        pulls = prbase.list_pull_requests(args.repo)
        if not pulls:
            print(f"{args.repo} has no open pull requests")
            return 0
        width = max(len(p.short) for p in pulls)
        for pull in pulls:
            mergeable = "" if pull.mergeable == "MERGEABLE" else f"  ({pull.mergeable})"
            print(f"{pull.short:<{width}}  {pull.base:<8}  {pull.title}{mergeable}")
        print(f"\n{len(pulls)} open pull request(s) on {args.repo}")
        print(f"--base-ref {prbase.MERGED} builds all of them into one state to measure against")
        return 0

    if args.cores:
        core_ids = [c.strip() for c in args.cores.split(",") if c.strip()]
    elif args.base_ref:
        # A change's own run wants its base first, so the ratios it prints are
        # against the base rather than against whichever project sorted first.
        core_ids = list(caps.PR_CORES)
    else:
        core_ids = list(caps.DEFAULT_CORES)
    if args.base_ref and caps.BASE_ID not in core_ids:
        core_ids.insert(0, caps.BASE_ID)
    unknown = [c for c in core_ids if c not in caps.ALL_CORES]
    if unknown:
        raise SystemExit(
            f"unknown core(s): {', '.join(unknown)}; known: {', '.join(sorted(caps.ALL_CORES))}"
        )
    if args.server_core not in core_ids:
        # The server core is named so the report can state it, not because it has
        # to be a client under test; keeping it out of the list would hide which
        # process was on the other end.
        runner.log(
            f"note: the server core {args.server_core} is not in the comparison list"
        )
    if args.runs < 1:
        raise SystemExit("--runs must be at least 1")

    outdir: Path = args.out
    workdir: Path = args.work or (outdir / "run")
    outdir.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    cores.cleanup_at_exit()

    base_notes: list[str] = []
    if args.base_ref and args.base_ref.startswith("@"):
        runner.log(f"resolving --base-ref {args.base_ref} against {args.repo}")
        excluded = {
            int(n) for n in args.exclude_prs.replace(",", " ").split() if n.isdigit()
        }
        resolved, base_notes = prbase.resolve_base_ref(
            ROOT, args.base_ref, repo=args.repo, exclude=excluded
        )
        args.base_ref = resolved
        for note in base_notes:
            runner.log(f"  base: {note}")

    runner.log(f"resolving cores: {', '.join(core_ids)}")
    given = {
        core_id: getattr(args, f"bin_{core_id.replace('-', '_')}")
        for core_id in core_ids
        if getattr(args, f"bin_{core_id.replace('-', '_')}", None)
    }
    binaries, missing = cores.resolve_all(
        core_ids,
        root=ROOT,
        bin_dir=outdir / "bin",
        given=given,
        allow_build=not args.no_build,
        allow_download=not args.no_download,
        toolchain=args.xray_rust_toolchain,
        base_ref=args.base_ref,
    )
    for entry in missing:
        runner.log(f"  {entry.core_id} is unavailable: {entry.reason}")
    for binary in binaries.values():
        runner.log(f"  {binary.core.label}: {binary.version} ({binary.origin})")

    # The server core needs a binary too, even when it is not under test.
    if args.server_core not in binaries:
        extra, extra_missing = cores.resolve_all(
            [args.server_core],
            root=ROOT,
            bin_dir=outdir / "bin",
            given=given,
            allow_build=not args.no_build,
            allow_download=not args.no_download,
            toolchain=args.xray_rust_toolchain,
            base_ref=args.base_ref,
        )
        binaries.update(extra)
        missing.extend(extra_missing)

    if args.server_core not in binaries:
        raise SystemExit(
            f"the server core {args.server_core} could not be resolved: "
            + "; ".join(e.reason for e in missing if e.core_id == args.server_core)
        )
    if len(binaries) < 2 and not args.allow_single_core:
        raise SystemExit(
            f"only {len(binaries)} core could be resolved ({', '.join(binaries)}). "
            f"A comparison needs two. Pass --allow-single-core to measure one core "
            f"on its own, or check the reasons above."
        )
    unavailable = missing

    sink_port = args.sink_port or cores.free_port()
    engine = runner.Runner(
        root=ROOT,
        workdir=workdir,
        binaries=binaries,
        server_core=args.server_core,
        runs=args.runs,
        bytes_override=args.bytes,
        iterations_override=args.iterations,
        timeout=args.timeout,
        harness_ceiling=args.harness_ceiling_mbps,
        sink_port=sink_port,
        probe_only=args.probe_only,
        unavailable=unavailable,
        base_ref=args.base_ref or "",
        candidate_revision=_revision(ROOT),
    )
    for note in base_notes:
        # A number is not evidence without the state it was measured against, so
        # what `--base-ref` resolved to goes into the report and the artefact.
        engine.result.notes.append(f"the base is {note}")
    engine.start_sink()

    result_invocation = list(sys.argv[1:])
    started = time.monotonic()
    exit_code = 0
    try:
        if not args.only_user_configs:
            scenarios = matrix.select(
                args.suite, only=args.only, exclude=args.exclude
            )
            if not scenarios:
                raise SystemExit("no scenario matched --only/--exclude")
            engine.run_matrix(scenarios)

        supplied = userconfig.collect(
            paths=args.user_config,
            directory=args.user_config_dir,
            urls=args.user_config_url,
            workdir=workdir,
        )
        if args.user_target:
            host, _, port = args.user_target.rpartition(":")
            if not host or not port.isdigit():
                raise SystemExit(
                    f"--user-target must be HOST:PORT, got {args.user_target!r}"
                )
            for config in supplied:
                config.measure_host = host
                config.measure_port = int(port)
            runner.log(
                f"supplied configurations will be measured moving bytes against "
                f"{host}:{port}"
            )
        elif supplied:
            runner.log(
                "no --user-target, so supplied configurations are checked for "
                "whether the tunnel comes up and how fast; nothing is transferred"
            )
        if supplied:
            for config in supplied:
                if config.kind in ("link", "subscription"):
                    before = config.kind
                    config = engine.materialise(config)
                    runner.log(
                        f"user config {config.name}: {before} converted by "
                        f"`zray preset` -> {'ok' if config.runnable else 'not runnable'}"
                    )
                else:
                    runner.log(
                        f"user config {config.name}: "
                        f"{'ok' if config.runnable else 'not runnable'}"
                    )
                for core_id in core_ids:
                    cell = engine.run_user_config(config, core_id)
                    engine.result.cells.append(cell)
                    detail = (
                        f"{cell.throughput_mbps:.0f} Mbit/s"
                        if cell.throughput_mbps
                        else cell.reason or cell.status
                    )
                    runner.log(f"  {config.name} [{core_id}]: {detail}")
            engine.result.user_configs = [c.summary() for c in supplied]
    except KeyboardInterrupt:
        engine.result.notes.append("the run was interrupted; the cells recorded so far are kept")
        exit_code = 130
    finally:
        engine.finish()

    written = report.write(engine.result, outdir, argv=sys.argv[1:])
    gate_result = None
    if args.gate_regression is not None or args.gate_improvement is not None:
        gate_result = report.gate(
            report.candidate_pairs(written["aggregate"]),
            max_regression=args.gate_regression,
            min_improvement=args.gate_improvement,
        )
        (outdir / "gate.md").write_text(
            "# Regression gate\n\n**" + gate_result.verdict + "**\n\n"
            + "\n".join(gate_result.lines)
            + "\n"
        )
        runner.log(f"gate: {gate_result.verdict}")
        for line in gate_result.lines:
            if line.startswith("  FAIL"):
                runner.log(line)
        if not gate_result.ok:
            exit_code = exit_code or 1
    (outdir / "commands.sh").write_text(_replay_script(result_invocation, binaries))
    runner.log(
        f"wrote {written['report'].name}, {written['results'].name}, "
        f"{written['manifest'].name} and {len(written['charts'])} chart(s) in {outdir}"
    )
    runner.log(f"total wall time {(time.monotonic() - started) / 60:.1f} min")

    if args.print_report:
        print(written["report"].read_text())

    # A run that produced nothing is a failure, not a quiet success: it is the
    # outcome that looks like a passing check while doing nothing. A capability
    # probe counts `accepted` cells as its result.
    wanted = "accepted" if args.probe_only else "measured"
    produced = sum(1 for c in engine.result.cells if c.status == wanted)
    if not produced:
        runner.log(f"no cell was {wanted}")
        return 1
    runner.log(f"{produced} cell(s) {wanted} out of {len(engine.result.cells)}")
    if gate_result is not None:
        runner.log(f"gate: {gate_result.verdict} (gate.md)")
    return exit_code


def _revision(root: Path) -> str:
    """The commit under test, or `sha-dirty` when the tree is not that commit.

    A number from a modified tree is not a number from the commit it is
    attributed to, so the difference is recorded rather than dropped.
    """
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=60,
        )
        revision = head.stdout.strip()
        if head.returncode != 0 or not revision:
            return ""
        dirty = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=no"],
            cwd=root, capture_output=True, text=True, timeout=180,
        )
        return revision + ("-dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        return ""


def _support_doc(args) -> int:
    """Write or verify the generated comparison document.

    The check exists so the published table cannot quietly fall behind the
    capability data: CI runs it on every pull request and a mismatch is a failure
    rather than a diff nobody reads.
    """
    target = ROOT / "docs" / "benchmarks" / "protocol-support.md"
    if args.check:
        if not target.exists():
            print(f"missing: {target}")
            return 1
        expected = support_doc.render()
        actual = target.read_text()
        if expected == actual:
            print(f"ok {target.relative_to(ROOT)}")
            return 0
        print(f"stale: {target.relative_to(ROOT)}")
        print("  regenerate with: python3 bench.py --emit-support-doc")
        return 1
    support_doc.write(target)
    print(f"wrote {target}")
    return 0


def _replay_script(argv: list[str], binaries: dict) -> str:
    """A shell script that reproduces this run, with the binaries it used.

    The binaries are named with their digest, so a replay either uses the same
    artifact or visibly uses a different one.
    """
    quoted = " ".join(_shell_quote(a) for a in argv)
    lines = [
        "#!/bin/sh",
        "# Exact replay record for this run. Regenerating a chart or re-measuring",
        "# will not reproduce the numbers bit for bit; the digests below identify",
        "# what produced them.",
        "set -eu",
        'cd "$(dirname "$0")/../harness"',
        "",
    ]
    for core_id, binary in binaries.items():
        lines.append(
            f"# {core_id}: {binary.version} sha256={binary.digest} ({binary.origin})"
        )
    lines += ["", f"python3 bench.py {quoted}", ""]
    return "\n".join(lines)


def _shell_quote(value: str) -> str:
    if value and all(c.isalnum() or c in "-_./=,:+@" for c in value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    sys.exit(main())
