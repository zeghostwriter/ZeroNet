#!/usr/bin/env python3
"""Re-derive a run's aggregates from its raw cells, and fail if any disagree.

```sh
python3 validate_results.py docs/benchmarks/results/latest
python3 validate_results.py docs/benchmarks/results/2026-10-01-full --check-manifest
```

A benchmark is only worth reading if the summary can be checked. This does that
check, and it is deliberately unhelpful about anything it cannot verify: every
aggregate in `results.json` is recomputed from `cells` and compared, every cell
is checked for internal consistency, the harness ceiling and the fixture
identity are checked for provenance, and the artefact digests in
`manifest.json` are checked against the files on disk.

What it deliberately does *not* do is judge whether a number is good. A run where
one core is three times faster than another passes; a run where an aggregate
does not match its samples does not.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from zbench import report  # noqa: E402

#: A recomputed median must agree with the stored one to this relative
#: tolerance. The stored values are rounded to three decimals by the writer, so
#: anything tighter would fail on its own output.
TOLERANCE = 1e-6

ABSOLUTE_TOLERANCE = 1e-3


class Problems:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, message: str) -> None:
        self.items.append(message)

    def __bool__(self) -> bool:
        return bool(self.items)


def _median(values: list[float]) -> float | None:
    """The median, written out rather than imported.

    This file's whole purpose is to disagree with the report if the report is
    wrong. Calling `stats.summarise` -- the same helper `report.aggregate` used to
    produce these numbers -- meant a defect inside it appeared on both sides and
    validated clean. So the five numbers checked here are computed from the
    definitions instead.
    """
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _percentile(values: list[float], percent: float) -> float | None:
    """Nearest-rank percentile: the smallest value at or above the rank."""
    if not values:
        return None
    ordered = sorted(values)
    rank = int(-(-percent / 100.0 * len(ordered) // 1)) - 1
    return ordered[max(0, min(len(ordered) - 1, rank))]


def _mad(values: list[float]) -> float | None:
    """Median absolute deviation, scaled to be comparable with a standard
    deviation for normally distributed data."""
    centre = _median(values)
    if centre is None:
        return None
    return 1.4826 * (_median([abs(v - centre) for v in values]) or 0.0)


def _summarise(values: list[float]) -> dict:
    return {
        "median": _median(values),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "p95": _percentile(values, 95.0),
        "mad": _mad(values),
    }


def close(a: float | None, b: float | None) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    if math.isnan(a) or math.isnan(b):
        return False
    return abs(a - b) <= max(ABSOLUTE_TOLERANCE, TOLERANCE * max(abs(a), abs(b)))


def validate(directory: Path, *, check_manifest: bool = True) -> Problems:
    problems = Problems()
    results_path = directory / "results.json"
    if not results_path.exists():
        problems.add(f"{results_path} does not exist")
        return problems
    data = json.loads(results_path.read_text())

    if data.get("schema") != "zray-bench/3":
        problems.add(f"unexpected schema {data.get('schema')!r}")
    cells = data.get("cells") or []
    if not cells:
        problems.add("no cells recorded")
        return problems
    run = data.get("run") or {}
    probe_only = bool(run.get("probe_only"))
    if probe_only and not any(c.get("status") == "accepted" for c in cells):
        problems.add(
            "a capability probe recorded no accepted config, so it probed nothing"
        )
    aggregate = data.get("aggregate") or {}
    rows = aggregate.get("rows") or {}

    _check_cells(cells, problems, probe_only=probe_only)
    _check_aggregates(cells, rows, problems)
    _check_provenance(data, problems)
    if check_manifest:
        _check_manifest(directory, problems)
    return problems


def _check_cells(cells: list[dict], problems: Problems, *, probe_only: bool = False) -> None:
    seen_repeats: dict[tuple[str, str], set[int]] = {}
    cell_counts: dict[tuple[str, str], int] = {}
    for index, cell in enumerate(cells):
        where = f"cell[{index}] {cell.get('scenario')}/{cell.get('core')}"
        status = cell.get("status")
        if status == "accepted":
            # A probe cell's whole result is that the core accepted the config.
            if probe_only and not (cell.get("reason") or cell.get("diagnostic")):
                problems.add(f"{where}: accepted with no reason recorded")
        elif status == "measured":
            if cell.get("throughput_mbps") in (None, 0) and cell.get("latency_us_median") in (
                None,
                0,
            ) and cell.get("rss_peak_mb") in (None, 0):
                problems.add(f"{where}: measured but carries no number at all")
            if cell.get("bytes_moved") and cell.get("transfer_ms"):
                rate = (cell["bytes_moved"] * 8) / (cell["transfer_ms"] / 1000.0) / 1e6
                if not close(rate, cell.get("throughput_mbps"), ) and abs(
                    rate - (cell.get("throughput_mbps") or 0)
                ) > max(1.0, 0.02 * rate):
                    problems.add(
                        f"{where}: throughput_mbps {cell.get('throughput_mbps'):.1f} does "
                        f"not follow from bytes_moved/transfer_ms ({rate:.1f})"
                    )
            if cell.get("cpu_s") is not None and cell.get("cpu_s_per_GB") is not None:
                if cell.get("bytes_moved"):
                    expected = cell["cpu_s"] / (cell["bytes_moved"] / (1024**3))
                    if not close(expected, cell["cpu_s_per_GB"]) and abs(
                        expected - cell["cpu_s_per_GB"]
                    ) > max(0.01, 0.02 * expected):
                        problems.add(
                            f"{where}: cpu_s_per_GB {cell['cpu_s_per_GB']:.3f} does not "
                            f"follow from cpu_s/bytes ({expected:.3f})"
                        )
        else:
            if not (cell.get("reason") or cell.get("diagnostic")):
                problems.add(
                    f"{where}: status {status!r} with no reason and no diagnostic"
                )
        key = (cell.get("scenario"), cell.get("core"))
        seen_repeats.setdefault(key, set()).add(cell.get("repeat"))
        cell_counts[key] = cell_counts.get(key, 0) + 1
    # `seen_repeats` holds a set per key, so comparing it to `set(seen_repeats)`
    # compared a set with itself and could never fire. What has to be counted is
    # how many cells claimed each key.
    for key, count in cell_counts.items():
        repeats = seen_repeats.get(key, set())
        if count != len(repeats):
            problems.add(
                f"{key[0]}/{key[1]}: {count} cells share only {len(repeats)} "
                f"distinct repeat index/indices {sorted(r for r in repeats if r is not None)}, "
                f"so one index appears more than once"
            )


def _check_aggregates(cells: list[dict], rows: dict, problems: Problems) -> None:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for cell in cells:
        grouped.setdefault((cell["scenario"], cell["core"]), []).append(cell)

    for scenario, entry in rows.items():
        field = entry.get("metric")
        # Which metric a row leads with is a claim, and reading it back out of the
        # artefact validated the claim against itself. It is re-derived from the
        # workload the cells recorded instead.
        workloads = {
            c.get("workload")
            for cells in grouped.values() for c in cells if c["scenario"] == scenario
        }
        for workload in workloads:
            headline = report.HEADLINE.get(workload)
            expected_field = headline[0] if headline else None
            if expected_field and field and expected_field != field:
                problems.add(
                    f"{scenario}: leads with {field!r} but its workload is "
                    f"{workload!r}, which is measured as {expected_field!r}"
                )
        for core, record in entry.get("cores", {}).items():
            own = sorted(
                grouped.get((scenario, core), []), key=lambda c: c.get("repeat", 0)
            )
            if not own:
                problems.add(f"{scenario}/{core}: aggregate row with no cells")
                continue
            if record.get("repeats") != len(own):
                problems.add(
                    f"{scenario}/{core}: repeats {record.get('repeats')} but "
                    f"{len(own)} cells"
                )
            if record.get("status") != own[0].get("status"):
                problems.add(
                    f"{scenario}/{core}: aggregate status {record.get('status')!r} but "
                    f"cells say {own[0].get('status')!r}"
                )
            record = dict(record)
            record["_field"] = field
            if record.get("status") != "measured":
                _check_ratios(entry, own, record, f"{scenario}/{core}", problems)
                continue
            _check_ratios(entry, own, record, f"{scenario}/{core}", problems)
            # Nothing these measure can come out below zero. A negative median
            # is not a rounding artefact -- a CPU-second count, a byte count and a
            # resident-set size all have a floor at zero, so one of them is a
            # number that was never measured.
            for metric, value in record.items():
                if not metric.endswith(("_mb", "_s", "_GB", "_moved")):
                    continue
                if isinstance(value, dict) and isinstance(value.get("median"), (int, float)):
                    if value["median"] < 0:
                        problems.add(
                            f"{scenario}/{core}: {metric}.median is {value['median']}, "
                            f"which cannot be negative"
                        )
            for metric in (
                field,
                "throughput_mbps",
                "cpu_s_per_GB",
                "rss_idle_mb",
                "rss_peak_mb",
                "latency_us_median",
            ):
                summary = record.get(metric)
                if not summary:
                    continue
                values = [
                    c.get(metric)
                    for c in own
                    if isinstance(c.get(metric), (int, float))
                ]
                if not values:
                    problems.add(
                        f"{scenario}/{core}: {metric} summarised with no samples"
                    )
                    continue
                expected = _summarise(values)
                for key, actual in (
                    ("median", expected["median"]),
                    ("min", expected["min"]),
                    ("max", expected["max"]),
                    ("p95", expected["p95"]),
                    ("mad", expected["mad"]),
                ):
                    stored = summary.get(key)
                    if stored is None or actual is None:
                        continue
                    if not close(stored, actual):
                        problems.add(
                            f"{scenario}/{core}: {metric}.{key} is {stored} but the "
                            f"samples give {actual}"
                        )
                if summary.get("count") != len(values):
                    problems.add(
                        f"{scenario}/{core}: {metric}.count is {summary.get('count')} "
                        f"but {len(values)} samples are present"
                    )


def _check_ratios(entry: dict, own: list[dict], record: dict, where: str,
                  problems: Problems) -> None:
    """Check a paired comparison against itself and against its own cells.

    Every ratio in the report, the whole "This change" table and the gate's input
    come from `versus_baseline`, and none of it was checked: a run claiming a 99x
    improvement with 999 pairs validated clean. The bootstrap is not repeated here
    -- that would be re-running the writer -- but the claims it produces have to
    be consistent with the medians and the repeat count that went into it.
    """
    spread = record.get("baseline_self_spread")
    if isinstance(spread, dict):
        lo, hi = spread.get("min"), spread.get("max")
        if lo is not None and hi is not None and lo > hi:
            problems.add(f"{where}: the baseline's own spread is inverted, {lo} > {hi}")
        for name in ("min", "median", "max", "p95", "relative_spread"):
            value = spread.get(name)
            if value is not None and value < 0:
                problems.add(f"{where}: baseline_self_spread.{name} is {value}")

    versus = record.get("versus_baseline")
    if not versus:
        return
    ratio, low, high = versus.get("ratio"), versus.get("ci95_low"), versus.get("ci95_high")
    pairs = versus.get("pairs")
    measured = [c for c in own if isinstance(c.get(record.get("_field")), (int, float))]
    if pairs is not None and pairs > len(measured):
        problems.add(
            f"{where}: the comparison claims {pairs} pairs but only "
            f"{len(measured)} samples are present"
        )
    if ratio is not None and not (low is None or high is None):
        if not (low - 1e-9 <= ratio <= high + 1e-9):
            problems.add(
                f"{where}: the point estimate {ratio:.4f} lies outside its own "
                f"interval [{low:.4f}, {high:.4f}]"
            )
    if low is not None and high is not None and low > high:
        problems.add(f"{where}: the interval is inverted, {low} > {high}")
    # Direction has to follow the metric, and the metric has to follow the
    # workload. A flipped `higher_is_better` makes the gate invert its own
    # verdict, and nothing else in this file would notice.
    higher = entry.get("higher_is_better")
    verdict = versus.get("verdict") or ""
    if high is not None and low is not None and ratio is not None:
        resolved = verdict in ("candidate_better", "candidate_worse")
        spans = low <= 1.0 <= high
        if resolved and spans:
            problems.add(
                f"{where}: verdict {verdict!r} but the interval [{low:.3f}, "
                f"{high:.3f}] includes 1.00x, so nothing was resolved"
            )
        if verdict in ("candidate_better", "candidate_worse") and higher is not None:
            candidate_higher = ratio >= 1.0
            expected = "candidate_better" if candidate_higher == higher else "candidate_worse"
            if verdict != expected:
                problems.add(
                    f"{where}: ratio {ratio:.3f} on a "
                    f"{'higher' if higher else 'lower'}-is-better metric is "
                    f"{expected!r}, not {verdict!r}"
                )

def _check_provenance(data: dict, problems: Problems) -> None:
    run = data.get("run") or {}
    binaries = run.get("binaries") or []
    if not binaries:
        problems.add("no binaries recorded; a result must name what produced it")
    for binary in binaries:
        if not binary.get("binary_sha256"):
            problems.add(f"{binary.get('id')}: no binary digest recorded")
        if not binary.get("version"):
            problems.add(f"{binary.get('id')}: no version recorded")
    if not run.get("host", {}).get("os"):
        problems.add("no host description recorded")
    if not run.get("invocation"):
        problems.add("no invocation recorded; the run cannot be replayed")
    fixture = run.get("identity") or {}
    if not fixture.get("cert_sha256"):
        problems.add("no fixture certificate digest recorded")
    if not fixture.get("sni"):
        problems.add("no fixture SNI recorded")


def _check_manifest(directory: Path, problems: Problems) -> None:
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        problems.add(f"{manifest_path} does not exist")
        return
    manifest = json.loads(manifest_path.read_text())
    artifacts = manifest.get("artifacts") or {}
    if not artifacts:
        problems.add("manifest.json lists no artefacts")
    charts = directory / "charts"
    on_disk = {p.name for p in charts.glob("*.png")} if charts.exists() else set()
    for name, entry in artifacts.items():
        # Charts are looked for in `charts/`, everything else beside the report.
        path = (charts / name) if name.endswith(".png") else (directory / name)
        if not path.exists():
            problems.add(f"manifest lists {name} but the file is missing")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry.get("sha256"):
            problems.add(
                f"{name}: digest {entry.get('sha256', '')[:16]} does not match the file"
            )
    unlisted = on_disk - {p.name for p in charts.glob("*.png") if p.name in artifacts}
    for name in sorted(unlisted):
        problems.add(f"chart {name} is on disk but not listed in the manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="a results directory")
    parser.add_argument(
        "--no-manifest",
        action="store_true",
        help="skip the artefact digest check",
    )
    args = parser.parse_args()
    problems = validate(args.directory, check_manifest=not args.no_manifest)
    if problems:
        print(f"FAIL {args.directory}: {len(problems.items)} problem(s)")
        for item in problems.items:
            print(f"  - {item}")
        return 1
    print(f"ok {args.directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
