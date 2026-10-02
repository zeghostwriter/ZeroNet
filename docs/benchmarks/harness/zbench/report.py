"""Turning cells into something a reader can check.

The style rule for everything in this module: **show, do not tell.** A sentence
that says a core is faster is a claim; a bar that is taller is evidence. Every
number here is printed with its spread and its interval, every empty cell carries
the reason it is empty, and no conclusion is written in prose that the data does
not already say on its own. Where a comparison could be mistaken for a
conclusion, the row shows the baseline's own repeat-to-repeat spread next to it,
so the reader can see the size of the effect and the size of the noise together.

Outputs:

* `report.md`      tables, coverage, confounders, nothing else
* `results.json`   every cell, status and diagnostic, machine readable
* `manifest.json`  digests of every artefact plus the replay command
* `charts/*.png`   coverage, capability gaps, and per-group metrics
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from . import caps, matrix, stats
from .runner import (
    STATUS_ACCEPTED,
    STATUS_ERROR,
    STATUS_MEASURED,
    STATUS_SKIPPED,
    STATUS_TIMEOUT,
    STATUS_UNSUPPORTED,
    STATUS_UNSUPPORTED_CONFIRMED,
    Cell,
    Result,
)

#: The number a row is about, per workload. A latency row has no throughput
#: worth charting and a throughput row has no percentile worth charting.
HEADLINE = {
    matrix.DOWN: ("throughput_mbps", "Mbit/s", True),
    matrix.UP: ("throughput_mbps", "Mbit/s", True),
    matrix.DUPLEX: ("throughput_mbps", "Mbit/s", True),
    matrix.LATENCY: ("latency_us_median", "us", False),
    matrix.CHURN: ("ops_per_s", "connections/s", True),
    matrix.UDP: ("latency_us_median", "us", False),
    matrix.HOLD: ("rss_peak_mb", "MB resident", False),
    "passthrough": ("throughput_mbps", "Mbit/s", True),
    # A supplied config with no destination named is measured by establishing its
    # tunnel, so its headline is the rate of that and its unit says so.
    "tunnel": ("ops_per_s", "tunnels/s", True),
}

#: A cell at or above this fraction of the measured harness ceiling is limited
#: by the generator, and is marked as such wherever it appears.
HARNESS_BOUND = 0.85

#: Short forms for the charts, where there is no room for the full label. The
#: reason itself is in the table; the chart only has to show that the cell is
#: empty and of what kind.
SHORT_STATUS = {
    STATUS_ACCEPTED: "config ok",
    STATUS_UNSUPPORTED_CONFIRMED: "refused",
    STATUS_UNSUPPORTED: "out of scope",
    STATUS_ERROR: "failed",
    STATUS_TIMEOUT: "timed out",
    STATUS_SKIPPED: "not run",
}

# Visible markers. A blank cell is indistinguishable from a cell nobody looked
# at, so nothing in a table is ever blank.
MARKERS = {
    STATUS_MEASURED: "measured",
    STATUS_ACCEPTED: "config accepted, nothing measured",
    STATUS_UNSUPPORTED_CONFIRMED: "refused the config",
    STATUS_UNSUPPORTED: "out of scope",
    STATUS_ERROR: "ran and failed",
    STATUS_TIMEOUT: "timed out",
    STATUS_SKIPPED: "not run",
}


#: Linux reports CPU in clock ticks and macOS `ps` in hundredths, so a sample
#: below about 10 ms of CPU reads as zero. A table that prints `0.00` there is
#: claiming the work was free.
CPU_RESOLUTION_S = 0.010


def _fmt(value: float | None, unit: str = "") -> str:
    if value is None:
        return "-"
    if unit == "s/GB" and value == 0.0:
        return f"<{CPU_RESOLUTION_S:g}"
    if unit == "Mbit/s":
        return f"{value / 1000:.2f} Gbit/s" if value >= 10_000 else f"{value:,.0f} Mbit/s"
    if unit == "MB/s":
        return f"{value / 1000:.2f} GB/s" if value >= 1000 else f"{value:,.0f} MB/s"
    if unit == "MB resident":
        return f"{value:.1f} MB"
    if unit == "us":
        return f"{value / 1000:.2f} ms" if value >= 1000 else f"{value:,.0f} us"
    if unit == "connections/s":
        return f"{value:,.0f}/s"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    if abs(value) >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def _span(summary: dict | None) -> str:
    """min..max of the repeats, so a median is never shown without its spread."""
    if not summary or summary.get("median") is None:
        return ""
    lo, hi = summary.get("min"), summary.get("max")
    if lo is None or hi is None or lo == hi:
        return ""
    return f" <sub>[{_fmt(lo)}, {_fmt(hi)}]</sub>"


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def index_cells(result: Result) -> dict:
    grouped: dict[tuple[str, str], list[Cell]] = defaultdict(list)
    for cell in result.cells:
        grouped[(cell.scenario, cell.core)].append(cell)
    return grouped


#: Every metric the aggregate carries forward. `MBps` is here because it is
#: measured on every cell and the previous harness charted throughput in MB/s;
#: without it that unit is collected and never shown.
AGGREGATED_METRICS = (
    "throughput_mbps", "MBps", "cpu_s_per_GB", "rss_idle_mb", "rss_peak_mb",
    "rss_peak_reported_mb", "latency_us_median", "connect_us_median",
    "tcp_connect_us_median", "socks_connect_us_median", "ops_per_s",
    "threads_peak", "server_cpu_s", "server_rss_peak_mb", "transfer_ms",
)


def _aggregated_metrics(field: str) -> list[tuple[str, str]]:
    """The row's own headline metric first, then every other one recorded."""
    pairs = [(field, field)]
    pairs += [(m, m) for m in AGGREGATED_METRICS if m != field]
    return pairs


#: The per-metric tables the report prints, as (metric, title, unit).
PRINTED_METRICS = (
    ("MBps", "Throughput, the same rows in bytes rather than bits", "MB/s"),
    ("cpu_s_per_GB", "CPU seconds per gibibyte moved", "s/GB"),
    ("rss_idle_mb", "Resident memory before any traffic", "MB"),
    ("rss_peak_mb", "Peak resident memory during the scenario", "MB"),
    ("connect_us_median", "Time to a usable proxied connection, median", "us"),
    ("latency_us_median", "Validated round trip, median", "us"),
    ("ops_per_s", "Completed operations per second", "per second"),
    ("threads_peak", "Peak threads", ""),
    ("server_cpu_s", "CPU used by the server process", "s"),
)


def aggregate(result: Result) -> dict:
    """A per-(scenario, core) summary, the paired comparison, and the spread of
    the baseline against itself.

    That last part matters more than it looks. A comparison against a baseline
    is only meaningful next to the baseline's own repeat-to-repeat variation, so
    both are emitted and the report prints them on the same row.
    """
    grouped = index_cells(result)
    scenarios: list[str] = []
    for scenario, _core in grouped:
        if scenario not in scenarios:
            scenarios.append(scenario)

    core_order = [b["id"] for b in result.binaries]
    baseline = core_order[0] if core_order else None

    out: dict = {
        "scenarios": scenarios,
        "core_order": core_order,
        "baseline": baseline,
        # The labels are carried into the aggregate so every table can head its
        # columns the same way; `cover_label` reads them from here.
        "binaries": result.binaries,
        "rows": {},
    }
    for scenario in scenarios:
        cells_here = [c for (s, _), group in grouped.items() if s == scenario for c in group]
        workload = cells_here[0].workload
        group = cells_here[0].group
        field, unit, higher_better = HEADLINE.get(workload, HEADLINE[matrix.DOWN])
        entry: dict = {
            "workload": workload,
            "group": group,
            "metric": field,
            "unit": unit,
            "higher_is_better": higher_better,
            "link": cells_here[0].link,
            "cores": {},
        }
        per_core: dict[str, list[Cell]] = {}
        for core in core_order:
            cells = grouped.get((scenario, core), [])
            if not cells:
                continue
            per_core[core] = sorted(cells, key=lambda c: c.repeat)
            record: dict = {
                "status": cells[0].status,
                "reason": cells[0].reason,
                "diagnostic": cells[0].diagnostic,
                "repeats": len(cells),
                "streams": cells[0].streams,
                "harness_ceiling_mbps": cells[0].harness_ceiling_mbps,
            }
            if record["status"] != STATUS_MEASURED:
                entry["cores"][core] = record
                continue
            for metric, name in _aggregated_metrics(field):
                values = [
                    getattr(c, metric)
                    for c in per_core[core]
                    if getattr(c, metric) is not None
                ]
                if not values:
                    continue
                unit_name = {
                    "throughput_mbps": "Mbit/s",
                    "cpu_s_per_GB": "s/GB",
                    "rss_idle_mb": "MB",
                    "rss_peak_mb": "MB",
                    "rss_peak_reported_mb": "MB",
                    "latency_us_median": "us",
                    "connect_us_median": "us",
                    "tcp_connect_us_median": "us",
                    "socks_connect_us_median": "us",
                    "ops_per_s": "per second",
                    "server_cpu_s": "s",
                    "server_rss_peak_mb": "MB",
                    "transfer_ms": "ms",
                    # Bytes per second as well as bits per second. Both are
                    # measured, and the previous harness charted MB/s, so a reader
                    # comparing the two has to have it in front of them.
                    "MBps": "MB/s",
                }.get(metric, unit)
                # Summarised like every other metric, so the tables can read it.
                record[name] = stats.summarise(values, unit_name).as_dict()
            entry["cores"][core] = record

        # Paired comparison to the baseline, on matching repeat indices.
        if baseline and baseline in per_core:
            base_cells = per_core[baseline]
            for core, own in per_core.items():
                if core == baseline:
                    continue
                if len(own) != len(base_cells):
                    continue
                candidate = [getattr(c, field) for c in own]
                reference = [getattr(c, field) for c in base_cells]
                if any(v is None for v in candidate + reference):
                    continue
                entry["cores"][core]["versus_baseline"] = stats.paired_ratio(
                    candidate, reference, higher_is_better=higher_better
                ).as_dict()

            # The baseline against itself: the size of difference this run can
            # resolve, which is what a ratio is only meaningful next to.
            values = [getattr(c, field) for c in base_cells if getattr(c, field) is not None]
            if len(values) >= 2:
                low, high = min(values), max(values)
                entry["baseline_self_spread"] = {
                    "n": len(values),
                    "min": low,
                    "max": high,
                    "relative_spread": (
                        (high - low) / low if low else None
                    ),
                }
        out["rows"][scenario] = entry
    return out


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def coverage(result: Result) -> dict:
    """What each core did with each link, with the reason for every gap.

    `refused the config` means the core's own validator was handed a config for
    that combination and rejected it. That is a measurement, not a claim taken
    from a table, and the diagnostic it produced is kept.
    """
    links: list[str] = []
    #: link -> core -> the statuses seen across every scenario on that link
    seen: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for cell in result.cells:
        if cell.link not in links:
            links.append(cell.link)
        seen[cell.link][cell.core].append(
            {"status": cell.status, "reason": cell.reason, "diagnostic": cell.diagnostic}
        )

    # A link is covered for a core if any of its scenarios carried traffic, so
    # the roll-up takes the best status rather than the last one. Taking the last
    # would let a single failing scenario relabel a link that four others
    # measured, which is how a coverage table starts lying.
    severity = [
        STATUS_MEASURED,
        STATUS_UNSUPPORTED_CONFIRMED,
        STATUS_UNSUPPORTED,
        STATUS_ERROR,
        STATUS_TIMEOUT,
        STATUS_SKIPPED,
    ]
    rows: dict[str, dict[str, dict]] = {}
    for link, per_core in seen.items():
        rows[link] = {}
        for core, entries in per_core.items():
            best = min(
                entries,
                key=lambda e: severity.index(e["status"])
                if e["status"] in severity
                else len(severity),
            )
            rows[link][core] = {
                "status": best["status"],
                "reason": best["reason"],
                "diagnostic": best["diagnostic"],
                "scenarios": len(entries),
                "scenarios_measured": sum(
                    1
                    for e in entries
                    if e["status"] in (STATUS_MEASURED, STATUS_ACCEPTED)
                ),
            }
    return {
        "links": links,
        "rows": rows,
        "cores": {b["id"]: b["label"] for b in result.binaries},
    }


def status_label(status: str) -> str:
    return MARKERS.get(status, status)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(result: Result, agg: dict, cover: dict) -> str:
    out: list[str] = []
    add = out.append
    core_ids = agg["core_order"]
    labels = [cover["cores"].get(c, c) for c in core_ids]
    baseline = agg["baseline"]

    add("# Benchmark run")
    add("")
    add(f"Generated {result.finished or 'in progress'}.")
    add("")

    # -- the run ------------------------------------------------------------
    add("## The run")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Cores under test | {len(core_ids)} |")
    add(
        f"| Mode | {'capability probe (no traffic)' if result.probe_only else 'measurement'} |"
    )
    add(f"| Server core (every cell) | `{result.server_core}` |")
    add(f"| Scenarios | {len(agg['scenarios'])} |")
    add(f"| Repeats per cell | see `results.json` |")
    host = result.host
    add(
        f"| Host | {host.get('cpu', 'unknown CPU')}, {host.get('cpus')} hardware "
        f"threads, {host.get('os')} |"
    )
    if host.get("load_average"):
        add(f"| Load average at start | {host['load_average']} |")
    if result.harness_ceiling_mbps:
        add(
            f"| Harness ceiling (no core in the path) | "
            f"{result.harness_ceiling_mbps / 1000:.1f} Gbit/s -- {result.ceiling_note} |"
        )
    add("| Baseline core (first in `--cores`) | `%s` |" % (baseline or "-"))
    add("")
    add("### Binaries")
    add("")
    add("| Core | Version | Source | SHA-256 (first 16) | Build or download |")
    add("|---|---|---|---|---|")
    for binary in result.binaries:
        source = binary.get("version_source") or "binary"
        version = f"`{binary['version']}`"
        if source != "binary":
            # A version the binary does not print is a weaker claim than one it
            # does, and the difference has to be visible rather than implied by
            # the reader noticing there is no flag.
            version += f"<br><sub>{_escape(source[:80])}</sub>"
        add(
            f"| {binary['label']} | {version} | {binary['origin']} | "
            f"`{binary['binary_sha256'][:16]}` | {binary['build_command'] or '-'} |"
        )
    add("")
    for entry in result.unavailable:
        add(f"- **{entry['core']} was not measured**: {entry['reason']}")
    if result.unavailable:
        add("")

    if result.notes:
        add("### Recorded during the run")
        add("")
        for note in result.notes:
            add(f"- {note}")
        add("")

    add("### Method")
    add("")
    add(
        "Within a repeat, every core is measured for the same scenario back to back; "
        "the order is rotated by the repeat index and reversed on alternate repeats. "
        "Comparisons are therefore paired on the repeat index, and the interval on "
        "each ratio is a bootstrap over those pairs."
    )
    add("")

    # -- the change's own question, before anything else --------------------
    pairs: list[dict] = []
    if result.base_revision:
        pairs = candidate_pairs(agg)
        add("## This change, against the commit it is based on")
        add("")
        add(f"- candidate: `{result.candidate_revision or 'working tree'}`")
        add(f"- base: `{result.base_ref}` at `{result.base_revision}`")
        add(
            "- the two binaries are the same core, the same `--release` profile and "
            "the same toolchain, built into separate target directories"
        )
        add("")
        if not pairs:
            add(
                "No scenario produced a candidate/base pair. Either the base build "
                "failed, or none of the suite's scenarios moved."
            )
            add("")
        else:
            add(
                "| Scenario | Metric | Base | Candidate | Ratio | 95% interval | "
                "Base's own spread |"
            )
            add("|---|---|---|---|---|---|---|")
            for row in pairs:
                low, high = row["ci95"]
                spread = row.get("spread")
                add(
                    f"| `{row['scenario']}` | {row['metric']} | "
                    f"{_fmt(row['base'], row['unit'])} | "
                    f"{_fmt(row['candidate'], row['unit'])} | "
                    f"{row['ratio']:.2f}x | {low:.2f}-{high:.2f}x | "
                    f"{f'{spread:.1%}' if spread is not None else '-'} |"
                )
            add("")
            add(
                "\"Base's own spread\" is the base core's max over min across its own "
                "repeats. A ratio smaller than that is inside the run's noise, and the "
                "interval column is what settles it."
            )
            add("")

    # -- capability gaps, before any performance number ---------------------
    add("## Implemented surface, per project")
    add("")
    add(
        "This table is the capability data, not a measurement: it records what each "
        "project can be *configured* to do at the version in the table above. It is "
        "here because most of it cannot be reached by a loopback benchmark, and a gap "
        "that is only visible in a benchmark is a gap nobody looks for."
    )
    add("")
    add("Legend: `yes` `partial` `deprecated` `alpha` `prerelease` `removed` `no` `n-a`.")
    add("")
    # The capability table is about separate projects, so the candidate's own
    # base build is not a column in it. Its support is the candidate's, and the
    # run's coverage table above shows that for the build under test.
    project_ids = [c for c in core_ids if c in caps.project_cores()]
    project_labels = [cover["cores"].get(c, c) for c in project_ids]
    if project_ids != core_ids:
        add(
            f"`{caps.BASE_ID}` has no column here: it is this project built from "
            f"another commit, not a separate project."
        )
        add("")
    for area in caps.feature_areas():
        rows = [r for r in caps.FEATURES if r.area == area]
        add(f"### {area}")
        add("")
        add("| Feature | " + " | ".join(project_labels) + " | Note |")
        add("|---" * (len(project_ids) + 2) + "|")
        for row in rows:
            values = [caps.feature_value(row, c) for c in project_ids]
            note = f" {row.note}" if row.note else ""
            add(
                f"| {row.feature} | " + " | ".join(values) + f" |{note} |"
            )
        add("")

    add("### Not implemented in Zray, by comparison")
    add("")
    add(
        "Assembled from the two `beyond_*` notes each core carries, so the answer to "
        "\"what does the newest Xray-core allow that we have not implemented\" is a "
        "list rather than an impression."
    )
    add("")
    for core_id in project_ids:
        core = caps.get(core_id)
        key = "beyond_zray" if core_id != "zray" else "not_in_zray"
        text = core.notes.get(key, "")
        if not text:
            continue
        add(f"- **{core.label}** -- {text}")
    add("")

    # -- what this run actually covered ------------------------------------
    add("## Coverage of this run")
    add("")
    add(
        "`refused the config` means the core's own validator rejected a config for "
        "that combination, with the diagnostic kept in `results.json`. `out of scope` "
        "means the capability table said no and the harness did not attempt it."
    )
    add("")
    add("| Link | " + " | ".join(labels) + " |")
    add("|---" * (len(core_ids) + 1) + "|")
    for link in cover["links"]:
        values = []
        for core in core_ids:
            entry = cover["rows"].get(link, {}).get(core)
            if not entry:
                values.append("not run")
                continue
            detail = entry.get("diagnostic") or entry.get("reason") or ""
            label = status_label(entry["status"])
            values.append(
                f"{label}<br><sub>{_escape(detail[:110])}</sub>" if detail else label
            )
        add(f"| `{link}` | " + " | ".join(values) + " |")
    add("")

    missing = sum(
        1
        for rows in cover["rows"].values()
        for entry in rows.values()
        if entry["status"] not in (STATUS_MEASURED, STATUS_ACCEPTED)
    )
    total = sum(len(v) for v in cover["rows"].values())
    if result.probe_only:
        add(
            f"This was a capability probe: {total - missing} of {total} core/link "
            f"combinations had their config accepted, {missing} did not, and no "
            f"traffic was moved. The performance sections below are empty because "
            f"there is nothing in them, not because they failed."
        )
    else:
        add(
            f"{total - missing} of {total} core/link combinations carried traffic; "
            f"{missing} did not."
        )
    add("")

    # -- resolution ---------------------------------------------------------
    add("## Resolution of this run")
    add("")
    add(
        "The spread of the baseline core's own repeats, per scenario. It is the size "
        "of the effect a comparison has to exceed before it means anything, so it is "
        "printed next to the comparisons rather than in a footnote."
    )
    add("")
    add("| Scenario | Baseline repeats | min | max | spread |")
    add("|---|---|---|---|---|")
    for scenario in agg["scenarios"]:
        spread = agg["rows"][scenario].get("baseline_self_spread")
        if not spread:
            continue
        entry = agg["rows"][scenario]
        rel = spread.get("relative_spread")
        add(
            f"| `{scenario}` | {spread['n']} | {_fmt(spread['min'], entry['unit'])} | "
            f"{_fmt(spread['max'], entry['unit'])} | "
            f"{f'{rel:.1%}' if rel is not None else '-'} |"
        )
    add("")

    # -- performance, per group --------------------------------------------
    for group in matrix.GROUPS:
        rows = [s for s in agg["scenarios"] if agg["rows"][s]["group"] == group]
        if not rows:
            continue
        if result.probe_only:
            # The coverage table above is the whole result. A performance table
            # whose every cell reads "nothing measured" is noise around it.
            continue
        add(f"## {group}")
        add("")
        add(_group_preamble(group, agg, rows))
        add("")
        unit = agg["rows"][rows[0]]["unit"]
        higher = agg["rows"][rows[0]]["higher_is_better"]
        add(
            f"Median of the repeats, in {unit}, with the min..max of the repeats in "
            f"brackets. {'Higher' if higher else 'Lower'} is better."
        )
        add("")
        add("| Scenario | " + " | ".join(labels) + " |")
        add("|---" * (len(core_ids) + 1) + "|")
        for scenario in rows:
            add("| `" + scenario + "` | " + " | ".join(_row_cells(agg, scenario, core_ids, baseline)) + " |")
        add("")
        for metric, title, unit_hint in PRINTED_METRICS:
            block = _metric_table(agg, rows, core_ids, metric, unit_hint)
            if block:
                add(f"### {title}")
                add("")
                add(block)
                add("")

    # -- failures -----------------------------------------------------------
    failures = [c for c in result.cells if c.status in (STATUS_ERROR, STATUS_TIMEOUT)]
    if failures:
        add("## Cells that ran and did not produce a number")
        add("")
        add(
            "Distinct from the coverage table: these cores accepted a config and then "
            "did not carry traffic. The core's own log tail is in `results.json`."
        )
        add("")
        add("| Scenario | Core | Repeat | Reason |")
        add("|---|---|---|---|")
        for cell in failures:
            add(
                f"| `{cell.scenario}` | {cell.core} | {cell.repeat} | "
                f"{_escape((cell.reason or '')[:200])} |"
            )
        add("")

    # -- user configs -------------------------------------------------------
    if result.user_configs:
        add("## Configurations supplied from outside this repository")
        add("")
        add(
            "Measured in place, so these rows include whatever network is in the "
            "way. They are comparable between cores only when every core reached the "
            "same endpoint, which each row's status shows. A config is measured one "
            "of two ways, and the row says which: with `--user-target`, by moving "
            "bytes to that destination; without one, by whether the tunnel to the "
            "config's own server comes up and how fast. The second is what any config "
            "supports, because the only endpoint a config names is its own proxy "
            "server, which does not answer this harness's protocol."
        )
        add("")
        add("| Config | Kind | Local port | Destination | Runnable | Problems |")
        add("|---|---|---|---|---|---|")
        for entry in result.user_configs:
            add(
                f"| `{entry['name']}` | {entry['kind']} | {entry['proxy_port'] or '-'} | "
                f"{entry['target'] or '-'} | {'yes' if entry['runnable'] else 'no'} | "
                f"{_escape('; '.join(entry['problems'])[:160]) or '-'} |"
            )
        add("")
        rows = [s for s in agg["scenarios"] if agg["rows"][s]["group"] == "user"]
        if rows:
            add("| Config | " + " | ".join(labels) + " |")
            add("|---" * (len(core_ids) + 1) + "|")
            for scenario in rows:
                add(
                    "| `" + scenario + "` | "
                    + " | ".join(_row_cells(agg, scenario, core_ids, baseline))
                    + " |"
                )
            add("")

    # -- confounders --------------------------------------------------------
    add("## Confounders")
    add("")
    for item in confounders(result, agg):
        add(f"- {item}")
    add("")
    add("## Re-running this")
    add("")
    add("```sh")
    add("cd docs/benchmarks/harness")
    add("python3 bench.py " + " ".join(result.invocation[1:]))
    add("```")
    add("")
    add(
        "`manifest.json` next to this file carries the digest of every artefact and "
        "the replay command; `python3 validate_results.py <dir>` re-derives every "
        "aggregate in `results.json` from the raw cells and fails if any of them "
        "disagrees."
    )
    add("")
    return "\n".join(out)


def _group_preamble(group: str, agg: dict, rows: list[str]) -> str:
    """A factual description of what the group varies. No conclusions."""
    body = {
        "baseline": "One VLESS link at three security layers, at four concurrency "
        "levels, plus one upload, one duplex and two setup workloads.",
        "security": "Each row differs from its `vless-raw-tls-down-8` or "
        "`vless-raw-reality-down-8` counterpart in exactly one setting.",
        "transport": "One protocol over every transport except raw, over TLS, at "
        "eight flows; the raw row is the baseline group's.",
        "protocol": "Every protocol that can carry a TCP stream to a local sink, with "
        "and without a security layer.",
        "setup": "Connection establishment, measured as a validated round trip and as "
        "a connect-and-close rate.",
        "memory": "Idle flows held open with no payload. Idle memory is recorded for "
        "every cell in every group.",
        "udp": "Datagrams through a SOCKS5 UDP ASSOCIATE, which is a different path "
        "from the TCP rows.",
    }.get(group, "")
    links = sorted({agg["rows"][s].get("link", "") for s in rows if agg["rows"][s].get("link")})
    if links:
        body += f" Links: {', '.join(f'`{l}`' for l in links)}."
    return body


def _row_cells(agg: dict, scenario: str, core_ids: list[str], baseline: str | None) -> list[str]:
    entry = agg["rows"][scenario]
    cells = []
    for core in core_ids:
        record = entry["cores"].get(core)
        if not record:
            cells.append("not run")
            continue
        if record["status"] != STATUS_MEASURED:
            detail = record.get("diagnostic") or record.get("reason") or ""
            cells.append(
                f"**{status_label(record['status'])}**"
                + (f"<br><sub>{_escape(detail[:110])}</sub>" if detail else "")
            )
            continue
        summary = record.get(entry["metric"]) or {}
        text = _fmt(summary.get("median"), entry["unit"]) + _span(summary)
        versus = record.get("versus_baseline")
        if versus and baseline and core != baseline:
            text += f"<br>{_ratio_cell(versus)}"
        cells.append(text)
    return cells


def _ratio_cell(versus: dict) -> str:
    ratio = versus.get("ratio")
    if ratio is None:
        return "no ratio"
    lo, hi = versus.get("ci95_low"), versus.get("ci95_high")
    verdict = versus.get("verdict", "")
    if lo is not None and hi is not None:
        span = f"{lo:.2f}-{hi:.2f}x"
    else:
        span = ""
    if verdict == "within_noise":
        return f"{ratio:.2f}x ({span}, interval spans 1.00x)"
    return f"{ratio:.2f}x ({span}, interval excludes 1.00x)"


def _metric_table(agg: dict, rows: list[str], core_ids: list[str], metric: str, unit: str) -> str:
    lines = ["| Scenario | " + " | ".join(cover_label(agg, c) for c in core_ids) + " |",
             "|---" * (len(core_ids) + 1) + "|"]
    unit = _UNIT_LABEL.get(unit, unit)
    any_value = False
    for scenario in rows:
        values = []
        for core in core_ids:
            record = agg["rows"][scenario]["cores"].get(core)
            summary = (record or {}).get(metric)
            if (
                not record
                or record["status"] != STATUS_MEASURED
                or not isinstance(summary, dict)
            ):
                if not isinstance(summary, dict):
                    values.append("-")
                    continue
            any_value = True
            values.append(_fmt(summary.get("median"), unit) + _span(summary))
        lines.append(f"| `{scenario}` | " + " | ".join(values) + " |")
    return "\n".join(lines) if any_value else ""


#: Units the metric tables pass as hints that the number formatter has no branch
#: for, so the value printed with nothing after it -- "3.50" for a count of CPU
#: seconds. Both spellings are normalised to the label actually printed.
_UNIT_LABEL = {
    "MB": " MB",
    "s": " s",
    "ms": " ms",
    "MB resident": " MB resident",
    "threads": " threads",
}


def cover_label(agg: dict, core_id: str) -> str:
    """The heading a core's column carries.

    The group table and the per-metric tables below it must agree: one printed
    `Zray-core` and the other `zray` in the same section, which reads as two
    different cores.
    """
    for binary in agg.get("binaries") or []:
        if binary.get("id") == core_id:
            return binary.get("label") or core_id
    return core_id


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def candidate_pairs(agg: dict, candidate: str = "zray") -> list[dict]:
    """The candidate against its own base, one entry per scenario.

    This is the only comparison whose ratio means "this change". Everything else
    in the report is context, and keeping the two apart is what stops a five-line
    diff from being read as a verdict about a whole project.
    """
    rows: list[dict] = []
    for scenario, entry in agg["rows"].items():
        record = entry["cores"].get(candidate)
        base_record = entry["cores"].get(caps.BASE_ID)
        if not record or record.get("status") != STATUS_MEASURED:
            continue
        if not base_record or base_record.get("status") != STATUS_MEASURED:
            continue
        versus = record.get("versus_baseline")
        if not versus or versus.get("ratio") is None:
            continue
        rows.append(
            {
                "scenario": scenario,
                "group": entry["group"],
                "metric": entry["metric"],
                "unit": entry["unit"],
                "higher_is_better": entry["higher_is_better"],
                "candidate": (record.get(entry["metric"]) or {}).get("median"),
                "base": (base_record.get(entry["metric"]) or {}).get("median"),
                "ratio": versus.get("ratio"),
                "ci95": (versus.get("ci95_low"), versus.get("ci95_high")),
                "verdict": versus.get("verdict"),
                "pairs": versus.get("pairs"),
                "spread": (entry.get("baseline_self_spread") or {}).get(
                    "relative_spread"
                ),
            }
        )
    return rows


@dataclass
class Gate:
    ok: bool
    verdict: str
    lines: list[str]


def gate(
    pairs: list[dict],
    *,
    max_regression: float | None = None,
    min_improvement: float | None = None,
) -> Gate:
    """Decide whether a candidate is allowed to land, from the paired intervals.

    A scenario fails when its whole interval lies on the wrong side of the
    tolerance. It is not enough for the point estimate to be worse: with three
    repeats a 4% regression and a 40% one look identical until the interval is
    read, and a gate that cannot tell them apart is a gate that fails at random.

    Direction is read from the metric, never from the sign of the ratio. A ratio
    above 1.0 is an improvement for a throughput row and a regression for a memory
    row, and a gate that assumes otherwise passes a memory regression with a
    straight face.
    """
    if not pairs:
        return Gate(
            False,
            "no comparison",
            ["no scenario produced a candidate/base pair, so nothing could be gated"],
        )

    # The tolerance arrives as a percentage ("5 means 5%") against a ratio that
    # runs from 0 to 1, so it is scaled here rather than at the call sites.
    if max_regression is not None:
        max_regression = max_regression / 100.0
    if min_improvement is not None:
        min_improvement = min_improvement / 100.0

    failures: list[str] = []
    improved: list[dict] = []
    regressed: list[dict] = []
    unresolved: list[dict] = []

    for row in pairs:
        low, high = row["ci95"]
        if row["verdict"] == "within_noise" or low is None or high is None:
            unresolved.append(row)
            continue
        higher = row["higher_is_better"]
        # `ratio` is candidate over reference, so above 1.0 means more of the
        # metric. That is an improvement when more is better and a regression when
        # less is. Reading it the other way round reported a 40% throughput
        # regression as "1 scenario resolved better" and cleared it.
        candidate_higher = row["ratio"] >= 1.0
        if candidate_higher == higher:
            improved.append(row)
        else:
            regressed.append(row)
        if max_regression is not None:
            # Worse than the tolerance across the whole interval. On a
            # higher-is-better metric that is an interval entirely below
            # 1 - tolerance; on a lower-is-better one, entirely above 1 + it.
            beyond = high < 1.0 - max_regression if higher else low > 1.0 + max_regression
            if beyond:
                margin = (1.0 - high) if higher else (low - 1.0)
                failures.append(
                    f"`{row['scenario']}` {row['metric']} worse by at least "
                    f"{margin * 100:.0f}% ({row['ratio']:.2f}x, 95% "
                    f"{low:.2f}-{high:.2f}x, tolerance {max_regression:.0%})"
                )

    parts = [
        f"- {len(improved)} scenario(s) resolved better",
        f"- {len(regressed)} scenario(s) resolved worse",
        f"- {len(unresolved)} scenario(s) unresolved: the interval spans 1.00x",
    ]
    if min_improvement is not None:
        # Cleared means the whole interval clears it, so this is the end nearest
        # 1.0x again. Accepting either end counted an improvement the interval
        # did not support.
        cleared = []
        for r in improved:
            low_r, high_r = r["ci95"]
            margin = (low_r - 1.0) if r["higher_is_better"] else (1.0 - high_r)
            if margin is not None and margin > min_improvement:
                cleared.append(r)
        parts.append(
            f"- {len(cleared)} scenario(s) cleared an improvement of "
            f"{min_improvement:.0%}"
        )
    if failures:
        return Gate(
            False,
            f"worse than the base by more than the tolerance on "
            f"{len(failures)} scenario(s)",
            parts + [""] + [f"  FAIL {line}" for line in failures],
        )
    if not improved and not regressed:
        # A gate that passes because nothing resolved anything is not a pass. The
        # distinction matters: "no regression found" and "no measurement" are
        # different sentences, and conflating them is how a run with too few
        # repeats reports a clean bill of health.
        return Gate(
            True,
            "no scenario resolved a difference, so nothing was gated",
            parts
            + [
                "",
                "  The run could not separate the two builds on any scenario. That "
                "is a measurement that was too small, not a finding of equality.",
            ],
        )
    return Gate(True, "within the requested tolerance", parts)


def confounders(result: Result, agg: dict) -> list[str]:
    """Stated as properties of the measurement, not as conclusions about cores."""
    out = [
        "Every byte crosses loopback, so a row is a measurement of work per byte. It "
        "is not a measurement of a link, and windowed transports cannot be ranked by "
        "it.",
        "One server process serves every client for a link. It is excluded from the "
        "client's CPU and memory but shares loopback CPU, so absolute values understate "
        "a dedicated-server deployment. The server's own CPU is a column above.",
        "Zray and Xray-core verify the fixture certificate chain; sing-box has no client "
        "CA option and uses `insecure: true`. The TLS rows therefore differ in "
        "certificate verification as well as in the core.",
        "Peak memory is the maximum of a sampled resident set: 50 ms on Linux, 200 ms "
        "on macOS. The kernel's own high-water mark is recorded per cell in "
        "`results.json` as `rss_peak_reported_mb`, alongside the server's peak "
        "resident set in `server_rss_peak_mb`; neither is a column here, because "
        "neither has a repeat-to-repeat distribution to compare across cores.",
        "Linux reports CPU in clock ticks, so a window under 10 ms of CPU reads as "
        "zero. A cell whose sampling produced fewer than two readings has no "
        "difference to report at all, and is marked in `results.json` with a "
        "`notes` sentence rather than being shown as a measured zero.",
        "Each comparison's interval is a bootstrap over the paired repeats in that one "
        "run. An interval that spans 1.00x is a difference this run could not resolve.",
        "The harness ceiling is measured with no core in the path, once per stream "
        f"count. A row at or above {HARNESS_BOUND:.0%} of the ceiling for its own "
        "stream count is bounded by the generator rather than by the core.",
        "The generated REALITY server widens `minClientVer` and `maxClientVer`. Left at "
        "their defaults those bounds are a client-version policy, and the rows would "
        "measure version strings rather than the protocol.",
    ]
    # Each row is judged against the ceiling measured at its own stream count.
    # The ceiling is a property of the generator's loop, and the loop is not the
    # same at one flow as at sixty-four: measured on one host the same generator
    # reached 78 Gbit/s at 1 stream, 86 at 8 and 5.7 at 64. Testing every row
    # against one number silently freed the many-flow rows -- the ones the
    # generator is actually holding back -- and convicted none of them.
    bound = [
        (scenario, core)
        for scenario, entry in agg["rows"].items()
        for core, record in entry["cores"].items()
        if record.get("status") == STATUS_MEASURED
        and (record.get("throughput_mbps") or {}).get("median")
        and record.get("harness_ceiling_mbps")
        and record["throughput_mbps"]["median"]
        >= record["harness_ceiling_mbps"] * HARNESS_BOUND
    ]
    if bound:
        out.insert(
            0,
            f"{len(bound)} core/scenario pairs reached at least {HARNESS_BOUND:.0%} of "
            f"the measured ceiling: "
            + ", ".join(f"`{s}`/{c}" for s, c in bound[:12])
            + ("..." if len(bound) > 12 else "")
            + ". The differences between them are smaller than the generator's own "
            "variation.",
        )
    return out


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

BG = "#0D0F12"
FG = "#E5E7EB"
GRID = "#374151"
SERIES = ["#FBBF24", "#60A5FA", "#34D399", "#F472B6", "#A78BFA", "#94A3B8"]


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.facecolor": BG,
            "axes.facecolor": BG,
            "axes.edgecolor": GRID,
            "text.color": FG,
            "axes.labelcolor": FG,
            "xtick.color": FG,
            "ytick.color": FG,
            "font.size": 10,
            "savefig.facecolor": BG,
        }
    )
    return plt


def _status_value(status: str) -> float:
    # A probe run's whole point is the config check, so "accepted" is its success
    # state. It had no entry here and fell through to the same 0.30 as "not run",
    # which made the capability job's charts say the opposite of its own table.
    return {
        STATUS_MEASURED: 1.0,
        STATUS_ACCEPTED: 0.88,
        STATUS_UNSUPPORTED: 0.45,
        STATUS_UNSUPPORTED_CONFIRMED: 0.15,
        STATUS_ERROR: 0.62,
        STATUS_TIMEOUT: 0.62,
        STATUS_SKIPPED: 0.3,
    }.get(status, 0.3)


def _draw_grid(
    plt,
    ax,
    row_keys: list,
    row_labels: list[str],
    col_keys: list,
    col_labels: list[str],
    values,
    *,
    title: str,
    note: str = "",
):
    """A labelled grid: the machine-readable keys drive the values, and the
    display labels are only ever drawn.

    Two parallel lists rather than one, because the keys here are indices into
    the capability table and enum members, and an axis label has to be a string.
    """
    import numpy as np

    grid = np.array(
        [[values(r, c) for c in col_keys] for r in row_keys], dtype=float
    )
    ax.imshow(grid, aspect="auto", cmap="cividis", vmin=0, vmax=1)
    ax.set_xticks(range(len(col_labels)))
    ax.set_xticklabels(col_labels, rotation=90, fontsize=7)
    ax.set_yticks(range(len(row_labels)))
    ax.set_yticklabels(row_labels, fontsize=7)
    for i, r in enumerate(row_keys):
        for j, c in enumerate(col_keys):
            v = float(grid[i, j])
            if v:
                ax.text(
                    j, i, f"{v:.2f}".rstrip("0").rstrip("."), ha="center",
                    va="center", fontsize=6, color="#0D0F12",
                )
    ax.set_title(title, fontsize=10, color=FG, pad=8)
    if note:
        ax.text(0, -0.06, note, transform=ax.transAxes, fontsize=7, color="#9CA3AF")


def render_charts(result: Result, agg: dict, cover: dict, outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    plt = _plt()
    import numpy as np

    core_ids = agg["core_order"]
    labels = [cover["cores"].get(c, c) for c in core_ids]
    written: list[Path] = []
    written_names: set[str] = set()

    # -- 1. implemented surface, all four projects --------------------------
    chart_ids = [c for c in core_ids if c in caps.project_cores()]
    chart_labels = [cover["cores"].get(c, c) for c in chart_ids]
    if chart_ids:
        rows = list(caps.FEATURES)
        fig, ax = plt.subplots(figsize=(7.0, 0.235 * len(rows) + 2.0))
        _draw_grid(
            plt, ax,
            rows,
            [f"{r.area}: {r.feature}" for r in rows],
            chart_ids,
            chart_labels,
            lambda r, c: caps.scale_value(caps.feature_value(r, c)),
            title="Implemented surface per project (1.00 yes, 0.00 no)",
            note=(
                "Scale: yes 1.00, partial 0.72, deprecated 0.55, alpha 0.45, "
                "prerelease 0.38, removed 0.16, no 0.00. Source: zbench/caps.py"
            ),
        )
        fig.tight_layout()
        path = outdir / "capability-surface.png"
        fig.savefig(path, dpi=110, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    # -- 2. protocol x transport, one panel per core -----------------------
    protocols = list(caps.PROTOCOLS)
    transports = list(caps.TRANSPORTS)
    if chart_ids:
        fig, axes = plt.subplots(
            1, len(chart_ids), figsize=(4.2 * len(chart_ids), 5.2), squeeze=False
        )
        for index, core_id in enumerate(chart_ids):
            core = caps.get(core_id)
            ax = axes[0][index]

            def value(r: str, c: str, core=core) -> float:
                return 0.0 if core.why_not(r, c, "tls") else 1.0

            _draw_grid(
                plt, ax, protocols, protocols, transports, transports, value,
                title=f"{core.label} -- client protocol x transport, over TLS",
            )
        fig.suptitle(
            "Protocol x transport: 1.00 where the core can be configured for it, "
            "0.00 where it cannot",
            fontsize=11, color=FG,
        )
        fig.tight_layout(rect=(0, 0, 1, 0.96))
        path = outdir / "protocol-transport-grid.png"
        fig.savefig(path, dpi=110, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    # -- 3. what this run covered -----------------------------------------
    links = cover["links"]
    if links and core_ids:
        fig, ax = plt.subplots(figsize=(max(9, 0.55 * len(links)), 2.6))
        _draw_grid(
            plt, ax, links, links, core_ids, labels,
            lambda r, c: _status_value(
                cover["rows"].get(r, {}).get(c, {}).get("status", STATUS_SKIPPED)
            ),
            title="Coverage of this run",
            note=(
                "1.00 carried traffic, 0.62 ran and failed or timed out, 0.45 out of "
                "scope, 0.30 not run, 0.88 a probe's config check accepted it, "
                "0.15 the core's own config check refused it"
            ),
        )
        fig.tight_layout()
        path = outdir / "run-coverage.png"
        fig.savefig(path, dpi=110, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    # -- 4. resolution: the baseline against itself ------------------------
    spread_rows = [
        s for s in agg["scenarios"] if agg["rows"][s].get("baseline_self_spread")
    ]
    if spread_rows:
        fig, ax = plt.subplots(figsize=(max(10, 0.7 * len(spread_rows)), 4.2))
        index = np.arange(len(spread_rows))
        values = [
            (agg["rows"][s]["baseline_self_spread"]["relative_spread"] or 0.0) * 100
            for s in spread_rows
        ]
        ax.bar(index, values, 0.6, color="#F472B6")
        for x, v in zip(index, values):
            ax.text(x, v, f"{v:.1f}%", ha="center", va="bottom", fontsize=7, color=FG)
        ax.set_xticks(index)
        ax.set_xticklabels(spread_rows, rotation=70, ha="right", fontsize=7)
        ax.set_ylabel("baseline max/min across repeats (%)")
        ax.set_title(
            f"Run-to-run variation of {cover['cores'].get(agg['baseline'], agg['baseline'])} "
            "measured against itself",
            fontsize=11, color=FG,
        )
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout()
        path = outdir / "resolution.png"
        fig.savefig(path, dpi=110, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    # -- 5. per-group metrics, with missing cells drawn as missing ---------
    for group in matrix.GROUPS:
        rows = [s for s in agg["scenarios"] if agg["rows"][s]["group"] == group]
        if not rows:
            continue
        entry0 = agg["rows"][rows[0]]
        headline = entry0["metric"]
        # A metric already drawn as the group's headline is not drawn again: the
        # memory group leads with `rss_peak_mb`, which also had a `peak-memory`
        # entry, so every run shipped two byte-identical charts under two names.
        seen: set[str] = set()
        for metric, filename in (
            (headline, f"{group}-{_slug(headline)}.png"),
            ("cpu_s_per_GB", f"{group}-cpu-per-gb.png"),
            ("rss_peak_mb", f"{group}-peak-memory.png"),
            ("rss_idle_mb", f"{group}-idle-memory.png"),
            ("connect_us_median", f"{group}-connect-us.png"),
        ):
            if metric in seen or filename in written_names:
                continue
            seen.add(metric)
            path = _metric_chart(plt, agg, cover, rows, core_ids, labels, metric,
                                 entry0["unit"], outdir / filename, group,
                                 result.harness_ceiling_mbps)
            if path:
                written.append(path)
                written_names.add(filename)
    return written


def _metric_chart(plt, agg, cover, rows, core_ids, labels, metric, unit, path, group, ceiling):
    import numpy as np

    series: dict[str, list] = {}
    statuses: dict[str, list] = {}
    for core in core_ids:
        series[core] = []
        statuses[core] = []
        for scenario in rows:
            record = agg["rows"][scenario]["cores"].get(core)
            if not record or record["status"] != STATUS_MEASURED:
                series[core].append(None)
                statuses[core].append(record["status"] if record else STATUS_SKIPPED)
                continue
            summary = record.get(metric) or {}
            series[core].append(summary.get("median"))
            statuses[core].append(STATUS_MEASURED)
    if not any(any(v is not None for v in s) for s in series.values()):
        return None

    index = np.arange(len(rows))
    width = 0.8 / max(1, len(core_ids))
    fig, ax = plt.subplots(figsize=(max(10, 0.95 * len(rows)), 5.6))
    for i, core in enumerate(core_ids):
        xs = index + (i - (len(core_ids) - 1) / 2) * width
        ys = series[core]
        present_x = [x for x, y in zip(xs, ys) if y is not None]
        present_y = [y for y in ys if y is not None]
        if present_y:
            ax.bar(present_x, present_y, width, color=SERIES[i % len(SERIES)],
                   label=labels[i])
            for x, y in zip(present_x, present_y):
                ax.text(x, y, _fmt(y, unit), rotation=90, ha="center", va="bottom",
                        fontsize=6, color=FG)

    # The scale is set by the data, not by the ceiling. A ceiling an order of
    # magnitude above every bar, drawn as a line, flattens the bars it is meant
    # to be compared against; when it is that far out it belongs in the title.
    top = max(
        (v for series in series.values() for v in series if v is not None),
        default=1.0,
    )
    ax.set_ylim(0, top * 1.28 if top > 0 else 1)
    floor = (top * 1.28 if top > 0 else 1) * 0.02

    # A missing value is drawn as a hatched box with a short label. A gap in a
    # chart reads as an oversight; a labelled box reads as a result, and the
    # reason for it is a table cell away.
    for i, core in enumerate(core_ids):
        for x, y, status in zip(
            index + (i - (len(core_ids) - 1) / 2) * width,
            series[core],
            statuses[core],
        ):
            if y is not None:
                continue
            ax.bar(x, floor * 6, width, color="none", edgecolor="#6B7280",
                   hatch="///", linewidth=0.6, alpha=0.6)
            ax.text(x, floor * 7, SHORT_STATUS.get(status, status), ha="center",
                    va="bottom", fontsize=5.5, color="#9CA3AF", rotation=90)

    subtitle = []
    # A horizontal ceiling line is only a true statement about rows that all ran
    # at the same flow count. Across a mixed chart it would draw one number over
    # rows measured under different conditions, so it is only drawn when every
    # row shares that ceiling, and otherwise the variation is stated instead.
    ceilings = {
        r["harness_ceiling_mbps"]
        for r in (agg["rows"][name]["cores"].get(core) or {} for name in rows for core in core_ids)
        if r.get("harness_ceiling_mbps")
    }
    if ceiling and metric == "throughput_mbps" and len(ceilings) == 1:
        if ceiling <= top * 3:
            ax.axhline(ceiling, color="#94A3B8", linestyle="--", linewidth=1)
            ax.text(len(rows) - 0.45, ceiling, " harness ceiling", va="bottom",
                    ha="right", fontsize=7, color="#94A3B8")
        else:
            subtitle.append(f"harness ceiling {ceiling:,.0f} {unit}, off this scale")
    elif len(ceilings) > 1:
        subtitle.append(
            "harness ceiling varies by flow count ("
            + ", ".join(f"{c / 1000:,.0f} {unit}" for c in sorted(ceilings))
            + ")"
        )
    direction = (
        "higher is better" if agg["rows"][rows[0]]["higher_is_better"] else "lower is better"
    )
    title = f"{group}: {metric} ({direction})"
    if subtitle:
        title += "  --  " + "; ".join(subtitle)
    ax.set_xticks(index)
    ax.set_xticklabels(rows, rotation=65, ha="right", fontsize=7)
    ax.set_ylabel(f"{metric}  ({unit})")
    ax.spines[["top", "right"]].set_visible(False)
    # The legend goes above the axes rather than inside them: a bar in the
    # tallest group otherwise grows straight through it, which hides both the
    # colour key and the number on the bar.
    handles, legend_labels = ax.get_legend_handles_labels()
    fig.suptitle(title, fontsize=12, color=FG, y=0.995)
    if handles:
        fig.legend(
            handles, legend_labels, frameon=False, fontsize=8, ncol=len(handles),
            loc="upper center", bbox_to_anchor=(0.5, 0.955),
        )
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(fig)
    return path


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text).strip("-")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def write(result: Result, outdir: Path, argv: list[str] | None = None) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    agg = aggregate(result)
    cover = coverage(result)

    results_path = outdir / "results.json"
    results_path.write_text(
        json.dumps(
            {
                "schema": result.schema,
                "run": {k: v for k, v in result.as_dict().items() if k != "cells"},
                "aggregate": agg,
                "coverage": cover,
                "cells": [asdict(c) for c in result.cells],
            },
            indent=1,
            default=str,
        )
        + "\n"
    )
    report_path = outdir / "report.md"
    report_path.write_text(render_markdown(result, agg, cover))
    charts = render_charts(result, agg, cover, outdir / "charts")

    manifest = {
        "schema": "zray-bench-manifest/1",
        "generated": result.finished,
        "replay": {
            "cwd": "docs/benchmarks/harness",
            "argv": argv if argv is not None else result.invocation[1:],
        },
        "host": result.host,
        "binaries": result.binaries,
        "server_core": result.server_core,
        "unavailable": result.unavailable,
        "harness_ceiling_mbps": result.harness_ceiling_mbps,
        "fixture": result.identity,
        "cells": len(result.cells),
        "measured_cells": sum(1 for c in result.cells if c.status == STATUS_MEASURED),
        "artifacts": {
            path.name: _digest(path)
            for path in [results_path, report_path, *charts]
        },
    }
    manifest_path = outdir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=1, default=str) + "\n")
    return {
        "results": results_path,
        "report": report_path,
        "manifest": manifest_path,
        "charts": charts,
        "aggregate": agg,
        "coverage": cover,
    }


def _digest(path: Path) -> dict:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
