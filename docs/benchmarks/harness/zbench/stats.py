"""Aggregating repeats into a number, and saying how much to trust it.

Three or five repeats on a shared runner do not establish a difference; they
establish a median and a rough sense of spread. This module keeps those two
apart:

* `summarise` reports the median with a median absolute deviation, so a single
  wild sample is visible instead of hidden inside an average.
* `paired_ratio` compares two cores *within* the same repeat and bootstraps the
  distribution of the ratio. A ratio computed from already-aggregated medians
  would divide away the correlation between the two cores' samples, which is the
  whole reason for pairing.
* `verdict` refuses to call a win when the interval straddles the threshold. A
  harness that prints "Zray is 12% faster" from three samples it cannot
  distinguish is the failure mode this file exists to prevent.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

# Seeded so a rerun of the same data produces the same interval. An unseeded
# bootstrap makes a report irreproducible, which is a strange property for a
# document meant to be evidence.
BOOTSTRAP_SEED = 20260902
BOOTSTRAP_RESAMPLES = 4000


def median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    if n % 2:
        return ordered[n // 2]
    return (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0


def mad(values: list[float]) -> float | None:
    """Median absolute deviation, scaled to be comparable with a standard
    deviation for normally distributed data."""
    if not values:
        return None
    centre = median(values)
    if centre is None:
        return None
    return 1.4826 * median([abs(v - centre) for v in values])


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * p / 100.0))
    return ordered[min(rank, len(ordered)) - 1]


@dataclass
class Summary:
    count: int
    median: float | None
    minimum: float | None
    maximum: float | None
    p95: float | None
    dispersion: float | None
    unit: str = ""
    values: list[float] = field(default_factory=list, repr=False)

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "median": self.median,
            "min": self.minimum,
            "max": self.maximum,
            "p95": self.p95,
            "mad": self.dispersion,
            "unit": self.unit,
        }


def summarise(values: list[float], unit: str = "") -> Summary:
    clean = [v for v in values if v is not None and math.isfinite(v)]
    return Summary(
        count=len(clean),
        median=median(clean),
        minimum=min(clean) if clean else None,
        maximum=max(clean) if clean else None,
        p95=percentile(clean, 95.0),
        dispersion=mad(clean),
        unit=unit,
        values=clean,
    )


# ---------------------------------------------------------------------------
# Paired comparison
# ---------------------------------------------------------------------------


@dataclass
class Comparison:
    ratio: float | None
    ci_low: float | None
    ci_high: float | None
    pairs: int
    verdict: str
    explanation: str

    def as_dict(self) -> dict:
        return {
            "ratio": self.ratio,
            "ci95_low": self.ci_low,
            "ci95_high": self.ci_high,
            "pairs": self.pairs,
            "verdict": self.verdict,
            "explanation": self.explanation,
        }


#: A difference smaller than this is inside the run-to-run noise the harness can
#: actually resolve. It is not a claim about the cores; it is a claim about this
#: host with this sample count.
DEFAULT_TOLERANCE = 0.05


def paired_ratio(
    candidate: list[float],
    reference: list[float],
    *,
    higher_is_better: bool = True,
    tolerance: float = DEFAULT_TOLERANCE,
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> Comparison:
    """Bootstrap a paired ratio of `candidate` to `reference`.

    The two lists must be the same length and in the same order: element *i* is
    the same repeat on both cores. That is the pairing, and it is what removes
    the "the machine was busier during the third run" variance that dominates an
    unpaired comparison on a shared runner.
    """
    pairs = [
        (c, r)
        for c, r in zip(candidate, reference)
        if c is not None and r is not None and math.isfinite(c) and math.isfinite(r)
    ]
    if len(pairs) < 2:
        return Comparison(
            None,
            None,
            None,
            len(pairs),
            "unproven",
            f"only {len(pairs)} usable pair(s); a ratio needs at least 2",
        )
    # A zero reference sample has no ratio, so it cannot enter the bootstrap. It
    # has to leave the reported pair count too: counting a pair the statistics
    # never saw is how a single ratio ends up described as a three-pair result.
    ratios = [c / r for c, r in pairs if r]
    usable = len(ratios)
    if usable < 2:
        return Comparison(
            None,
            None,
            None,
            usable,
            "unproven",
            f"only {usable} usable pair(s) after dropping "
            f"{len(pairs) - usable} with a zero reference sample; a ratio needs "
            f"at least 2",
        )

    rng = random.Random(seed)
    draws = []
    for _ in range(resamples):
        sample = [ratios[rng.randrange(len(ratios))] for _ in ratios]
        draws.append(median(sample))
    draws.sort()
    lo = percentile(draws, 2.5)
    hi = percentile(draws, 97.5)
    point = median(ratios)

    if lo is None or hi is None or point is None:
        return Comparison(point, lo, hi, usable, "unproven", "bootstrap produced no interval")

    # Direction is decided by the metric, never by the sign of the ratio. A ratio
    # above 1.0 is more throughput on a throughput row and more memory on a memory
    # row, so reading the ratio alone called a 20% memory increase
    # "candidate_cheaper" and printed that it was "21% more cheaper".
    if lo > 1.0 + tolerance:
        candidate_higher, margin = True, lo - 1.0
    elif hi < 1.0 - tolerance:
        candidate_higher, margin = False, 1.0 - hi
    else:
        return Comparison(
            point,
            lo,
            hi,
            usable,
            "within_noise",
            f"the 95% interval [{lo:.2f}, {hi:.2f}]x includes 1.0x, so this run "
            f"cannot resolve a difference of {tolerance:.0%} or more",
        )

    # The margin is read off the end of the interval nearest 1.0, because that is
    # the end the whole interval guarantees. Quoting the far end promises more
    # than the data supports.
    verdict = "candidate_better" if candidate_higher == higher_is_better else "candidate_worse"
    return Comparison(
        point,
        lo,
        hi,
        usable,
        verdict,
        f"the whole 95% interval [{lo:.2f}, {hi:.2f}]x lies on one side of "
        f"1.0x; the candidate's value is at least {margin:.0%} "
        f"{'higher' if candidate_higher else 'lower'} than the reference",
    )
