"""A multi-core benchmark harness for Zray.

The package is split so that each decision lives in one place:

* `caps`     what each core can do, and why a cell is empty
* `cores`    finding, building, starting and reaping each core
* `configs`  one config per dialect, for the same job
* `matrix`   which scenarios exist, and in which suite
* `measure`  sampling a running process
* `stats`    medians, spread, and paired bootstrap intervals
* `runner`   the loop
* `report`   tables, coverage and charts
* `userconfig`  configurations supplied from outside the repo
"""

__all__ = [
    "caps",
    "cores",
    "configs",
    "matrix",
    "measure",
    "runner",
    "stats",
    "report",
    "userconfig",
]
