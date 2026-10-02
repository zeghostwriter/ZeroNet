# Results

One directory per run, named for the day it was taken. A run is never
overwritten, because the whole value of a measurement is being able to compare
it with the one before it.

```
results/
  2026-04-legacy/   the earlier two-protocol comparison, kept for the README table
  latest/           written by the most recent local run; not committed
```

CI runs are attached to the workflow run as the `benchmark-<run id>` artefact
rather than committed here: they are ninety megabytes of charts and a results
file whose value is in the commit it was taken on, and that pairing lives in the
workflow run itself. To keep one:

```sh
# after a run
gh run download <run id> -n benchmark-<run id> -D docs/benchmarks/results/$(date +%F)
(cd docs/benchmarks/harness && python3 validate_results.py ../results/$(date +%F))
```

The date directory is then a complete, independently checkable record: the
report, the raw cells, the manifest with the binary digests, and the charts.
