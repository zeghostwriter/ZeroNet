# feed-eval

Measures which GitHub config feeds actually work **from the network it runs
on**. Run it from inside Iran; results from anywhere else say nothing about
Iranian users. PLAN.md §3 was produced with these scripts on 2026-09-23.

Requirements: Python 3.11+, `curl`, a `zray` binary built from Zray-Core,
and optionally the Xray oracle (`../scripts/fetch-xray-oracle.sh` in
Zray-Core) for differential runs.

```bash
# 1. Download feeds (name<TAB>url per line)
while IFS=$'\t' read n u; do curl -sL --compressed -o "$n.txt" "$u"; done < feeds.tsv

# 2. Parse with Zray, TCP stage (<=1500/feed), real stage (100 random TCP-open/feed)
python3 pipe.py /path/to/zray 1500 100 radikal limilco epodonios ...

# 3. Which working servers each feed contains
python3 analyze.py

# 4. Zray vs Xray on the same TCP-open links (finds Zray bugs)
python3 diff.py /path/to/zray /path/to/xray 60 radikal barryfar
```

- `pipe.py` writes `plain/<feed>.txt` (decoded links) and `pipe_results.json`.
- `diff.py` writes `diff_results.json`.
- `xconv.py` converts share links to Xray outbounds for the oracle.

Outputs contain third-party server credentials copied from public feeds. They
are ignored by git and should not be committed.

## Finding Zray bugs (differential against Xray)

```bash
# Rejected-by-Zray links, bucketed by error; needs plain/ from pipe.py
python3 - <<'PY'   # writes rejected.json (see catx.py for the category rules)
PY
python3 catx.py /path/to/xray 60              # do Zray-rejected categories work in Xray?
python3 sdiff.py /path/to/zray /path/to/xray 80   # parse-OK links by transport: Xray-first, Zray retest (silent bugs)
python3 strata.py /path/to/zray                # stratified yield test used in PLAN.md §3.3
```

`rejected.json` is produced by running `zray check` over `plain/*.txt` and
keeping `[link, error, category]` rows. Its generator is inlined in the
2026-09-23 session. The format is simple enough to regenerate.
