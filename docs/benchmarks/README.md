# Benchmarks

Zray measured against [Xray-core](https://github.com/XTLS/Xray-core),
[sing-box](https://github.com/SagerNet/sing-box) and
[xray-rust](https://github.com/aimalygin/xray-rust), in GitHub Actions, on a
recorded runner.

```sh
# in CI: Actions -> benchmark -> Run workflow
#   cores, suite, repeats, and your own configurations
# locally, for a quick look (this is not where results come from)
cd docs/benchmarks/harness
python3 bench.py --suite smoke
```

## What comes out

| File | What it is |
|---|---|
| `report.md` | the tables: throughput, CPU per gibibyte, memory, setup cost, coverage, and what is missing |
| `results.json` | every cell, every status, every diagnostic, machine readable |
| `manifest.json` | the digest of every artefact, the binary digests, the host, and the replay command |
| `commands.sh` | the exact command that produced the run |
| `charts/*.png` | coverage, capability gaps, per-group metrics, and the run's own resolution |
| `../protocol-support.md` | the published comparison of what each project can be *configured* to do |

`python3 validate_results.py <dir>` re-derives every aggregate from the raw
cells and fails if any of them disagrees. It runs in CI on every run.

## Running it in CI

`.github/workflows/benchmark.yml` has four jobs.

**`capability`** runs on every pull request that touches `crates/` or this
directory. It starts no long-lived process and moves no bulk data: every core's
own config validator is handed each generated configuration and its answer is
recorded, with the diagnostic the validator produced. This is the job that shows,
in review, that a connection type has stopped being accepted by one of the four
cores.

It also builds xray-rust from its pinned tag, which is the one comparator the
run is least likely to have otherwise, and whose gaps are the largest: at
v0.7.0 it refuses `vmess`, `trojan`, `shadowsocks` and `shadowsocks2022` as
outbound protocols, refuses `tlsSettings.certificates` on any transport other
than raw, and refuses `mux.enabled`. Those are the project's own diagnostics,
recorded rather than asserted.

The job runs the harness's twenty checks and verifies that `protocol-support.md`
matches the capability data in the code, so the published table cannot drift.

**`pr`** runs on every pull request and answers the question a reviewer is
actually asking: *did this change move the number?* It builds Zray twice -- once
at the head, once at the merge base with the branch, each into its own target
directory -- and measures both under the identical configuration, alongside
Xray-core, sing-box and xray-rust for context. The base is the baseline, so
every ratio in the report is candidate/base.

This is a different comparison from `measure`, and the difference is the point.
Four projects differ in source, in toolchain chain and in everything a change
did not touch, so a five-line diff to a buffer copy cannot move that ratio in
either direction: a regression hides inside the gap between two projects and the
job reports nothing. Two builds of the same project can move.

`--gate-regression 5` turns the result into a gate. A scenario fails when its
*whole* 95% interval lies more than 5% on the wrong side, and the direction comes
from the metric rather than from the sign of the ratio, so a memory increase is
read as a regression and not as an improvement. The output is `gate.md` in the
artefact, the reason for every failure is in the job summary, and the exit status
is non-zero.

**`measure`** runs the suite. On a push to `main` that is `standard`; on a
schedule it is `full`; on `workflow_dispatch` it is whatever you ask for. It
records the runner's hardware and its load average, uploads the whole result
directory as an artefact, and appends the report to the job summary.

**`comment`** posts the report on the pull request, replacing the previous one,
with the change's own table outside the collapsible part. It is skipped for pull
requests from forks, where the token cannot write.

### Comparing two commits by hand

```sh
# the current working tree against any ref, with a 5% gate
python3 bench.py --base-ref v0.2.0 --gate-regression 5
```

`--base-ref` builds the base in a detached worktree with its own target
directory. A shared target directory reuses same-package fingerprints when
source timestamps precede a previous build, and then the "base" is silently the
candidate -- the one failure mode here that produces a confident wrong number
rather than an obvious one. The base's commit and the candidate's are both
recorded in the report, and a base binary whose commit disagrees with the ref it
was given is called out in the notes rather than quietly relabelled.

#### Against the state the branch will actually land on

With several pull requests open, the number that matters is not "this branch
against `main`" but "this branch against `main` with the other pull requests
applied". Two sentinels do that:

```sh
# what is open, and what a combined baseline would be made of
python3 bench.py --list-prs --repo zeghostwriter/ZeroNet

# every open pull request merged into one commit, built as the base
python3 bench.py --base-ref @merged-prs --repo zeghostwriter/ZeroNet --gate-regression 5

# the other end of the comparison: main with none of them applied
python3 bench.py --base-ref @main --repo zeghostwriter/ZeroNet
```

`@merged-prs` fetches each pull request by number, merges every head into the
base in turn, and hands the resulting commit to the builder -- the same builder
`--base-ref v0.2.0` uses, so it is a thing that gets compiled rather than a ref
that gets trusted. The merge is real: a conflict stops the run and names the pull
request that caused it, rather than producing a baseline that is half of each
thing. What the baseline is made of is written into the report, because a ratio
without the state it was measured against is not evidence.

The two ends answer different questions and both are worth having. `@main` says
what this change did. `@merged-prs` says what this change did once everything
else lands with it, which is the only one of the two that matches what a user
will actually run.

## Two findings from actually running the comparison

**Not all ten open pull requests combine.** Merging them all into `main` fails in
`crates/zero-protocol/src/vision.rs`, which **#30**, **#33** and **#38** each
edit. So there is no single "everything lands" state to measure against today,
and "do all our changes improve" cannot be answered until either #38 lands first
or the other side rebases. The harness refuses rather than producing a baseline
that is half of each thing, and it names the pull request and the file.

**Your own benchmark runs, in CI, against either end of that.** Candidate is this
branch in both runs; the base differs:

- `--base-ref @main` — `main` with no pull request applied
- `--base-ref bench/prs-merged` — `main` with the nine that combine

Comparing the base rows across the two runs is a direct measurement of what the
other pull requests do, with the same candidate and the same host underneath both.

Two bugs only running it could find:

- **A pull request head moves**, and `git fetch` refuses a non-fast-forward update
  to a remote-tracking ref. The baseline of any busy repository could only ever be
  built once. Found on the second run.
- **`gh` authenticates from the environment in Actions and nowhere else**, so the
  sentinel failed on a dispatch run with advice about `GH_TOKEN` instead of a
  measurement.

### Supplying your own configurations

`workflow_dispatch` takes a `user_configs` textarea and a `user_config_urls`
field. Paste one JSON document per block, or a base64 subscription body, or
share links:

```
vless://00000000-0000-4000-8000-000000000001@example.com:443?encryption=none&security=tls&type=ws#one
vless://00000000-0000-4000-8000-000000000002@example.org:443?encryption=none&security=reality#two
```

A share link or a subscription is converted once, with `zray preset`, and the
resulting file is what all four cores are given. That is deliberate: translating
a link per core would compare the four link parsers rather than the four
transports, and a mistranslation would look like a missing feature. The report
records that the conversion happened.

A configuration that is already JSON is measured as it stands. Two things are
then required of it, and both are reported per row rather than assumed:

* a local `socks`, `mixed` or `http` inbound, so there is a port to drive;
* a server address in the first proxy outbound, which is where the tunnel goes.

A supplied config is then measured one of two ways, and the row says which.

**Without `user_target`, the tunnel is measured.** The only endpoint a config
names is its own proxy server, and that endpoint speaks the proxy protocol rather
than this harness's framed one -- so pointing a transfer at it fails for every
core every time, whatever the core. What can be measured for any config is
whether the tunnel comes up at all, how many it can establish per second, and
how long the whole path takes, broken down into TCP, SOCKS greeting and SOCKS
request. That is a real measurement of your configuration over your network.

**With `user_target`, bytes are moved.** Name a `HOST:PORT` that answers this
harness's protocol -- typically a sink you run yourself -- and the row becomes a
throughput measurement against it:

```sh
./loadgen/target/release/loadgen sink --port 9000 &
python3 bench.py --only-user-configs --user-config mine.json \
  --user-target 127.0.0.1:9000 --cores zray,xray,singbox
```

Both rows include whatever network is in the way. They are comparable between
cores only when every core reached the same endpoint, which the row shows.

## The measurement

### What is measured

| Metric | How |
|---|---|
| Throughput | validated bytes over the transfer window, first payload byte to last |
| CPU per gibibyte | client process `utime + stime` over the sample window, divided by the bytes the client moved |
| Idle memory | the client's resident set 0.7 s after its port accepts a connection, before any traffic |
| Peak memory | the maximum of the sampled resident set during the scenario |
| Connect time | the three stages separately: TCP connect, SOCKS greeting, SOCKS request |
| Round trip | a full validated request and response, with percentiles |
| Setup rate | completed connect-and-close cycles per second |
| Thread count | peak, where the platform exposes it |
| Server cost | the server process's own CPU and peak memory, because it shares loopback CPU with the client |

### The four rules that make it mean something

**The payload is validated.** The sink writes a deterministic keystream and the
generator checks every byte, and each concurrent flow uses a different region of
it, so a core that interleaves two sessions' bytes onto one carrier is caught
rather than hidden behind a correct total. An unvalidated stream measures how
fast the harness can read.

**The transfer window excludes setup.** Connection establishment is reported in
its own columns. A core that answers SOCKS before it dials and one that dials
first hide that difference inside a wall-clock rate, and the difference is
exactly what someone reading these numbers wants to see.

**The harness has a published ceiling.** Before the first scenario, the same
validated loop runs over a bare socket with no core in the path. A row at or
above 85% of that ceiling is bounded by the generator, and the report says so on
the row and in the confounders. A chart that implied more precision than the
harness has would be a chart that lied quietly.

**Order is rotated and then reversed.** Within a repeat, every core is measured
back to back for the same scenario; the order is rotated by the repeat index and
reversed on alternate repeats. Comparisons are therefore paired on the repeat
index, and each interval is a bootstrap over those pairs. The report also prints
the baseline core measured against itself, so the size of an effect and the size
of the run's noise can be read on the same row.

### Suites

| Suite | Scenarios | Approximate cost on a shared runner |
|---|---:|---|
| `smoke` | 11 | minutes |
| `standard` | 39 | under an hour |
| `full` | 49 | hours, including a 5000-flow memory row, the UDP rows and the per-fingerprint rows |

```
--only SUBSTRING     run only scenarios whose id contains this (repeatable)
--exclude SUBSTRING  skip scenarios whose id contains this (repeatable)
--runs N             repeats per cell; three is the minimum worth reading
--bytes 512M         bytes per transfer sample, per direction
--iterations 1000    round trips per latency and setup sample
--cores a,b,c        comma separated; the first is the baseline
--server-core NAME   the core that serves the proxy side of every cell
--base-ref REF       build Zray from REF as the `zray-base` baseline
--gate-regression N  fail when the candidate is worse than the base by more than N%
--gate-improvement N report the scenarios that clear an improvement of N%
--probe-only         ask each core whether it accepts the config; no traffic
```

`--only vless-raw-tls` narrows a run to one connection type, which is the fast
way to see whether a change moved it.

## What is measured on the server side

One server process serves every client for a given link, so the client is the
only thing that varies across a row. The server core is a single choice for a
run (`--server-core`, default `xray`) and is named in the report. A link the
server core cannot serve is skipped with the reason, never quietly measured
against a different server.

## Where the four cores differ

`../protocol-support.md` is generated from `zbench/caps.py` and is the answer to
"what can each project be configured to do". It is much larger than the
benchmark, because a loopback benchmark cannot reach most of it. Two of its
charts are the fastest way to see a gap:

* `protocol-transport-grid.png` -- one panel per core, protocol against
  transport, `1.00` where the core can be configured for that combination and
  `0.00` where it cannot. The empty cells are the gaps.
* `capability-surface.png` -- every row of the published table, all four cores,
  on one scale, so a column reads top to bottom.

A few differences that change how a row should be read:

* **xray-rust has no server mode.** Its inbounds are socks, http and tun, and
  server-side VLESS is a stated non-goal, so it is only ever measured as a
  client. It publishes no binaries; the harness builds a pinned tag, and records
  a digest for whatever it built.
* **sing-box cannot be given a private CA as a client.** The generated client
  uses `insecure: true` against a loopback-only certificate, while Zray and
  Xray-core verify the chain. The TLS rows therefore differ in certificate
  verification as well as in the core.
* **A REALITY server rejects clients outside `minClientVer`.** Xray-core's default
  lower bound is the current Xray version. The generated fixture widens both
  bounds, because otherwise the row measures a version string rather than the
  protocol.
* **Where a core's own config check refuses a combination, that is recorded as a
  measurement**, with the diagnostic, and distinguished in the report from a core
  that accepted the config and then failed to carry traffic.

## Adding a scenario

Add it to `zbench/matrix.py`. The link axes are a `Link` (protocol, transport,
security, and the Vision and mux attributes), the workload is a mode the load
generator implements, and the suite list decides when it runs. Two things are
worth knowing:

* If a core cannot be configured for the combination, the harness finds that out
  from the core's own validator and records it. There is no need to keep the
  capability table in step by hand for it to be correct in the run's output.
* If the load generator cannot express the combination in a core's dialect, the
  cell is skipped with that reason, never approximated.

## Adding a core

Add a `Core` to `zbench/caps.py` with its dialect, its protocol and transport
sets, and a `resolve_*` function in `zbench/cores.py` that finds or builds the
binary, plus the argv that runs a config and the argv that validates one. A core
that cannot be built is recorded as unavailable with the reason and the run
continues with the rest; a run with fewer than two cores fails unless
`--allow-single-core` is given.

`zray-base` is the one core that is not a separate project, and it is the model
for a candidate-versus-baseline comparison: the same `Core` shape, a `resolve_*`
that builds from a ref in an isolated worktree, and a `source_revision` that
travels into the report.

## The harness's own checks

`python3 test_harness.py` runs nineteen checks and needs no proxy core. Four of
them exist because a defect in this harness produces a confident wrong number
rather than a visible failure, and the last four found:

- a duplex run reported `bytes_sent: 0` after writing 128 MB, because the writer
  thread had its own byte counters
- a per-flow size that was not a multiple of eight failed validation with a
  "payload mismatch" that was not one, so `--bytes 100M --streams 3` reported
  corruption on a healthy transfer
- integer division dropped the remainder, so 100,000,000 bytes over three flows
  moved 99,999,999 -- and the same truncation understated the ceiling every other
  row is compared against
- the duplex path half-closed after its reader had already returned, which
  discarded the sink's completion byte through any relay that tears a connection
  down on EOF

The load generator's own arithmetic is checked through a real SOCKS hop against a
real sink, and a peer that returns zeros is checked to be rejected, so the tail
fix cannot have turned validation into a rubber stamp.

## Layout

```
harness/
  bench.py              the command line
  validate_results.py   re-derives every aggregate; fails on a disagreement
  split_configs.py      turns the workflow's textarea into files
  requirements.txt      matplotlib, for the charts only
  loadgen/              the traffic generator and the data sink, stdlib only
  zbench/
    caps.py             what each core can do, and the published comparison table
    cores.py            finding, building, starting and reaping each core
    configs.py          one configuration per dialect, for the same job
    matrix.py           the scenarios and the suites
    measure.py          sampling a running process
    stats.py            medians, spread, paired bootstrap intervals
    runner.py           the loop
    report.py           tables, coverage, confounders, charts
    support_doc.py      the generated comparison document
    userconfig.py       configurations supplied from outside the repository
```

## History

The numbers in the repository README come from an earlier harness that measured
one protocol at two security layers against one comparator, on a 4-vCPU Xeon.
They are kept in [`results/2026-04-legacy/`](results/2026-04-legacy/) with the
method that produced them, because a published claim should stay backed by a
file. They were measured on different hardware from the current runs and are
not comparable with them; the README table says so where it appears.
