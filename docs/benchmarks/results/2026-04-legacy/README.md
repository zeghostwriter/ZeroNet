# 2026-04: the earlier Zray-core vs Xray-core comparison

These are the numbers quoted in the repository README's performance table. They
are kept because a published number should stay backed by a file that says how
it was produced, not because they are the current measurement.

## What produced them

An earlier harness, now replaced: one protocol (VLESS) at two security layers
(plain TCP and TLS 1.3 with a private CA), one comparator, 1/8/64 concurrent
streams, 2 GB per test, three runs per cell, median reported.

- Host: 4 vCPU Intel Xeon @ 2.80 GHz, 15 GB RAM, Linux 6.18, loopback.
- Xray-core v26.3.27 release build against Zray-core 0.1.0, `cargo build
  --release -p zray-cli`.
- The payload was **not** validated, the transfer window included connection
  setup, no ceiling for the load generator was measured, and the core order was
  fixed rather than rotated.

## Why they are not comparable with the current runs

The current harness validates the payload, separates the transfer window from
setup, measures and publishes its own ceiling, rotates and reverses the core
order, and prints the baseline's repeat-to-repeat spread next to every
comparison. The 2026-04 numbers have none of those, and they were taken on
different hardware.

They are kept verbatim. The point of replacing a harness is not to erase what it
showed, it is to stop quoting a number whose method cannot account for it.

## Exactly what the file contains

So that "nothing was lost" is a claim anyone can check rather than take on
trust. `results.json` holds four rows -- one per core and security layer -- each
with two memory figures and four throughput tests:

- `idle_rss_mb`
- `peak_rss_mb`
- `download 1 stream`
- `download 64 streams`
- `download 8 streams`
- `upload 1 stream`

| Row | `idle_rss_mb` | `peak_rss_mb` | `download 1 stream` MB/s | `download 64 streams` MB/s | `download 8 streams` MB/s | `upload 1 stream` MB/s |
|---|---:|---:|---:|---:|---:|---:|
| `plain/xray` | 29.5 | 45.6 | 873 | 1,085 | 1,239 | 818 |
| `plain/zray` | 8.0 | 17.1 | 799 | 1,344 | 1,345 | 876 |
| `tls/xray` | 29.3 | 51.5 | 349 | 758 | 826 | 342 |
| `tls/zray` | 8.0 | 21.1 | 532 | 828 | 911 | 353 |

Each `MB/s` and `cpu_s_per_GB` figure is the median of three runs.

## What the current harness measures that this did not

Every row and metric above is still measurable, and the current harness also
records the same throughput in `MB/s`, so these numbers can be read against new
ones without converting anything. Beyond that, itemised in
[`docs/benchmarks/README.md`](../../README.md): sing-box and xray-rust as
comparators; REALITY, Shadowsocks 2022, Trojan, VMess, AnyTLS, gRPC,
HTTPUpgrade, XHTTP, mux, Vision, QUIC and UDP; latency, churn and
connection-hold workloads; a validated payload; a measured generator ceiling, per
stream count; rotated core order; paired bootstrap intervals; a gate against the
change's own base; and the capability and coverage surfaces these charts cannot
show.
