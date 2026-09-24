# Zray-core vs Xray-core benchmark

The charts in the main README come from this harness. Everything needed to
reproduce them is in [`harness/`](harness).

## Setup

- **Xray-core** v26.3.27 (official `Xray-linux-64` release build) against
  **Zray-core** 0.1.0 (`cargo build --release -p zray-cli`).
- Same machine for everything: 4 vCPU Intel Xeon @ 2.80 GHz, 15 GB RAM,
  Linux 6.18, loopback network.
- One **Xray-core** server for both runs, so the only thing that changes is
  the client core. The client under test is started from the *same* JSON
  config (Zray reads Xray configs as they are):
  - `client-tls.json`: SOCKS inbound → VLESS over TCP + TLS 1.3 (private CA
    verified with `usage: "verify"`; Zray refuses `allowInsecure`).
  - `client-plain.json`: SOCKS inbound → VLESS over plain TCP.
- `loadgen` opens SOCKS5 connections through the client to a local data sink
  and moves 2 GB per test, split over 1, 8 or 64 parallel streams.
- Each test runs 3 times on a freshly started client; the median is reported.

## What is measured

| Metric | How |
|---|---|
| Throughput | bytes moved ÷ wall-clock time, in MB/s |
| CPU per GB | client process `utime + stime` (from `/proc/<pid>/stat`) ÷ GB moved |
| Idle memory | client `VmRSS` 1.5 s after start, before any traffic |
| Peak memory | client `VmHWM` after all tests |

## Results (medians)

| | Xray-core | Zray-core | |
|---|---:|---:|---|
| TLS, 1 stream ↓ | 349 MB/s | **532 MB/s** | +53% |
| TLS, 8 streams ↓ | 826 MB/s | **911 MB/s** | +10% |
| TLS, 64 streams ↓ | 758 MB/s | **828 MB/s** | +9% |
| TLS, 1 stream ↑ | 342 MB/s | **353 MB/s** | +3% |
| TLS, CPU per GB (1 stream ↓) | 3.01 s | **1.62 s** | −46% |
| Plain TCP, 1 stream ↓ | **873 MB/s** | 799 MB/s | −8% |
| Plain TCP, 8 streams ↓ | 1239 MB/s | **1345 MB/s** | +9% |
| Plain TCP, 64 streams ↓ | 1085 MB/s | **1344 MB/s** | +24% |
| Plain TCP, 1 stream ↑ | 818 MB/s | **877 MB/s** | +7% |
| Idle memory | 29.3 MB | **8.0 MB** | 3.7× less |
| Peak memory (TLS run) | 51.5 MB | **21.1 MB** | 2.4× less |

Zray-core uses less CPU per gigabyte in every test. The one result where
Xray-core is faster, a single plain-TCP download, is shown as measured.
Raw numbers are in [`results.json`](results.json).

## Running it

```sh
cargo build --release -p zray-cli                      # from the repo root
cd docs/benchmarks/harness
# Put an Xray-core binary here as ./xray, then create a private CA and a
# server certificate for bench.local (ca.pem, cert.pem, key.pem).
(cd loadgen && cargo build --release)
python3 run.py      # writes results.json
python3 charts.py   # writes the PNG charts (needs matplotlib)
```

Loopback numbers show how much work each core does per byte; they are not
what you will see over a real internet link, where the network is the limit.
