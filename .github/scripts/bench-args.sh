#!/bin/bash
# Assemble a bench.py argument list and write it one argument per line.
#
# The three benchmark jobs used to build this list inline, and one of them
# overwrote `--runs` instead of `--cores` by indexing the array by position --
# so the probe silently stopped working on any run where xray-rust failed to
# build. Positional edits of an argument array are not reviewable: the diff does
# not show which element moved.
#
# This resolves the core list and every option by name, from the environment, and
# writes the result out for the caller to read with `mapfile`. One implementation,
# so a change to how a run is assembled happens in one place.
#
# Required environment:
#   OUT              file to write the argument list to, one per line
# Optional, each with the harness's own default:
#   BENCH_CORES      comma separated; the first is the baseline
#   BENCH_SERVER     core that serves the proxy side of every cell
#   BENCH_SUITE      smoke | standard | full
#   BENCH_RUNS       repeats per cell
#   BENCH_BYTES      bytes per transfer sample
#   BENCH_ITERATIONS round trips per latency and setup sample
#   BENCH_ONLY       comma separated scenario id substrings to keep
#   BENCH_EXCLUDE    comma separated scenario id substrings to drop
#   BENCH_URLS       comma separated https config URLs
#   BENCH_USER_DIR   directory of configurations to measure
#   BENCH_BASE_REF   git ref to build zray-base from
#   BENCH_GATE       regression tolerance, e.g. 5 for 5%
#   BENCH_EXTRA      extra arguments, space separated, appended verbatim
set -euo pipefail

: "${OUT:?OUT is required}"

args=()
add() { args+=("$@"); }

# Split a comma separated list onto stdout, dropping empty fields.
split() {
  local value="${1:-}" part
  local IFS=,
  for part in $value; do
    [[ -n "$part" ]] && printf '%s\n' "$part"
  done
}

add --suite "${BENCH_SUITE:-standard}"
add --server-core "${BENCH_SERVER:-xray}"
add --runs "${BENCH_RUNS:-3}"
add --bytes "${BENCH_BYTES:-512M}"
add --iterations "${BENCH_ITERATIONS:-1000}"

if [[ -n "${BENCH_CORES:-}" ]]; then
  add --cores "$BENCH_CORES"
elif [[ -n "${BENCH_BASE_REF:-}" ]]; then
  # A change's own run wants its base first, so the ratios it prints are against
  # the base rather than against whichever project sorted first.
  add --cores zray-base,zray,xray,singbox,xray-rust
else
  add --cores zray,xray,singbox,xray-rust
fi

while read -r value; do add --only "$value"; done < <(split "${BENCH_ONLY:-}")
while read -r value; do add --exclude "$value"; done < <(split "${BENCH_EXCLUDE:-}")
while read -r value; do add --user-config-url "$value"; done < <(split "${BENCH_URLS:-}")

[[ -n "${BENCH_USER_DIR:-}" ]] && add --user-config-dir "$BENCH_USER_DIR"
[[ -n "${BENCH_USER_TARGET:-}" ]] && add --user-target "$BENCH_USER_TARGET"
[[ -n "${BENCH_BASE_REF:-}" ]] && add --base-ref "$BENCH_BASE_REF"
[[ -n "${BENCH_REPO:-}" ]] && add --repo "$BENCH_REPO"
[[ -n "${BENCH_GATE:-}" ]] && add --gate-regression "$BENCH_GATE"
if [[ -n "${BENCH_EXTRA:-}" ]]; then
  # Word splitting is the point: BENCH_EXTRA carries whole arguments.
  # shellcheck disable=SC2206
  extra=(${BENCH_EXTRA})
  add "${extra[@]}"
fi

mkdir -p "$(dirname "$OUT")"
printf '%s\n' "${args[@]}" > "$OUT"

# Echo the assembled command so it lands in the job log and the step summary,
# rather than being reconstructed by whoever reads the failure afterwards.
printf 'bench.py'
printf ' %q' "${args[@]}"
printf '\n'
