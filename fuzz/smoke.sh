#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Lithium Project
# SPDX-License-Identifier: AGPL-3.0-only

#
# Smoke-fuzz every target in parallel for a fixed wall-clock budget.
#
#   ./fuzz/smoke.sh --timeout 300 --workers 30
#

set -euo pipefail

TIMEOUT=60
WORKERS="$(nproc 2>/dev/null || echo 4)"
ARCH="x86_64-unknown-linux-gnu"

usage() {
    cat <<'EOF'
Usage: smoke.sh [--timeout SECONDS] [--workers N] [--target TRIPLE]

  -t, --timeout   wall-clock budget in seconds (default 60)
  -w, --workers   parallel libFuzzer processes to spread over targets
                  (default: nproc)
      --target    rustc target triple (default x86_64-unknown-linux-gnu)
  -h, --help      show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t | --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -w | --workers) WORKERS="${2:?}"; shift 2 ;;
        --target) ARCH="${2:?}"; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$TIMEOUT" =~ ^[0-9]+$ && "$TIMEOUT" -gt 0 ]] || { echo "--timeout must be a positive integer" >&2; exit 2; }
[[ "$WORKERS" =~ ^[0-9]+$ && "$WORKERS" -gt 0 ]] || { echo "--workers must be a positive integer" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 1; }
cargo +nightly fuzz --help >/dev/null 2>&1 || {
    echo "cargo-fuzz not installed: cargo install cargo-fuzz" >&2
    exit 1
}

mapfile -t TARGETS < <(cargo +nightly fuzz list)
N=${#TARGETS[@]}
(( N > 0 )) || { echo "no fuzz targets found" >&2; exit 1; }

LOGDIR="$SCRIPT_DIR/smoke-logs"
mkdir -p "$LOGDIR"
rm -f "$LOGDIR"/*.log 2>/dev/null || true

echo "building $N targets for $ARCH ..."
cargo +nightly fuzz build --target "$ARCH"

ARTDIR="$SCRIPT_DIR/artifacts"
mkdir -p "$ARTDIR"
BEFORE="$(mktemp)"
find "$ARTDIR" -type f 2>/dev/null | sort >"$BEFORE"

trap 'echo; echo "interrupted, killing workers ..."; kill 0 2>/dev/null; exit 130' INT TERM

run_one() {
    cargo +nightly fuzz run "$1" --target "$ARCH" -- \
        -max_total_time="$2" >"$LOGDIR/$1.$3.log" 2>&1 || true
}

PER_TARGET=$(( WORKERS / N ))

if (( PER_TARGET >= 1 )); then
    echo "workers=$WORKERS targets=$N -> $PER_TARGET worker(s)/target, ${TIMEOUT}s, all in parallel"
    for t in "${TARGETS[@]}"; do
        for ((j = 1; j <= PER_TARGET; j++)); do
            run_one "$t" "$TIMEOUT" "$j" &
        done
    done
    wait
else
    BATCHES=$(( (N + WORKERS - 1) / WORKERS ))
    PER=$(( TIMEOUT / BATCHES )); (( PER >= 1 )) || PER=1
    echo "workers=$WORKERS < targets=$N -> $BATCHES batch(es) of $WORKERS, ${PER}s each"
    idx=0
    while (( idx < N )); do
        for ((c = 0; c < WORKERS && idx < N; c++, idx++)); do
            run_one "${TARGETS[$idx]}" "$PER" 1 &
        done
        wait
    done
fi

AFTER="$(mktemp)"
find "$ARTDIR" -type f 2>/dev/null | sort >"$AFTER"
mapfile -t NEW < <(comm -13 "$BEFORE" "$AFTER")
rm -f "$BEFORE" "$AFTER"

echo
if (( ${#NEW[@]} > 0 )); then
    echo "found ${#NEW[@]} new artifact(s) (logs in $LOGDIR):"
    printf '  %s\n' "${NEW[@]}"
else
    echo "SMOKE OK: all $N targets ran, no new artifacts"
fi
