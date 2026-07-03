#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Lithium Project
# SPDX-License-Identifier: AGPL-3.0-only

#
# Smoke-fuzz every target in parallel for a fixed wall-clock budget.
#
#   ./fuzz/smoke.sh --timeout 300 --workers 30
#

set -euo pipefail
shopt -s nullglob

TIMEOUT=60
WORKERS=""
ARCH="x86_64-unknown-linux-gnu"

usage() {
    cat <<'EOF'
Usage: smoke.sh [--timeout SECONDS] [--workers N] [--target TRIPLE]

  -t, --timeout   wall-clock budget in seconds (default 60)
  -w, --workers   parallel libFuzzer processes to spread over targets
                  (default: number of fuzz targets)
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

[[ "$TIMEOUT" =~ ^[0-9]+$ && "$TIMEOUT" -gt 0 ]] || {
    echo "--timeout must be a positive integer" >&2
    exit 2
}

if [[ -n "$WORKERS" ]]; then
    [[ "$WORKERS" =~ ^[0-9]+$ && "$WORKERS" -gt 0 ]] || {
        echo "--workers must be a positive integer" >&2
        exit 2
    }
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

command -v cargo >/dev/null || {
    echo "cargo not found" >&2
    exit 1
}

cargo +nightly fuzz --help >/dev/null 2>&1 || {
    echo "cargo-fuzz not installed: cargo install cargo-fuzz" >&2
    exit 1
}

mapfile -t TARGETS < <(cargo +nightly fuzz list)
N=${#TARGETS[@]}
(( N > 0 )) || {
    echo "no fuzz targets found" >&2
    exit 1
}

if [[ -z "$WORKERS" ]]; then
    WORKERS="$N"
fi

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
    local target="$1"
    local timeout="$2"
    local worker="$3"

    cargo +nightly fuzz run "$target" --target "$ARCH" -- \
        -max_total_time="$timeout" >"$LOGDIR/$target.$worker.log" 2>&1 || true
}

fmt_human() {
    local n="${1:-0}"

    awk -v n="$n" '
        BEGIN {
            if (n !~ /^[0-9]+$/) {
                print n
                exit
            }

            split("K M G T P", units, " ")

            value = n + 0
            unit = 0

            while (value >= 1000 && unit < 5) {
                value /= 1000
                unit++
            }

            if (unit == 0) {
                printf "%.0f\n", value
            } else if (value >= 100 || value == int(value)) {
                printf "%.0f%s\n", value, units[unit]
            } else if (value >= 10) {
                printf "%.1f%s\n", value, units[unit]
            } else {
                printf "%.2f%s\n", value, units[unit]
            }
        }
    '
}

repeat_char() {
    local char="$1"
    local count="$2"

    printf '%*s' "$count" '' | tr ' ' "$char"
}

artifact_count_for_target() {
    local target="$1"
    local count=0
    local file

    for file in "${NEW[@]}"; do
        if [[ "$file" == "$ARTDIR/$target/"* ]]; then
            ((count++))
        fi
    done

    printf '%d\n' "$count"
}

summarize_logs() {
    local target="$1"
    local logs=("$LOGDIR/$target".*.log)

    if (( ${#logs[@]} == 0 )); then
        printf '0 0 0 0\n'
        return
    fi

    awk '
        function flush_file() {
            if (seen_file) {
                total_execs += stat_execs > 0 ? stat_execs : last_counter
            }

            seen_file = 1
            stat_execs = 0
            last_counter = 0
        }

        FNR == 1 {
            flush_file()
        }

        {
            if (match($0, /#[0-9]+/)) {
                value = substr($0, RSTART + 1, RLENGTH - 1) + 0

                if (value > last_counter) {
                    last_counter = value
                }
            }

            if (match($0, /stat::number_of_executed_units: *[0-9]+/)) {
                value = substr($0, RSTART, RLENGTH)
                sub(/.*: */, "", value)
                stat_execs = value + 0
            }

            if (match($0, /cov: *[0-9]+/)) {
                value = substr($0, RSTART, RLENGTH)
                sub(/cov: */, "", value)
                value += 0

                if (value > max_cov) {
                    max_cov = value
                }
            }

            if (match($0, /ft: *[0-9]+/)) {
                value = substr($0, RSTART, RLENGTH)
                sub(/ft: */, "", value)
                value += 0

                if (value > max_ft) {
                    max_ft = value
                }
            }

            if (match($0, /exec\/s: *[0-9]+/)) {
                value = substr($0, RSTART, RLENGTH)
                sub(/exec\/s: */, "", value)
                value += 0

                if (value > max_exec_s) {
                    max_exec_s = value
                }
            }
        }

        END {
            if (seen_file) {
                total_execs += stat_execs > 0 ? stat_execs : last_counter
            }

            printf "%d %d %d %d\n", total_execs, max_cov, max_ft, max_exec_s
        }
    ' "${logs[@]}"
}

print_summary() {
    local total_runs=0
    local total_execs=0
    local total_artifacts=${#NEW[@]}

    local target_width=24
    local runs_width=6
    local execs_width=10
    local cov_width=10
    local ft_width=10
    local exec_s_width=10
    local artifacts_width=10

    local target runs execs cov ft exec_s artifacts
    local execs_fmt cov_fmt ft_fmt exec_s_fmt artifacts_fmt
    local line_width

    for target in "${TARGETS[@]}"; do
        if (( ${#target} > target_width )); then
            target_width=${#target}
        fi
    done

    line_width=$((target_width + runs_width + execs_width + cov_width + ft_width + exec_s_width + artifacts_width + 22))

    echo
    echo "Smoke fuzz summary"
    repeat_char "=" "$line_width"
    echo

    printf "| %-*s | %*s | %*s | %*s | %*s | %*s | %*s |\n" \
        "$target_width" "target" \
        "$runs_width" "runs" \
        "$execs_width" "execs" \
        "$cov_width" "cov" \
        "$ft_width" "ft" \
        "$exec_s_width" "exec/s" \
        "$artifacts_width" "artifacts"

    printf "|-%s-|-%s-|-%s-|-%s-|-%s-|-%s-|-%s-|\n" \
        "$(repeat_char "-" "$target_width")" \
        "$(repeat_char "-" "$runs_width")" \
        "$(repeat_char "-" "$execs_width")" \
        "$(repeat_char "-" "$cov_width")" \
        "$(repeat_char "-" "$ft_width")" \
        "$(repeat_char "-" "$exec_s_width")" \
        "$(repeat_char "-" "$artifacts_width")"

    for target in "${TARGETS[@]}"; do
        local logs=("$LOGDIR/$target".*.log)

        runs=${#logs[@]}

        read -r execs cov ft exec_s < <(summarize_logs "$target")
        artifacts="$(artifact_count_for_target "$target")"

        total_runs=$((total_runs + runs))
        total_execs=$((total_execs + execs))

        execs_fmt="$(fmt_human "$execs")"
        cov_fmt="$(fmt_human "$cov")"
        ft_fmt="$(fmt_human "$ft")"
        exec_s_fmt="$(fmt_human "$exec_s")"
        artifacts_fmt="$(fmt_human "$artifacts")"

        printf "| %-*s | %*s | %*s | %*s | %*s | %*s | %*s |\n" \
            "$target_width" "$target" \
            "$runs_width" "$runs" \
            "$execs_width" "$execs_fmt" \
            "$cov_width" "$cov_fmt" \
            "$ft_width" "$ft_fmt" \
            "$exec_s_width" "$exec_s_fmt" \
            "$artifacts_width" "$artifacts_fmt"
    done

    printf "|-%s-|-%s-|-%s-|-%s-|-%s-|-%s-|-%s-|\n" \
        "$(repeat_char "-" "$target_width")" \
        "$(repeat_char "-" "$runs_width")" \
        "$(repeat_char "-" "$execs_width")" \
        "$(repeat_char "-" "$cov_width")" \
        "$(repeat_char "-" "$ft_width")" \
        "$(repeat_char "-" "$exec_s_width")" \
        "$(repeat_char "-" "$artifacts_width")"

    printf "| %-*s | %*s | %*s | %*s | %*s | %*s | %*s |\n" \
        "$target_width" "TOTAL" \
        "$runs_width" "$(fmt_human "$total_runs")" \
        "$execs_width" "$(fmt_human "$total_execs")" \
        "$cov_width" "-" \
        "$ft_width" "-" \
        "$exec_s_width" "-" \
        "$artifacts_width" "$(fmt_human "$total_artifacts")"

    repeat_char "=" "$line_width"
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
    PER=$(( TIMEOUT / BATCHES ))
    (( PER >= 1 )) || PER=1

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

print_summary

echo
if (( ${#NEW[@]} > 0 )); then
    echo "found ${#NEW[@]} new artifact(s) (logs in $LOGDIR):"
    printf '  %s\n' "${NEW[@]}"
    exit 1
else
    echo "SMOKE OK: all $N targets ran, no new artifacts"
fi