#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage: collect-container-logs.sh [options]

Collect Docker Compose and application JSONL logs into a tar.gz archive.
Run this script directly on the Linux host that runs the containers.

Options:
  --compose-dir PATH   Compose project directory (default: current directory)
  --service NAME       Compose service name (default: mpvm-client)
  --since DURATION     Docker log period, e.g. 6h, 24h, 7d (default: 24h)
  --from ISO8601        Include application events at/after UTC timestamp
  --to ISO8601          Include application events before UTC timestamp
  --last-hour           Automatically collect only the last 60 minutes
  --output-dir PATH    Directory for the resulting archive
                       (default: ./output/support-bundles)
  -h, --help           Show this help

The final stdout line is the absolute path to the generated archive.
EOF
}

compose_dir=$(pwd)
service=mpvm-client
since=24h
from_time=
to_time=
output_dir=./output/support-bundles
last_hour=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --compose-dir)
            [ "$#" -ge 2 ] || { echo "Missing value for --compose-dir" >&2; exit 2; }
            compose_dir=$2
            shift 2
            ;;
        --service)
            [ "$#" -ge 2 ] || { echo "Missing value for --service" >&2; exit 2; }
            service=$2
            shift 2
            ;;
        --since)
            [ "$#" -ge 2 ] || { echo "Missing value for --since" >&2; exit 2; }
            since=$2
            shift 2
            ;;
        --from)
            [ "$#" -ge 2 ] || { echo "Missing value for --from" >&2; exit 2; }
            from_time=$2
            shift 2
            ;;
        --to)
            [ "$#" -ge 2 ] || { echo "Missing value for --to" >&2; exit 2; }
            to_time=$2
            shift 2
            ;;
        --last-hour)
            last_hour=true
            since=1h
            shift
            ;;
        --output-dir)
            [ "$#" -ge 2 ] || { echo "Missing value for --output-dir" >&2; exit 2; }
            output_dir=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$last_hour" = true ]; then
    from_time=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
    to_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi

case "$service" in
    ''|*[!A-Za-z0-9_.-]*)
        echo "Invalid service name: $service" >&2
        exit 2
        ;;
esac

case "$since" in
    *[!A-Za-z0-9_.-]*|'')
        echo "Invalid --since value: $since" >&2
        exit 2
        ;;
esac

case "${from_time}${to_time}" in
    *[!0-9T:+.Z-]*)
        echo "Invalid --from/--to value; use UTC ISO8601, e.g. 2026-09-01T04:00:00Z" >&2
        exit 2
        ;;
esac
[ -z "$from_time" ] || [ -n "$to_time" ] || {
    echo "--from and --to must be provided together" >&2
    exit 2
}
[ -z "$to_time" ] || [ -n "$from_time" ] || {
    echo "--from and --to must be provided together" >&2
    exit 2
}

for command in docker tar mktemp; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Required command not found: $command" >&2
        exit 1
    }
done

[ -d "$compose_dir" ] || {
    echo "Compose directory does not exist: $compose_dir" >&2
    exit 1
}

compose_dir=$(CDPATH= cd -- "$compose_dir" && pwd)
mkdir -p -- "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)

timestamp=$(date -u +%Y%m%d-%H%M%S)
archive="$output_dir/mpvm-support-$timestamp.tar.gz"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/mpvm-support.XXXXXX")

cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p -- "$work_dir/app-logs"
cd -- "$compose_dir"

date -u +%Y-%m-%dT%H:%M:%SZ > "$work_dir/collected-at.txt"
uname -a > "$work_dir/host.txt" 2>&1 || true
df -h > "$work_dir/disk-usage.txt" 2>&1 || true
docker version > "$work_dir/docker-version.txt" 2>&1 || true
docker compose ps --all > "$work_dir/compose-ps.txt" 2>&1 || true
docker compose logs --no-color --timestamps --since "$since" "$service" \
    > "$work_dir/container.log" 2>&1 || true

container_id=$(docker compose ps -q "$service" 2>/dev/null | head -n 1 || true)
if [ -n "$container_id" ]; then
    # Intentionally avoid a full inspect: it contains environment secrets.
    docker inspect --format '{{json .State}}' "$container_id" \
        > "$work_dir/container-state.json" 2>&1 || true
    docker inspect --format '{{.Config.Image}}' "$container_id" \
        > "$work_dir/container-image.txt" 2>&1 || true
    docker stats --no-stream "$container_id" \
        > "$work_dir/container-stats.txt" 2>&1 || true
    docker cp "$container_id:/app/output/logs/." "$work_dir/app-logs" \
        > "$work_dir/docker-cp.txt" 2>&1 || true

    if [ -n "$from_time" ]; then
        # JSONL timestamps are ISO8601 UTC, so lexical comparison is stable.
        for log_file in "$work_dir"/app-logs/*.jsonl*; do
            [ -f "$log_file" ] || continue
            filtered="$log_file.filtered"
            awk -v from="$from_time" -v to="$to_time" '
                match($0, /"timestamp":"[^"]+"/) {
                    ts=substr($0, RSTART+13, RLENGTH-14)
                    if (ts >= from && ts < to) print
                }
            ' "$log_file" > "$filtered"
            mv -- "$filtered" "$log_file"
        done
    fi
else
    echo "No running or created container found for service '$service'." \
        > "$work_dir/container-not-found.txt"
fi

cat > "$work_dir/manifest.txt" <<EOF
service=$service
compose_directory=$compose_dir
docker_logs_since=$since
application_logs_from=$from_time
application_logs_to=$to_time
archive_created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

tar -czf "$archive" -C "$work_dir" .

echo "Support archive created successfully." >&2
echo "$archive"
