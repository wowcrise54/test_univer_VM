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
  --trace-id ID         Keep only application events with this trace_id
                       (follows one request across API, MP VM and database logs)
  --exclude-debug       Do not include debug-payloads.jsonl* (request/response
                       bodies recorded by MPVM_DEBUG_MODE); they may hold
                       business data even though secrets are redacted
  --output-dir PATH    Directory for the resulting archive
                       (default: ./output/support-bundles)
  -h, --help           Show this help

When the application runs with MPVM_DEBUG_MODE=true the archive also contains
debug-payloads.jsonl* (inbound API and outbound MP VM requests/responses with
headers and bodies); logging-config.txt shows the effective logging settings.
Debug logs grow quickly: combine --last-hour or --from/--to with --trace-id to
keep the archive small.

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
trace_id=
exclude_debug=false

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
        --trace-id)
            [ "$#" -ge 2 ] || { echo "Missing value for --trace-id" >&2; exit 2; }
            trace_id=$2
            shift 2
            ;;
        --exclude-debug)
            exclude_debug=true
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

case "$trace_id" in
    *[!A-Za-z0-9._:-]*)
        echo "Invalid --trace-id value: only letters, digits and . _ : - are allowed" >&2
        exit 2
        ;;
esac
[ "${#trace_id}" -le 128 ] || {
    echo "--trace-id is longer than 128 characters" >&2
    exit 2
}

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
    # Only logging variables are read from the container environment (never the
    # whole environment: it contains secrets). MPVM_LOG_* and MPVM_DEBUG_* hold
    # levels, paths and limits only.
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container_id" 2>/dev/null \
        | grep -E '^MPVM_(LOG|DEBUG)_[A-Z_]+=' > "$work_dir/logging-config.txt" || true

    # MPVM_LOG_DIR may be customised; a relative value is resolved against /app.
    container_log_dir=/app/output/logs
    configured_log_dir=$(sed -n 's/^MPVM_LOG_DIR=//p' "$work_dir/logging-config.txt" | head -n 1)
    case "$configured_log_dir" in
        '') ;;
        /*) container_log_dir=$configured_log_dir ;;
        *) container_log_dir=/app/$configured_log_dir ;;
    esac
    echo "$container_log_dir" > "$work_dir/log-directory.txt"
    docker cp "$container_id:$container_log_dir/." "$work_dir/app-logs" \
        > "$work_dir/docker-cp.txt" 2>&1 || true
fi

# The logs live on a bind mount (./output:/app/output), so the host copy is a
# valid fallback when the container is gone or docker cp returned nothing.
if [ -z "$(ls -A "$work_dir/app-logs" 2>/dev/null)" ] && [ -d "$compose_dir/output/logs" ]; then
    cp -R -- "$compose_dir/output/logs/." "$work_dir/app-logs/" 2>/dev/null || true
    echo "Application logs copied from $compose_dir/output/logs" > "$work_dir/host-log-fallback.txt"
fi
if [ -z "$container_id" ]; then
    echo "No running or created container found for service '$service'." \
        > "$work_dir/container-not-found.txt"
fi

debug_files_found=false
for debug_file in "$work_dir"/app-logs/debug-*; do
    [ -f "$debug_file" ] || continue
    debug_files_found=true
    break
done

if [ "$exclude_debug" = true ]; then
    rm -f -- "$work_dir"/app-logs/debug-*
fi

if [ -n "$from_time" ]; then
    # JSONL timestamps are ISO8601 UTC. Compare only YYYY-MM-DDTHH:MM:SS: with a
    # fractional part ("...:00.000+00:00") a plain string compare would sort
    # before "...:00Z" and drop events that fall exactly on the boundary.
    for log_file in "$work_dir"/app-logs/*.jsonl*; do
        [ -f "$log_file" ] || continue
        filtered="$log_file.filtered"
        awk -v from="$from_time" -v to="$to_time" '
            BEGIN { from = substr(from, 1, 19); to = substr(to, 1, 19) }
            match($0, /"timestamp":"[^"]+"/) {
                ts=substr($0, RSTART+13, 19)
                if (ts >= from && ts < to) print
            }
        ' "$log_file" > "$filtered"
        mv -- "$filtered" "$log_file"
    done
fi

if [ -n "$trace_id" ]; then
    # Events are compact JSON, so the correlation field has a fixed spelling.
    for log_file in "$work_dir"/app-logs/*.jsonl*; do
        [ -f "$log_file" ] || continue
        filtered="$log_file.filtered"
        grep -F -- "\"trace_id\":\"$trace_id\"" "$log_file" > "$filtered" || true
        mv -- "$filtered" "$log_file"
    done
fi

ls -l "$work_dir/app-logs" > "$work_dir/app-logs-inventory.txt" 2>&1 || true

logs_size_kb=$(du -sk "$work_dir/app-logs" 2>/dev/null | cut -f 1)
if [ "$debug_files_found" = true ] && [ "$exclude_debug" != true ] \
    && [ -z "$from_time" ] && [ -z "$trace_id" ] && [ "${logs_size_kb:-0}" -gt 204800 ]; then
    echo "Warning: debug logs are large (${logs_size_kb} KB). Use --last-hour, --from/--to," \
        "--trace-id or --exclude-debug to keep the archive small." >&2
fi

debug_mode_setting=$(sed -n 's/^MPVM_DEBUG_MODE=//p' "$work_dir/logging-config.txt" 2>/dev/null | head -n 1)

cat > "$work_dir/manifest.txt" <<EOF
service=$service
compose_directory=$compose_dir
docker_logs_since=$since
application_logs_from=$from_time
application_logs_to=$to_time
application_logs_trace_id=$trace_id
debug_mode_setting=${debug_mode_setting:-unset}
debug_log_files_found=$debug_files_found
debug_logs_excluded=$exclude_debug
archive_created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

tar -czf "$archive" -C "$work_dir" .

echo "Support archive created successfully." >&2
echo "$archive"
