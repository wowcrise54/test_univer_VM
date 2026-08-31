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
  --output-dir PATH    Directory for the resulting archive
                       (default: ./output/support-bundles)
  -h, --help           Show this help

The final stdout line is the absolute path to the generated archive.
EOF
}

compose_dir=$(pwd)
service=mpvm-client
since=24h
output_dir=./output/support-bundles

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
else
    echo "No running or created container found for service '$service'." \
        > "$work_dir/container-not-found.txt"
fi

cat > "$work_dir/manifest.txt" <<EOF
service=$service
compose_directory=$compose_dir
docker_logs_since=$since
archive_created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

tar -czf "$archive" -C "$work_dir" .

echo "Support archive created successfully." >&2
echo "$archive"
