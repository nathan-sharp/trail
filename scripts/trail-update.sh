#!/usr/bin/env bash
# TRAIL Forced System Update Command (installed at /usr/local/bin/trail-update)
# Usage: trail-update

set -euo pipefail

INSTALL_DIR="${TRAIL_INSTALL_DIR:-/opt/trail}"
MAX_HEALTH_RETRIES=30

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
    echo "Error: TRAIL installation not found at ${INSTALL_DIR}." >&2
    exit 1
fi

cd "${INSTALL_DIR}"

echo "[1/4] Backing up local config/seeds.txt and pulling latest TRAIL code..."
SEEDS_BACKUP="$(mktemp)"
if [[ -f "config/seeds.txt" ]]; then
    cp "config/seeds.txt" "${SEEDS_BACKUP}"
fi

git fetch --depth 1 origin main
git checkout -B main origin/main

if [[ -s "${SEEDS_BACKUP}" ]]; then
    cat "${SEEDS_BACKUP}" "config/seeds.txt" | awk '!seen[$0]++' > "config/seeds.txt.merged"
    mv "config/seeds.txt.merged" "config/seeds.txt"
fi
rm -f "${SEEDS_BACKUP}"

if [[ -f "${INSTALL_DIR}/scripts/trail-update.sh" ]]; then
    cp "${INSTALL_DIR}/scripts/trail-update.sh" /usr/local/bin/trail-update
    chmod 755 /usr/local/bin/trail-update
fi

echo "[2/4] Upgrading Raspberry Pi host Debian packages..."
apt-get update -qq
apt-get upgrade -y --no-install-recommends >/dev/null

echo "[3/4] Pulling latest container images and rebuilding TRAIL..."
docker compose pull
docker compose build --pull
docker compose up -d --force-recreate --remove-orphans

echo "[4/4] Verifying TRAIL health status..."
for ((i = 1; i <= MAX_HEALTH_RETRIES; i++)); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
        echo "TRAIL forced update complete. Server is healthy at http://127.0.0.1:8080/status"
        exit 0
    fi
    sleep 2
done

echo "Warning: Health check did not respond within 60 seconds. Check 'sudo docker logs trail-server'." >&2
exit 1
