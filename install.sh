#!/usr/bin/env bash
# TRAIL (Text Retrieval & Automated Indexing Library) One-Command Installer (v2026)
# Usage (Interactive):
#   curl -fsSL https://raw.githubusercontent.com/nathan-sharp/trail/main/install.sh | sudo bash
# Usage (Non-Interactive):
#   curl -fsSL https://raw.githubusercontent.com/nathan-sharp/trail/main/install.sh | sudo bash -s -- https://search.example.com YOUR_CF_TOKEN

set -euo pipefail

INSTALL_DIR="${TRAIL_INSTALL_DIR:-/opt/trail}"
REPO_URL="${TRAIL_REPO_URL:-https://github.com/nathan-sharp/trail.git}"
ARG_BASE_URL="${1:-${TRAIL_BASE_URL:-}}"
ARG_CF_TOKEN="${2:-${CLOUDFLARE_TUNNEL_TOKEN:-}}"
MAX_HEALTH_RETRIES=30

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: Run this installer as root (use sudo)." >&2
    exit 1
fi

if [[ -z "${ARG_BASE_URL}" ]] && [[ -r /dev/tty ]]; then
    read -r -p "Enter public Base URL [http://localhost:8080]: " ARG_BASE_URL < /dev/tty || true
fi
ARG_BASE_URL="${ARG_BASE_URL:-http://localhost:8080}"
ARG_BASE_URL="${ARG_BASE_URL%/}"

if [[ ! "${ARG_BASE_URL}" =~ ^https?://[A-Za-z0-9._:\-]+$ ]]; then
    echo "Error: TRAIL_BASE_URL failed allow-list validation (must be http:// or https:// hostname)." >&2
    exit 1
fi

if [[ -z "${ARG_CF_TOKEN}" ]] && [[ -r /dev/tty ]]; then
    read -r -p "Enter Cloudflare Tunnel Token (or press Enter for LAN-only): " ARG_CF_TOKEN < /dev/tty || true
fi
ARG_CF_TOKEN="${ARG_CF_TOKEN:-}"

if [[ ! "${ARG_CF_TOKEN}" =~ ^[A-Za-z0-9._\-=]*$ ]]; then
    echo "Error: CLOUDFLARE_TUNNEL_TOKEN contains disallowed characters." >&2
    exit 1
fi

echo "[1/5] Installing prerequisite packages (git, curl, ca-certificates)..."
apt-get update -qq
apt-get install -y --no-install-recommends git curl ca-certificates >/dev/null

if ! command -v docker >/dev/null 2>&1; then
    echo "[2/5] Installing Docker Engine and Docker Compose plugin..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
else
    echo "[2/5] Docker Engine already installed."
fi

echo "[3/5] Fetching TRAIL repository (${REPO_URL}) into ${INSTALL_DIR}..."
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    git -C "${INSTALL_DIR}" pull --ff-only
else
    mkdir -p "${INSTALL_DIR}"
    git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

echo "[4/5] Writing configuration to ${INSTALL_DIR}/.env (mode 0600)..."
if [[ ! -f ".env" ]]; then
    cp .env.example .env
fi
chmod 600 .env
sed -i "s|^TRAIL_BASE_URL=.*|TRAIL_BASE_URL=${ARG_BASE_URL}|" .env
if [[ -n "${ARG_CF_TOKEN}" ]]; then
    sed -i "s|^CLOUDFLARE_TUNNEL_TOKEN=.*|CLOUDFLARE_TUNNEL_TOKEN=${ARG_CF_TOKEN}|" .env
fi

echo "[5/5] Starting TRAIL stack (auto-provisioning USB drive and containers)..."
docker compose up -d --build

for ((i = 1; i <= MAX_HEALTH_RETRIES; i++)); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
        echo "TRAIL v2026 is online at ${ARG_BASE_URL} (Local: http://127.0.0.1:8080/)."
        echo "Edit seed URLs at: ${INSTALL_DIR}/config/seeds.txt"
        exit 0
    fi
    sleep 2
done

echo "Warning: Health check did not respond within 60 seconds. Check 'docker logs trail-server'." >&2
exit 1
