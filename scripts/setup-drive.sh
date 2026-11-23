#!/usr/bin/env bash
# Optional standalone host helper that invokes trail.disk to auto-detect,
# format (with label TRAIL_DATA if uninitialized), and mount the USB drive.

set -euo pipefail

MOUNT_ROOT="${TRAIL_USB_MOUNT_ROOT:-/mnt/usb2tb}"
DATA_DIR="${MOUNT_ROOT}/trail-data"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: Run this script with sudo." >&2
    exit 1
fi

export TRAIL_DATA_DIR="${DATA_DIR}"
export TRAIL_AUTO_FORMAT="${TRAIL_AUTO_FORMAT:-true}"
export TRAIL_MIN_USB_GB="${TRAIL_MIN_USB_GB:-500}"

python3 -m trail.disk
