"""Automated USB disk detector, partitioner, ext4 formatter, and mount initializer."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, List, Optional, Tuple

MIN_USB_CAPACITY_BYTES: int = 500_000_000_000  # 500 GB in SI bytes (5.0 * 10^11 B)
MAX_BLOCK_DEVICES: int = 64
MAX_PARTITIONS_PER_DISK: int = 32
TRAIL_UID: int = 10001
TRAIL_GID: int = 10001
TRAIL_FS_LABEL: str = "TRAIL_DATA"
ALLOWED_DEV_PATTERN = re.compile(
    r"^/dev/(sd[a-z][0-9]{0,2}|nvme[0-9]+n[0-9]+(p[0-9]+)?|vd[a-z][0-9]{0,2})$"
)
PROTECTED_MOUNTPOINTS: Tuple[str, ...] = (
    "/",
    "/boot",
    "/boot/firmware",
    "/etc",
    "/var",
    "/usr",
    "[SWAP]",
)


@dataclass(frozen=True)
class BlockPartition:
    """Metadata for a single candidate partition or block device."""

    path: str
    size_bytes: int
    fstype: str
    mountpoint: str
    uuid: str
    label: str = ""
    is_whole_disk: bool = False


@dataclass(frozen=True)
class BlockDisk:
    """Metadata for a top-level physical disk and its child partitions."""

    name: str
    path: str
    transport: str
    size_bytes: int
    mountpoint: str
    fstype: str
    uuid: str
    label: str
    partitions: Tuple[BlockPartition, ...]


LsblkProvider = Callable[[], str]
CommandRunner = Callable[[List[str]], Tuple[int, str]]


def is_valid_device_path(dev_path: str) -> bool:
    """Verify device path matches positive allow-list and excludes /dev/mmcblk*."""
    if not isinstance(dev_path, str):
        return False
    trimmed = dev_path.strip()
    if trimmed.startswith("/dev/mmcblk"):
        return False
    return bool(ALLOWED_DEV_PATTERN.match(trimmed))


def default_command_runner(cmd: List[str]) -> Tuple[int, str]:
    """Execute an external command without a shell and return (exit_code, output)."""
    assert isinstance(cmd, list) and len(cmd) > 0, "cmd must be a non-empty list"
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return (int(proc.returncode), output.strip())
    except (OSError, subprocess.SubprocessError):
        return (1, "Command execution failed")


def default_lsblk_provider() -> str:
    """Query lsblk in JSON byte mode for block device topology including LABEL."""
    code, out = default_command_runner(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,PATH,SIZE,TYPE,TRAN,FSTYPE,MOUNTPOINT,UUID,LABEL",
        ]
    )
    return out if code == 0 else ""


def _parse_partition(node: dict) -> Optional[BlockPartition]:
    """Convert an lsblk child JSON dictionary into a validated BlockPartition."""
    assert isinstance(node, dict), "node must be a dict"
    path = str(node.get("path") or "").strip()
    if not path:
        name = str(node.get("name") or "").strip()
        path = f"/dev/{name}" if name else ""
    try:
        size_b = int(node.get("size") or 0)
    except (ValueError, TypeError):
        size_b = 0
    return BlockPartition(
        path=path,
        size_bytes=size_b,
        fstype=str(node.get("fstype") or "").strip().lower(),
        mountpoint=str(node.get("mountpoint") or "").strip(),
        uuid=str(node.get("uuid") or "").strip(),
        label=str(node.get("label") or "").strip(),
        is_whole_disk=False,
    )


def parse_lsblk_json(raw_json: str) -> List[BlockDisk]:
    """Parse lsblk JSON output into a bounded list of BlockDisk objects."""
    if not isinstance(raw_json, str) or not raw_json.strip():
        return []
    try:
        payload = json.loads(raw_json)
    except ValueError:
        return []
    raw_devs = payload.get("blockdevices")
    if not isinstance(raw_devs, list):
        return []

    disks: List[BlockDisk] = []
    bound = min(len(raw_devs), MAX_BLOCK_DEVICES)
    for idx in range(bound):
        entry = raw_devs[idx]
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type") or "").lower() != "disk":
            continue
        name = str(entry.get("name") or "").strip()
        path = str(entry.get("path") or f"/dev/{name}").strip()
        try:
            size_b = int(entry.get("size") or 0)
        except (ValueError, TypeError):
            size_b = 0

        children = entry.get("children")
        parts: List[BlockPartition] = []
        if isinstance(children, list):
            p_bound = min(len(children), MAX_PARTITIONS_PER_DISK)
            for p_idx in range(p_bound):
                if isinstance(children[p_idx], dict):
                    parsed_p = _parse_partition(children[p_idx])
                    if parsed_p is not None:
                        parts.append(parsed_p)

        disks.append(
            BlockDisk(
                name=name,
                path=path,
                transport=str(entry.get("tran") or "").strip().lower(),
                size_bytes=size_b,
                mountpoint=str(entry.get("mountpoint") or "").strip(),
                fstype=str(entry.get("fstype") or "").strip().lower(),
                uuid=str(entry.get("uuid") or "").strip(),
                label=str(entry.get("label") or "").strip(),
                partitions=tuple(parts),
            )
        )
    return disks


def is_protected_boot_or_root_disk(disk: BlockDisk) -> bool:
    """Return True if the disk is /dev/mmcblk* or hosts any OS boot/root mount."""
    assert isinstance(disk, BlockDisk), "disk must be a BlockDisk"
    if disk.name.startswith("mmcblk") or disk.path.startswith("/dev/mmcblk"):
        return True
    if disk.mountpoint in PROTECTED_MOUNTPOINTS:
        return True
    bound = min(len(disk.partitions), MAX_PARTITIONS_PER_DISK)
    for idx in range(bound):
        part_mp = disk.partitions[idx].mountpoint
        if part_mp in PROTECTED_MOUNTPOINTS:
            return True
    return False


def _select_best_partition(disk: BlockDisk, min_bytes: int) -> Optional[BlockPartition]:
    """Pick the largest partition >= min_bytes, or whole disk if unpartitioned."""
    assert isinstance(disk, BlockDisk), "disk must be a BlockDisk"
    best: Optional[BlockPartition] = None
    bound = min(len(disk.partitions), MAX_PARTITIONS_PER_DISK)
    for idx in range(bound):
        part = disk.partitions[idx]
        if not is_valid_device_path(part.path):
            continue
        if part.size_bytes >= min_bytes:
            if best is None or part.size_bytes > best.size_bytes:
                best = part
    if best is not None:
        return best
    if len(disk.partitions) == 0 and is_valid_device_path(disk.path):
        return BlockPartition(
            path=disk.path,
            size_bytes=disk.size_bytes,
            fstype=disk.fstype,
            mountpoint=disk.mountpoint,
            uuid=disk.uuid,
            label=disk.label,
            is_whole_disk=True,
        )
    return None


def select_target_usb_partition(
    disks: List[BlockDisk],
    override_device: str = "",
    min_capacity_bytes: int = MIN_USB_CAPACITY_BYTES,
) -> Tuple[bool, Optional[BlockPartition], str]:
    """Select the target USB partition >= 500 GB or validate TRAIL_USB_DEVICE."""
    assert isinstance(disks, list), "disks must be a list"
    assert min_capacity_bytes > 0, "min_capacity_bytes must be positive"
    clean_override = (override_device or "").strip()

    if clean_override:
        if not is_valid_device_path(clean_override):
            return (False, None, "Override device path failed allow-list check")
        bound = min(len(disks), MAX_BLOCK_DEVICES)
        for idx in range(bound):
            disk = disks[idx]
            if is_protected_boot_or_root_disk(disk):
                if disk.path == clean_override or any(
                    p.path == clean_override for p in disk.partitions
                ):
                    return (False, None, "Override device points to protected OS disk")
            if disk.path == clean_override:
                part = _select_best_partition(disk, 1)
                if part is not None:
                    return (True, part, "Selected via TRAIL_USB_DEVICE disk override")
            p_bound = min(len(disk.partitions), MAX_PARTITIONS_PER_DISK)
            for p_idx in range(p_bound):
                part = disk.partitions[p_idx]
                if part.path == clean_override:
                    return (True, part, "Selected via TRAIL_USB_DEVICE partition override")
        return (False, None, "Override device not found in block device table")

    bound = min(len(disks), MAX_BLOCK_DEVICES)
    for idx in range(bound):
        disk = disks[idx]
        if is_protected_boot_or_root_disk(disk):
            continue
        if disk.transport != "usb":
            continue
        if disk.size_bytes < min_capacity_bytes:
            continue
        candidate = _select_best_partition(disk, min_capacity_bytes)
        if candidate is not None:
            return (True, candidate, f"Auto-detected USB partition {candidate.path}")

    return (False, None, "No non-boot USB disk >= 500 GB detected")


def _provision_and_format_partition(
    partition: BlockPartition,
    auto_format: bool,
    runner: CommandRunner,
) -> Tuple[bool, str, str]:
    """Partition raw disk if needed and format as ext4 with label TRAIL_DATA.

    Returns (ok, target_partition_path, status_message).
    """
    assert isinstance(partition, BlockPartition), "partition must be a BlockPartition"
    target_path = partition.path
    is_initialized = (
        partition.fstype == "ext4" and partition.label == TRAIL_FS_LABEL
    )
    if is_initialized:
        return (True, target_path, f"Verified existing {TRAIL_FS_LABEL} ext4 volume")

    needs_format = (not partition.fstype) or (
        auto_format and partition.label != TRAIL_FS_LABEL
    )
    if not needs_format:
        return (True, target_path, f"Using existing {partition.fstype} volume")

    if not auto_format:
        return (
            False,
            target_path,
            f"Device {target_path} is unformatted and TRAIL_AUTO_FORMAT is disabled",
        )

    if partition.mountpoint:
        runner(["umount", partition.path])

    if partition.is_whole_disk:
        code_p, _ = runner(
            [
                "parted",
                "-s",
                partition.path,
                "mklabel",
                "gpt",
                "mkpart",
                TRAIL_FS_LABEL,
                "ext4",
                "1MiB",
                "100%",
            ]
        )
        if code_p == 0:
            target_path = (
                f"{partition.path}p1"
                if partition.path[-1].isdigit()
                else f"{partition.path}1"
            )
        else:
            target_path = partition.path

    code_mkfs, msg_mkfs = runner(
        ["mkfs.ext4", "-F", "-L", TRAIL_FS_LABEL, target_path]
    )
    if code_mkfs != 0:
        return (False, target_path, f"mkfs.ext4 failed on {target_path}: {msg_mkfs}")
    return (True, target_path, f"Formatted {target_path} as ext4 ({TRAIL_FS_LABEL})")


def setup_external_drive(
    target_dir: Path,
    override_device: str = "",
    min_capacity_bytes: int = MIN_USB_CAPACITY_BYTES,
    auto_format: bool = True,
    lsblk_provider: Optional[LsblkProvider] = None,
    runner: Optional[CommandRunner] = None,
) -> Tuple[bool, str]:
    """Auto-detect, format if uninitialized, mount, and set UID 10001 ownership."""
    assert isinstance(target_dir, Path), "target_dir must be a Path"
    active_lsblk = lsblk_provider if lsblk_provider is not None else default_lsblk_provider
    active_runner = runner if runner is not None else default_command_runner

    target_dir.mkdir(parents=True, exist_ok=True)
    disks = parse_lsblk_json(active_lsblk())
    ok, partition, reason = select_target_usb_partition(
        disks, override_device=override_device, min_capacity_bytes=min_capacity_bytes
    )

    if ok and partition is not None:
        ok_fmt, dev_to_mount, fmt_msg = _provision_and_format_partition(
            partition, auto_format=auto_format, runner=active_runner
        )
        if not ok_fmt:
            return (False, fmt_msg)

        if partition.mountpoint != str(target_dir):
            code, msg = active_runner(["mount", dev_to_mount, str(target_dir)])
            if code != 0:
                return (False, f"Mount failed for {dev_to_mount}: {msg}")
        reason = f"{reason}; {fmt_msg}"
    elif override_device.strip():
        return (False, reason)

    try:
        if hasattr(os, "chown"):
            os.chown(target_dir, TRAIL_UID, TRAIL_GID)
    except OSError:
        pass
    return (True, reason)


def main() -> int:
    """CLI entrypoint for standalone disk initialization."""
    data_dir = Path(os.environ.get("TRAIL_DATA_DIR", "/app/data"))
    override_dev = os.environ.get("TRAIL_USB_DEVICE", "").strip()
    auto_fmt_raw = os.environ.get("TRAIL_AUTO_FORMAT", "true").strip().lower()
    auto_fmt = auto_fmt_raw in ("1", "true", "yes")
    try:
        min_gb = int(os.environ.get("TRAIL_MIN_USB_GB", "500"))
    except ValueError:
        min_gb = 500
    min_bytes = max(1, min_gb) * 1_000_000_000

    ok, msg = setup_external_drive(
        target_dir=data_dir,
        override_device=override_dev,
        min_capacity_bytes=min_bytes,
        auto_format=auto_fmt,
    )
    sys.stderr.write(f"trail-disk-init: {msg}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
