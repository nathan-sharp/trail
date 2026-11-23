"""Main process orchestrator for TRAIL drive setup, privilege drop, version checks, and server."""

import os
from pathlib import Path
import signal
import sys
import threading

from trail.config import TrailConfig, load_config_from_env
from trail.crawler import TrailCrawler
from trail.disk import TRAIL_GID, TRAIL_UID, setup_external_drive
from trail.server import create_http_server
from trail.storage import TrailStorage
from trail.updater import TrailUpdateMonitor

MAX_CRAWL_CYCLES: int = 10000000


def _initialize_drive_and_drop_privileges(data_dir: Path) -> bool:
    """Auto-setup external USB drive if running as root, then drop to UID 10001."""
    assert isinstance(data_dir, Path), "data_dir must be a Path"
    override_dev = os.environ.get("TRAIL_USB_DEVICE", "").strip()
    auto_fmt_raw = os.environ.get("TRAIL_AUTO_FORMAT", "true").strip().lower()
    auto_fmt = auto_fmt_raw in ("1", "true", "yes")
    try:
        min_gb = int(os.environ.get("TRAIL_MIN_USB_GB", "500"))
    except ValueError:
        min_gb = 500

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        ok, msg = setup_external_drive(
            target_dir=data_dir,
            override_device=override_dev,
            min_capacity_bytes=max(1, min_gb) * 1_000_000_000,
            auto_format=auto_fmt,
        )
        sys.stderr.write(f"TRAIL disk setup: {msg}\n")
        if not ok:
            return False
        if hasattr(os, "setgroups"):
            os.setgroups([])
        os.setgid(TRAIL_GID)
        os.setuid(TRAIL_UID)
        assert os.getuid() == TRAIL_UID, "Failed to drop real UID"
        assert os.geteuid() == TRAIL_UID, "Failed to drop effective UID"
    return True


def _crawler_loop(
    crawler: TrailCrawler,
    config: TrailConfig,
    stop_event: threading.Event,
    max_cycles: int = MAX_CRAWL_CYCLES,
) -> None:
    """Run bounded crawl batches at fixed intervals until stop_event is set."""
    assert max_cycles >= 1, "max_cycles must be >= 1"
    for _ in range(max_cycles):
        if stop_event.is_set():
            break
        try:
            crawler.run_single_batch()
        except Exception:
            pass
        if stop_event.wait(timeout=float(config.crawl_interval_seconds)):
            break


def _update_monitor_loop(
    monitor: TrailUpdateMonitor,
    config: TrailConfig,
    stop_event: threading.Event,
    max_cycles: int = MAX_CRAWL_CYCLES,
) -> None:
    """Run bounded version audits at fixed intervals until stop_event is set."""
    assert max_cycles >= 1, "max_cycles must be >= 1"
    for _ in range(max_cycles):
        if stop_event.is_set():
            break
        try:
            monitor.refresh()
        except Exception:
            pass
        if stop_event.wait(timeout=float(config.update_check_interval_seconds)):
            break


def main() -> int:
    """Initialize external drive, drop privileges, and start crawler, updater, and server."""
    workspace_root = Path(__file__).resolve().parent.parent
    config = load_config_from_env(workspace_root)

    if not _initialize_drive_and_drop_privileges(config.db_path.parent):
        return 1

    storage = TrailStorage(config.db_path)
    crawler = TrailCrawler(config, storage, workspace_root)
    crawler.load_seeds_into_queue()
    update_monitor = TrailUpdateMonitor(config)

    stop_event = threading.Event()
    crawler_worker = threading.Thread(
        target=_crawler_loop,
        args=(crawler, config, stop_event),
        name="trail-crawler-worker",
        daemon=True,
    )
    crawler_worker.start()

    update_worker = threading.Thread(
        target=_update_monitor_loop,
        args=(update_monitor, config, stop_event),
        name="trail-update-monitor",
        daemon=True,
    )
    update_worker.start()

    httpd = create_http_server(config, storage, update_monitor)

    def _handle_signal(signum: int, _frame) -> None:
        stop_event.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    sys.stderr.write(
        f"TRAIL listening on http://{config.host}:{config.port} "
        f"(DB: {config.db_path})\n"
    )
    try:
        httpd.serve_forever()
    finally:
        stop_event.set()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
