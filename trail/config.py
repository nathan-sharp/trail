"""Configuration loader and path-traversal guard for TRAIL."""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import List, Tuple

MAX_SEED_LINES: int = 1000
MAX_LINE_CHARS: int = 2048


@dataclass(frozen=True)
class TrailConfig:
    """Immutable runtime configuration for TRAIL."""

    base_url: str
    db_path: Path
    seeds_path: Path
    host: str
    port: int
    max_hop_depth: int
    max_pages_per_domain: int
    crawl_delay_seconds: int
    crawl_batch_size: int
    crawl_interval_seconds: int
    results_per_page: int
    user_agent: str


def validate_confined_path(base_dir: Path, target_path: Path) -> Tuple[bool, Path]:
    """Verify target_path resolves strictly inside base_dir to prevent Path Traversal."""
    assert isinstance(base_dir, Path), "base_dir must be a Path instance"
    assert isinstance(target_path, Path), "target_path must be a Path instance"
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        is_inside = (
            resolved_target == resolved_base
            or resolved_base in resolved_target.parents
        )
        return (is_inside, resolved_target)
    except (OSError, RuntimeError, ValueError):
        return (False, base_dir)


def _parse_bounded_int(raw_val: str, default: int, min_val: int, max_val: int) -> int:
    """Parse an integer within explicit static bounds [min_val, max_val]."""
    assert min_val <= default <= max_val, "default out of bounds"
    try:
        parsed = int(raw_val.strip())
    except (ValueError, AttributeError):
        return default
    if parsed < min_val:
        return min_val
    if parsed > max_val:
        return max_val
    return parsed


def load_config_from_env(workspace_root: Path) -> TrailConfig:
    """Load and validate TrailConfig from environment variables."""
    assert isinstance(workspace_root, Path), "workspace_root must be a Path"
    raw_base_url = os.environ.get("TRAIL_BASE_URL", "http://localhost:8080").strip()
    base_url = raw_base_url.rstrip("/") if raw_base_url else "http://localhost:8080"

    db_raw = Path(os.environ.get("TRAIL_DB_PATH", str(workspace_root / "data" / "trail.db")))
    seeds_raw = Path(os.environ.get("TRAIL_SEEDS_PATH", str(workspace_root / "config" / "seeds.txt")))

    ok_db, safe_db = validate_confined_path(workspace_root, db_raw)
    if not ok_db:
        safe_db = (workspace_root / "data" / "trail.db").resolve()

    ok_seeds, safe_seeds = validate_confined_path(workspace_root, seeds_raw)
    if not ok_seeds:
        safe_seeds = (workspace_root / "config" / "seeds.txt").resolve()

    return TrailConfig(
        base_url=base_url,
        db_path=safe_db,
        seeds_path=safe_seeds,
        host=os.environ.get("TRAIL_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=_parse_bounded_int(os.environ.get("TRAIL_PORT", "8080"), 8080, 1, 65535),
        max_hop_depth=_parse_bounded_int(os.environ.get("TRAIL_MAX_HOP_DEPTH", "2"), 2, 0, 10),
        max_pages_per_domain=_parse_bounded_int(
            os.environ.get("TRAIL_MAX_PAGES_PER_DOMAIN", "50"), 50, 1, 10000
        ),
        crawl_delay_seconds=_parse_bounded_int(
            os.environ.get("TRAIL_CRAWL_DELAY_SECONDS", "2"), 2, 1, 3600
        ),
        crawl_batch_size=_parse_bounded_int(
            os.environ.get("TRAIL_CRAWL_BATCH_SIZE", "10"), 10, 1, 500
        ),
        crawl_interval_seconds=_parse_bounded_int(
            os.environ.get("TRAIL_CRAWL_INTERVAL_SECONDS", "30"), 30, 5, 86400
        ),
        results_per_page=_parse_bounded_int(
            os.environ.get("TRAIL_RESULTS_PER_PAGE", "10"), 10, 1, 50
        ),
        user_agent="TRAIL/1.0 (+Self-Hosted-HTML2-Search)",
    )


def load_seed_urls(seeds_path: Path, allowed_base_dir: Path) -> List[str]:
    """Read up to MAX_SEED_LINES seed URLs from a confined configuration file."""
    assert isinstance(seeds_path, Path), "seeds_path must be a Path"
    assert isinstance(allowed_base_dir, Path), "allowed_base_dir must be a Path"
    is_safe, resolved_path = validate_confined_path(allowed_base_dir, seeds_path)
    if not is_safe or not resolved_path.is_file():
        return []

    seeds: List[str] = []
    try:
        with resolved_path.open("r", encoding="utf-8", errors="replace") as handle:
            for _ in range(MAX_SEED_LINES):
                line = handle.readline(MAX_LINE_CHARS)
                if not line:
                    break
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                seeds.append(stripped)
    except OSError:
        return []
    return seeds
