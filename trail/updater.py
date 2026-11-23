"""Automated version checker and system updater using NJS ISO Timestamp Versioning.

Specification: https://njs.dev/other/versioning/
Format: vYYYY, vYYYY-MM, vYYYY-MM-DD, vYYYY-MM-DDThh, vYYYY-MM-DDThh:mm, or vYYYY-MM-DDThh:mm:ss.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import sys
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.request

from trail import __version__ as TRAIL_LOCAL_VERSION
from trail.config import TrailConfig, load_config_from_env
from trail.crawler import HttpFetcher, _NoRedirectHandler
from trail.disk import CommandRunner, default_command_runner
from trail.security import DnsResolver, normalize_and_validate_url

MAX_MANIFEST_BYTES: int = 65536
MAX_SEMVER_VALUE: int = 999999
MAX_APT_LINES: int = 500
MAX_UPDATE_CYCLES: int = 1000000
MAX_PRIOR_RELEASES: int = 10000
ISO_FRAGMENT_LENGTHS: Tuple[int, ...] = (4, 7, 10, 13, 16, 19)

NJS_ISO_VERSION_PATTERN = re.compile(
    r"^v?(\d{4})(?:-(\d{2})(?:-(\d{2})(?:T(\d{2})(?::(\d{2})(?::(\d{2}))?)?)?)?)?Z?$"
)
DOT_VERSION_PATTERN = re.compile(r"v?(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?")


@dataclass(frozen=True)
class ComponentVersionStatus:
    """Version comparison state for a single system component."""

    name: str
    installed_version: str
    latest_version: str
    is_up_to_date: bool
    status_label: str


@dataclass(frozen=True)
class SystemUpdateReport:
    """Aggregated version audit report for TRAIL and dependent subsystems."""

    checked_at: int
    all_up_to_date: bool
    components: Tuple[ComponentVersionStatus, ...]
    last_update_action: str


def parse_njs_iso_version(
    version_text: str,
) -> Tuple[bool, Tuple[int, int, int, int, int, int], str]:
    """Parse an NJS ISO Timestamp Version into (year, month, day, hour, minute, second).

    Validates strict ISO 8601 leading-zero format and calendar bounds.
    """
    if not isinstance(version_text, str):
        return (False, (0, 0, 0, 0, 0, 0), "")
    trimmed = version_text.strip()
    match = NJS_ISO_VERSION_PATTERN.match(trimmed)
    if not match:
        return (False, (0, 0, 0, 0, 0, 0), "")

    year = int(match.group(1))
    month = int(match.group(2)) if match.group(2) is not None else 0
    day = int(match.group(3)) if match.group(3) is not None else 0
    hour = int(match.group(4)) if match.group(4) is not None else 0
    minute = int(match.group(5)) if match.group(5) is not None else 0
    second = int(match.group(6)) if match.group(6) is not None else 0

    if match.group(2) is not None and not (1 <= month <= 12):
        return (False, (0, 0, 0, 0, 0, 0), "")
    if match.group(3) is not None and not (1 <= day <= 31):
        return (False, (0, 0, 0, 0, 0, 0), "")
    if match.group(4) is not None and not (0 <= hour <= 23):
        return (False, (0, 0, 0, 0, 0, 0), "")
    if match.group(5) is not None and not (0 <= minute <= 59):
        return (False, (0, 0, 0, 0, 0, 0), "")
    if match.group(6) is not None and not (0 <= second <= 59):
        return (False, (0, 0, 0, 0, 0, 0), "")

    core = trimmed.lstrip("v").rstrip("Z")
    canonical = f"v{core}"
    return (True, (year, month, day, hour, minute, second), canonical)


def format_njs_iso_version(
    release_utc: str, prior_releases_utc: Sequence[str]
) -> Tuple[bool, str]:
    """Generate the shortest unique NJS ISO Timestamp Version (vYYYY..vYYYY-MM-DDThh:mm:ss)."""
    ok_t, _, canonical_t = parse_njs_iso_version(release_utc)
    if not ok_t:
        return (False, "")
    raw_iso = canonical_t[1:]

    normalized_priors: List[str] = []
    bound = min(len(prior_releases_utc), MAX_PRIOR_RELEASES)
    for idx in range(bound):
        ok_p, _, can_p = parse_njs_iso_version(prior_releases_utc[idx])
        if ok_p and can_p[1:] != raw_iso:
            normalized_priors.append(can_p[1:])

    for length in ISO_FRAGMENT_LENGTHS:
        if len(raw_iso) < length:
            continue
        candidate_frag = raw_iso[:length]
        collision = False
        for p_idx in range(len(normalized_priors)):
            prior_iso = normalized_priors[p_idx]
            if prior_iso[:length] == candidate_frag:
                collision = True
                break
        if not collision:
            return (True, f"v{candidate_frag}")

    return (True, f"v{raw_iso}")


def parse_semver(version_text: str) -> Tuple[bool, Tuple[int, int, int, int, int, int]]:
    """Parse NJS ISO Timestamp Version or 3-part dot version into a 6-int tuple."""
    ok_iso, iso_tup, _ = parse_njs_iso_version(version_text)
    if ok_iso:
        return (True, iso_tup)
    if not isinstance(version_text, str):
        return (False, (0, 0, 0, 0, 0, 0))
    match = DOT_VERSION_PATTERN.search(version_text.strip())
    if not match:
        return (False, (0, 0, 0, 0, 0, 0))
    major = min(int(match.group(1)), MAX_SEMVER_VALUE)
    minor = min(int(match.group(2)), MAX_SEMVER_VALUE)
    patch = min(int(match.group(3) or "0"), MAX_SEMVER_VALUE)
    return (True, (major, minor, patch, 0, 0, 0))


def is_version_up_to_date(installed: str, latest: str) -> bool:
    """Return True if installed NJS ISO or dot version is >= latest version."""
    assert isinstance(installed, str) and isinstance(latest, str), "strings required"
    ok_inst_iso, tup_inst_iso, _ = parse_njs_iso_version(installed)
    ok_lat_iso, tup_lat_iso, _ = parse_njs_iso_version(latest)
    if ok_inst_iso and ok_lat_iso:
        return tup_inst_iso >= tup_lat_iso

    ok_inst, tup_inst = parse_semver(installed)
    ok_lat, tup_lat = parse_semver(latest)
    if not ok_inst or not ok_lat:
        return installed.strip() == latest.strip()
    return tup_inst >= tup_lat


def default_json_fetcher(
    url: str, user_agent: str, max_bytes: int
) -> Tuple[int, str, Dict[str, str], bytes]:
    """Fetch JSON or text version metadata over HTTP/HTTPS without redirects."""
    assert isinstance(url, str) and len(url) > 0, "url required"
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/json,text/plain;q=0.9,*/*;q=0.1",
        },
        method="GET",
    )
    try:
        with opener.open(req, timeout=10) as resp:
            status = int(resp.status)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return (status, url, headers, resp.read(max_bytes))
    except (urllib.error.URLError, OSError, ValueError):
        return (0, url, {}, b"")


def derive_github_release_api_url(repo_url: str) -> str:
    """Convert a https://github.com/<owner>/<repo> URL into its Releases API URL."""
    if not isinstance(repo_url, str) or not repo_url.strip():
        return ""
    match = re.match(
        r"^https://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git|/)?$",
        repo_url.strip(),
    )
    if not match:
        return ""
    owner, repo = match.group(1), match.group(2)
    return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"


def _normalize_extracted_version(candidate: str) -> Tuple[bool, str]:
    """Validate candidate as either an NJS ISO Timestamp Version or dot version."""
    ok_iso, _, canonical_iso = parse_njs_iso_version(candidate)
    if ok_iso:
        return (True, canonical_iso)
    match = DOT_VERSION_PATTERN.search(candidate)
    if match:
        maj = int(match.group(1))
        min_v = int(match.group(2))
        pat = int(match.group(3) or "0")
        return (True, f"{maj}.{min_v}.{pat}")
    return (False, "")


def fetch_latest_version_from_url(
    target_url: str,
    user_agent: str,
    resolver: Optional[DnsResolver] = None,
    fetcher: Optional[HttpFetcher] = None,
) -> Tuple[bool, str]:
    """Query an SSRF-validated manifest or GitHub API URL for an NJS ISO or dot version."""
    if not isinstance(target_url, str) or not target_url.strip():
        return (False, "")
    ok_url, norm_url, _ = normalize_and_validate_url(target_url, resolver=resolver)
    if not ok_url:
        return (False, "")

    active_fetcher = fetcher if fetcher is not None else default_json_fetcher
    status, _, _, body_bytes = active_fetcher(norm_url, user_agent, MAX_MANIFEST_BYTES)
    if status != 200 or not body_bytes:
        return (False, "")

    raw_text = body_bytes.decode("utf-8", errors="replace").strip()
    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, dict):
            candidate = str(
                parsed.get("tag_name")
                or parsed.get("version")
                or parsed.get("latest")
                or ""
            ).strip()
            ok_v, ver_str = _normalize_extracted_version(candidate)
            if ok_v:
                return (True, ver_str)
    except ValueError:
        pass

    return _normalize_extracted_version(raw_text[:64])


def check_debian_pending_upgrades(runner: CommandRunner) -> Tuple[bool, int]:
    """Run read-only 'apt-get -s upgrade' to count pending OS package updates."""
    code, output = runner(["apt-get", "-s", "upgrade"])
    if code != 0:
        return (True, 0)
    lines = output.splitlines()
    bound = min(len(lines), MAX_APT_LINES)
    for idx in range(bound):
        match = re.match(r"^(\d+)\s+upgraded,", lines[idx].strip())
        if match:
            count = int(match.group(1))
            return (count == 0, count)
    return (True, 0)


def check_all_system_versions(
    config: TrailConfig,
    installed_cloudflared: str = "",
    resolver: Optional[DnsResolver] = None,
    fetcher: Optional[HttpFetcher] = None,
    runner: Optional[CommandRunner] = None,
) -> SystemUpdateReport:
    """Audit TRAIL (NJS ISO Version), Python, SQLite, cloudflared, and OS packages."""
    active_runner = runner if runner is not None else default_command_runner
    now_ts = int(time.time())

    manifest_url = config.version_manifest_url or derive_github_release_api_url(
        config.repo_url
    )
    ok_trail, latest_trail = fetch_latest_version_from_url(
        manifest_url, config.user_agent, resolver=resolver, fetcher=fetcher
    )
    if not ok_trail:
        latest_trail = TRAIL_LOCAL_VERSION
    trail_ok = is_version_up_to_date(TRAIL_LOCAL_VERSION, latest_trail)

    ok_cf, latest_cf = fetch_latest_version_from_url(
        config.cloudflared_release_url,
        config.user_agent,
        resolver=resolver,
        fetcher=fetcher,
    )
    local_cf = (
        installed_cloudflared.strip()
        or os.environ.get("TRAIL_CLOUDFLARED_VERSION", "").strip()
        or (latest_cf if ok_cf else "latest")
    )
    if not ok_cf:
        latest_cf = local_cf
    cf_ok = is_version_up_to_date(local_cf, latest_cf)

    apt_ok, pending_pkgs = check_debian_pending_upgrades(active_runner)
    py_ver = platform.python_version()
    sq_ver = sqlite3.sqlite_version

    components = (
        ComponentVersionStatus(
            name="TRAIL Engine (NJS ISO Version)",
            installed_version=TRAIL_LOCAL_VERSION,
            latest_version=latest_trail,
            is_up_to_date=trail_ok,
            status_label="UP_TO_DATE" if trail_ok else "UPDATE_AVAILABLE",
        ),
        ComponentVersionStatus(
            name="Cloudflared Tunnel",
            installed_version=local_cf,
            latest_version=latest_cf,
            is_up_to_date=cf_ok,
            status_label="UP_TO_DATE" if cf_ok else "UPDATE_AVAILABLE",
        ),
        ComponentVersionStatus(
            name="Debian OS Packages",
            installed_version=f"{pending_pkgs} pending",
            latest_version="0 pending",
            is_up_to_date=apt_ok,
            status_label="UP_TO_DATE" if apt_ok else "UPDATE_AVAILABLE",
        ),
        ComponentVersionStatus(
            name="Python Runtime",
            installed_version=py_ver,
            latest_version=py_ver,
            is_up_to_date=True,
            status_label="UP_TO_DATE",
        ),
        ComponentVersionStatus(
            name="SQLite FTS5 Engine",
            installed_version=sq_ver,
            latest_version=sq_ver,
            is_up_to_date=True,
            status_label="UP_TO_DATE",
        ),
    )
    all_ok = trail_ok and cf_ok and apt_ok
    return SystemUpdateReport(
        checked_at=now_ts,
        all_up_to_date=all_ok,
        components=components,
        last_update_action="VERIFIED" if all_ok else "PENDING_UPDATE",
    )


def apply_system_updates(
    config: TrailConfig,
    resolver: Optional[DnsResolver] = None,
    runner: Optional[CommandRunner] = None,
) -> Tuple[bool, str]:
    """Pull latest verified Git commits, upgrade Debian packages, and pull images."""
    active_runner = runner if runner is not None else default_command_runner
    actions: List[str] = []

    if config.repo_url:
        ok_repo, norm_repo, _ = normalize_and_validate_url(
            config.repo_url, resolver=resolver
        )
        if not ok_repo:
            return (False, "Blocked invalid or non-public TRAIL_REPO_URL")
        code_git, _ = active_runner(["git", "pull", "--ff-only", norm_repo])
        actions.append("git:ok" if code_git == 0 else "git:skipped")

    code_apt_u, _ = active_runner(["apt-get", "update"])
    if code_apt_u == 0:
        code_apt_g, _ = active_runner(
            ["apt-get", "upgrade", "-y", "--no-install-recommends"]
        )
        actions.append("apt:upgraded" if code_apt_g == 0 else "apt:skipped")

    if Path("/var/run/docker.sock").exists():
        code_dc_p, _ = active_runner(["docker", "compose", "pull"])
        code_dc_u, _ = active_runner(
            ["docker", "compose", "up", "-d", "--build", "--remove-orphans"]
        )
        actions.append(
            "compose:updated"
            if (code_dc_p == 0 and code_dc_u == 0)
            else "compose:skipped"
        )

    summary = ", ".join(actions) if actions else "no_actions_configured"
    return (True, summary)


class TrailUpdateMonitor:
    """Thread-safe holder for the latest SystemUpdateReport."""

    def __init__(self, config: TrailConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._report = SystemUpdateReport(
            checked_at=int(time.time()),
            all_up_to_date=True,
            components=(
                ComponentVersionStatus(
                    name="TRAIL Engine (NJS ISO Version)",
                    installed_version=TRAIL_LOCAL_VERSION,
                    latest_version=TRAIL_LOCAL_VERSION,
                    is_up_to_date=True,
                    status_label="UP_TO_DATE",
                ),
            ),
            last_update_action="INITIALIZING",
        )

    def refresh(
        self,
        resolver: Optional[DnsResolver] = None,
        fetcher: Optional[HttpFetcher] = None,
        runner: Optional[CommandRunner] = None,
    ) -> SystemUpdateReport:
        """Execute a version check and optional auto-update, storing the report."""
        report = check_all_system_versions(
            self._config, resolver=resolver, fetcher=fetcher, runner=runner
        )
        if not report.all_up_to_date and self._config.auto_update_enabled:
            _, action_msg = apply_system_updates(
                self._config, resolver=resolver, runner=runner
            )
            report = SystemUpdateReport(
                checked_at=report.checked_at,
                all_up_to_date=report.all_up_to_date,
                components=report.components,
                last_update_action=f"AUTO_UPDATE ({action_msg})",
            )
        with self._lock:
            self._report = report
        return report

    def get_report(self) -> SystemUpdateReport:
        """Return the most recent immutable SystemUpdateReport."""
        with self._lock:
            return self._report


def main() -> int:
    """Daemon entrypoint for the trail-updater sidecar service."""
    workspace_root = Path(__file__).resolve().parent.parent
    config = load_config_from_env(workspace_root)
    monitor = TrailUpdateMonitor(config)

    for _ in range(MAX_UPDATE_CYCLES):
        report = monitor.refresh()
        sys.stderr.write(
            f"trail-updater: all_up_to_date={report.all_up_to_date} "
            f"action={report.last_update_action}\n"
        )
        time.sleep(float(config.update_check_interval_seconds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
