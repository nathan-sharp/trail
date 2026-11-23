"""IEEE 29119 Unit Test Suite for TRAIL following the strict Arrange-Act-Assert (AAA) pattern."""

import json
from pathlib import Path
import tempfile
from typing import Dict, List, Tuple
import unittest

from trail import __version__ as TRAIL_VERSION
from trail.config import (
    DEFAULT_TRAIL_REPO_URL,
    TrailConfig,
    load_config_from_env,
    validate_confined_path,
)
from trail.crawler import TrailCrawler, fetch_url_safely
from trail.disk import (
    MIN_USB_CAPACITY_BYTES,
    TRAIL_FS_LABEL,
    parse_lsblk_json,
    select_target_usb_partition,
    setup_external_drive,
)
from trail.security import (
    is_public_ip_address,
    normalize_and_validate_url,
    sanitize_fts5_query,
)
from trail.server import dispatch_get_request
from trail.storage import TrailStorage
from trail.updater import (
    TrailUpdateMonitor,
    apply_system_updates,
    check_all_system_versions,
    derive_github_release_api_url,
    format_njs_iso_version,
    is_version_up_to_date,
    parse_njs_iso_version,
)


def _stub_public_resolver(hostname: str, _port: int) -> List[str]:
    """Deterministic DNS stub returning a public IPv4 address for example domains."""
    mapping = {
        "example.com": ["93.184.215.14"],
        "ext.org": ["93.184.215.15"],
        "api.github.com": ["140.82.121.6"],
        "github.com": ["140.82.121.4"],
        "internal.corp": ["192.168.1.50"],
        "metadata.cloud": ["169.254.169.254"],
        "loop.back": ["127.0.0.1"],
    }
    return mapping.get(hostname, [])


def _sample_lsblk_json(
    usb_fstype: str = "exfat",
    usb_label: str = "",
    unpartitioned: bool = False,
) -> str:
    """Build a Raspberry Pi lsblk JSON payload with SD card, root disk, 64 GB USB, and 2 TB USB HDD."""
    usb_disk = {
        "name": "sdc",
        "path": "/dev/sdc",
        "size": 2000398934016,
        "type": "disk",
        "tran": "usb",
        "fstype": None if not unpartitioned else usb_fstype,
        "mountpoint": None,
        "uuid": None,
        "label": None if not unpartitioned else usb_label,
        "children": []
        if unpartitioned
        else [
            {
                "name": "sdc1",
                "path": "/dev/sdc1",
                "size": 2000397885440,
                "type": "part",
                "fstype": usb_fstype,
                "mountpoint": None,
                "uuid": "TRAIL-2TB-UUID",
                "label": usb_label,
            }
        ],
    }
    payload = {
        "blockdevices": [
            {
                "name": "mmcblk0",
                "path": "/dev/mmcblk0",
                "size": 64000000000,
                "type": "disk",
                "tran": "mmc",
                "fstype": None,
                "mountpoint": None,
                "uuid": None,
                "label": None,
                "children": [
                    {
                        "name": "mmcblk0p1",
                        "path": "/dev/mmcblk0p1",
                        "size": 536870912,
                        "type": "part",
                        "fstype": "vfat",
                        "mountpoint": "/boot/firmware",
                        "uuid": "BOOT-1234",
                        "label": "single-boot",
                    },
                    {
                        "name": "mmcblk0p2",
                        "path": "/dev/mmcblk0p2",
                        "size": 63000000000,
                        "type": "part",
                        "fstype": "ext4",
                        "mountpoint": "/",
                        "uuid": "ROOT-5678",
                        "label": "rootfs",
                    },
                ],
            },
            {
                "name": "sda",
                "path": "/dev/sda",
                "size": 1000000000000,
                "type": "disk",
                "tran": "usb",
                "fstype": None,
                "mountpoint": None,
                "uuid": None,
                "label": None,
                "children": [
                    {
                        "name": "sda1",
                        "path": "/dev/sda1",
                        "size": 1000000000000,
                        "type": "part",
                        "fstype": "ext4",
                        "mountpoint": "/var",
                        "uuid": "OS-VAR-999",
                        "label": "os-var",
                    }
                ],
            },
            {
                "name": "sdb",
                "path": "/dev/sdb",
                "size": 64000000000,
                "type": "disk",
                "tran": "usb",
                "fstype": None,
                "mountpoint": None,
                "uuid": None,
                "label": None,
                "children": [
                    {
                        "name": "sdb1",
                        "path": "/dev/sdb1",
                        "size": 64000000000,
                        "type": "part",
                        "fstype": "ext4",
                        "mountpoint": None,
                        "uuid": "SMALL-USB",
                        "label": "flash",
                    }
                ],
            },
            usb_disk,
        ]
    }
    return json.dumps(payload)


class TestTrailSecurity(unittest.TestCase):
    """Verify OWASP ASVS V4 SSRF defenses and ASVS V5 input validation."""

    def test_validate_confined_path_blocks_traversal(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            base_dir = Path(tmp)
            escaped_path = base_dir / ".." / "etc" / "passwd"

            # Act
            is_inside, _ = validate_confined_path(base_dir, escaped_path)

            # Assert
            self.assertFalse(is_inside)

    def test_is_public_ip_rejects_private_and_loopback_ranges(self) -> None:
        # Arrange
        non_public_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "0.0.0.0",
        ]

        # Act
        outcomes = [is_public_ip_address(ip) for ip in non_public_ips]
        public_outcome = is_public_ip_address("93.184.215.14")

        # Assert
        self.assertEqual(outcomes, [False] * len(non_public_ips))
        self.assertTrue(public_outcome)

    def test_normalize_and_validate_url_blocks_ssrf_targets(self) -> None:
        # Arrange
        ssrf_urls = [
            "http://localhost/admin",
            "http://127.0.0.1:8080/healthz",
            "http://internal.corp/secret",
            "http://metadata.cloud/latest/meta-data/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://example.com:8080/nonstandard-port",
        ]

        # Act
        results = [
            normalize_and_validate_url(u, resolver=_stub_public_resolver)[0]
            for u in ssrf_urls
        ]
        valid_ok, valid_url, valid_host = normalize_and_validate_url(
            "HTTPS://Example.COM/docs/../index.html#frag",
            resolver=_stub_public_resolver,
        )

        # Assert
        self.assertEqual(results, [False] * len(ssrf_urls))
        self.assertTrue(valid_ok)
        self.assertEqual(valid_url, "https://example.com/index.html")
        self.assertEqual(valid_host, "example.com")

    def test_fetch_url_safely_blocks_redirect_to_private_ip(self) -> None:
        # Arrange
        def _redirect_fetcher(
            url: str, _ua: str, _max_b: int
        ) -> Tuple[int, str, Dict[str, str], bytes]:
            if url == "https://example.com/start":
                return (
                    302,
                    url,
                    {"location": "http://internal.corp/admin"},
                    b"",
                )
            return (200, url, {"content-type": "text/html"}, b"<title>Secret</title>")

        # Act
        ok, final_url, _, body = fetch_url_safely(
            "https://example.com/start",
            "TRAIL/v2026",
            1024,
            resolver=_stub_public_resolver,
            fetcher=_redirect_fetcher,
        )

        # Assert
        self.assertFalse(ok)
        self.assertEqual(final_url, "")
        self.assertEqual(body, "")

    def test_sanitize_fts5_query_blocks_control_chars_and_formats_tokens(self) -> None:
        # Arrange
        valid_input = "retro netscape 1995"
        invalid_control_input = "retro\x00inject"

        # Act
        ok_valid, disp_valid, expr_valid = sanitize_fts5_query(valid_input)
        ok_bad, _, _ = sanitize_fts5_query(invalid_control_input)

        # Assert
        self.assertTrue(ok_valid)
        self.assertEqual(disp_valid, "retro netscape 1995")
        self.assertEqual(expr_valid, '"retro" AND "netscape" AND "1995"')
        self.assertFalse(ok_bad)


class TestTrailDiskAutomation(unittest.TestCase):
    """Verify USB disk auto-detection (>= 500 GB), automatic ext4 formatting, and idempotency."""

    def test_auto_detects_non_boot_usb_disk_500gb_or_greater(self) -> None:
        # Arrange
        disks = parse_lsblk_json(_sample_lsblk_json())

        # Act
        ok, selected, _ = select_target_usb_partition(
            disks, override_device="", min_capacity_bytes=MIN_USB_CAPACITY_BYTES
        )

        # Assert
        self.assertTrue(ok)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.path, "/dev/sdc1")
        self.assertEqual(selected.uuid, "TRAIL-2TB-UUID")

    def test_override_device_accepts_valid_usb_and_rejects_mmcblk_or_os_disk(self) -> None:
        # Arrange
        disks = parse_lsblk_json(_sample_lsblk_json())

        # Act
        ok_valid, part_valid, _ = select_target_usb_partition(
            disks, override_device="/dev/sdb1", min_capacity_bytes=MIN_USB_CAPACITY_BYTES
        )
        ok_mmc, _, _ = select_target_usb_partition(
            disks,
            override_device="/dev/mmcblk0p2",
            min_capacity_bytes=MIN_USB_CAPACITY_BYTES,
        )
        ok_os_var, _, _ = select_target_usb_partition(
            disks, override_device="/dev/sda1", min_capacity_bytes=MIN_USB_CAPACITY_BYTES
        )

        # Assert
        self.assertTrue(ok_valid)
        assert part_valid is not None
        self.assertEqual(part_valid.path, "/dev/sdb1")
        self.assertFalse(ok_mmc)
        self.assertFalse(ok_os_var)

    def test_setup_external_drive_auto_formats_uninitialized_drive_then_mounts(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp) / "usb-mount"
            executed_cmds: List[List[str]] = []

            def _mock_runner(cmd: List[str]) -> Tuple[int, str]:
                executed_cmds.append(cmd)
                return (0, "ok")

            # Act
            ok, reason = setup_external_drive(
                target_dir=target_dir,
                override_device="",
                min_capacity_bytes=MIN_USB_CAPACITY_BYTES,
                auto_format=True,
                lsblk_provider=lambda: _sample_lsblk_json(
                    usb_fstype="exfat", usb_label="FACTORY"
                ),
                runner=_mock_runner,
            )

            # Assert
            self.assertTrue(ok)
            self.assertIn("Formatted /dev/sdc1 as ext4 (TRAIL_DATA)", reason)
            self.assertEqual(
                executed_cmds,
                [
                    ["mkfs.ext4", "-F", "-L", TRAIL_FS_LABEL, "/dev/sdc1"],
                    ["mount", "/dev/sdc1", str(target_dir)],
                ],
            )

    def test_setup_external_drive_partitions_raw_unpartitioned_disk_and_formats(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp) / "usb-mount"
            executed_cmds: List[List[str]] = []

            def _mock_runner(cmd: List[str]) -> Tuple[int, str]:
                executed_cmds.append(cmd)
                return (0, "ok")

            # Act
            ok, _ = setup_external_drive(
                target_dir=target_dir,
                override_device="",
                min_capacity_bytes=MIN_USB_CAPACITY_BYTES,
                auto_format=True,
                lsblk_provider=lambda: _sample_lsblk_json(
                    usb_fstype="", usb_label="", unpartitioned=True
                ),
                runner=_mock_runner,
            )

            # Assert
            self.assertTrue(ok)
            self.assertEqual(
                executed_cmds,
                [
                    [
                        "parted",
                        "-s",
                        "/dev/sdc",
                        "mklabel",
                        "gpt",
                        "mkpart",
                        TRAIL_FS_LABEL,
                        "ext4",
                        "1MiB",
                        "100%",
                    ],
                    ["mkfs.ext4", "-F", "-L", TRAIL_FS_LABEL, "/dev/sdc1"],
                    ["mount", "/dev/sdc1", str(target_dir)],
                ],
            )

    def test_setup_external_drive_skips_formatting_when_already_labeled_trail_data(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp) / "usb-mount"
            executed_cmds: List[List[str]] = []

            def _mock_runner(cmd: List[str]) -> Tuple[int, str]:
                executed_cmds.append(cmd)
                return (0, "ok")

            # Act
            ok, reason = setup_external_drive(
                target_dir=target_dir,
                override_device="",
                min_capacity_bytes=MIN_USB_CAPACITY_BYTES,
                auto_format=True,
                lsblk_provider=lambda: _sample_lsblk_json(
                    usb_fstype="ext4", usb_label=TRAIL_FS_LABEL
                ),
                runner=_mock_runner,
            )

            # Assert
            self.assertTrue(ok)
            self.assertIn("Verified existing TRAIL_DATA ext4 volume", reason)
            self.assertEqual(
                executed_cmds,
                [["mount", "/dev/sdc1", str(target_dir)]],
            )


class TestTrailVersionAndAutoUpdate(unittest.TestCase):
    """Verify NJS ISO Timestamp Versioning (https://njs.dev/other/versioning/) and auto-updater."""

    def test_default_repo_and_initial_njs_iso_version(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # Act
            cfg = load_config_from_env(root)

            # Assert
            self.assertEqual(TRAIL_VERSION, "v2026")
            self.assertEqual(DEFAULT_TRAIL_REPO_URL, "https://github.com/nathan-sharp/trail")
            self.assertEqual(cfg.repo_url, "https://github.com/nathan-sharp/trail")

    def test_njs_iso_version_example_timeline_and_comparison(self) -> None:
        # Arrange
        priors_empty: List[str] = []
        priors_1990 = ["1989-03-12"]
        priors_1991_jul_09 = ["1989-03-12", "1990-11-12", "1991-03-15"]
        priors_1991_jul_14 = ["1989-03-12", "1990-11-12", "1991-03-15", "1991-07-15T09"]
        priors_1991_aug_01 = priors_1991_jul_14
        priors_1991_aug_06 = priors_1991_jul_14 + ["1991-08-01"]

        # Act
        _, v_1989 = format_njs_iso_version("1989-03-12", priors_empty)
        _, v_1990 = format_njs_iso_version("1990-11-12", priors_1990)
        _, v_1991_03 = format_njs_iso_version("1991-03-15", ["1991-07-15T09"])
        _, v_1991_07 = format_njs_iso_version("1991-07-15T09", priors_1991_jul_09)
        _, v_1991_07_15t14 = format_njs_iso_version("1991-07-15T14", priors_1991_jul_14)
        _, v_1991_08 = format_njs_iso_version("1991-08-01", priors_1991_aug_01)
        _, v_1991_08_06 = format_njs_iso_version("1991-08-06", priors_1991_aug_06)
        invalid_no_leading_zero, _, _ = parse_njs_iso_version("v1991-8-6")

        # Assert
        self.assertEqual(v_1989, "v1989")
        self.assertEqual(v_1990, "v1990")
        self.assertEqual(v_1991_03, "v1991-03")
        self.assertEqual(v_1991_07, "v1991-07")
        self.assertEqual(v_1991_07_15t14, "v1991-07-15T14")
        self.assertEqual(v_1991_08, "v1991-08")
        self.assertEqual(v_1991_08_06, "v1991-08-06")
        self.assertFalse(invalid_no_leading_zero)
        self.assertTrue(is_version_up_to_date("v2026", "v2025"))
        self.assertFalse(is_version_up_to_date("v2026", "v2026-12"))
        self.assertFalse(is_version_up_to_date("v1991-07", "v1991-07-15T14"))

    def test_check_all_system_versions_detects_outdated_njs_iso_version(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = TrailConfig(
                base_url="http://localhost:8080",
                db_path=root / "trail.db",
                seeds_path=root / "seeds.txt",
                host="127.0.0.1",
                port=8080,
                max_hop_depth=1,
                max_pages_per_domain=10,
                crawl_delay_seconds=1,
                crawl_batch_size=5,
                crawl_interval_seconds=30,
                results_per_page=10,
                user_agent="TRAIL/v2026",
            )

            def _mock_fetcher(
                url: str, _ua: str, _max_b: int
            ) -> Tuple[int, str, Dict[str, str], bytes]:
                if "nathan-sharp/trail" in url:
                    return (
                        200,
                        url,
                        {"content-type": "application/json"},
                        b'{"tag_name": "v2026-12"}',
                    )
                if "cloudflare/cloudflared" in url:
                    return (
                        200,
                        url,
                        {"content-type": "application/json"},
                        b'{"tag_name": "2026.11.0"}',
                    )
                return (404, url, {}, b"")

            def _mock_runner(cmd: List[str]) -> Tuple[int, str]:
                if cmd == ["apt-get", "-s", "upgrade"]:
                    return (0, "2 upgraded, 0 newly installed, 0 to remove.")
                return (0, "")

            # Act
            api_url = derive_github_release_api_url(config.repo_url)
            report = check_all_system_versions(
                config=config,
                installed_cloudflared="2024.11.1",
                resolver=_stub_public_resolver,
                fetcher=_mock_fetcher,
                runner=_mock_runner,
            )

            # Assert
            self.assertEqual(
                api_url,
                "https://api.github.com/repos/nathan-sharp/trail/releases/latest",
            )
            self.assertFalse(report.all_up_to_date)
            self.assertEqual(report.components[0].installed_version, "v2026")
            self.assertEqual(report.components[0].latest_version, "v2026-12")
            self.assertFalse(report.components[0].is_up_to_date)
            self.assertEqual(report.components[1].latest_version, "2026.11.0")
            self.assertFalse(report.components[1].is_up_to_date)
            self.assertEqual(report.components[2].installed_version, "2 pending")
            self.assertFalse(report.components[2].is_up_to_date)

    def test_update_monitor_triggers_auto_update_and_renders_html20_status(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = TrailConfig(
                base_url="http://localhost:8080",
                db_path=root / "trail.db",
                seeds_path=root / "seeds.txt",
                host="127.0.0.1",
                port=8080,
                max_hop_depth=1,
                max_pages_per_domain=10,
                crawl_delay_seconds=1,
                crawl_batch_size=5,
                crawl_interval_seconds=30,
                results_per_page=10,
                user_agent="TRAIL/v2026",
                auto_update_enabled=True,
            )
            storage = TrailStorage(config.db_path)
            monitor = TrailUpdateMonitor(config)
            executed_cmds: List[List[str]] = []

            def _mock_fetcher(
                url: str, _ua: str, _max_b: int
            ) -> Tuple[int, str, Dict[str, str], bytes]:
                return (
                    200,
                    url,
                    {"content-type": "application/json"},
                    b'{"tag_name": "v2026-12-01"}',
                )

            def _mock_runner(cmd: List[str]) -> Tuple[int, str]:
                executed_cmds.append(cmd)
                if cmd == ["apt-get", "-s", "upgrade"]:
                    return (0, "1 upgraded, 0 newly installed.")
                return (0, "ok")

            # Act
            monitor.refresh(
                resolver=_stub_public_resolver,
                fetcher=_mock_fetcher,
                runner=_mock_runner,
            )
            status_code, _, html_bytes = dispatch_get_request(
                "/status", config, storage, monitor
            )
            html_text = html_bytes.decode("utf-8")

            # Assert
            self.assertEqual(status_code, 200)
            self.assertIn('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">', html_text)
            self.assertIn("UPDATE_AVAILABLE", html_text)
            self.assertIn("v2026-12-01", html_text)
            self.assertIn("AUTO_UPDATE (git:ok, apt:upgraded)", html_text)
            self.assertIn(
                ["git", "pull", "--ff-only", "https://github.com/nathan-sharp/trail"],
                executed_cmds,
            )

    def test_apply_system_updates_blocks_ssrf_repo_url(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = TrailConfig(
                base_url="http://localhost:8080",
                db_path=root / "trail.db",
                seeds_path=root / "seeds.txt",
                host="127.0.0.1",
                port=8080,
                max_hop_depth=1,
                max_pages_per_domain=10,
                crawl_delay_seconds=1,
                crawl_batch_size=5,
                crawl_interval_seconds=30,
                results_per_page=10,
                user_agent="TRAIL/v2026",
                repo_url="http://internal.corp/trail.git",
                auto_update_enabled=True,
            )

            # Act
            ok, msg = apply_system_updates(
                config, resolver=_stub_public_resolver, runner=lambda _c: (0, "")
            )

            # Assert
            self.assertFalse(ok)
            self.assertIn("Blocked invalid or non-public TRAIL_REPO_URL", msg)


class TestTrailStorageAndCrawler(unittest.TestCase):
    """Verify SQLite FTS5 indexing, BM25 ranking, and open-hop crawling."""

    def test_storage_bm25_ranking_orders_title_match_first(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            storage = TrailStorage(db_path)
            storage.index_document(
                "https://example.com/body-only",
                "example.com",
                "General Computing Archive",
                "This document mentions netscape browser once in the body.",
            )
            storage.index_document(
                "https://example.com/title-hit",
                "example.com",
                "Netscape Navigator HTML 2.0 Specification",
                "Netscape Navigator supports RFC 1866 HTML 2.0 forms.",
            )

            # Act
            ok, hits, total = storage.search("netscape", page=1, per_page=10)

            # Assert
            self.assertTrue(ok)
            self.assertEqual(total, 2)
            self.assertEqual(len(hits), 2)
            self.assertEqual(hits[0].url, "https://example.com/title-hit")

    def test_crawler_respects_robots_and_follows_open_hop_within_depth(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds_file = root / "config" / "seeds.txt"
            seeds_file.parent.mkdir(parents=True, exist_ok=True)
            seeds_file.write_text("https://example.com/index.html\n", encoding="utf-8")

            config = TrailConfig(
                base_url="http://localhost:8080",
                db_path=root / "data" / "trail.db",
                seeds_path=seeds_file,
                host="127.0.0.1",
                port=8080,
                max_hop_depth=1,
                max_pages_per_domain=10,
                crawl_delay_seconds=0,
                crawl_batch_size=10,
                crawl_interval_seconds=30,
                results_per_page=10,
                user_agent="TRAIL/v2026",
            )
            storage = TrailStorage(config.db_path)

            pages: Dict[str, bytes] = {
                "https://example.com/robots.txt": b"User-agent: *\nDisallow: /private.html\n",
                "https://ext.org/robots.txt": b"User-agent: *\nAllow: /\n",
                "https://example.com/index.html": (
                    b"<HTML><HEAD><TITLE>Seed Home</TITLE></HEAD><BODY>"
                    b"Welcome to TRAIL seed page. "
                    b'<A HREF="/private.html">Blocked</A>'
                    b'<A HREF="https://ext.org/hop1.html">External Hop 1</A>'
                    b"</BODY></HTML>"
                ),
                "https://ext.org/hop1.html": (
                    b"<HTML><HEAD><TITLE>External Hop One</TITLE></HEAD><BODY>"
                    b"Hop one content across domain boundary. "
                    b'<A HREF="https://ext.org/hop2.html">Too Deep Hop 2</A>'
                    b"</BODY></HTML>"
                ),
                "https://ext.org/hop2.html": b"<HTML><TITLE>Should Not Crawl</TITLE></HTML>",
            }

            def _mock_fetcher(
                url: str, _ua: str, _max_b: int
            ) -> Tuple[int, str, Dict[str, str], bytes]:
                if url in pages:
                    return (200, url, {"content-type": "text/html"}, pages[url])
                return (404, url, {}, b"")

            crawler = TrailCrawler(
                config=config,
                storage=storage,
                workspace_root=root,
                resolver=_stub_public_resolver,
                fetcher=_mock_fetcher,
            )

            # Act
            batch_one_indexed = crawler.run_single_batch()
            batch_two_indexed = crawler.run_single_batch()
            docs_count, pending_count = storage.get_index_counts()
            ok_search, hop_hits, _ = storage.search("boundary", page=1, per_page=10)

            # Assert
            self.assertEqual(batch_one_indexed, 1)
            self.assertEqual(batch_two_indexed, 1)
            self.assertEqual(docs_count, 2)
            self.assertEqual(pending_count, 0)
            self.assertTrue(ok_search)
            self.assertEqual(len(hop_hits), 1)
            self.assertEqual(hop_hits[0].url, "https://ext.org/hop1.html")


class TestTrailHtml20AndOpenSearch(unittest.TestCase):
    """Verify RFC 1866 HTML 2.0 compliance, XSS encoding, and OpenSearch 1.1 output."""

    def test_html20_output_excludes_css_and_js_and_escapes_xss(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = TrailConfig(
                base_url="https://search.example.org",
                db_path=root / "trail.db",
                seeds_path=root / "seeds.txt",
                host="127.0.0.1",
                port=8080,
                max_hop_depth=1,
                max_pages_per_domain=10,
                crawl_delay_seconds=1,
                crawl_batch_size=5,
                crawl_interval_seconds=30,
                results_per_page=10,
                user_agent="TRAIL/v2026",
            )
            storage = TrailStorage(config.db_path)
            storage.index_document(
                "https://example.com/xss",
                "example.com",
                "<script>alert(1)</script>Retro computing",
                "Body with <b>tags</b> and retro text.",
            )

            # Act
            status, headers, body_bytes = dispatch_get_request(
                "/search?q=retro&page=1", config, storage
            )
            body_text = body_bytes.decode("utf-8")

            # Assert
            self.assertEqual(status, 200)
            self.assertIn('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">', body_text)
            self.assertNotIn("<script>", body_text.lower())
            self.assertNotIn("<style", body_text.lower())
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body_text)
            self.assertIn("TRAIL v2026 [UP_TO_DATE]", body_text)
            self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_opensearch_xml_endpoint_conforms_to_1_1_spec(self) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = TrailConfig(
                base_url="https://trail.example.org",
                db_path=root / "trail.db",
                seeds_path=root / "seeds.txt",
                host="127.0.0.1",
                port=8080,
                max_hop_depth=1,
                max_pages_per_domain=10,
                crawl_delay_seconds=1,
                crawl_batch_size=5,
                crawl_interval_seconds=30,
                results_per_page=10,
                user_agent="TRAIL/v2026",
            )
            storage = TrailStorage(config.db_path)

            # Act
            status, headers, xml_bytes = dispatch_get_request(
                "/opensearch.xml", config, storage
            )
            xml_text = xml_bytes.decode("utf-8")

            # Assert
            self.assertEqual(status, 200)
            self.assertEqual(
                headers["Content-Type"],
                "application/opensearchdescription+xml; charset=utf-8",
            )
            self.assertIn(
                'xmlns="http://a9.com/-/spec/opensearch/1.1/"',
                xml_text,
            )
            self.assertIn(
                'template="https://trail.example.org/search?q={searchTerms}&amp;page={startPage?}"',
                xml_text,
            )


if __name__ == "__main__":
    unittest.main()
