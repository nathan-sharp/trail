"""Bounded open-hop web crawler with SSRF redirect guard and robots.txt parser."""

from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import urllib.robotparser

from trail.config import TrailConfig, load_seed_urls
from trail.security import DnsResolver, normalize_and_validate_url
from trail.storage import TrailStorage

MAX_HTML_BYTES: int = 1048576
MAX_ROBOTS_BYTES: int = 65536
MAX_EXTRACTED_LINKS: int = 200
MAX_TEXT_SEGMENTS: int = 5000
MAX_REDIRECT_HOPS: int = 3
MAX_ROBOTS_CACHE: int = 256
HTTP_TIMEOUT_SECONDS: int = 10
IGNORED_TAGS: Tuple[str, ...] = ("script", "style", "noscript", "svg", "template")


@dataclass(frozen=True)
class ParsedHtmlPage:
    """Extracted title, body text, and outlinks from an HTML document."""

    title: str
    body: str
    links: List[str]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirects so every hop passes SSRF validation."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BoundedHtmlExtractor(HTMLParser):
    """Non-recursive HTML 2.0/5 parser with fixed collection bounds."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title: bool = False
        self._ignored_depth: int = 0
        self._title_parts: List[str] = []
        self._text_parts: List[str] = []
        self._links: List[str] = []

    def handle_starttag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        lower_tag = tag.lower()
        if lower_tag in IGNORED_TAGS:
            self._ignored_depth += 1
            return
        if lower_tag == "title":
            self._in_title = True
            return
        if lower_tag == "a" and len(self._links) < MAX_EXTRACTED_LINKS:
            bound = min(len(attrs), 32)
            for idx in range(bound):
                attr_name, attr_val = attrs[idx]
                if attr_name and attr_name.lower() == "href" and attr_val:
                    self._links.append(attr_val.strip())
                    break

    def handle_endtag(self, tag: str) -> None:
        lower_tag = tag.lower()
        if lower_tag in IGNORED_TAGS and self._ignored_depth > 0:
            self._ignored_depth -= 1
            return
        if lower_tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._ignored_depth > 0:
            return
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self._in_title and len(self._title_parts) < 32:
            self._title_parts.append(cleaned)
        elif len(self._text_parts) < MAX_TEXT_SEGMENTS:
            self._text_parts.append(cleaned)

    def to_parsed_page(self, fallback_title: str) -> ParsedHtmlPage:
        """Assemble extracted segments into an immutable ParsedHtmlPage."""
        title_str = " ".join(self._title_parts).strip() or fallback_title
        body_str = " ".join(self._text_parts).strip()
        return ParsedHtmlPage(title=title_str, body=body_str, links=list(self._links))


def parse_html_document(raw_html: str, fallback_title: str) -> ParsedHtmlPage:
    """Extract title, plain text, and links from raw HTML within fixed bounds."""
    assert isinstance(raw_html, str), "raw_html must be a string"
    assert isinstance(fallback_title, str), "fallback_title must be a string"
    extractor = BoundedHtmlExtractor()
    try:
        extractor.feed(raw_html[:MAX_HTML_BYTES])
        extractor.close()
    except Exception:
        pass
    return extractor.to_parsed_page(fallback_title)


HttpFetcher = Callable[[str, str, int], Tuple[int, str, Dict[str, str], bytes]]


def default_http_fetcher(
    url: str, user_agent: str, max_bytes: int
) -> Tuple[int, str, Dict[str, str], bytes]:
    """Perform a single HTTP GET without automatic redirect following."""
    assert isinstance(url, str) and len(url) > 0, "url required"
    assert max_bytes > 0, "max_bytes must be positive"
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            status = int(resp.status)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            payload = resp.read(max_bytes)
            return (status, url, headers, payload)
    except urllib.error.HTTPError as err:
        headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        return (int(err.code), url, headers, b"")
    except (urllib.error.URLError, OSError, ValueError):
        return (0, url, {}, b"")


def fetch_url_safely(
    initial_url: str,
    user_agent: str,
    max_bytes: int,
    resolver: Optional[DnsResolver] = None,
    fetcher: Optional[HttpFetcher] = None,
) -> Tuple[bool, str, str, str]:
    """Fetch a URL enforcing SSRF validation across up to MAX_REDIRECT_HOPS hops.

    Returns (ok, final_url, final_domain, decoded_text).
    """
    active_fetcher = fetcher if fetcher is not None else default_http_fetcher
    current_url = initial_url

    for _ in range(MAX_REDIRECT_HOPS + 1):
        is_valid, norm_url, domain = normalize_and_validate_url(
            current_url, resolver=resolver
        )
        if not is_valid:
            return (False, "", "", "")

        status, _, headers, body_bytes = active_fetcher(norm_url, user_agent, max_bytes)
        if status in (301, 302, 303, 307, 308):
            location = headers.get("location", "").strip()
            if not location:
                return (False, "", "", "")
            ok_redir, next_url, _ = normalize_and_validate_url(
                location, base_url=norm_url, resolver=resolver
            )
            if not ok_redir:
                return (False, "", "", "")
            current_url = next_url
            continue

        if status != 200 or not body_bytes:
            return (False, norm_url, domain, "")

        content_type = headers.get("content-type", "text/html").lower()
        if "text/html" not in content_type and "text/plain" not in content_type:
            return (False, norm_url, domain, "")

        decoded = body_bytes.decode("utf-8", errors="replace")
        return (True, norm_url, domain, decoded)

    return (False, "", "", "")


class TrailCrawler:
    """Bounded open-hop crawler engine."""

    def __init__(
        self,
        config: TrailConfig,
        storage: TrailStorage,
        workspace_root: Path,
        resolver: Optional[DnsResolver] = None,
        fetcher: Optional[HttpFetcher] = None,
    ) -> None:
        self._config = config
        self._storage = storage
        self._workspace_root = workspace_root
        self._resolver = resolver
        self._fetcher = fetcher
        self._robots_cache: Dict[str, urllib.robotparser.RobotFileParser] = {}

    def load_seeds_into_queue(self) -> int:
        """Read config/seeds.txt, validate URLs, and insert at depth 0."""
        raw_seeds = load_seed_urls(self._config.seeds_path, self._workspace_root)
        added = 0
        bound = min(len(raw_seeds), 1000)
        for idx in range(bound):
            ok, norm_url, domain = normalize_and_validate_url(
                raw_seeds[idx], resolver=self._resolver
            )
            if ok and self._storage.enqueue_url(
                norm_url, domain, 0, self._config.max_hop_depth
            ):
                added += 1
        return added

    def _is_allowed_by_robots(self, url: str, domain: str) -> bool:
        """Verify RFC 9309 robots.txt permission for the target URL."""
        assert isinstance(url, str) and isinstance(domain, str), "invalid args"
        if domain not in self._robots_cache:
            if len(self._robots_cache) >= MAX_ROBOTS_CACHE:
                self._robots_cache.clear()
            rp = urllib.robotparser.RobotFileParser()
            robots_url = f"https://{domain}/robots.txt"
            ok, _, _, text = fetch_url_safely(
                robots_url,
                self._config.user_agent,
                MAX_ROBOTS_BYTES,
                resolver=self._resolver,
                fetcher=self._fetcher,
            )
            if ok and text:
                rp.parse(text.splitlines()[:1000])
            else:
                rp.parse([])
            self._robots_cache[domain] = rp
        return bool(self._robots_cache[domain].can_fetch(self._config.user_agent, url))

    def run_single_batch(self) -> int:
        """Execute one bounded crawl batch and return the number of indexed pages."""
        self.load_seeds_into_queue()
        batch = self._storage.fetch_pending_batch(
            self._config.crawl_batch_size,
            self._config.max_pages_per_domain,
            self._config.crawl_delay_seconds,
        )
        indexed_count = 0
        bound = min(len(batch), self._config.crawl_batch_size)
        for idx in range(bound):
            item = batch[idx]
            if not self._is_allowed_by_robots(item.url, item.domain):
                self._storage.mark_failed(item.url, item.domain)
                continue

            ok, final_url, final_domain, html_text = fetch_url_safely(
                item.url,
                self._config.user_agent,
                MAX_HTML_BYTES,
                resolver=self._resolver,
                fetcher=self._fetcher,
            )
            if not ok or not html_text:
                self._storage.mark_failed(item.url, item.domain)
                continue

            parsed = parse_html_document(html_text, fallback_title=final_url)
            if self._storage.index_document(
                final_url, final_domain, parsed.title, parsed.body
            ):
                indexed_count += 1
                if final_url != item.url:
                    self._storage.mark_failed(item.url, item.domain)
                self._enqueue_outlinks(final_url, parsed.links, item.depth + 1)
            else:
                self._storage.mark_failed(item.url, item.domain)
        return indexed_count

    def _enqueue_outlinks(
        self, base_url: str, raw_links: List[str], next_depth: int
    ) -> None:
        """Validate and enqueue discovered links for open-hop crawling."""
        if next_depth > self._config.max_hop_depth:
            return
        bound = min(len(raw_links), MAX_EXTRACTED_LINKS)
        for idx in range(bound):
            ok, norm_url, domain = normalize_and_validate_url(
                raw_links[idx], base_url=base_url, resolver=self._resolver
            )
            if ok:
                self._storage.enqueue_url(
                    norm_url, domain, next_depth, self._config.max_hop_depth
                )
