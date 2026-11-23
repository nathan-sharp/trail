"""RFC 1866 HTML 2.0 and OpenSearch 1.1 HTTP server with zero CSS or JS."""

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote_plus, urlparse

from trail import __version__ as TRAIL_VERSION
from trail.config import TrailConfig
from trail.storage import SearchResult, TrailStorage
from trail.updater import SystemUpdateReport, TrailUpdateMonitor

MAX_RENDERED_RESULTS: int = 50
MAX_PAGE_NUMBER: int = 100
MAX_COMPONENTS_DISPLAY: int = 16


def _escape_html(text: str) -> str:
    """Apply context-aware HTML entity encoding."""
    assert isinstance(text, str), "text must be a string"
    return html.escape(text, quote=True)


def _safe_href(url: str) -> str:
    """Guarantee rendered anchor href starts with http:// or https://."""
    assert isinstance(url, str), "url must be a string"
    lower = url.lower().strip()
    if lower.startswith("http://") or lower.startswith("https://"):
        return _escape_html(url.strip())
    return "#"


def render_opensearch_xml(base_url: str) -> str:
    """Render an OpenSearch 1.1 description XML document."""
    assert isinstance(base_url, str) and len(base_url) > 0, "base_url required"
    safe_base = _escape_html(base_url.rstrip("/"))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">\n'
        "  <ShortName>TRAIL</ShortName>\n"
        "  <Description>TRAIL (Text Retrieval and Automated Indexing Library)</Description>\n"
        "  <InputEncoding>UTF-8</InputEncoding>\n"
        "  <OutputEncoding>UTF-8</OutputEncoding>\n"
        f'  <Url type="text/html" method="get" '
        f'template="{safe_base}/search?q={{searchTerms}}&amp;page={{startPage?}}"/>\n'
        "</OpenSearchDescription>\n"
    )


def _render_result_list(results: List[SearchResult]) -> str:
    """Render search results inside an HTML 2.0 <DL> definition list."""
    assert isinstance(results, list), "results must be a list"
    if not results:
        return "<P>No matching documents found.</P>\n"
    lines: List[str] = ["<DL>\n"]
    bound = min(len(results), MAX_RENDERED_RESULTS)
    for idx in range(bound):
        item = results[idx]
        href = _safe_href(item.url)
        title = _escape_html(item.title or item.url)
        snippet = _escape_html(item.snippet)
        display_url = _escape_html(item.url)
        lines.append(f'  <DT><B><A HREF="{href}">{title}</A></B></DT>\n')
        lines.append(f"  <DD>{snippet}<BR>\n")
        lines.append(f"  URL: {display_url}</DD>\n")
    lines.append("</DL>\n")
    return "".join(lines)


def _render_pagination(query: str, page: int, per_page: int, total: int) -> str:
    """Render HTML 2.0 anchor links for previous and next result pages."""
    if total <= per_page:
        return ""
    encoded_q = quote_plus(query)
    nav_parts: List[str] = ["<P>Page Navigation: "]
    if page > 1:
        prev_p = page - 1
        nav_parts.append(f'<A HREF="/search?q={encoded_q}&amp;page={prev_p}">[Previous]</A> ')
    nav_parts.append(f"<B>Page {page}</B> ")
    if page * per_page < total and page < MAX_PAGE_NUMBER:
        next_p = page + 1
        nav_parts.append(f'<A HREF="/search?q={encoded_q}&amp;page={next_p}">[Next]</A>')
    nav_parts.append("</P>\n")
    return "".join(nav_parts)


def render_html20_status_page(report: SystemUpdateReport) -> str:
    """Render an RFC 1866 HTML 2.0 system version report without status brackets."""
    assert isinstance(report, SystemUpdateReport), "report required"
    action = _escape_html(report.last_update_action)
    lines: List[str] = [
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n',
        "<HTML>\n<HEAD>\n<TITLE>TRAIL System Version Status</TITLE>\n</HEAD>\n<BODY>\n",
        "<H1>TRAIL System Version Status</H1>\n",
        f"<P>Last Action: {action}</P>\n",
        "<HR>\n<DL>\n",
    ]
    bound = min(len(report.components), MAX_COMPONENTS_DISPLAY)
    for idx in range(bound):
        comp = report.components[idx]
        c_name = _escape_html(comp.name)
        c_inst = _escape_html(comp.installed_version)
        c_lat = _escape_html(comp.latest_version)
        lines.append(f"  <DT><B>{c_name}</B></DT>\n")
        lines.append(
            f"  <DD>Installed Version: {c_inst} | Latest Version: {c_lat}</DD>\n"
        )
    lines.append("</DL>\n<HR>\n")
    lines.append('<P><A HREF="/">Return to TRAIL Search</A></P>\n</BODY>\n</HTML>\n')
    return "".join(lines)


def render_html20_search_page(
    query: str,
    page: int,
    per_page: int,
    total_hits: int,
    results: List[SearchResult],
    indexed_docs: int,
    pending_queue: int,
    error_message: str = "",
) -> str:
    """Render a strict RFC 1866 HTML 2.0 search interface without CSS or JS."""
    safe_q = _escape_html(query)
    safe_ver = _escape_html(TRAIL_VERSION)
    header = (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        "<HTML>\n"
        "<HEAD>\n"
        "<TITLE>TRAIL Search Engine</TITLE>\n"
        '<LINK REL="search" TYPE="application/opensearchdescription+xml" '
        'TITLE="TRAIL Search" HREF="/opensearch.xml">\n'
        "</HEAD>\n"
        "<BODY>\n"
        "<H1>TRAIL</H1>\n"
        "<P>Text Retrieval &amp; Automated Indexing Library</P>\n"
        '<FORM ACTION="/search" METHOD="GET">\n'
        "<P>Query: "
        f'<INPUT TYPE="text" NAME="q" SIZE="40" MAXLENGTH="200" VALUE="{safe_q}"> '
        '<INPUT TYPE="submit" VALUE="Search"></P>\n'
        "</FORM>\n"
        "<HR>\n"
    )
    body_section = ""
    if error_message:
        safe_err = _escape_html(error_message)
        body_section = f"<P><B>Error:</B> {safe_err}</P>\n"
    elif query.strip():
        body_section = (
            f"<P>Results for <B>{safe_q}</B>: {total_hits} documents found "
            f"(Page {page}).</P>\n"
            + _render_result_list(results)
            + _render_pagination(query, page, per_page, total_hits)
        )
    else:
        body_section = "<P>Enter search terms above and press Search.</P>\n"

    ver_label = safe_ver if safe_ver.startswith("v") else f"v{safe_ver}"
    footer = (
        "<HR>\n"
        f"<P>TRAIL {ver_label} | "
        f"Index Status: {indexed_docs} documents indexed | "
        f"{pending_queue} URLs queued | "
        '<A HREF="/status">Version Status</A> | '
        '<A HREF="/opensearch.xml">OpenSearch 1.1 XML</A></P>\n'
        "</BODY>\n"
        "</HTML>\n"
    )
    return header + body_section + footer


def parse_page_param(raw_values: List[str]) -> Tuple[bool, int]:
    """Validate the 'page' query parameter as an integer in [1, MAX_PAGE_NUMBER]."""
    if not raw_values:
        return (True, 1)
    raw = raw_values[0].strip()
    if not raw:
        return (True, 1)
    try:
        val = int(raw)
    except ValueError:
        return (False, 1)
    if val < 1 or val > MAX_PAGE_NUMBER:
        return (False, 1)
    return (True, val)


def dispatch_get_request(
    request_target: str,
    config: TrailConfig,
    storage: TrailStorage,
    update_monitor: Optional[TrailUpdateMonitor] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    """Pure HTTP GET dispatcher returning (status_code, headers, body_bytes)."""
    assert isinstance(request_target, str), "request_target must be a string"
    parsed = urlparse(request_target)
    path = parsed.path or "/"

    base_headers: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
    }

    if path == "/healthz":
        headers = dict(base_headers)
        headers["Content-Type"] = "text/plain; charset=us-ascii"
        return (200, headers, b"OK\n")

    if path == "/opensearch.xml":
        xml_body = render_opensearch_xml(config.base_url).encode("utf-8")
        headers = dict(base_headers)
        headers["Content-Type"] = "application/opensearchdescription+xml; charset=utf-8"
        return (200, headers, xml_body)

    active_monitor = (
        update_monitor if update_monitor is not None else TrailUpdateMonitor(config)
    )
    report = active_monitor.get_report()

    if path == "/status":
        status_html = render_html20_status_page(report).encode("utf-8")
        headers = dict(base_headers)
        headers["Content-Type"] = "text/html; charset=utf-8"
        return (200, headers, status_html)

    if path not in ("/", "/search"):
        docs, pending = storage.get_index_counts()
        not_found = render_html20_search_page(
            "",
            1,
            config.results_per_page,
            0,
            [],
            docs,
            pending,
            "Path not found.",
        ).encode("utf-8")
        headers = dict(base_headers)
        headers["Content-Type"] = "text/html; charset=utf-8"
        return (404, headers, not_found)

    params = parse_qs(parsed.query, keep_blank_values=True)
    raw_q = params.get("q", [""])[0]
    page_ok, page_num = parse_page_param(params.get("page", []))
    docs, pending = storage.get_index_counts()

    if not page_ok:
        bad_page = render_html20_search_page(
            raw_q[:200],
            1,
            config.results_per_page,
            0,
            [],
            docs,
            pending,
            "Page parameter must be an integer between 1 and 100.",
        ).encode("utf-8")
        headers = dict(base_headers)
        headers["Content-Type"] = "text/html; charset=utf-8"
        return (400, headers, bad_page)

    if not raw_q.strip():
        home_body = render_html20_search_page(
            "", 1, config.results_per_page, 0, [], docs, pending
        ).encode("utf-8")
        headers = dict(base_headers)
        headers["Content-Type"] = "text/html; charset=utf-8"
        return (200, headers, home_body)

    ok_q, results, total = storage.search(raw_q, page_num, config.results_per_page)
    if not ok_q:
        bad_q = render_html20_search_page(
            "",
            1,
            config.results_per_page,
            0,
            [],
            docs,
            pending,
            "Query contains invalid characters or exceeds 200 characters.",
        ).encode("utf-8")
        headers = dict(base_headers)
        headers["Content-Type"] = "text/html; charset=utf-8"
        return (400, headers, bad_q)

    html_body = render_html20_search_page(
        raw_q.strip(),
        page_num,
        config.results_per_page,
        total,
        results,
        docs,
        pending,
    ).encode("utf-8")
    headers = dict(base_headers)
    headers["Content-Type"] = "text/html; charset=utf-8"
    return (200, headers, html_body)


class TrailHttpHandler(BaseHTTPRequestHandler):
    """Privacy-preserving HTTP/1.0 and HTTP/1.1 request handler."""

    protocol_version = "HTTP/1.0"
    trail_config: TrailConfig
    trail_storage: TrailStorage
    trail_update_monitor: Optional[TrailUpdateMonitor] = None

    def log_message(self, format: str, *args) -> None:
        """Disable client IP and search query logging (revDSG/GDPR compliance)."""
        return

    def do_GET(self) -> None:
        """Handle HTTP GET requests with fail-closed error handling."""
        try:
            status, headers, payload = dispatch_get_request(
                self.path,
                self.trail_config,
                self.trail_storage,
                self.trail_update_monitor,
            )
            self.send_response(status)
            for key, val in headers.items():
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception:
            fallback = (
                b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'
                b"<HTML><HEAD><TITLE>Error</TITLE></HEAD>"
                b"<BODY><H1>500 Internal Server Error</H1></BODY></HTML>\n"
            )
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(fallback)))
            self.end_headers()
            self.wfile.write(fallback)

    def do_HEAD(self) -> None:
        """Handle HTTP HEAD requests identically to GET without body."""
        try:
            status, headers, payload = dispatch_get_request(
                self.path,
                self.trail_config,
                self.trail_storage,
                self.trail_update_monitor,
            )
            self.send_response(status)
            for key, val in headers.items():
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
        except Exception:
            self.send_response(500)
            self.end_headers()


def create_http_server(
    config: TrailConfig,
    storage: TrailStorage,
    update_monitor: Optional[TrailUpdateMonitor] = None,
) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer instance."""

    class _BoundHandler(TrailHttpHandler):
        trail_config = config
        trail_storage = storage
        trail_update_monitor = update_monitor

    return ThreadingHTTPServer((config.host, config.port), _BoundHandler)
