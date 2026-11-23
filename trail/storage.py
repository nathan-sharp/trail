"""SQLite FTS5 storage and BM25 ranking engine optimized for USB HDD I/O."""

from dataclasses import dataclass
from pathlib import Path
import sqlite3
import time
from typing import List, Tuple

from trail.security import sanitize_fts5_query

MAX_RESULTS_LIMIT: int = 50
MAX_QUEUE_BATCH: int = 500
MAX_TITLE_CHARS: int = 256
MAX_BODY_CHARS: int = 100000
MAX_SNIPPET_CHARS: int = 240

SCHEMA_SQL: str = """
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    snippet TEXT NOT NULL,
    crawled_at INTEGER NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    url,
    title,
    body,
    content='documents',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, url, title, body)
    VALUES (new.id, new.url, new.title, new.body);
END;

CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, url, title, body)
    VALUES ('delete', old.id, old.url, old.title, old.body);
END;

CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, url, title, body)
    VALUES ('delete', old.id, old.url, old.title, old.body);
    INSERT INTO documents_fts(rowid, url, title, body)
    VALUES (new.id, new.url, new.title, new.body);
END;

CREATE TABLE IF NOT EXISTS crawl_queue (
    url TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    depth INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'done', 'failed')),
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_queue_status_depth
ON crawl_queue(status, depth, updated_at);

CREATE TABLE IF NOT EXISTS domain_stats (
    domain TEXT PRIMARY KEY,
    pages_crawled INTEGER NOT NULL DEFAULT 0,
    last_crawled_at INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass(frozen=True)
class SearchResult:
    """Single full-text search hit."""

    url: str
    title: str
    snippet: str
    crawled_at: int
    score: float


@dataclass(frozen=True)
class QueueItem:
    """Single pending URL in the crawl queue."""

    url: str
    domain: str
    depth: int


class TrailStorage:
    """Deterministic SQLite FTS5 storage manager."""

    def __init__(self, db_path: Path) -> None:
        assert isinstance(db_path, Path), "db_path must be a Path"
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection configured with WAL and 64 MB page cache."""
        conn = sqlite3.connect(str(self._db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=-65536;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        """Initialize database tables, triggers, and indices."""
        conn = self._connect()
        try:
            with conn:
                conn.executescript(SCHEMA_SQL)
        finally:
            conn.close()

    def enqueue_url(
        self, url: str, domain: str, depth: int, max_depth: int
    ) -> bool:
        """Insert a URL into crawl_queue if within depth bounds and not present."""
        assert isinstance(url, str) and len(url) > 0, "url required"
        assert isinstance(domain, str) and len(domain) > 0, "domain required"
        assert isinstance(depth, int) and depth >= 0, "depth must be >= 0"
        if depth > max_depth:
            return False
        now_ts = int(time.time())
        conn = self._connect()
        try:
            with conn:
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO crawl_queue(url, domain, depth, status, updated_at)
                    VALUES (?, ?, ?, 'pending', ?)
                    """,
                    (url, domain, depth, now_ts),
                )
                return cur.rowcount > 0
        finally:
            conn.close()

    def fetch_pending_batch(
        self, batch_size: int, max_pages_per_domain: int, min_delay_seconds: int
    ) -> List[QueueItem]:
        """Fetch up to batch_size pending URLs respecting domain quotas and delay."""
        assert 1 <= batch_size <= MAX_QUEUE_BATCH, "batch_size out of bounds"
        assert max_pages_per_domain >= 1, "max_pages_per_domain must be >= 1"
        cutoff_ts = int(time.time()) - max(0, min_delay_seconds)
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT q.url, q.domain, q.depth
                FROM crawl_queue AS q
                LEFT JOIN domain_stats AS d ON q.domain = d.domain
                WHERE q.status = 'pending'
                  AND COALESCE(d.pages_crawled, 0) < ?
                  AND COALESCE(d.last_crawled_at, 0) <= ?
                ORDER BY q.depth ASC, q.updated_at ASC
                LIMIT ?
                """,
                (max_pages_per_domain, cutoff_ts, batch_size),
            ).fetchall()
        finally:
            conn.close()

        items: List[QueueItem] = []
        bound = min(len(rows), MAX_QUEUE_BATCH)
        for idx in range(bound):
            row = rows[idx]
            items.append(QueueItem(url=str(row[0]), domain=str(row[1]), depth=int(row[2])))
        return items

    def index_document(
        self, url: str, domain: str, title: str, body: str
    ) -> bool:
        """Upsert an indexed document and increment domain crawl metrics."""
        assert isinstance(url, str) and len(url) > 0, "url required"
        assert isinstance(domain, str) and len(domain) > 0, "domain required"
        clean_title = (title or url).strip()[:MAX_TITLE_CHARS]
        clean_body = (body or "").strip()[:MAX_BODY_CHARS]
        snippet = " ".join(clean_body.split())[:MAX_SNIPPET_CHARS]
        now_ts = int(time.time())

        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO documents(url, domain, title, body, snippet, crawled_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        domain=excluded.domain,
                        title=excluded.title,
                        body=excluded.body,
                        snippet=excluded.snippet,
                        crawled_at=excluded.crawled_at
                    """,
                    (url, domain, clean_title, clean_body, snippet, now_ts),
                )
                conn.execute(
                    """
                    UPDATE crawl_queue
                    SET status = 'done', updated_at = ?
                    WHERE url = ?
                    """,
                    (now_ts, url),
                )
                conn.execute(
                    """
                    INSERT INTO domain_stats(domain, pages_crawled, last_crawled_at)
                    VALUES (?, 1, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        pages_crawled = domain_stats.pages_crawled + 1,
                        last_crawled_at = excluded.last_crawled_at
                    """,
                    (domain, now_ts),
                )
            return True
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def mark_failed(self, url: str, domain: str) -> None:
        """Mark a queued URL as failed and record domain attempt timestamp."""
        assert isinstance(url, str) and len(url) > 0, "url required"
        assert isinstance(domain, str) and len(domain) > 0, "domain required"
        now_ts = int(time.time())
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    "UPDATE crawl_queue SET status = 'failed', updated_at = ? WHERE url = ?",
                    (now_ts, url),
                )
                conn.execute(
                    """
                    INSERT INTO domain_stats(domain, pages_crawled, last_crawled_at)
                    VALUES (?, 0, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        last_crawled_at = excluded.last_crawled_at
                    """,
                    (domain, now_ts),
                )
        finally:
            conn.close()

    def search(
        self, raw_query: str, page: int, per_page: int
    ) -> Tuple[bool, List[SearchResult], int]:
        """Execute parameterized FTS5 BM25 search with pagination."""
        assert 1 <= page <= 100, "page out of bounds"
        assert 1 <= per_page <= MAX_RESULTS_LIMIT, "per_page out of bounds"
        is_valid, _, fts_expr = sanitize_fts5_query(raw_query)
        if not is_valid:
            return (False, [], 0)
        if not fts_expr:
            return (True, [], 0)

        offset = (page - 1) * per_page
        conn = self._connect()
        try:
            count_row = conn.execute(
                "SELECT COUNT(*) FROM documents_fts WHERE documents_fts MATCH ?",
                (fts_expr,),
            ).fetchone()
            total = int(count_row[0]) if count_row else 0

            rows = conn.execute(
                """
                SELECT d.url, d.title, d.snippet, d.crawled_at,
                       bm25(documents_fts, 1.0, 10.0, 2.0) AS rank_score
                FROM documents_fts
                JOIN documents AS d ON d.id = documents_fts.rowid
                WHERE documents_fts MATCH ?
                ORDER BY rank_score ASC, d.id ASC
                LIMIT ? OFFSET ?
                """,
                (fts_expr, per_page, offset),
            ).fetchall()
        except sqlite3.Error:
            return (False, [], 0)
        finally:
            conn.close()

        results: List[SearchResult] = []
        bound = min(len(rows), MAX_RESULTS_LIMIT)
        for idx in range(bound):
            row = rows[idx]
            results.append(
                SearchResult(
                    url=str(row[0]),
                    title=str(row[1]),
                    snippet=str(row[2]),
                    crawled_at=int(row[3]),
                    score=float(row[4]),
                )
            )
        return (True, results, total)

    def get_index_counts(self) -> Tuple[int, int]:
        """Return (indexed_documents_count, pending_queue_count)."""
        conn = self._connect()
        try:
            doc_row = conn.execute("SELECT COUNT(*) FROM documents").fetchone()
            q_row = conn.execute(
                "SELECT COUNT(*) FROM crawl_queue WHERE status = 'pending'"
            ).fetchone()
            docs = int(doc_row[0]) if doc_row else 0
            pending = int(q_row[0]) if q_row else 0
            return (docs, pending)
        except sqlite3.Error:
            return (0, 0)
        finally:
            conn.close()
