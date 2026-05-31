import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional

from ..parsers.base import ParsedLog


class Database:
    """SQLite storage for parsed logs and baselines."""

    def __init__(self, db_path: str, retention_days: int = 30):
        self.db_path = db_path
        self.retention_days = retention_days
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "connection"):
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._local.connection = sqlite3.connect(self.db_path)
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        """Context manager for database cursor."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source_ip TEXT NOT NULL,
                    log_type TEXT NOT NULL,
                    action TEXT,
                    protocol TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    interface TEXT,
                    direction TEXT,
                    raw TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_timestamp
                ON logs(timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_src_ip
                ON logs(src_ip)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_action
                ON logs(action)
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    hour_of_day INTEGER,
                    day_of_week INTEGER,
                    mean REAL NOT NULL,
                    std_dev REAL NOT NULL,
                    sample_count INTEGER NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(metric_name, hour_of_day, day_of_week)
                )
            """)

    def store_log(self, log: ParsedLog) -> int:
        """Store a parsed log entry."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO logs (
                    timestamp, source_ip, log_type, action, protocol,
                    src_ip, src_port, dst_ip, dst_port, interface, direction, raw
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log.timestamp.isoformat(),
                log.source_ip,
                log.log_type,
                log.action,
                log.protocol,
                log.src_ip,
                log.src_port,
                log.dst_ip,
                log.dst_port,
                log.interface,
                log.direction,
                log.raw,
            ))
            return cursor.lastrowid

    def get_blocks_by_ip(self, src_ip: str, minutes: int = 1) -> int:
        """Count blocked connections from an IP in the last N minutes."""
        since = datetime.now() - timedelta(minutes=minutes)
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) FROM logs
                WHERE src_ip = ? AND action = 'block' AND timestamp > ?
            """, (src_ip, since.isoformat()))
            return cursor.fetchone()[0]

    def get_ports_hit_by_ip(self, src_ip: str, seconds: int = 60) -> list[int]:
        """Get unique destination ports hit by an IP in the last N seconds."""
        since = datetime.now() - timedelta(seconds=seconds)
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT DISTINCT dst_port FROM logs
                WHERE src_ip = ? AND dst_port IS NOT NULL AND timestamp > ?
            """, (src_ip, since.isoformat()))
            return [row[0] for row in cursor.fetchall()]

    def get_hourly_stats(self, hours: int = 1) -> dict:
        """Get statistics for the last N hours."""
        since = datetime.now() - timedelta(hours=hours)
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN action = 'pass' THEN 1 ELSE 0 END) as passed
                FROM logs WHERE timestamp > ?
            """, (since.isoformat(),))
            row = cursor.fetchone()
            return {
                "total": row[0] or 0,
                "blocked": row[1] or 0,
                "passed": row[2] or 0,
            }

    def get_top_sources(self, hours: int = 1, limit: int = 10) -> list[tuple[str, int]]:
        """Get top source IPs by connection count."""
        since = datetime.now() - timedelta(hours=hours)
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT src_ip, COUNT(*) as count
                FROM logs
                WHERE timestamp > ? AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
            """, (since.isoformat(), limit))
            return [(row[0], row[1]) for row in cursor.fetchall()]

    def get_protocol_distribution(self, hours: int = 1) -> dict[str, int]:
        """Get protocol distribution for the last N hours."""
        since = datetime.now() - timedelta(hours=hours)
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM logs
                WHERE timestamp > ? AND protocol IS NOT NULL
                GROUP BY protocol
            """, (since.isoformat(),))
            return {row[0]: row[1] for row in cursor.fetchall()}

    def save_baseline(
        self,
        metric_name: str,
        mean: float,
        std_dev: float,
        sample_count: int,
        hour_of_day: Optional[int] = None,
        day_of_week: Optional[int] = None,
    ) -> None:
        """Save or update a baseline metric."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO baselines (metric_name, hour_of_day, day_of_week, mean, std_dev, sample_count)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(metric_name, hour_of_day, day_of_week)
                DO UPDATE SET mean = ?, std_dev = ?, sample_count = ?, updated_at = CURRENT_TIMESTAMP
            """, (
                metric_name, hour_of_day, day_of_week, mean, std_dev, sample_count,
                mean, std_dev, sample_count
            ))

    def get_baseline(
        self,
        metric_name: str,
        hour_of_day: Optional[int] = None,
        day_of_week: Optional[int] = None,
    ) -> Optional[dict]:
        """Get a baseline metric."""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT mean, std_dev, sample_count FROM baselines
                WHERE metric_name = ? AND hour_of_day IS ? AND day_of_week IS ?
            """, (metric_name, hour_of_day, day_of_week))
            row = cursor.fetchone()
            if row:
                return {"mean": row[0], "std_dev": row[1], "sample_count": row[2]}
            return None

    def get_first_log_timestamp(self) -> Optional[datetime]:
        """Get the timestamp of the first log entry."""
        with self._cursor() as cursor:
            cursor.execute("SELECT MIN(timestamp) FROM logs")
            row = cursor.fetchone()
            if row and row[0]:
                return datetime.fromisoformat(row[0])
            return None

    def cleanup_old_logs(self) -> int:
        """Remove logs older than retention period."""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        with self._cursor() as cursor:
            cursor.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff.isoformat(),))
            return cursor.rowcount
