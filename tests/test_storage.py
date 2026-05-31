"""Tests for storage options (retention, store_raw)."""

import os
import tempfile
import unittest
from datetime import datetime

from src.parsers.base import ParsedLog
from src.storage.database import Database


def _log(raw="126,,,1,igb1,match,block,in,4,...,192.168.1.5,8.8.8.8,1,53,0"):
    return ParsedLog(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        source_ip="10.0.0.1",
        log_type="filterlog",
        action="block",
        protocol="udp",
        src_ip="192.168.1.5",
        src_port=1234,
        dst_ip="8.8.8.8",
        dst_port=53,
        interface="igb1",
        direction="in",
        raw=raw,
    )


class TestStoreRaw(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def _stored_raw(self, store_raw):
        db = Database(self.path, retention_days=30, store_raw=store_raw)
        db.store_log(_log())
        with db._cursor() as cur:
            cur.execute("SELECT raw FROM logs ORDER BY id DESC LIMIT 1")
            return cur.fetchone()[0]

    def test_raw_kept_by_default(self):
        self.assertIn("8.8.8.8", self._stored_raw(True))

    def test_raw_dropped_when_disabled(self):
        self.assertEqual(self._stored_raw(False), "")

    def test_other_fields_still_stored_without_raw(self):
        db = Database(self.path, store_raw=False)
        db.store_log(_log())
        with db._cursor() as cur:
            cur.execute("SELECT src_ip, dst_ip, dst_port, raw FROM logs LIMIT 1")
            row = cur.fetchone()
        self.assertEqual((row[0], row[1], row[2], row[3]), ("192.168.1.5", "8.8.8.8", 53, ""))


if __name__ == "__main__":
    unittest.main()
