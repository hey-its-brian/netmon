"""Tests for log parsers."""

import unittest
from datetime import datetime

from src.parsers.pfsense import PfSenseParser


class TestPfSenseParser(unittest.TestCase):
    """Tests for pfSense filterlog parser."""

    def setUp(self):
        self.parser = PfSenseParser()

    def test_can_parse_filterlog(self):
        """Test detection of filterlog entries."""
        log = "<134>Jan 15 10:30:00 pfsense filterlog[12345]: 1,,,1000,em0,match,block,in,4,..."
        self.assertTrue(self.parser.can_parse(log))

    def test_cannot_parse_other_logs(self):
        """Test rejection of non-filterlog entries."""
        log = "<134>Jan 15 10:30:00 pfsense sshd[1234]: Connection from 10.0.0.1"
        self.assertFalse(self.parser.can_parse(log))

    def test_parse_tcp_block(self):
        """Test parsing a blocked TCP connection."""
        # Example pfSense filterlog format
        log = (
            "<134>Jan 15 10:30:00 pfsense filterlog[12345]: "
            "1,,,1000,em0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
            "192.168.1.100,10.0.0.1,54321,22,0,S,1234567890,,64240,,"
        )
        result = self.parser.parse(log, "10.0.0.1")

        self.assertIsNotNone(result)
        self.assertEqual(result.action, "block")
        self.assertEqual(result.protocol, "tcp")
        self.assertEqual(result.src_ip, "192.168.1.100")
        self.assertEqual(result.dst_ip, "10.0.0.1")
        self.assertEqual(result.src_port, 54321)
        self.assertEqual(result.dst_port, 22)
        self.assertEqual(result.direction, "in")
        self.assertEqual(result.interface, "em0")

    def test_parse_udp_pass(self):
        """Test parsing an allowed UDP connection."""
        log = (
            "<134>Jan 15 10:30:00 pfsense filterlog[12345]: "
            "2,,,2000,em1,match,pass,out,4,0x0,,64,12346,0,DF,17,udp,60,"
            "10.0.0.50,8.8.8.8,12345,53"
        )
        result = self.parser.parse(log, "10.0.0.1")

        self.assertIsNotNone(result)
        self.assertEqual(result.action, "pass")
        self.assertEqual(result.protocol, "udp")
        self.assertEqual(result.src_ip, "10.0.0.50")
        self.assertEqual(result.dst_ip, "8.8.8.8")
        self.assertEqual(result.dst_port, 53)
        self.assertEqual(result.direction, "out")

    def test_parse_invalid_log(self):
        """Test handling of malformed log entries."""
        log = "<134>Jan 15 10:30:00 pfsense filterlog[12345]: invalid,data"
        result = self.parser.parse(log, "10.0.0.1")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
