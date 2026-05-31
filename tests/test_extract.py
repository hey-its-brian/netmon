"""Tests for the pfSense extract command and the rules.yaml round trip."""

import os
import tempfile
import unittest
from datetime import datetime

from src.detection.correlation import CorrelationDetector
from src.parsers.base import ParsedLog
from src.ruleset.pfsense import (
    parse_pfsense_aliases,
    parse_pfsense_interfaces,
    parse_pfsense_rules,
)
from src.ruleset.yaml_io import dump_ruleset, load_ruleset
from src.tools.extract_pfsense import main as extract_main

SAMPLE_CONFIG = os.path.join(
    os.path.dirname(__file__), "..", "samples", "example_config.xml"
)


def _log(action, protocol, src_ip, dst_ip, dst_port, interface="igb1.20"):
    return ParsedLog(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        source_ip="10.0.0.1",
        log_type="filterlog",
        action=action,
        protocol=protocol,
        src_ip=src_ip,
        src_port=12345,
        dst_ip=dst_ip,
        dst_port=dst_port,
        interface=interface,
        direction="in",
        raw="",
    )


class TestExtractRoundTrip(unittest.TestCase):
    def setUp(self):
        fd, self.out = tempfile.mkstemp(suffix=".yaml")
        os.close(fd)

    def tearDown(self):
        if os.path.exists(self.out):
            os.remove(self.out)

    def test_extract_command_writes_ruleset(self):
        self.assertEqual(extract_main([SAMPLE_CONFIG, "-o", self.out]), 0)
        rules, ifaces, aliases = load_ruleset(self.out)
        self.assertEqual(len(rules), 4)
        self.assertEqual(ifaces["opt1"]["device"], "igb1.20")
        self.assertEqual(aliases["DNS_Servers"]["type"], "host")

    def test_yaml_round_trip_preserves_everything(self):
        rules = parse_pfsense_rules(SAMPLE_CONFIG)
        ifaces = parse_pfsense_interfaces(SAMPLE_CONFIG)
        aliases = parse_pfsense_aliases(SAMPLE_CONFIG)
        dump_ruleset(rules, ifaces, aliases, self.out)
        r2, i2, a2 = load_ruleset(self.out)
        self.assertEqual(i2, ifaces)
        self.assertEqual(a2, aliases)
        self.assertEqual([r.__dict__ for r in r2], [r.__dict__ for r in rules])

    def test_correlation_via_ruleset_path_matches_xml_path(self):
        extract_main([SAMPLE_CONFIG, "-o", self.out])
        detector = CorrelationDetector(
            {"enabled": True, "ruleset_path": self.out, "alert_on_no_match": True}
        )
        self.assertTrue(detector.enabled)
        self.assertEqual(len(detector.rules), 4)

        # intended block -> silent
        self.assertEqual(
            detector.evaluate(_log("block", "udp", "192.168.20.105", "8.8.8.8", 53)), []
        )
        # genuine mismatch -> CRITICAL
        a = detector.evaluate(
            _log("block", "tcp", "192.168.1.6", "172.253.115.108", 993, interface="igb1")
        )
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].rule_name, "action_mismatch")


if __name__ == "__main__":
    unittest.main()
