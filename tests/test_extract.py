"""Tests for the pfSense extract command and the rules.yaml round trip."""

import os
import tempfile
import unittest
from datetime import datetime

from src.detection.correlation import CorrelationDetector
from src.parsers.base import ParsedLog
from src.ruleset.yaml_io import dump_ruleset, load_ruleset
from src.ruleset.pfsense import parse_pfsense_interfaces, parse_pfsense_rules
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
        rc = extract_main([SAMPLE_CONFIG, "-o", self.out])
        self.assertEqual(rc, 0)
        rules, ifaces = load_ruleset(self.out)
        self.assertEqual(len(rules), 2)
        self.assertEqual(ifaces.get("opt2"), "igb1.20")

    def test_yaml_round_trip_preserves_fields(self):
        rules = parse_pfsense_rules(SAMPLE_CONFIG)
        ifaces = parse_pfsense_interfaces(SAMPLE_CONFIG)
        dump_ruleset(rules, ifaces, self.out)
        loaded_rules, loaded_ifaces = load_ruleset(self.out)
        self.assertEqual(loaded_ifaces, ifaces)
        self.assertEqual([r.__dict__ for r in loaded_rules], [r.__dict__ for r in rules])

    def test_correlation_via_ruleset_path_matches_xml_path(self):
        extract_main([SAMPLE_CONFIG, "-o", self.out])
        detector = CorrelationDetector(
            {"enabled": True, "ruleset_path": self.out, "alert_on_no_match": True}
        )
        self.assertTrue(detector.enabled)
        self.assertEqual(len(detector.rules), 2)

        # action_mismatch (pass rule on LAN, traffic blocked)
        a = detector.evaluate(
            _log("block", "tcp", "192.168.1.6", "172.253.115.108", 993, interface="igb1")
        )
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].rule_name, "action_mismatch")

        # consistent block on the VLAN device -> no alert
        b = detector.evaluate(
            _log("block", "udp", "192.168.20.105", "1.1.1.1", 53, interface="igb1.20")
        )
        self.assertEqual(b, [])

        # no rule governs this -> no_matching_rule
        c = detector.evaluate(_log("block", "udp", "192.168.20.105", "8.8.8.8", 53))
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].rule_name, "no_matching_rule")


if __name__ == "__main__":
    unittest.main()
