"""Tests for the pfSense ruleset parser and rule-to-log correlation detector."""

import os
import unittest
from datetime import datetime

from src.detection.correlation import CorrelationDetector
from src.parsers.base import ParsedLog
from src.ruleset.pfsense import parse_pfsense_rules

SAMPLE_CONFIG = os.path.join(
    os.path.dirname(__file__), "..", "samples", "example_config.xml"
)


def _log(action, protocol, src_ip, dst_ip, dst_port):
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
        interface="igb1.20",
        direction="in",
        raw="",
    )


class TestRulesetParser(unittest.TestCase):
    def test_parses_sample_config(self):
        rules = parse_pfsense_rules(SAMPLE_CONFIG)
        self.assertEqual(len(rules), 2)

    def test_extracts_rule_fields(self):
        rules = parse_pfsense_rules(SAMPLE_CONFIG)
        block_rule = next(r for r in rules if r.action == "block")
        self.assertEqual(block_rule.protocol, "udp")
        self.assertEqual(block_rule.dst_ip, "1.1.1.1")
        self.assertEqual(block_rule.dst_port, "53")
        # <any></any> source should be treated as None
        self.assertIsNone(block_rule.src_ip)


class TestCorrelationDetector(unittest.TestCase):
    def setUp(self):
        self.detector = CorrelationDetector(
            {"enabled": True, "config_path": SAMPLE_CONFIG, "alert_on_no_match": True}
        )

    def test_disabled_by_default(self):
        d = CorrelationDetector({})
        self.assertFalse(d.enabled)
        self.assertEqual(d.evaluate(_log("block", "udp", "x", "1.1.1.1", 53)), [])

    def test_consistent_action_no_alert(self):
        # Rule blocks udp -> 1.1.1.1:53 and the log shows block: agreement.
        alerts = self.detector.evaluate(_log("block", "udp", "192.168.20.105", "1.1.1.1", 53))
        self.assertEqual(alerts, [])

    def test_action_mismatch(self):
        # Rule passes tcp -> 172.253.115.108:993 but the log shows block.
        alerts = self.detector.evaluate(
            _log("block", "tcp", "192.168.1.6", "172.253.115.108", 993)
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "action_mismatch")

    def test_no_matching_rule(self):
        alerts = self.detector.evaluate(_log("block", "udp", "192.168.20.105", "8.8.8.8", 53))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "no_matching_rule")

    def test_no_match_suppressed_when_disabled(self):
        detector = CorrelationDetector(
            {"enabled": True, "config_path": SAMPLE_CONFIG, "alert_on_no_match": False}
        )
        alerts = detector.evaluate(_log("block", "udp", "192.168.20.105", "8.8.8.8", 53))
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
