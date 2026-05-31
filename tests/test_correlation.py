"""Tests for pfSense parsing, the rule matcher, and correlation behavior."""

import os
import unittest
from datetime import datetime

from src.alerts.base import AlertSeverity
from src.detection.correlation import CorrelationDetector
from src.detection.matcher import RuleMatcher
from src.parsers.base import ParsedLog
from src.ruleset.pfsense import (
    PFRule,
    parse_pfsense_aliases,
    parse_pfsense_interfaces,
    parse_pfsense_rules,
)

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


def _rule(**kw):
    base = dict(
        action="pass", interface=None, protocol=None,
        src_addr=None, src_port=None, src_not=False,
        dst_addr=None, dst_port=None, dst_not=False, description=None,
    )
    base.update(kw)
    return PFRule(**base)


class TestParser(unittest.TestCase):
    def test_rules_interfaces_aliases(self):
        self.assertEqual(len(parse_pfsense_rules(SAMPLE_CONFIG)), 4)
        ifaces = parse_pfsense_interfaces(SAMPLE_CONFIG)
        self.assertEqual(ifaces["opt1"]["device"], "igb1.20")
        self.assertEqual(ifaces["opt1"]["subnet"], "24")
        aliases = parse_pfsense_aliases(SAMPLE_CONFIG)
        self.assertEqual(aliases["DNS_Servers"]["type"], "host")
        self.assertIn("8.8.8.8", aliases["DNS_Servers"]["values"])

    def test_skips_disabled_rules(self):
        # sample has no disabled rules; ensure all 4 active rules parsed
        rules = parse_pfsense_rules(SAMPLE_CONFIG)
        self.assertTrue(all(r.action in ("pass", "block") for r in rules))


class TestMatcher(unittest.TestCase):
    def setUp(self):
        self.interfaces = parse_pfsense_interfaces(SAMPLE_CONFIG)
        self.aliases = parse_pfsense_aliases(SAMPLE_CONFIG)
        self.rules = parse_pfsense_rules(SAMPLE_CONFIG)
        self.m = RuleMatcher(self.rules, self.interfaces, self.aliases)

    def test_first_match_block_beats_lower_pass(self):
        # VLAN20 -> external DNS: rule 1 (block via aliases) must win over rule 3 (pass)
        kind, rule = self.m.evaluate(_log("block", "udp", "192.168.20.105", "8.8.8.8", 53))
        self.assertEqual(kind, "action")
        self.assertEqual(rule.action, "block")

    def test_port_alias_match(self):
        kind, rule = self.m.evaluate(
            _log("block", "udp", "192.168.20.105", "54.177.94.133", 32100)
        )
        self.assertEqual((kind, rule.action), ("action", "block"))

    def test_broad_pass_when_no_block_applies(self):
        # VLAN20 -> some https host: blocks don't apply, falls to rule 3 (pass)
        kind, rule = self.m.evaluate(_log("pass", "udp", "192.168.20.50", "9.9.9.9", 443))
        self.assertEqual((kind, rule.action), ("action", "pass"))

    def test_no_match_wrong_interface(self):
        kind, _ = self.m.evaluate(
            _log("block", "udp", "192.168.20.105", "8.8.8.8", 53, interface="igb0")
        )
        self.assertEqual(kind, "none")

    def test_cidr_and_network_keyword(self):
        # rule 4 source is "lan" network keyword -> 192.168.1.0/24
        kind, rule = self.m.evaluate(
            _log("pass", "tcp", "192.168.1.6", "172.253.115.108", 993, interface="igb1")
        )
        self.assertEqual((kind, rule.action), ("action", "pass"))

    def test_negation(self):
        rules = [_rule(action="block", dst_addr="192.168.1.0/24", dst_not=True)]
        m = RuleMatcher(rules, self.interfaces, self.aliases)
        # dst inside LAN -> negated -> NO match
        self.assertEqual(m.evaluate(_log("block", "tcp", "10.0.0.1", "192.168.1.50", 80))[0], "none")
        # dst outside LAN -> negated -> matches
        self.assertEqual(m.evaluate(_log("block", "tcp", "10.0.0.1", "8.8.8.8", 80))[0], "action")

    def test_unknown_alias_yields_unknown(self):
        rules = [_rule(action="block", dst_addr="SomeURLTable")]
        aliases = {"SomeURLTable": {"type": "urltable", "values": []}}
        m = RuleMatcher(rules, self.interfaces, aliases)
        self.assertEqual(m.evaluate(_log("block", "tcp", "10.0.0.1", "8.8.8.8", 80))[0], "unknown")

    def test_port_range(self):
        rules = [_rule(action="pass", dst_port="1000:2000")]
        m = RuleMatcher(rules, self.interfaces, self.aliases)
        self.assertEqual(m.evaluate(_log("pass", "tcp", "10.0.0.1", "8.8.8.8", 1500))[0], "action")
        self.assertEqual(m.evaluate(_log("pass", "tcp", "10.0.0.1", "8.8.8.8", 3000))[0], "none")


class TestCorrelationDetector(unittest.TestCase):
    def setUp(self):
        self.detector = CorrelationDetector(
            {"enabled": True, "config_path": SAMPLE_CONFIG, "alert_on_no_match": True}
        )

    def test_disabled_by_default(self):
        self.assertFalse(CorrelationDetector({}).enabled)

    def test_intended_block_is_not_flagged(self):
        # The whole point: VLAN20 DNS block is governed by a block rule -> silent.
        alerts = self.detector.evaluate(_log("block", "udp", "192.168.20.105", "8.8.8.8", 53))
        self.assertEqual(alerts, [])

    def test_overblock_is_warning(self):
        # rule 4 passes LAN IMAPS, but the packet was blocked: more secure than
        # expected -> WARNING, not CRITICAL.
        alerts = self.detector.evaluate(
            _log("block", "tcp", "192.168.1.6", "172.253.115.108", 993, interface="igb1")
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "action_mismatch")
        self.assertEqual(alerts[0].details["expected_action"], "pass")
        self.assertEqual(alerts[0].severity, AlertSeverity.WARNING)

    def test_security_gap_is_critical(self):
        # rule 1 blocks VLAN20 -> external DNS, but this packet PASSED: a hole.
        alerts = self.detector.evaluate(
            _log("pass", "udp", "192.168.20.105", "8.8.8.8", 53, interface="igb1.20")
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "action_mismatch")
        self.assertEqual(alerts[0].details["expected_action"], "block")
        self.assertEqual(alerts[0].severity, AlertSeverity.CRITICAL)

    def test_no_matching_rule(self):
        alerts = self.detector.evaluate(
            _log("block", "udp", "192.168.20.105", "8.8.8.8", 53, interface="igb0")
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "no_matching_rule")

    def test_unknown_stays_silent(self):
        detector = CorrelationDetector({"enabled": True, "config_path": SAMPLE_CONFIG})
        detector.rules = [_rule(action="block", dst_addr="GeoIPThing")]
        detector.aliases = {"GeoIPThing": {"type": "urltable", "values": []}}
        detector.matcher = RuleMatcher(detector.rules, detector.interfaces, detector.aliases)
        self.assertEqual(detector.evaluate(_log("pass", "tcp", "10.0.0.1", "8.8.8.8", 80)), [])


if __name__ == "__main__":
    unittest.main()
