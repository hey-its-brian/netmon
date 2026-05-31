"""Rule-to-log correlation detection.

Compares each live log entry against the *actual* pfSense ruleset (loaded from a
sanitized rules.yaml, or parsed straight from a config.xml backup) and flags:

  - action_mismatch: the first rule that governs this traffic (pfSense is
                     first-match) specifies an action that conflicts with what
                     the packet actually did (e.g. rule passes, packet blocked).
  - no_matching_rule: no configured rule governs this traffic at all.

Matching is delegated to RuleMatcher, which resolves aliases, CIDRs, interface
network keywords, and negation. When the ruleset references something it can't
resolve and that could match first, the detector stays silent rather than emit a
guessed alert.
"""

import logging
from datetime import datetime
from typing import Dict, List

from ..alerts.base import Alert, AlertSeverity
from ..parsers.base import ParsedLog
from ..ruleset.pfsense import (
    PFRule,
    parse_pfsense_aliases,
    parse_pfsense_interfaces,
    parse_pfsense_rules,
)
from ..ruleset.yaml_io import load_ruleset
from .matcher import RuleMatcher, normalize_action

logger = logging.getLogger(__name__)


class CorrelationDetector:
    """Correlates live log entries against the configured pfSense ruleset."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", False)
        self.alert_on_no_match = config.get("alert_on_no_match", True)
        self.rules: List[PFRule] = []
        self.interfaces: Dict[str, dict] = {}
        self.aliases: Dict[str, dict] = {}
        self.matcher = None

        ruleset_path = config.get("ruleset_path")
        config_path = config.get("config_path")
        if self.enabled:
            source = ruleset_path or config_path
            if not source:
                logger.warning(
                    "Correlation enabled but no ruleset_path/config_path set; disabling."
                )
                self.enabled = False
            else:
                try:
                    if ruleset_path:
                        self.rules, self.interfaces, self.aliases = load_ruleset(ruleset_path)
                    else:
                        self.rules = parse_pfsense_rules(config_path)
                        self.interfaces = parse_pfsense_interfaces(config_path)
                        self.aliases = parse_pfsense_aliases(config_path)
                    self.matcher = RuleMatcher(self.rules, self.interfaces, self.aliases)
                    logger.info(
                        "Loaded %d rule(s), %d interface(s), %d alias(es) from %s",
                        len(self.rules),
                        len(self.interfaces),
                        len(self.aliases),
                        source,
                    )
                except Exception as e:  # noqa: BLE001 - never let a bad ruleset crash startup
                    logger.error("Failed to load pfSense ruleset from %s: %s", source, e)
                    self.enabled = False

    def evaluate(self, log: ParsedLog) -> List[Alert]:
        """Evaluate a single log entry against the configured ruleset."""
        if not self.enabled or not self.matcher:
            return []

        kind, rule = self.matcher.evaluate(log)

        # Undecidable (an unresolvable rule could match first) -> stay silent.
        if kind == "unknown":
            return []

        if kind == "none":
            if not self.alert_on_no_match:
                return []
            return [
                Alert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.INFO,
                    rule_name="no_matching_rule",
                    message=f"No firewall rule matched {log.src_ip} -> {log.dst_ip}",
                    details={
                        "source_ip": log.src_ip,
                        "destination_ip": log.dst_ip,
                        "destination_port": log.dst_port,
                        "protocol": log.protocol,
                        "action": log.action,
                        "interface": log.interface,
                    },
                )
            ]

        # kind == "action": compare the governing rule's action to what happened.
        expected = normalize_action(rule.action)
        observed = normalize_action(log.action)
        if expected and observed and expected != observed:
            return [
                Alert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.CRITICAL,
                    rule_name="action_mismatch",
                    message=(
                        f"Observed action '{observed}' conflicts with the governing "
                        f"rule (expects '{expected}')"
                    ),
                    details={
                        "source_ip": log.src_ip,
                        "destination_ip": log.dst_ip,
                        "destination_port": log.dst_port,
                        "protocol": log.protocol,
                        "observed_action": observed,
                        "expected_action": expected,
                        "rule": rule.description or "(no description)",
                        "interface": log.interface,
                    },
                )
            ]

        return []
