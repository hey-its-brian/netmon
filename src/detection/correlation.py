"""Rule-to-log correlation detection.

Ported from yalt_inspector's analyzer. Unlike RuleEngine (which applies
hard-coded thresholds), this detector compares each live log entry against the
*actual* pfSense firewall ruleset loaded from a config backup, and flags:

  - no_matching_rule: traffic that matches no configured rule at all
  - action_mismatch:  traffic whose observed action conflicts with the action
                      of every rule that matched it (e.g. rules say block, the
                      packet passed)

Interface matching: a pfSense config rule's <interface> uses the logical name
(lan, wan, opt1...) while filterlog reports the device name (igb1.20). We bridge
the two with the {logical: device} map parsed from the config's <interfaces>
section. When the map can resolve a rule's interface, it is enforced; when it
cannot (unknown name, or no <interfaces> section at all) interface matching
falls back to lenient ("any") so we never raise false no_matching_rule alerts.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from ..alerts.base import Alert, AlertSeverity
from ..parsers.base import ParsedLog
from ..ruleset.pfsense import PFRule, parse_pfsense_interfaces, parse_pfsense_rules

logger = logging.getLogger(__name__)


def _normalize_action(action: Optional[str]) -> Optional[str]:
    """Map a rule/log action to the vocabulary used in filterlog (pass/block)."""
    if not action:
        return None
    action = action.lower()
    # pfSense config <type> can be pass / block / reject; logs only show pass/block.
    if action == "reject":
        return "block"
    return action


def _match_field(rule_value: Optional[str], log_value: Optional[str]) -> bool:
    """A rule field of None means "any" and matches anything."""
    if rule_value is None:
        return True
    if log_value is None:
        return False
    return rule_value == log_value


def _interface_matches(
    rule_iface: Optional[str], log_iface: Optional[str], iface_map: Dict[str, str]
) -> bool:
    """Compare a rule's logical interface against the log's device interface.

    Lenient by design: if the rule has no interface, the map is empty, or the
    rule's logical name(s) can't be resolved to a device, we treat it as "any".
    Floating rules can list several interfaces (e.g. "wan,lan").
    """
    if not rule_iface:
        return True
    if not iface_map:
        return True

    devices = []
    for logical in rule_iface.split(","):
        logical = logical.strip()
        device = iface_map.get(logical)
        if device:
            devices.append(device)

    # Couldn't resolve any of the rule's interfaces -> don't constrain on it.
    if not devices:
        return True
    if log_iface is None:
        return False
    return log_iface in devices


def _rule_matches_log(rule: PFRule, log: ParsedLog, iface_map: Dict[str, str]) -> bool:
    """Return True if a configured rule could govern this log entry."""
    # interface (logical rule name resolved to device via the interface map)
    if not _interface_matches(rule.interface, log.interface, iface_map):
        return False

    # protocol
    if not _match_field(rule.protocol, log.protocol):
        return False

    # source / destination IPs (only constrain when the rule specifies one)
    if rule.src_ip and rule.src_ip != log.src_ip:
        return False
    if rule.dst_ip and rule.dst_ip != log.dst_ip:
        return False

    # ports (rule ports are strings from XML; log ports are ints)
    if rule.dst_port and log.dst_port is not None:
        if rule.dst_port != str(log.dst_port):
            return False
    if rule.src_port and log.src_port is not None:
        if rule.src_port != str(log.src_port):
            return False

    return True


class CorrelationDetector:
    """Correlates live log entries against the configured pfSense ruleset."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", False)
        self.alert_on_no_match = config.get("alert_on_no_match", True)
        self.rules: List[PFRule] = []
        self.iface_map: Dict[str, str] = {}

        config_path = config.get("config_path")
        if self.enabled:
            if not config_path:
                logger.warning(
                    "Correlation detection enabled but no config_path set; disabling."
                )
                self.enabled = False
            else:
                try:
                    self.rules = parse_pfsense_rules(config_path)
                    self.iface_map = parse_pfsense_interfaces(config_path)
                    logger.info(
                        "Loaded %d firewall rule(s) and %d interface mapping(s) from %s",
                        len(self.rules),
                        len(self.iface_map),
                        config_path,
                    )
                    if self.iface_map:
                        logger.info("Interface map: %s", self.iface_map)
                except Exception as e:  # noqa: BLE001 - never let a bad config crash startup
                    logger.error("Failed to load pfSense ruleset from %s: %s", config_path, e)
                    self.enabled = False

    def evaluate(self, log: ParsedLog) -> List[Alert]:
        """Evaluate a single log entry against the configured ruleset."""
        if not self.enabled or not self.rules:
            return []

        matching = [r for r in self.rules if _rule_matches_log(r, log, self.iface_map)]

        # No configured rule governs this traffic.
        if not matching:
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

        # Every matching rule disagrees with the observed action.
        rule_actions = {_normalize_action(r.action) for r in matching if r.action}
        rule_actions.discard(None)
        log_action = _normalize_action(log.action)

        if rule_actions and log_action and all(a != log_action for a in rule_actions):
            return [
                Alert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.CRITICAL,
                    rule_name="action_mismatch",
                    message=(
                        f"Observed action '{log_action}' conflicts with configured "
                        f"rule action(s) {sorted(rule_actions)}"
                    ),
                    details={
                        "source_ip": log.src_ip,
                        "destination_ip": log.dst_ip,
                        "destination_port": log.dst_port,
                        "protocol": log.protocol,
                        "observed_action": log_action,
                        "rule_actions": sorted(rule_actions),
                        "matched_rules": len(matching),
                    },
                )
            ]

        return []
