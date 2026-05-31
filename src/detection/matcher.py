"""Replicate pfSense's rule evaluation closely enough to trust the verdict.

Given a log entry, find the first rule that governs it (pfSense is first-match)
and report that rule's action. The matcher understands:

  - aliases (host/network/port), resolved recursively
  - CIDRs and literal IPs (via the ipaddress module)
  - interface network keywords ("lan" = LAN subnet, "lanip" = LAN address,
    "(self)" = any firewall IP)
  - negation (<not>)
  - port ranges (low:high) and port aliases

A field the matcher cannot resolve (a URL-table alias, geoip, an unknown
keyword) yields UNKNOWN. If an UNKNOWN rule could match before any confident
match, evaluate() returns ("unknown", None) and the caller stays silent — better
no alert than a guessed one.
"""

import ipaddress
import logging
from typing import Dict, List, Optional, Tuple

from ..ruleset.pfsense import PFRule

logger = logging.getLogger(__name__)

YES = "yes"
NO = "no"
UNKNOWN = "unknown"


def normalize_action(action: Optional[str]) -> Optional[str]:
    """Map a rule/log action to filterlog vocabulary (pass/block)."""
    if not action:
        return None
    action = action.lower()
    return "block" if action == "reject" else action


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


class RuleMatcher:
    def __init__(
        self,
        rules: List[PFRule],
        interfaces: Dict[str, dict],
        aliases: Dict[str, dict],
    ):
        self.rules = rules
        self.interfaces = interfaces or {}
        self.aliases = aliases or {}

        self._iface_networks: Dict[str, "ipaddress._BaseNetwork"] = {}
        self._iface_ips: Dict[str, "ipaddress._BaseAddress"] = {}
        for logical, info in self.interfaces.items():
            ipaddr = (info or {}).get("ipaddr")
            subnet = (info or {}).get("subnet")
            if ipaddr and _as_ip(ipaddr):
                self._iface_ips[logical] = ipaddress.ip_address(ipaddr)
                if subnet:
                    try:
                        self._iface_networks[logical] = ipaddress.ip_network(
                            f"{ipaddr}/{subnet}", strict=False
                        )
                    except ValueError:
                        pass

        self._addr_cache: Dict[str, Tuple[list, bool]] = {}
        self._port_cache: Dict[str, Tuple[list, bool]] = {}

    # ---- public API -------------------------------------------------------

    def evaluate(self, log) -> Tuple[str, Optional[PFRule]]:
        """Return one of:
        ("action", rule)  -> rule is the first confident match; use rule.action
        ("none", None)    -> no rule governs this traffic (confident)
        ("unknown", None) -> an unresolvable rule could match first; undecidable
        """
        for rule in self.rules:
            result = self._match(rule, log)
            if result == YES:
                return ("action", rule)
            if result == UNKNOWN:
                return ("unknown", None)
            # NO -> keep scanning
        return ("none", None)

    # ---- per-rule matching ------------------------------------------------

    def _match(self, rule: PFRule, log) -> str:
        if not self._iface_matches(rule.interface, log.interface):
            return NO

        if rule.protocol and log.protocol:
            # pfSense stores combined protocols as "tcp/udp".
            rule_protos = set(rule.protocol.lower().split("/"))
            if log.protocol.lower() not in rule_protos:
                return NO

        results = [
            self._addr_matches(rule.src_addr, rule.src_not, log.src_ip),
            self._addr_matches(rule.dst_addr, rule.dst_not, log.dst_ip),
            self._port_matches(rule.src_port, log.src_port),
            self._port_matches(rule.dst_port, log.dst_port),
        ]
        if NO in results:
            return NO
        if UNKNOWN in results:
            return UNKNOWN
        return YES

    def _iface_matches(self, rule_iface: Optional[str], log_iface: Optional[str]) -> bool:
        # No interface on the rule = floating / all interfaces.
        if not rule_iface:
            return True
        # Can't compare without a log interface; don't constrain on it.
        if log_iface is None:
            return True
        # Resolve the rule's logical interface(s) to device name(s). If none
        # resolve, the rule targets an interface this packet isn't on (e.g. an
        # unconfigured opt4, or a different interface) -> it does not apply.
        devices = []
        for logical in rule_iface.split(","):
            info = self.interfaces.get(logical.strip())
            if info and info.get("device"):
                devices.append(info["device"])
        return log_iface in devices

    def _addr_matches(self, spec: Optional[str], negated: bool, log_ip: Optional[str]) -> str:
        if spec is None:
            base = YES  # "any"
        else:
            base = self._ip_in_spec(log_ip, spec)
        if base == UNKNOWN:
            return UNKNOWN
        if negated:
            return NO if base == YES else YES
        return base

    def _ip_in_spec(self, log_ip: Optional[str], spec: str) -> str:
        if log_ip is None:
            return NO
        networks, resolved = self._resolve_addr(spec)
        if not resolved:
            return UNKNOWN
        ip = _as_ip(log_ip)
        if ip is None:
            return NO
        for net in networks:
            if ip in net:
                return YES
        return NO

    def _resolve_addr(self, spec: str, depth: int = 0) -> Tuple[list, bool]:
        """Resolve an address spec to a list of ip_networks. Returns
        (networks, resolved) where resolved=False means unresolvable."""
        spec = spec.strip()
        if depth == 0 and spec in self._addr_cache:
            return self._addr_cache[spec]
        if depth > 10:
            return [], False

        result = self._resolve_addr_uncached(spec, depth)
        if depth == 0:
            self._addr_cache[spec] = result
        return result

    def _resolve_addr_uncached(self, spec: str, depth: int) -> Tuple[list, bool]:
        # Alias?
        alias = self.aliases.get(spec)
        if alias is not None:
            if alias.get("type") not in ("host", "network"):
                return [], False  # port/url/geoip alias in an address position
            networks = []
            resolved = True
            for value in alias.get("values", []):
                sub, ok = self._resolve_addr(value, depth + 1)
                if ok:
                    networks.extend(sub)
                else:
                    resolved = False
            return networks, resolved

        # "(self)" -> any firewall interface IP
        if spec == "(self)":
            return [ipaddress.ip_network(ip) for ip in self._iface_ips.values()], True

        # "<iface> net" keyword (stored as the logical name, e.g. "lan", "opt1")
        if spec in self._iface_networks:
            return [self._iface_networks[spec]], True

        # "<iface>ip" keyword (e.g. "lanip", "opt1ip")
        if spec.endswith("ip") and spec[:-2] in self._iface_ips:
            return [ipaddress.ip_network(self._iface_ips[spec[:-2]])], True

        # Literal IP or CIDR
        try:
            return [ipaddress.ip_network(spec, strict=False)], True
        except ValueError:
            return [], False  # unknown alias/keyword we can't resolve

    def _port_matches(self, spec: Optional[str], log_port: Optional[int]) -> str:
        if spec is None:
            return YES  # "any"
        if log_port is None:
            return NO
        ranges, resolved = self._resolve_port(spec)
        if not resolved:
            return UNKNOWN
        for lo, hi in ranges:
            if lo <= log_port <= hi:
                return YES
        return NO

    def _resolve_port(self, spec: str, depth: int = 0) -> Tuple[list, bool]:
        spec = str(spec).strip()
        if depth == 0 and spec in self._port_cache:
            return self._port_cache[spec]
        if depth > 10:
            return [], False

        result = self._resolve_port_uncached(spec, depth)
        if depth == 0:
            self._port_cache[spec] = result
        return result

    def _resolve_port_uncached(self, spec: str, depth: int) -> Tuple[list, bool]:
        alias = self.aliases.get(spec)
        if alias is not None:
            if alias.get("type") != "port":
                return [], False
            ranges = []
            resolved = True
            for value in alias.get("values", []):
                sub, ok = self._resolve_port(value, depth + 1)
                if ok:
                    ranges.extend(sub)
                else:
                    resolved = False
            return ranges, resolved

        sep = ":" if ":" in spec else ("-" if "-" in spec else None)
        if sep:
            lo, _, hi = spec.partition(sep)
            try:
                return [(int(lo), int(hi))], True
            except ValueError:
                return [], False
        try:
            p = int(spec)
            return [(p, p)], True
        except ValueError:
            return [], False
