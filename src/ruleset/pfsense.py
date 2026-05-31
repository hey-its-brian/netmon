"""pfSense configuration parsing.

Ported from yalt_inspector and extended. Reads a pfSense config backup
(config.xml) and extracts everything the correlation matcher needs to replicate
how pfSense actually evaluates traffic:

  - firewall rules (in document order, disabled rules skipped)
  - the <aliases> table (named host/network/port groups)
  - the <interfaces> map, including each interface's IP/subnet so "LAN net"
    style rules can be resolved to a CIDR.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class PFRule:
    """A single firewall rule from the pfSense config backup.

    Address fields hold the raw spec (a literal IP, a CIDR, an alias name, or a
    network keyword like "lan"/"lanip"/"(self)"); the matcher resolves them.
    """
    action: str
    interface: Optional[str]
    protocol: Optional[str]
    src_addr: Optional[str]
    src_port: Optional[str]
    src_not: bool
    dst_addr: Optional[str]
    dst_port: Optional[str]
    dst_not: bool
    description: Optional[str]


def _parse_endpoint(elem) -> Tuple[Optional[str], Optional[str], bool]:
    """Parse a <source>/<destination> element into (address, port, negated)."""
    if elem is None:
        return None, None, False

    negated = elem.find("not") is not None

    port = elem.findtext("port")
    port = port.strip() if port else None

    # "any" address — but a port may still be specified.
    if elem.find("any") is not None:
        return None, port, negated

    addr = elem.findtext("address") or elem.findtext("network")
    addr = addr.strip() if addr else None
    return addr, port, negated


def parse_pfsense_rules(path: str) -> List[PFRule]:
    """Parse the <filter> section into PFRule objects, in document order.

    Disabled rules are skipped (they don't affect live traffic).
    """
    tree = ET.parse(path)
    root = tree.getroot()

    rules: List[PFRule] = []

    filter_section = root.find("filter")
    if filter_section is None:
        return rules

    for elem in filter_section.findall("rule"):
        if elem.find("disabled") is not None:
            continue

        action = elem.findtext("type") or "pass"
        interface = elem.findtext("interface")
        protocol = elem.findtext("protocol")
        description = elem.findtext("descr")

        src_addr, src_port, src_not = _parse_endpoint(elem.find("source"))
        dst_addr, dst_port, dst_not = _parse_endpoint(elem.find("destination"))

        rules.append(
            PFRule(
                action=action,
                interface=interface,
                protocol=protocol,
                src_addr=src_addr,
                src_port=src_port,
                src_not=src_not,
                dst_addr=dst_addr,
                dst_port=dst_port,
                dst_not=dst_not,
                description=description,
            )
        )

    return rules


def parse_pfsense_interfaces(path: str) -> Dict[str, dict]:
    """Parse <interfaces> into {logical: {device, ipaddr, subnet}}.

    device is the filterlog device name (igb0, igb1.20...). ipaddr/subnet let the
    matcher turn "lan net" style rules into a concrete CIDR.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    mapping: Dict[str, dict] = {}

    interfaces = root.find("interfaces")
    if interfaces is None:
        return mapping

    for iface in list(interfaces):
        logical = iface.tag  # wan / lan / opt1 / opt2 / ...
        device = iface.findtext("if")
        if not device:
            continue
        ipaddr = (iface.findtext("ipaddr") or "").strip() or None
        subnet = (iface.findtext("subnet") or "").strip() or None
        mapping[logical] = {
            "device": device.strip(),
            "ipaddr": ipaddr,
            "subnet": subnet,
        }

    return mapping


def parse_pfsense_aliases(path: str) -> Dict[str, dict]:
    """Parse <aliases> into {name: {type, values}}.

    type is host/network/port/url/urltable/...; values is the space-separated
    address/port list. host and network aliases resolve to IPs/CIDRs; port
    aliases to ports; everything else is left for the matcher to treat as
    unresolvable (so it stays silent rather than guessing).
    """
    tree = ET.parse(path)
    root = tree.getroot()

    out: Dict[str, dict] = {}

    aliases = root.find("aliases")
    if aliases is None:
        return out

    for alias in aliases.findall("alias"):
        name = alias.findtext("name")
        if not name:
            continue
        atype = (alias.findtext("type") or "").strip()
        address = alias.findtext("address") or ""
        out[name.strip()] = {"type": atype, "values": address.split()}

    return out
