import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedLog


class PfSenseParser(BaseParser):
    """Parser for pfSense filterlog (firewall) entries.

    pfSense filterlog format (comma-separated):
    https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-log-format.html

    Common fields:
    0: rule number
    1: sub-rule number
    2: anchor
    3: tracker
    4: interface
    5: reason
    6: action (pass/block)
    7: direction (in/out)
    8: IP version (4/6)

    For IPv4 (index 8 = 4):
    9: TOS
    10: ECN
    11: TTL
    12: ID
    13: Offset
    14: Flags
    15: Protocol ID
    16: Protocol name
    17: Length
    18: Source IP
    19: Destination IP

    For TCP/UDP:
    20: Source port
    21: Destination port
    """

    FILTERLOG_PATTERN = re.compile(
        r"filterlog\[\d+\]:\s*(.+)$"
    )

    def can_parse(self, raw_log: str) -> bool:
        """Check if this is a pfSense filterlog entry."""
        return "filterlog[" in raw_log

    def parse(self, raw_log: str, source_ip: str) -> Optional[ParsedLog]:
        """Parse a pfSense filterlog entry."""
        match = self.FILTERLOG_PATTERN.search(raw_log)
        if not match:
            return None

        csv_data = match.group(1)
        fields = csv_data.split(",")

        if len(fields) < 20:
            return None

        try:
            interface = fields[4]
            action = fields[6].lower()
            direction = fields[7].lower()
            ip_version = fields[8]

            if ip_version != "4":
                # Skip IPv6 for now
                return None

            protocol = fields[16].lower()
            log_src_ip = fields[18]
            log_dst_ip = fields[19]

            src_port = None
            dst_port = None

            if protocol in ("tcp", "udp") and len(fields) >= 22:
                src_port = int(fields[20]) if fields[20].isdigit() else None
                dst_port = int(fields[21]) if fields[21].isdigit() else None

            timestamp = self._extract_timestamp(raw_log)

            return ParsedLog(
                timestamp=timestamp,
                source_ip=source_ip,
                log_type="filterlog",
                action=action,
                protocol=protocol,
                src_ip=log_src_ip,
                src_port=src_port,
                dst_ip=log_dst_ip,
                dst_port=dst_port,
                interface=interface,
                direction=direction,
                raw=raw_log,
            )

        except (IndexError, ValueError):
            return None

    def _extract_timestamp(self, raw_log: str) -> datetime:
        """Extract timestamp from syslog header.

        Standard syslog format: <PRI>Mon DD HH:MM:SS hostname ...
        """
        # Try to find standard syslog timestamp
        timestamp_pattern = re.compile(
            r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"
        )
        match = timestamp_pattern.search(raw_log)

        if match:
            month_str, day, hour, minute, second = match.groups()
            months = {
                "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
                "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
                "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
            }
            month = months.get(month_str, 1)
            year = datetime.now().year

            return datetime(year, month, int(day), int(hour), int(minute), int(second))

        return datetime.now()
