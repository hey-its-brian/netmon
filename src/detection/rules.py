from datetime import datetime
from typing import Optional

from ..alerts.base import Alert, AlertSeverity
from ..parsers.base import ParsedLog
from ..storage.database import Database


class RuleEngine:
    """Rule-based anomaly detection engine."""

    def __init__(self, config: dict, database: Database):
        self.config = config
        self.db = database
        self.blocked_threshold = config.get("blocked_threshold", 100)
        self.port_scan_threshold = config.get("port_scan_threshold", 20)
        self.suspicious_ports = set(config.get("suspicious_ports", [23, 445, 3389, 5900]))

    def evaluate(self, log: ParsedLog) -> list[Alert]:
        """Evaluate all rules against a log entry."""
        alerts = []

        alert = self._check_blocked_threshold(log)
        if alert:
            alerts.append(alert)

        alert = self._check_port_scan(log)
        if alert:
            alerts.append(alert)

        alert = self._check_suspicious_port(log)
        if alert:
            alerts.append(alert)

        return alerts

    def _check_blocked_threshold(self, log: ParsedLog) -> Optional[Alert]:
        """Check if an IP has exceeded the blocked connection threshold."""
        if log.action != "block" or not log.src_ip:
            return None

        block_count = self.db.get_blocks_by_ip(log.src_ip, minutes=1)

        if block_count >= self.blocked_threshold:
            # Only alert once when crossing threshold
            if block_count == self.blocked_threshold:
                return Alert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.WARNING,
                    rule_name="high_block_rate",
                    message=f"High volume of blocked connections from {log.src_ip}",
                    details={
                        "source_ip": log.src_ip,
                        "block_count": block_count,
                        "threshold": self.blocked_threshold,
                        "period": "1 minute",
                    },
                )
        return None

    def _check_port_scan(self, log: ParsedLog) -> Optional[Alert]:
        """Detect potential port scans."""
        if not log.src_ip or not log.dst_port:
            return None

        ports_hit = self.db.get_ports_hit_by_ip(log.src_ip, seconds=60)

        if len(ports_hit) >= self.port_scan_threshold:
            # Only alert once when crossing threshold
            if len(ports_hit) == self.port_scan_threshold:
                return Alert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.CRITICAL,
                    rule_name="port_scan",
                    message=f"Potential port scan detected from {log.src_ip}",
                    details={
                        "source_ip": log.src_ip,
                        "ports_scanned": len(ports_hit),
                        "threshold": self.port_scan_threshold,
                        "period": "60 seconds",
                        "sample_ports": sorted(ports_hit)[:10],
                    },
                )
        return None

    def _check_suspicious_port(self, log: ParsedLog) -> Optional[Alert]:
        """Check for connections to suspicious ports from external IPs."""
        if not log.dst_port or log.direction != "in":
            return None

        if log.dst_port not in self.suspicious_ports:
            return None

        # Skip internal IPs
        if log.src_ip and self._is_internal_ip(log.src_ip):
            return None

        return Alert(
            timestamp=datetime.now(),
            severity=AlertSeverity.WARNING,
            rule_name="suspicious_port",
            message=f"Connection attempt to suspicious port {log.dst_port}",
            details={
                "source_ip": log.src_ip,
                "destination_ip": log.dst_ip,
                "destination_port": log.dst_port,
                "protocol": log.protocol,
                "action": log.action,
            },
        )

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if an IP is in a private range."""
        if not ip:
            return False

        parts = ip.split(".")
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8
            if first == 127:
                return True

            return False
        except ValueError:
            return False
