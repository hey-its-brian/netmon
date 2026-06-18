from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Represents an alert."""
    timestamp: datetime
    severity: AlertSeverity
    rule_name: str
    message: str
    details: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert alert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "rule_name": self.rule_name,
            "message": self.message,
            "details": self.details,
        }


class BaseAlerter(ABC):
    """Base class for alert handlers."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True if successful."""
        pass

    def close(self) -> None:
        """Release resources on shutdown. Default is a no-op; alerters that hold
        connections or background threads (e.g. MQTT) override this."""
        pass
