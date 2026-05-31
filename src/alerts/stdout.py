import json
import sys
from datetime import datetime

from .base import Alert, AlertSeverity, BaseAlerter


class StdoutAlerter(BaseAlerter):
    """Outputs alerts to stdout (Docker logs)."""

    SEVERITY_COLORS = {
        AlertSeverity.INFO: "\033[36m",      # Cyan
        AlertSeverity.WARNING: "\033[33m",   # Yellow
        AlertSeverity.CRITICAL: "\033[31m",  # Red
    }
    RESET = "\033[0m"

    def __init__(self, use_json: bool = False, use_color: bool = True):
        self.use_json = use_json
        self.use_color = use_color and sys.stdout.isatty()

    def send(self, alert: Alert) -> bool:
        """Print alert to stdout."""
        if self.use_json:
            print(json.dumps(alert.to_dict()), flush=True)
        else:
            self._print_formatted(alert)
        return True

    def _print_formatted(self, alert: Alert) -> None:
        """Print a formatted alert."""
        severity = alert.severity.value.upper()
        timestamp = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        if self.use_color:
            color = self.SEVERITY_COLORS.get(alert.severity, "")
            severity_str = f"{color}[{severity}]{self.RESET}"
        else:
            severity_str = f"[{severity}]"

        print(f"{timestamp} {severity_str} {alert.rule_name}: {alert.message}", flush=True)

        if alert.details:
            for key, value in alert.details.items():
                print(f"  {key}: {value}", flush=True)
