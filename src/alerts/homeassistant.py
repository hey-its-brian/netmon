"""Home Assistant alerter.

POSTs alerts to a Home Assistant webhook so HA's own automations/notify (mobile
app, etc.) deliver them. Webhooks need no auth token — the webhook ID in the URL
is the shared secret — which keeps this simple and tokenless for a homelab.

Set up in HA: Settings -> Automations -> new automation -> trigger "Webhook" with
an ID (e.g. netmon_alert), action "Notify". The exposed URL is
    http://<ha-host>:8123/api/webhook/<id>
The POSTed JSON is available to the automation as trigger.json (title, message,
severity, rule_name, details).

The HTTP POST runs in a daemon thread so a slow/unreachable HA never stalls log
ingestion. Delivery is best-effort; failures are logged, not raised.
"""

import json
import logging
import threading
import urllib.request

from .base import Alert, AlertSeverity, BaseAlerter

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.CRITICAL: 2,
}


def _rank(severity: str) -> int:
    try:
        return _SEVERITY_RANK[AlertSeverity(severity.lower())]
    except (ValueError, KeyError, AttributeError):
        return _SEVERITY_RANK[AlertSeverity.CRITICAL]


class HomeAssistantAlerter(BaseAlerter):
    """Pushes alerts at or above a severity threshold to a Home Assistant webhook."""

    def __init__(self, webhook_url: str, min_severity: str = "critical", timeout: int = 5):
        self.webhook_url = webhook_url
        self.timeout = timeout
        self.min_rank = _rank(min_severity)

    def send(self, alert: Alert) -> bool:
        if _SEVERITY_RANK.get(alert.severity, 0) < self.min_rank:
            return True  # below threshold — nothing to push (still logged elsewhere)
        self._dispatch(self._build_payload(alert))
        return True

    def _build_payload(self, alert: Alert) -> dict:
        return {
            "title": f"netmon: {alert.rule_name} ({alert.severity.value.upper()})",
            "message": alert.message,
            "severity": alert.severity.value,
            "rule_name": alert.rule_name,
            "timestamp": alert.timestamp.isoformat(),
            "details": alert.details or {},
        }

    def _dispatch(self, payload: dict) -> None:
        threading.Thread(target=self._post, args=(payload,), daemon=True).start()

    def _post(self, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except Exception as e:  # noqa: BLE001 - best-effort delivery
            logger.error("Home Assistant alert POST to %s failed: %s", self.webhook_url, e)
