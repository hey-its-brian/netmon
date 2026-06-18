"""MQTT alerter with Home Assistant MQTT Discovery.

Publishes alerts to an MQTT broker and announces two Home Assistant entities via
MQTT Discovery, so HA wires itself up with no manual webhook/automation config:

  - an **event** entity (``event.netmon_alert``) that fires once per alert, with
    ``event_type`` = severity (info/warning/critical) and the rule/message/details
    as attributes. Drive automations off this (e.g. notify your phone when
    ``event_type == "critical"``).
  - a **sensor** entity (``sensor.netmon_last_alert``) holding the most recent
    alert message, with severity/rule/details as attributes. Published retained,
    so it survives HA and netmon restarts. Good for dashboards.

Both entities share one HA device ("netmon") and an availability topic backed by
an MQTT Last-Will, so HA shows them "unavailable" whenever netmon is down.

Delivery is non-blocking: paho's background loop owns the socket, reconnects on
its own, and ``publish()`` just queues — a slow or unreachable broker never
stalls log ingestion. ``paho.mqtt`` is imported lazily so the rest of the app
(and the test suite, which injects a fake client) doesn't hard-require it.
"""

import json
import logging

from .base import Alert, AlertSeverity, BaseAlerter

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.CRITICAL: 2,
}
_EVENT_TYPES = [s.value for s in (AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL)]

_PAYLOAD_ONLINE = "online"
_PAYLOAD_OFFLINE = "offline"


def _rank(severity: str) -> int:
    try:
        return _SEVERITY_RANK[AlertSeverity(severity.lower())]
    except (ValueError, KeyError, AttributeError):
        return _SEVERITY_RANK[AlertSeverity.CRITICAL]


class MqttAlerter(BaseAlerter):
    """Publishes alerts to MQTT and self-describes via Home Assistant discovery."""

    def __init__(
        self,
        host: str,
        port: int = 1883,
        *,
        username: str = None,
        password: str = None,
        base_topic: str = "netmon",
        discovery_prefix: str = "homeassistant",
        min_severity: str = "info",
        client_id: str = "netmon",
        keepalive: int = 60,
        client=None,
        auto_connect: bool = True,
    ):
        self.host = host
        self.port = port
        self.base_topic = base_topic.rstrip("/")
        self.discovery_prefix = discovery_prefix.rstrip("/")
        self.min_rank = _rank(min_severity)
        self.keepalive = keepalive

        # Topics
        self.availability_topic = f"{self.base_topic}/status"
        self.event_topic = f"{self.base_topic}/event"
        self.sensor_topic = f"{self.base_topic}/alert"

        if client is None:
            import paho.mqtt.client as mqtt

            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        self._client = client

        if username:
            self._client.username_pw_set(username, password)
        self._client.on_connect = self._on_connect
        # Last-Will: if netmon dies, the broker marks us offline for HA.
        self._client.will_set(self.availability_topic, _PAYLOAD_OFFLINE, qos=1, retain=True)

        if auto_connect:
            self._client.connect_async(host, port, keepalive)
            self._client.loop_start()

    # -- paho callbacks --------------------------------------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        """(Re)announce ourselves every time the connection is (re)established."""
        if getattr(reason_code, "is_failure", False):
            logger.error("MQTT connect failed: %s", reason_code)
            return
        logger.info("MQTT connected to %s:%s", self.host, self.port)
        client.publish(self.availability_topic, _PAYLOAD_ONLINE, qos=1, retain=True)
        for topic, payload in self.discovery_configs().items():
            client.publish(topic, json.dumps(payload), qos=1, retain=True)

    # -- discovery -------------------------------------------------------

    def _device(self) -> dict:
        return {
            "identifiers": ["netmon"],
            "name": "netmon",
            "manufacturer": "netmon",
            "model": "Log-O-Matic",
        }

    def discovery_configs(self) -> dict:
        """Map of {discovery_topic: config_payload} for the HA entities."""
        availability = {
            "availability_topic": self.availability_topic,
            "payload_available": _PAYLOAD_ONLINE,
            "payload_not_available": _PAYLOAD_OFFLINE,
        }
        device = self._device()
        event_config = {
            "name": "Alert",
            "unique_id": "netmon_alert_event",
            "state_topic": self.event_topic,
            "event_types": _EVENT_TYPES,
            "icon": "mdi:shield-alert",
            "device": device,
            **availability,
        }
        sensor_config = {
            "name": "Last alert",
            "unique_id": "netmon_last_alert",
            "state_topic": self.sensor_topic,
            "value_template": "{{ value_json.message }}",
            "json_attributes_topic": self.sensor_topic,
            "icon": "mdi:shield-alert",
            "device": device,
            **availability,
        }
        return {
            f"{self.discovery_prefix}/event/netmon/alert/config": event_config,
            f"{self.discovery_prefix}/sensor/netmon/last_alert/config": sensor_config,
        }

    # -- payloads --------------------------------------------------------

    def _event_payload(self, alert: Alert) -> dict:
        # HA's event platform requires `event_type` to be one of `event_types`.
        return {
            "event_type": alert.severity.value,
            "rule_name": alert.rule_name,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat(),
            "details": alert.details or {},
        }

    def _sensor_payload(self, alert: Alert) -> dict:
        return {
            "message": alert.message,
            "severity": alert.severity.value,
            "rule_name": alert.rule_name,
            "timestamp": alert.timestamp.isoformat(),
            "details": alert.details or {},
        }

    # -- BaseAlerter -----------------------------------------------------

    def send(self, alert: Alert) -> bool:
        if _SEVERITY_RANK.get(alert.severity, 0) < self.min_rank:
            return True  # below threshold — nothing to publish (still logged elsewhere)
        # Event: momentary, not retained (a retained event would re-fire on every
        # HA/broker reconnect). Sensor: retained, so "last alert" survives restarts.
        self._client.publish(self.event_topic, json.dumps(self._event_payload(alert)), qos=1, retain=False)
        self._client.publish(self.sensor_topic, json.dumps(self._sensor_payload(alert)), qos=1, retain=True)
        return True

    def close(self) -> None:
        """Mark offline and stop the network loop cleanly on shutdown."""
        try:
            self._client.publish(self.availability_topic, _PAYLOAD_OFFLINE, qos=1, retain=True)
            self._client.loop_stop()
            self._client.disconnect()
        except Exception as e:  # noqa: BLE001 - best-effort teardown
            logger.error("MQTT shutdown error: %s", e)
