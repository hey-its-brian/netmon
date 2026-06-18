"""Tests for the MQTT alerter (severity gate, payloads, discovery, lifecycle).

A fake MQTT client records publish() calls so these run without a broker or the
paho package. The alerter imports paho lazily and only when it builds its own
client, so injecting a fake here keeps the suite dependency-free.
"""

import json
import unittest
from datetime import datetime

from src.alerts.base import Alert, AlertSeverity
from src.alerts.mqtt import MqttAlerter


class FakeClient:
    """Records publish() calls; no-ops the connection methods."""

    def __init__(self):
        self.published = []          # list of (topic, payload, qos, retain)
        self.will = None
        self.userpass = None
        self.on_connect = None
        self.loop_started = False
        self.disconnected = False

    def username_pw_set(self, username, password=None):
        self.userpass = (username, password)

    def will_set(self, topic, payload, qos=0, retain=False):
        self.will = (topic, payload, qos, retain)

    def publish(self, topic, payload=None, qos=0, retain=False):
        self.published.append((topic, payload, qos, retain))

    def loop_start(self):
        self.loop_started = True

    def loop_stop(self):
        self.loop_started = False

    def connect_async(self, *a, **k):
        pass

    def disconnect(self):
        self.disconnected = True

    # helpers for assertions
    def topics(self):
        return [t for (t, _p, _q, _r) in self.published]

    def payload_for(self, topic):
        for (t, p, _q, _r) in self.published:
            if t == topic:
                return json.loads(p) if isinstance(p, str) and p.startswith(("{", "[")) else p
        return None


def _alert(severity, rule_name="action_mismatch", message="m"):
    return Alert(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        severity=severity,
        rule_name=rule_name,
        message=message,
        details={"source_ip": "192.168.1.5"},
    )


def _alerter(client, **kwargs):
    return MqttAlerter("broker.local", client=client, auto_connect=False, **kwargs)


class TestMqttAlerter(unittest.TestCase):
    def test_below_threshold_not_published(self):
        c = FakeClient()
        a = _alerter(c, min_severity="critical")
        self.assertTrue(a.send(_alert(AlertSeverity.WARNING)))
        self.assertTrue(a.send(_alert(AlertSeverity.INFO)))
        self.assertEqual(c.published, [])

    def test_at_threshold_publishes_event_and_sensor(self):
        c = FakeClient()
        a = _alerter(c, min_severity="critical")
        a.send(_alert(AlertSeverity.CRITICAL))
        self.assertIn(a.event_topic, c.topics())
        self.assertIn(a.sensor_topic, c.topics())

    def test_warning_threshold_includes_warning_excludes_info(self):
        c = FakeClient()
        a = _alerter(c, min_severity="warning")
        a.send(_alert(AlertSeverity.WARNING))
        a.send(_alert(AlertSeverity.INFO))
        # warning publishes 2 messages (event + sensor); info publishes none
        self.assertEqual(len(c.published), 2)

    def test_default_severity_publishes_everything(self):
        c = FakeClient()
        a = _alerter(c)  # default min_severity="info"
        a.send(_alert(AlertSeverity.INFO))
        self.assertEqual(len(c.published), 2)

    def test_event_payload_shape(self):
        c = FakeClient()
        a = _alerter(c)
        a.send(_alert(AlertSeverity.CRITICAL))
        payload = c.payload_for(a.event_topic)
        self.assertEqual(payload["event_type"], "critical")  # HA requires event_type
        self.assertEqual(payload["rule_name"], "action_mismatch")
        self.assertEqual(payload["details"]["source_ip"], "192.168.1.5")

    def test_sensor_payload_shape(self):
        c = FakeClient()
        a = _alerter(c)
        a.send(_alert(AlertSeverity.WARNING, message="over-blocked"))
        payload = c.payload_for(a.sensor_topic)
        self.assertEqual(payload["severity"], "warning")
        self.assertEqual(payload["message"], "over-blocked")

    def test_event_not_retained_sensor_retained(self):
        c = FakeClient()
        a = _alerter(c)
        a.send(_alert(AlertSeverity.CRITICAL))
        retain = {t: r for (t, _p, _q, r) in c.published}
        self.assertFalse(retain[a.event_topic])   # momentary — must not re-fire on reconnect
        self.assertTrue(retain[a.sensor_topic])    # retained — survives restart

    def test_lwt_set_to_offline(self):
        c = FakeClient()
        a = _alerter(c)
        self.assertEqual(c.will[0], a.availability_topic)
        self.assertEqual(c.will[1], "offline")
        self.assertTrue(c.will[3])  # retained

    def test_on_connect_announces_online_and_discovery(self):
        c = FakeClient()
        a = _alerter(c)
        a._on_connect(c, None, {}, _ReasonOK())
        # availability online
        self.assertIn((a.availability_topic, "online", 1, True), c.published)
        # both discovery configs published retained
        for topic in a.discovery_configs():
            cfg = c.payload_for(topic)
            self.assertIn("device", cfg)
            self.assertEqual(cfg["device"]["identifiers"], ["netmon"])

    def test_discovery_topics_use_prefix(self):
        c = FakeClient()
        a = _alerter(c, discovery_prefix="ha")
        topics = list(a.discovery_configs().keys())
        self.assertIn("ha/event/netmon/alert/config", topics)
        self.assertIn("ha/sensor/netmon/last_alert/config", topics)

    def test_event_config_declares_severity_event_types(self):
        c = FakeClient()
        a = _alerter(c)
        cfg = a.discovery_configs()["homeassistant/event/netmon/alert/config"]
        self.assertEqual(cfg["event_types"], ["info", "warning", "critical"])

    def test_username_password_set_when_given(self):
        c = FakeClient()
        _alerter(c, username="user", password="pw")
        self.assertEqual(c.userpass, ("user", "pw"))

    def test_close_marks_offline_and_stops_loop(self):
        c = FakeClient()
        a = _alerter(c)
        a.close()
        self.assertIn((a.availability_topic, "offline", 1, True), c.published)
        self.assertFalse(c.loop_started)
        self.assertTrue(c.disconnected)


class _ReasonOK:
    """Stand-in for paho's ReasonCode on a successful connect."""

    is_failure = False


if __name__ == "__main__":
    unittest.main()
