"""Tests for the Home Assistant alerter (severity filter, payload, POST)."""

import json
import unittest
from datetime import datetime
from unittest import mock

from src.alerts.base import Alert, AlertSeverity
from src.alerts.homeassistant import HomeAssistantAlerter

URL = "http://ha.local:8123/api/webhook/netmon_alert"


def _alert(severity, rule_name="action_mismatch", message="m"):
    return Alert(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        severity=severity,
        rule_name=rule_name,
        message=message,
        details={"source_ip": "192.168.1.5"},
    )


class TestHomeAssistantAlerter(unittest.TestCase):
    def test_below_threshold_not_dispatched(self):
        a = HomeAssistantAlerter(URL, min_severity="critical")
        with mock.patch.object(a, "_dispatch") as disp:
            self.assertTrue(a.send(_alert(AlertSeverity.WARNING)))
            self.assertTrue(a.send(_alert(AlertSeverity.INFO)))
            disp.assert_not_called()

    def test_at_threshold_dispatched(self):
        a = HomeAssistantAlerter(URL, min_severity="critical")
        with mock.patch.object(a, "_dispatch") as disp:
            a.send(_alert(AlertSeverity.CRITICAL))
            disp.assert_called_once()

    def test_warning_threshold_includes_warning(self):
        a = HomeAssistantAlerter(URL, min_severity="warning")
        with mock.patch.object(a, "_dispatch") as disp:
            a.send(_alert(AlertSeverity.WARNING))
            a.send(_alert(AlertSeverity.INFO))
            self.assertEqual(disp.call_count, 1)

    def test_payload_shape(self):
        a = HomeAssistantAlerter(URL)
        payload = a._build_payload(_alert(AlertSeverity.CRITICAL))
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["rule_name"], "action_mismatch")
        self.assertIn("CRITICAL", payload["title"])
        self.assertEqual(payload["details"]["source_ip"], "192.168.1.5")

    def test_post_sends_json_to_url(self):
        a = HomeAssistantAlerter(URL)
        captured = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b""

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["method"] = req.get_method()
            return FakeResp()

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            a._post(a._build_payload(_alert(AlertSeverity.CRITICAL)))

        self.assertEqual(captured["url"], URL)
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["body"]["rule_name"], "action_mismatch")

    def test_post_swallows_errors(self):
        a = HomeAssistantAlerter(URL)
        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
            a._post({"x": 1})  # must not raise


if __name__ == "__main__":
    unittest.main()
