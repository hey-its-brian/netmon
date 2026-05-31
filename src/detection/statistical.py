import math
from datetime import datetime, timedelta
from typing import Optional

from ..alerts.base import Alert, AlertSeverity
from ..storage.database import Database


class StatisticalDetector:
    """Statistical baseline anomaly detection."""

    def __init__(self, config: dict, database: Database):
        self.config = config
        self.db = database
        self.enabled = config.get("enabled", True)
        self.learning_days = config.get("learning_days", 7)
        self.deviation_threshold = config.get("deviation_threshold", 3.0)
        self._last_update = None
        self._update_interval = timedelta(hours=1)

    def is_learning(self) -> bool:
        """Check if we're still in the learning period."""
        first_log = self.db.get_first_log_timestamp()
        if not first_log:
            return True

        days_of_data = (datetime.now() - first_log).days
        return days_of_data < self.learning_days

    def update_baselines(self) -> None:
        """Update baseline metrics (called periodically)."""
        if not self.enabled:
            return

        now = datetime.now()

        # Only update once per hour
        if self._last_update and (now - self._last_update) < self._update_interval:
            return

        self._last_update = now
        self._update_hourly_connection_baseline()
        self._update_block_ratio_baseline()

    def _update_hourly_connection_baseline(self) -> None:
        """Update the hourly connection count baseline."""
        hour = datetime.now().hour
        stats = self.db.get_hourly_stats(hours=1)
        current_count = stats["total"]

        metric_name = "hourly_connections"
        existing = self.db.get_baseline(metric_name, hour_of_day=hour)

        if existing:
            # Incremental update using Welford's algorithm
            n = existing["sample_count"] + 1
            old_mean = existing["mean"]
            old_std = existing["std_dev"]

            delta = current_count - old_mean
            new_mean = old_mean + delta / n

            # Update variance
            if n > 1:
                old_variance = old_std ** 2
                new_variance = old_variance + (delta * (current_count - new_mean) - old_variance) / n
                new_std = math.sqrt(max(0, new_variance))
            else:
                new_std = 0

            self.db.save_baseline(metric_name, new_mean, new_std, n, hour_of_day=hour)
        else:
            # First sample
            self.db.save_baseline(metric_name, float(current_count), 0.0, 1, hour_of_day=hour)

    def _update_block_ratio_baseline(self) -> None:
        """Update the block ratio baseline."""
        stats = self.db.get_hourly_stats(hours=1)
        if stats["total"] == 0:
            return

        current_ratio = stats["blocked"] / stats["total"]
        metric_name = "block_ratio"
        existing = self.db.get_baseline(metric_name)

        if existing:
            n = existing["sample_count"] + 1
            old_mean = existing["mean"]
            old_std = existing["std_dev"]

            delta = current_ratio - old_mean
            new_mean = old_mean + delta / n

            if n > 1:
                old_variance = old_std ** 2
                new_variance = old_variance + (delta * (current_ratio - new_mean) - old_variance) / n
                new_std = math.sqrt(max(0, new_variance))
            else:
                new_std = 0

            self.db.save_baseline(metric_name, new_mean, new_std, n)
        else:
            self.db.save_baseline(metric_name, current_ratio, 0.0, 1)

    def check_deviations(self) -> list[Alert]:
        """Check current metrics against baselines."""
        if not self.enabled or self.is_learning():
            return []

        alerts = []

        alert = self._check_hourly_connections()
        if alert:
            alerts.append(alert)

        alert = self._check_block_ratio()
        if alert:
            alerts.append(alert)

        return alerts

    def _check_hourly_connections(self) -> Optional[Alert]:
        """Check if current hourly connections deviate from baseline."""
        hour = datetime.now().hour
        baseline = self.db.get_baseline("hourly_connections", hour_of_day=hour)

        if not baseline or baseline["std_dev"] == 0:
            return None

        stats = self.db.get_hourly_stats(hours=1)
        current = stats["total"]

        z_score = (current - baseline["mean"]) / baseline["std_dev"]

        if abs(z_score) > self.deviation_threshold:
            direction = "above" if z_score > 0 else "below"
            return Alert(
                timestamp=datetime.now(),
                severity=AlertSeverity.WARNING,
                rule_name="connection_anomaly",
                message=f"Hourly connections significantly {direction} normal",
                details={
                    "current": current,
                    "baseline_mean": round(baseline["mean"], 2),
                    "baseline_std": round(baseline["std_dev"], 2),
                    "z_score": round(z_score, 2),
                    "threshold": self.deviation_threshold,
                },
            )
        return None

    def _check_block_ratio(self) -> Optional[Alert]:
        """Check if block ratio deviates from baseline."""
        baseline = self.db.get_baseline("block_ratio")

        if not baseline or baseline["std_dev"] == 0:
            return None

        stats = self.db.get_hourly_stats(hours=1)
        if stats["total"] == 0:
            return None

        current_ratio = stats["blocked"] / stats["total"]
        z_score = (current_ratio - baseline["mean"]) / baseline["std_dev"]

        if z_score > self.deviation_threshold:
            return Alert(
                timestamp=datetime.now(),
                severity=AlertSeverity.WARNING,
                rule_name="block_ratio_anomaly",
                message="Unusual increase in blocked connections",
                details={
                    "current_ratio": round(current_ratio * 100, 1),
                    "baseline_ratio": round(baseline["mean"] * 100, 1),
                    "z_score": round(z_score, 2),
                    "blocked": stats["blocked"],
                    "total": stats["total"],
                },
            )
        return None
