import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

import yaml

from .alerts.base import BaseAlerter
from .alerts.stdout import StdoutAlerter
from .detection.correlation import CorrelationDetector
from .detection.rules import RuleEngine
from .detection.statistical import StatisticalDetector
from .parsers.base import BaseParser, ParsedLog
from .parsers.pfsense import PfSenseParser
from .storage.database import Database
from .syslog_server import SyslogServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class NetworkLogMonitor:
    """Main application class."""

    def __init__(self, config_path: str = "settings.yaml"):
        self.config = self._load_config(config_path)
        self.parsers: list[BaseParser] = []
        self.alerters: list[BaseAlerter] = []
        self.database: Optional[Database] = None
        self.rule_engine: Optional[RuleEngine] = None
        self.stat_detector: Optional[StatisticalDetector] = None
        self.correlation_detector: Optional[CorrelationDetector] = None
        self.syslog_server: Optional[SyslogServer] = None
        self._running = False
        self._stats_task: Optional[asyncio.Task] = None

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return {}

        with open(path) as f:
            return yaml.safe_load(f) or {}

    def _setup_components(self) -> None:
        """Initialize all components."""
        # Storage
        storage_config = self.config.get("storage", {})
        db_path = storage_config.get("database", "/data/netmon.db")
        retention_days = storage_config.get("retention_days", 30)
        store_raw = storage_config.get("store_raw", True)
        self.database = Database(db_path, retention_days, store_raw)
        logger.info(f"Database initialized: {db_path}")

        # Parsers
        self.parsers = [PfSenseParser()]
        logger.info(f"Loaded {len(self.parsers)} parser(s)")

        # Detection
        detection_config = self.config.get("detection", {})
        self.rule_engine = RuleEngine(
            detection_config.get("rules", {}),
            self.database,
        )
        self.stat_detector = StatisticalDetector(
            detection_config.get("statistical", {}),
            self.database,
        )
        self.correlation_detector = CorrelationDetector(
            detection_config.get("correlation", {}),
        )
        logger.info("Detection engines initialized")

        # Alerters
        alerts_config = self.config.get("alerts", {})
        if alerts_config.get("stdout", True):
            self.alerters.append(StdoutAlerter())
        logger.info(f"Loaded {len(self.alerters)} alerter(s)")

        # Syslog server
        syslog_config = self.config.get("syslog", {})
        host = syslog_config.get("host", "0.0.0.0")
        port = syslog_config.get("port", 514)
        self.syslog_server = SyslogServer(host, port, self._handle_log)

    def _handle_log(self, raw_log: str, source_ip: str) -> None:
        """Process a received log message."""
        parsed: Optional[ParsedLog] = None

        for parser in self.parsers:
            if parser.can_parse(raw_log):
                parsed = parser.parse(raw_log, source_ip)
                if parsed:
                    break

        if not parsed:
            logger.debug(f"No parser matched: {raw_log[:100]}")
            return

        # Store the log
        self.database.store_log(parsed)

        # Run rule-based (threshold) detection
        alerts = self.rule_engine.evaluate(parsed)
        for alert in alerts:
            self._send_alert(alert)

        # Run rule-to-log correlation against the configured pfSense ruleset
        for alert in self.correlation_detector.evaluate(parsed):
            self._send_alert(alert)

    def _send_alert(self, alert) -> None:
        """Send an alert through all alerters."""
        for alerter in self.alerters:
            try:
                alerter.send(alert)
            except Exception as e:
                logger.error(f"Failed to send alert via {type(alerter).__name__}: {e}")

    async def _periodic_tasks(self) -> None:
        """Run periodic maintenance tasks."""
        while self._running:
            try:
                # Update statistical baselines
                self.stat_detector.update_baselines()

                # Check for statistical anomalies
                if not self.stat_detector.is_learning():
                    alerts = self.stat_detector.check_deviations()
                    for alert in alerts:
                        self._send_alert(alert)
                else:
                    logger.info("Statistical detector in learning mode")

                # Cleanup old logs periodically
                deleted = self.database.cleanup_old_logs()
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} old log entries")

            except Exception as e:
                logger.error(f"Error in periodic tasks: {e}")

            await asyncio.sleep(3600)  # Run every hour

    async def run(self) -> None:
        """Run the application."""
        self._setup_components()
        self._running = True

        # Start syslog server
        await self.syslog_server.start()

        # Start periodic tasks
        self._stats_task = asyncio.create_task(self._periodic_tasks())

        logger.info("Network Log Monitor started")

        # Wait for shutdown signal
        stop_event = asyncio.Event()

        def signal_handler():
            logger.info("Shutdown signal received")
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)

        await stop_event.wait()
        await self.shutdown()

    def replay_file(self, path: str) -> dict:
        """Replay a log file through the full pipeline (parse -> store -> detect).

        Useful for testing and for analysing an existing pfSense filter.log
        without a live syslog feed. Note: threshold/statistical rules that key
        off "the last N minutes from now" will not fire on historical data, but
        parsing, storage, and rule-to-log correlation work fully.
        """
        self._setup_components()

        stats = {"lines": 0, "parsed": 0}
        path_obj = Path(path)
        with path_obj.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                stats["lines"] += 1
                self._handle_log_counting(line, "replay", stats)

        logger.info(
            "Replay complete: %d line(s) read, %d parsed and stored from %s",
            stats["lines"],
            stats["parsed"],
            path,
        )
        return stats

    def _handle_log_counting(self, raw_log: str, source_ip: str, stats: dict) -> None:
        """Like _handle_log but tracks how many lines actually parsed."""
        parsed: Optional[ParsedLog] = None
        for parser in self.parsers:
            if parser.can_parse(raw_log):
                parsed = parser.parse(raw_log, source_ip)
                if parsed:
                    break
        if not parsed:
            return

        stats["parsed"] += 1
        self.database.store_log(parsed)

        for alert in self.rule_engine.evaluate(parsed):
            self._send_alert(alert)
        for alert in self.correlation_detector.evaluate(parsed):
            self._send_alert(alert)

    async def shutdown(self) -> None:
        """Gracefully shutdown the application."""
        logger.info("Shutting down...")
        self._running = False

        if self._stats_task:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass

        if self.syslog_server:
            await self.syslog_server.stop()

        logger.info("Shutdown complete")


def main():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="netmon",
        description="Network log monitor: live syslog ingestion, storage, and detection.",
    )
    parser.add_argument(
        "config",
        nargs="?",
        default="settings.yaml",
        help="Path to settings.yaml (default: settings.yaml)",
    )
    parser.add_argument(
        "--replay",
        metavar="LOGFILE",
        help="Replay a pfSense log file through the pipeline instead of starting the syslog server.",
    )
    args = parser.parse_args()

    monitor = NetworkLogMonitor(args.config)

    if args.replay:
        monitor.replay_file(args.replay)
        return

    try:
        asyncio.run(monitor.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
