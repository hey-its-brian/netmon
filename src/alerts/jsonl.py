import json
import os
from pathlib import Path

from .base import Alert, BaseAlerter


class JsonlAlerter(BaseAlerter):
    """Appends each alert as one JSON line to a file.

    This is the feed for external dashboards (e.g. cyd-server-monitor, which
    counts recent alerts by reading this file). It's append-only and cheap;
    rotate/truncate it externally if you care about size.
    """

    def __init__(self, path: str):
        self.path = path
        parent = Path(path).parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)

    def send(self, alert: Alert) -> bool:
        line = json.dumps(alert.to_dict())
        with open(self.path, "a") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return True
