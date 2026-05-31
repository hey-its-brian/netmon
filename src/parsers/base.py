from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ParsedLog:
    """Represents a parsed log entry."""
    timestamp: datetime
    source_ip: str
    log_type: str
    action: Optional[str] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    interface: Optional[str] = None
    direction: Optional[str] = None
    raw: str = ""


class BaseParser(ABC):
    """Base class for log parsers."""

    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        """Check if this parser can handle the given log line."""
        pass

    @abstractmethod
    def parse(self, raw_log: str, source_ip: str) -> Optional[ParsedLog]:
        """Parse a raw log line into a ParsedLog object."""
        pass
