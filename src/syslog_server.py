import asyncio
import logging
from typing import Callable

logger = logging.getLogger(__name__)


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(self, callback: Callable[[str, str], None]):
        self.callback = callback

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle received syslog message."""
        try:
            message = data.decode("utf-8", errors="replace").strip()
            source_ip = addr[0]
            self.callback(message, source_ip)
        except Exception as e:
            logger.error(f"Error processing syslog message: {e}")

    def error_received(self, exc: Exception) -> None:
        """Handle protocol errors."""
        logger.error(f"Syslog protocol error: {exc}")


class SyslogServer:
    """Async UDP syslog server."""

    def __init__(self, host: str, port: int, callback: Callable[[str, str], None]):
        self.host = host
        self.port = port
        self.callback = callback
        self.transport = None
        self.protocol = None

    async def start(self) -> None:
        """Start the syslog server."""
        loop = asyncio.get_running_loop()

        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self.callback),
            local_addr=(self.host, self.port),
        )

        logger.info(f"Syslog server listening on {self.host}:{self.port}/udp")

    async def stop(self) -> None:
        """Stop the syslog server."""
        if self.transport:
            self.transport.close()
            logger.info("Syslog server stopped")
