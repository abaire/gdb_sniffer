"""Manages a socket to accept remote bridges to an XBDM."""
from __future__ import annotations

import logging
import socket
from typing import Callable
from typing import Optional
from typing import Tuple

from net import ip_transport

logger = logging.getLogger(__name__)


class Listener(ip_transport.IPTransport):
    """Creates a listener that will accept IPTransport connections."""

    def __init__(
            self,
            listen_addr: Tuple[str, int],
            handler: Callable[
                [socket.socket, Tuple[str, int]], Optional[ip_transport.IPTransport]
            ],
    ):
        super().__init__(None, "")
        self._sock = socket.create_server(listen_addr, backlog=1)
        self._handler = handler

        self.addr = self._sock.getsockname()
        self.name = f"{self.__class__.__name__}@{self.addr[1]}"

    def process(
            self,
            readable: [socket.socket],
            writable: [socket.socket],
            exceptional: [socket.socket],
    ) -> bool:
        self._process_sub_connections(readable, writable, exceptional)

        if not self._sock:
            return True

        if self._sock in exceptional:
            if self.name:
                logger.info(
                    f"Socket exception in IPTransport {self.name} to {self.addr}"
                )
            else:
                logger.info(f"Socket exception in IPTransport to {self.addr}")
            return False

        if self._sock in readable:
            remote, remote_addr = self._sock.accept()
            transport = self._handler(remote, remote_addr)
            if not transport:
                remote.shutdown(socket.SHUT_RDWR)
                remote.close()
                return True

            self._add_sub_connection(transport)
            logger.debug(
                f"Accepted connection from {remote_addr}"
            )

        return True

    def close(self):
        super().close()
