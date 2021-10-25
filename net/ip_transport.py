from __future__ import annotations

import logging
import socket
from typing import Callable
from typing import Optional
from typing import Tuple
from typing import Union

logger = logging.getLogger(__name__)


class IPTransport:
    """Models low level bidirectional socket transport."""

    def __init__(
            self,
            process_callback: Optional[Callable[[IPTransport], None]] = None,
            name: Optional[str] = None,
    ):
        self.name: Optional[str] = name
        self._sock: Optional[socket.socket] = None
        self.addr: Optional[Tuple[str, int]] = None
        self._read_buffer = bytearray()
        self._write_buffer = bytearray()
        self._on_bytes_read: Optional[Callable[[IPTransport], None]] = process_callback

        self._sub_connections = set()

    @property
    def connected(self) -> bool:
        return self._sock is not None

    @property
    def read_buffer(self) -> bytearray:
        return self._read_buffer

    def shift_read_buffer(self, size):
        self._read_buffer = bytearray(self._read_buffer[size:])

    def set_connection(self, sock, addr):
        logger.debug(f"{self.__class__.__name__}::set_connection to f{addr}")
        self._sock = sock
        self.addr = addr

    def close(self):
        if not self._sock:
            return
        if self.name:
            logger.info(f"Closing connection {self.name} to {self.addr}")
        else:
            logger.info(f"Closing connection to {self.addr}")
        self._sock.close()
        self._sock = None
        self.addr = None
        self._read_buffer.clear()
        self._write_buffer.clear()

        for connection in self._sub_connections:
            connection.close()

    def send(self, buffer: Union[bytes, bytearray]):
        self._write_buffer.extend(buffer)

    def broadcast(self, message: bytes) -> None:
        self._broadcast_sub_connections(message)
        self.send(message)

    def select(
            self,
            readable: [socket.socket],
            writable: [socket.socket],
            exceptional: [socket.socket],
    ) -> None:
        """Adds this transport's socket(s) to the given `select` arrays."""
        self._select_sub_connections(readable, writable, exceptional)

        if not self._sock:
            return

        readable.append(self._sock)
        exceptional.append(self._sock)
        if self._write_buffer:
            writable.append(self._sock)

    def process(
            self,
            readable: [socket.socket],
            writable: [socket.socket],
            exceptional: [socket.socket],
    ) -> bool:
        """Processes this transport's socket(s)."""
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
            data = self._sock.recv(4096)
            if not data:
                if self.name:
                    logger.info(
                        f"Remote closed in IPTransport '{self.name}' to {self.addr}"
                    )
                else:
                    logger.info(f"Remote closed in IPTransport to {self.addr}")
                self.close()
                return False

            self._recv(data)
            if self._on_bytes_read:
                self._on_bytes_read(self)

        if self._sock in writable:
            bytes_sent = self._sock.send(self._write_buffer)
            self._write_buffer = self._write_buffer[bytes_sent:]

        return True

    def _recv(self, data: bytes):
        self._read_buffer.extend(data)

    def _select_sub_connections(
            self,
            readable: [socket.socket],
            writable: [socket.socket],
            exceptional: [socket.socket],
    ):

        for connection in self._sub_connections:
            connection.select(readable, writable, exceptional)

    def _process_sub_connections(
            self,
            readable: [socket.socket],
            writable: [socket.socket],
            exceptional: [socket.socket],
    ):
        closed_connections = set()
        for connection in self._sub_connections:
            try:
                if not connection.process(readable, writable, exceptional):
                    connection.close()
                    closed_connections.add(connection)
            except ConnectionResetError:
                connection.close()
                closed_connections.add(connection)

        self._sub_connections -= closed_connections

    def _add_sub_connection(self, new_transport: IPTransport):
        self._sub_connections.add(new_transport)

    def _broadcast_sub_connections(self, message: bytes):
        for connection in self._sub_connections:
            connection.send(message)
