"""Provides a GDB logging proxy.

See https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
See https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html
"""

from __future__ import annotations

import logging
import socket
from typing import Optional
from typing import Tuple

from .packet import GDBPacket
from net import ip_transport

logger = logging.getLogger(__name__)


class GDBProxy(ip_transport.IPTransport):
    """GDB Remote Serial Protocol proxy."""

    def __init__(self, target_addr: Tuple[str, int], colorize: bool = False):
        super().__init__(process_callback=self._on_gdb_bytes_read)

        self.log_acks = False
        self.target_addr = target_addr

        self._target: Optional[ip_transport.IPTransport] = None
        if colorize:
            self.target_color = "\x1b[34m\x1b[47m"
            self.gdb_color = "\x1b[30m\x1b[47m"
        else:
            self.target_color = ""
            self.gdb_color = ""

        self._gdb_read_buffer: bytearray = bytearray()
        self._target_read_buffer: bytearray = bytearray()

    def set_connection(self, sock, addr):
        super().set_connection(sock, addr)

        logger.debug(f"{self.target_color}Connecting to target at {self.target_addr}")
        try:
            target_sock = socket.create_connection(self.target_addr)
        except ConnectionRefusedError:
            logger.error(f"{self.target_color}Connection to Target@{self.target_addr} refused.")
            self.close()
            return

        self._target = ip_transport.IPTransport(self._on_target_bytes_read, f"Target@{self.target_addr}")
        self._target.set_connection(target_sock, self.target_addr)
        self._add_sub_connection(self._target)

    def _on_gdb_bytes_read(self, _ignored):
        buffer = self._read_buffer
        self.shift_read_buffer(len(buffer))
        self._append_gdb_read_buffer(buffer)
        self._target._write_buffer.extend(buffer)

    def _on_target_bytes_read(self, _ignored):
        buffer = self._target.read_buffer
        self._target.shift_read_buffer(len(buffer))
        self._append_target_read_buffer(buffer)

        self._write_buffer.extend(buffer)

    def _append_gdb_read_buffer(self, data: bytes):
        self._unescape_and_append(self._gdb_read_buffer, data)
        bytes_consumed = self._log_rsp_bytes(f"{self.gdb_color}GDB    :", self._gdb_read_buffer)
        if bytes_consumed:
            self._gdb_read_buffer = bytearray(self._gdb_read_buffer[bytes_consumed:])

    def _append_target_read_buffer(self, data: bytes):
        self._unescape_and_append(self._target_read_buffer, data)
        bytes_consumed = self._log_rsp_bytes(f"{self.target_color}TARGET :", self._target_read_buffer)
        if bytes_consumed:
            self._target_read_buffer = bytearray(self._target_read_buffer[bytes_consumed:])

    @staticmethod
    def _unescape_and_append(buffer: bytearray, data: bytes):
        # RSP uses '}' as an escape character. Escapes are processed in this method
        # before adding to the read buffer to simplify parsing.

        if not data:
            return

        # Process any left over escapes.
        if buffer and buffer[-1] == GDBPacket.RSP_ESCAPE_CHAR:
            buffer[-1] = data[0] ^ 0x20
            data = data[1:]

        escape_char_index = data.find(GDBPacket.RSP_ESCAPE_CHAR)
        while escape_char_index >= 0:
            if escape_char_index == len(data):
                # If there are no more characters after the escape char, just add it to the buffer and let it be
                # processed when more data is received.
                break

            if escape_char_index:
                buffer.extend(data[: escape_char_index - 1])

            unescaped = data[escape_char_index + 1] ^ 0x20
            buffer.append(unescaped)
            data = data[escape_char_index + 2 :]

        buffer.extend(data)

    def _log_rsp_bytes(self, log_prefix: str, buffer: bytearray) -> int:
        total_bytes_consumed = 0
        pkt = GDBPacket()

        buffer_len = len(buffer)
        while total_bytes_consumed < buffer_len:
            if buffer[total_bytes_consumed] == ord("+"):
                if self.log_acks:
                    logger.info(f"{log_prefix}: ack")
                total_bytes_consumed += 1
                continue

            if buffer[total_bytes_consumed] == ord("-"):
                if self.log_acks:
                    logger.info(f"{log_prefix}: nack")
                total_bytes_consumed += 1
                continue

            if buffer[total_bytes_consumed] == 0x03:
                logger.info(f"{log_prefix}: Interrupt request")
                total_bytes_consumed += 1
                continue

            leader = buffer[total_bytes_consumed:].find(GDBPacket.PACKET_LEADER)
            if leader > 0:
                logger.warning(
                    f"{log_prefix} Skipping {leader} non-leader bytes {buffer[total_bytes_consumed:total_bytes_consumed + leader].hex()}"
                )

            bytes_consumed = pkt.parse(buffer[leader:])
            if not bytes_consumed:
                break
            total_bytes_consumed += bytes_consumed

            if pkt.data:
                logger.info(f"{log_prefix} Received packet {pkt}")
            else:
                logger.info(f"{log_prefix} Received empty packet")
            logger.debug(
                f"{log_prefix} After processing: [{len(buffer)}] {buffer.hex()}"
            )

        return total_bytes_consumed
