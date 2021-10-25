"""Provides a GDB logging proxy.

See https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
See https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html
"""

from __future__ import annotations

import logging
import socket
from typing import Optional
from typing import Tuple

from net import ip_transport

logger = logging.getLogger(__name__)


class GDBProxy(ip_transport.IPTransport):
    """GDB Remote Serial Protocol proxy."""

    def __init__(self, target_addr: Tuple[str, int]):
        super().__init__(process_callback=self._on_gdb_bytes_read)

        self.target_addr = target_addr

        self._target: Optional[ip_transport.IPTransport] = None

        # self._send_queue = collections.deque()

        # self._dispatch_table: Mapping[
        #     str, Callable[[GDBPacket], None]
        # ] = self._build_dispatch_table(self)

    def set_connection(self, sock, addr):
        super().set_connection(sock, addr)

        logger.debug(f"Connecting to target at {self.target_addr}")
        try:
            target_sock = socket.create_connection(self.target_addr)
        except ConnectionRefusedError:
            logger.error(f"Connection to Target@{self.target_addr} refused.")
            self.close()
            return

        self._target = ip_transport.IPTransport(self._on_target_bytes_read, f"Target@{self.target_addr}")
        self._target.set_connection(target_sock, self.target_addr)
        self._add_sub_connection(self._target)

    def _on_target_bytes_read(self, _ignored):
        buffer = self._target.read_buffer
        self._target.shift_read_buffer(len(buffer))

        logger.info(f"TARGET : {buffer}")
        self._write_buffer.extend(buffer)

    def _on_gdb_bytes_read(self, _ignored):
        buffer = self._read_buffer
        self.shift_read_buffer(len(buffer))

        logger.info(f"GDB    : {buffer}")
        self._target._write_buffer.extend(buffer)


    # @property
    # def has_buffered_data(self) -> bool:
    #     # TODO: Make this thread safe.
    #     return self._send_queue or self._read_buffer or self._write_buffer
    #
    # def send_packet(self, pkt: GDBPacket):
    #     self._send_queue.append(pkt)
    #     self._send_next_packet()
    #
    # def _send_next_packet(self):
    #     if not self._send_queue:
    #         return
    #
    #     pkt: GDBPacket = self._send_queue.popleft()
    #     data = pkt.serialize()
    #     logger.debug(f"Sending GDB packet: {data.decode('utf-8')}")
    #     self.send(data)
    #
    # def _recv(self, data: bytes):
    #     # RSP uses '}' as an escape character. Escapes are processed in this method
    #     # before adding to the read buffer to simplify parsing.
    #
    #     if not data:
    #         return
    #
    #     # Process any left over escapes.
    #     if self._read_buffer and self._read_buffer[-1] == GDBPacket.RSP_ESCAPE_CHAR:
    #         self._read_buffer[-1] = data[0] ^ 0x20
    #         data = data[1:]
    #
    #     escape_char_index = data.find(GDBPacket.RSP_ESCAPE_CHAR)
    #     while escape_char_index >= 0:
    #         if escape_char_index == len(data):
    #             # If there are no more characters after the escape char, just add it to the buffer and let it be
    #             # processed when more data is received.
    #             break
    #
    #         if escape_char_index:
    #             self._read_buffer.extend(data[: escape_char_index - 1])
    #
    #         unescaped = data[escape_char_index + 1] ^ 0x20
    #         self._read_buffer.append(unescaped)
    #         data = data[escape_char_index + 2 :]
    #
    #     self._read_buffer.extend(data)
    #
    # def _on_gdb_bytes_read(self, _ignored):
    #     pkt = GDBPacket()
    #
    #     while self._read_buffer:
    #         if self._read_buffer[0] == ord("+"):
    #             self.shift_read_buffer(1)
    #             continue
    #
    #         if self._read_buffer[0] == ord("-"):
    #             # TODO: Handle - acks.
    #             self.shift_read_buffer(1)
    #             continue
    #
    #         if self._read_buffer[0] == 0x03:
    #             # TODO: Handle interrupt requests.
    #             logger.warning("Skipping unsupported interrupt request")
    #             self.shift_read_buffer(1)
    #             continue
    #
    #         leader = self._read_buffer.find(GDBPacket.PACKET_LEADER)
    #         if leader > 0:
    #             logger.warning(
    #                 f"Skipping {leader} non-leader bytes {self._read_buffer[:leader].hex()}"
    #             )
    #
    #         bytes_consumed = pkt.parse(self._read_buffer)
    #         if not bytes_consumed:
    #             break
    #         self.shift_read_buffer(bytes_consumed)
    #
    #         logger.debug(f"Processed packet {pkt}")
    #         logger.debug(
    #             f"After processing: [{len(self._read_buffer)}] {self._read_buffer.hex()}"
    #         )
    #
    #         if pkt.checksum_ok:
    #             if not self.features["QStartNoAckMode"]:
    #                 self.send(b"+")
    #             self._process_packet(pkt)
    #         elif not self.features["QStartNoAckMode"]:
    #             self.send(b"-")
    #
    # def _process_packet(self, pkt: GDBPacket):
    #     """Dispatches the given packet to the appropriate handler."""
    #     if len(pkt.data) > 1:
    #         command_id = pkt.data[:2]
    #         handler = self._dispatch_table.get(command_id)
    #         if handler:
    #             handler(pkt)
    #             return
    #
    #     if pkt.data:
    #         command_id = pkt.data[0]
    #         handler = self._dispatch_table.get(command_id)
    #         if handler:
    #             handler(pkt)
    #             return
    #
    #     logger.warning(f"Unsupported GDB packet {pkt}")
    #
    # @staticmethod
    # def _build_dispatch_table(target) -> Mapping[str, Callable[[GDBPacket], None]]:
    #     """Populates _dispatch_table with handler callables."""
    #     return {
    #         "!": target._handle_enable_extended_mode,
    #         "?": target._handle_query_halt_reason,
    #         "A": target._handle_argv,
    #         "b": target._handle_deprecated_command,
    #         "B": target._handle_deprecated_command,
    #         "bc": target._handle_backward_continue,
    #         "bs": target._handle_backward_step,
    #         "c": target._handle_continue,
    #         "C": target._handle_continue_with_signal,
    #         "d": target._handle_deprecated_command,
    #         "D": target._handle_detach,
    #         "F": target._handle_file_io,
    #         "g": target._handle_read_general_register,
    #         "G": target._handle_write_general_register,
    #         "H": target._handle_select_thread_for_command_group,
    #         "i": target._handle_step_instruction,
    #         "I": target._handle_signal_step,
    #         "k": target._handle_kill,
    #         "m": target._handle_read_memory,
    #         "M": target._handle_write_memory,
    #         "p": target._handle_read_register,
    #         "P": target._handle_write_register,
    #         "q": target._handle_read_query,
    #         "Q": target._handle_write_query,
    #         "r": target._handle_deprecated_command,
    #         "R": target._handle_restart_system,
    #         "s": target._handle_single_step,
    #         "S": target._handle_single_step_with_signal,
    #         "t": target._handle_search_backward,
    #         "T": target._handle_check_thread_alive,
    #         "v": target._handle_extended_v_command,
    #         "X": target._handle_write_memory_binary,
    #         "z": target._handle_insert_breakpoint_type,
    #         "Z": target._handle_remove_breakpoint_type,
    #     }
    #
    # def _handle_enable_extended_mode(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_query_halt_reason(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_argv(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_backward_continue(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_backward_step(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_continue(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_continue_with_signal(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_deprecated_command(self, pkt: GDBPacket):
    #     logger.debug(f"Ignoring deprecated command: {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_detach(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_file_io(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_read_general_register(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_write_general_register(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_select_thread_for_command_group(self, pkt: GDBPacket):
    #     if len(pkt.data) < 3:
    #         logger.error(f"Command missing parameters: {pkt.data}")
    #         self.send_packet(GDBPacket("E"))
    #         return
    #
    #     op = pkt.data[1]
    #     thread_id = int(pkt.data[2:], 16)
    #     self._command_thread_id_context[op] = thread_id
    #     self.send_packet(GDBPacket("OK"))
    #
    # def _handle_step_instruction(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_signal_step(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_kill(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_read_memory(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_write_memory(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_read_register(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_write_register(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_read_query(self, pkt: GDBPacket):
    #     query = pkt.data[1:]
    #
    #     if query.startswith("Attached"):
    #         self._handle_query_attached(pkt)
    #         return
    #
    #     if query.startswith("Supported"):
    #         self._handle_query_supported(pkt)
    #         return
    #
    #     # if p.data == "qTStatus":
    #     #     self._handle_query_trace_status(p)
    #     #     return
    #
    #     logger.error(f"Unsupported query read packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_write_query(self, pkt: GDBPacket):
    #     if pkt.data == "QStartNoAckMode":
    #         self._start_no_ack_mode()
    #         return
    #
    #     logger.error(f"Unsupported query write packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_restart_system(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_single_step(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_single_step_with_signal(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_search_backward(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_check_thread_alive(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_extended_v_command(self, pkt: GDBPacket):
    #     if pkt.data == "vMustReplyEmpty":
    #         self.send_packet(GDBPacket())
    #         return
    #
    #     logger.error(f"Unsupported v packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_write_memory_binary(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_insert_breakpoint_type(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_remove_breakpoint_type(self, pkt: GDBPacket):
    #     logger.error(f"Unsupported packet {pkt.data}")
    #     self.send_packet(GDBPacket())
    #
    # def _handle_query_attached(self, _pkt: GDBPacket):
    #     # If attached to an existing process:
    #     self.send_packet(GDBPacket("1"))
    #     # elif started new process
    #     # self.send_packet(GDBPacket("0"))
    #
    # def _handle_query_supported(self, pkt: GDBPacket):
    #     request = pkt.data.split(":", 1)
    #     if len(request) != 2:
    #         logger.error(f"Unsupported qSupported message {pkt.data}")
    #         return
    #
    #     response = []
    #     features = request[1].split(";")
    #     for feature in features:
    #         if feature == "multiprocess+":
    #             # Do not support multiprocess extensions.
    #             response.append("multiprocess-")
    #             continue
    #         if feature == "swbreak+":
    #             self.features["swbreak"] = True
    #             response.append("swbreak+")
    #             continue
    #         if feature == "hwbreak+":
    #             self.features["hwbreak"] = True
    #             response.append("hwbreak+")
    #             continue
    #         if feature == "qRelocInsn+":
    #             response.append("qRelocInsn-")
    #             continue
    #         if feature == "fork-events+":
    #             response.append("fork-events-")
    #             continue
    #         if feature == "vfork-events+":
    #             response.append("vfork-events-")
    #             continue
    #         if feature == "exec-events+":
    #             response.append("exec-events-")
    #             continue
    #         if feature == "vContSupported+":
    #             response.append("vContSupported-")
    #             continue
    #         if feature == "QThreadEvents+":
    #             response.append("QThreadEvents-")
    #             continue
    #         if feature == "no-resumed+":
    #             response.append("no-resumed-")
    #             continue
    #         if feature == "xmlRegisters=i386":
    #             self.features["xmlRegisters"] = "i386"
    #             continue
    #
    #     response.append("QStartNoAckMode+")
    #
    #     pkt = GDBPacket(";".join(response))
    #     self.send_packet(pkt)
    #
    # def _start_no_ack_mode(self):
    #     self.features["QStartNoAckMode+"] = True
    #     self.send_packet(GDBPacket("OK"))
