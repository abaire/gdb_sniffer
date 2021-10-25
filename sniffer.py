#!/usr/bin/env python3
"""Logging proxy for GDB Remote Serial Protocol."""

import argparse
import logging
import threading
import select
import sys
from typing import Optional
from typing import Tuple

from gdb import proxy
from net import listener


logger = logging.getLogger(__name__)
SELECT_TIMEOUT_SECS = 0.100


class Sniffer:
    def __init__(self, target_addr: Tuple[str, int], listen_addr: Tuple[str, int]):
        self.target_addr = target_addr
        self.listen_addr = listen_addr
        self._running = True
        self._thread = threading.Thread(
            target=self._thread_main, name=f"GDB sniffer proxy"
        )

        def accept_connection(sock, addr):
            ret = proxy.GDBProxy(self.target_addr)
            ret.set_connection(sock, addr)
            return ret

        self._listener = listener.Listener(self.listen_addr, accept_connection)

    def run(self):
        self._thread.start()

    def _thread_main(self):
        while self._running:
            readable = []
            writable = []
            exceptional = []

            self._listener.select(readable, writable, exceptional)

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, SELECT_TIMEOUT_SECS
            )

            try:
                if not self._listener.process(readable, writable, exceptional):
                    self._listener.close()
                    print("GDB connection closed")
                    self._running = True

            except ConnectionResetError as e:
                logger.error("TODO: handle connection reset gracefully")
                logger.error(e)
                self._listener.close()

        logger.debug(f"Shutting down sniffer proxy to {self.target_addr}")
        self._close()

    def shutdown(self):
        logger.debug(f"Shutting down sniffer proxy to {self.target_addr}")
        self._running = False
        self._thread.join()
        self._thread = None
        self._close()

    def _close(self):
        if self._listener:
            self._listener.close()


def main(args):
    log_level = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(level=log_level)
    if args.color:
        from util import ansi_formatter
        ansi_formatter.colorize_logs()

    logger.debug("Startup")

    sniffer = Sniffer(args.target, (args.listen_ip, args.listen_port))
    sniffer.run()

    print("Enter 'quit' or 'exit' to shut down.")
    for line in sys.stdin:
        line = line.strip()
        if line.startswith("quit") or line.startswith("exit"):
            break
        print("Enter 'quit' or 'exit' to shut down.")

    sniffer.shutdown()

    return 0


def ip_addr(value) -> (str, Tuple[str, int]):
    components = value.split(":")
    if len(components) > 2:
        raise argparse.ArgumentTypeError(
            f"Address must be of the form [ip]:port"
        )

    components = list(components)
    components[1] = int(components[1])

    return tuple(components)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "target",
        metavar="target_addr",
        type=ip_addr,
        help="The GDB server to interact with. Format: ip[:port].",
    )

    parser.add_argument(
        "-lip",
        "--listen_ip",
        metavar="ip_address",
        default="",
        help="IP address to listen on for GDB connections.",
    )

    parser.add_argument(
        "-p",
        "--listen_port",
        metavar="port",
        type=int,
        default=0,
        help="Port to listen on for GDB connections.",
    )

    parser.add_argument(
        "-c",
        "--color",
        help="Enables colorized logs.",
        action="store_true",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enables verbose logging information.",
        action="store_true",
    )

    args = parser.parse_args()

    sys.exit(main(args))
