import logging


class ANSIFormatter(logging.Formatter):

    ANSI_BLACK = "\x1b[30m"
    ANSI_RED = "\x1b[31m"
    ANSI_GREEN = "\x1b[32m"
    ANSI_YELLOW = "\x1b[33m"
    ANSI_BLUE = "\x1b[34m"
    ANSI_MAGENTA = "\x1b[35m"
    ANSI_CYAN = "\x1b[36m"
    ANSI_WHITE = "\x1b[37m"

    ANSI_BRIGHT_BLACK = "\x1b[30m"
    ANSI_BRIGHT_RED = "\x1b[31m"
    ANSI_BRIGHT_GREEN = "\x1b[32m"
    ANSI_BRIGHT_YELLOW = "\x1b[33m"
    ANSI_BRIGHT_BLUE = "\x1b[34m"
    ANSI_BRIGHT_MAGENTA = "\x1b[35m"
    ANSI_BRIGHT_CYAN = "\x1b[36m"
    ANSI_BRIGHT_WHITE = "\x1b[37m"

    ANSI_DEFAULT = "\x1b[39m"

    ANSI_RESET = "\x1b[0m"
    ANSI_BOLD = "\x1b[1m"
    ANSI_UNDERLINE = "\x1b[4m"
    ANSI_REVERSED = "\x1b[7m"

    DEFAULT_FORMAT_STR = "%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"

    FORMATS = {
        logging.DEBUG: ANSI_BRIGHT_BLACK + r"%s" + ANSI_RESET,
        logging.INFO: ANSI_GREEN + r"%s" + ANSI_RESET,
        logging.WARNING: ANSI_YELLOW + r"%s" + ANSI_RESET,
        logging.ERROR: ANSI_RED + r"%s" + ANSI_RESET,
        logging.CRITICAL: ANSI_REVERSED + ANSI_RED + r"%s" + ANSI_RESET,
    }

    def __init__(self, fmt: str = DEFAULT_FORMAT_STR, **kw):
        super().__init__(fmt=fmt, **kw)

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno) % self._fmt
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def colorize_logs(**kw) -> ANSIFormatter:
    """Enables ANSI colorization of logs."""
    formatter = ANSIFormatter(**kw)

    for h in logging.root.handlers:
        h.setFormatter(formatter)

    return formatter
