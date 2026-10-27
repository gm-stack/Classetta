"""ANSI colours for the trace lines, and the formatter that applies them.

The lines themselves carry no escape codes: the log's console formatter
adds them, so a file or a pipe gets plain text.  A record says which
kind of trace it is through the `trace` field (see the `extra` argument
of the logging calls): a trap is red, the application's own calls cyan;
anything else keeps the terminal's own colour.
"""

from __future__ import annotations

import logging

RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"

_COLORS = {"trap": RED, "func": CYAN}


class TraceFormatter(logging.Formatter):
    """The plain message, with the trace lines in their colours when
    the stream is a terminal."""

    def __init__(self, fmt: str = "%(message)s", tty: bool = False):
        super().__init__(fmt)
        self.tty = tty

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        color = _COLORS.get(getattr(record, "trace", None))
        return f"{color}{text}{RESET}" if color and self.tty else text


def setup(log_file: str | None = None, level: int = logging.INFO) -> None:
    """One log for the whole run: the screen answers with colours, and
    a file -- when asked for -- gets the same lines plain.  `level`
    goes to the screen; the file always takes everything."""
    root = logging.getLogger("macrt")
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(TraceFormatter(tty=_is_tty(console.stream)))
    root.addHandler(console)
    if log_file:
        file = logging.FileHandler(log_file)
        file.setFormatter(TraceFormatter())        # no tty: plain
        root.addHandler(file)


def _is_tty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:                                # noqa: BLE001
        return False
