"""
macrt.ui.debugger - A window that watches the 68k processor.

It opens with --debug, alongside the Mac screen.  Pause and resume across
the top; the registers down the left; the breakpoints down the right; and
in the middle, a log of what's happened over the code around the program
counter, with the arrow at the line the PC is on.  Under that, a command
line: b, bt, bmr and bmw to break, the same with a c in front to clear.

The window never touches the processor.  The guest thread owns it and is
inside the core's native code whenever instructions are running; reading
the core from here then would read it half-written.  So the window only
leaves requests with the machine's Debug object -- pause, step, go, add a
breakpoint -- and reads back the snapshot that object takes when the core
is known to be at rest.  What it shows may be a moment old; it's never
half an instruction.

Pausing isn't exact.  The core is taken at the next safe point -- the next
trap, or the end of the next slice of instructions -- rather than at some
instruction chosen beforehand, which is what a pause button wants.  A
breakpoint is exact, and works another way: a hook the core stops on, in
the middle of running, which the machine's Debug object arranges.  Each
stop says why in the log -- the pause button, a step, or the breakpoint
that fired.

Nor is the listing a live view: it's the registers and the bytes as they
were when the core stopped.  While the application runs on, the window
keeps showing where it was stopped, which is the point of stopping it.

Where the routine around the PC is already known -- --debug reads the
symbol table for names alone, and --trace-functions for the full trace --
it's named under the listing.  Nothing here
goes and fetch one itself.
"""

from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPalette, QTextCursor
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
                             QPlainTextEdit, QPushButton, QTextEdit,
                             QVBoxLayout, QWidget)

POLL = 100                # ms between looks: the window's heartbeat
PAUSED, RUNNING, NOTHING = "paused", "running", "nothing to watch yet"
POINT_SIZE = 13
RAW_WIDTH = 20            # how wide the bytes column is, in characters
LOG_LINES = 500           # what the running log keeps: a game breaking in its
                          # own loop would otherwise fill it up


def _reverse_trap_names() -> dict[str, set[int]]:
    """Trap names to the keys they are: a break on a name catches every word
    that is one.  Built once, from the trap table the disassembler uses."""
    global _TRAP_NAMES
    if _TRAP_NAMES is None:
        from ..m68k import dispatch
        _TRAP_NAMES = {}
        for key, name in dispatch.NAMES.items():
            _TRAP_NAMES.setdefault(name, set()).add(key)
    return _TRAP_NAMES


_TRAP_NAMES = None


class DebuggerWindow(QMainWindow):
    """The window: buttons across the top, the registers down the left, the
    breakpoints down the right, and in the middle a log of what's happened
    over the listing, with a command line under it."""

    def __init__(self, display):
        super().__init__()
        self.display = display
        self.setWindowTitle("Classetta debugger")
        self.resize(1200, 620)
        self._shown = None              # what's on screen: not redrawn each poll
        self._logged_view = None        # the stop whose reason the log has: logged once
        self._closing = False           # the display's shutdown: let it close
        central = QWidget(self)
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        controls = QHBoxLayout()
        outer.addLayout(controls)
        self.play = QPushButton("Pause")
        self.step = QPushButton("Step")
        self.play.clicked.connect(self._toggled)
        self.step.clicked.connect(self._stepped)
        self.play.setEnabled(False)
        self.step.setEnabled(False)
        controls.addWidget(self.play)
        controls.addWidget(self.step)
        self.status = QLabel(NOTHING)
        self.status.setStyleSheet("color: #777")
        controls.addStretch(1)
        controls.addWidget(self.status)

        # Every panel is plain monospace text.  A table would look tidier,
        # but its columns fight each other for width and clip a value to
        # "$0000000"; text is exactly as wide as the numbers are.
        panels = QHBoxLayout()
        outer.addLayout(panels)
        self.registers = panel(mono(POINT_SIZE - 1))
        self.listing = panel(mono())
        self.log = panel(mono(POINT_SIZE - 1))
        self.breakpoints = panel(mono(POINT_SIZE - 1))
        # The register panel starts no wider than the widest register line
        # it can hold; it takes no part in the squeezing, and the listing
        # has the rest.  A routine name under the PC can be longer than
        # any of those, so _draw widens the panel for one it measures --
        # once, and never back: a name is never clipped, and the panel
        # doesn't shiver as the names change.
        self._registers_metrics = QFontMetrics(self.registers.font())
        self._registers_margin = (2 * self.registers.document().documentMargin()
                                  + 2 * self.registers.frameWidth())
        width = round(self._registers_metrics.horizontalAdvance(register_text_sample())
                      + self._registers_margin)
        self.registers.setFixedWidth(width)
        # The breakpoints panel takes the same width: a line is a command's
        # letters and one number, or "bt" and a trap's name, and the measure
        # that fits a register line fits either.
        self.breakpoints.setFixedWidth(width)
        panels.addWidget(self.registers, 0)
        panels.addWidget(rule(), 0)

        # The middle: the log over the listing, each half the height, with
        # the command line under them.  What happened, what runs next, and
        # what to do about it -- in the order a debugger works through them.
        middle = QVBoxLayout()
        panels.addLayout(middle, 1)
        middle.addWidget(self.log, 1)
        middle.addWidget(hrule(), 0)
        middle.addWidget(self.listing, 1)
        self.command = QLineEdit()
        self.command.setFont(mono(POINT_SIZE - 1))
        self.command.returnPressed.connect(self._command)
        middle.addWidget(self.command, 0)

        panels.addWidget(rule(), 0)
        panels.addWidget(self.breakpoints, 0)

        self._timer = QTimer(self, interval=POLL)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self._log("debugger open: b <addr>, bt <trap>, bmr/bmw <addr>; c in front clears one")

    # -- the machine, which there may not be one of yet -----------------------
    def _debug(self):
        """The processor's debugger hold, or None.  A processor exists only
        once some application's 68k code has started: a session of Python
        guests alone, or none yet at all, has nothing to watch.  So this is
        asked every poll, and a window opened before the game boots starts
        watching the moment there's something to watch."""
        from ..m68k.runtime import machine_exists
        system = self.display.system
        return system.machine.debug if machine_exists(system) else None

    # -- the buttons ----------------------------------------------------------
    def _toggled(self) -> None:
        debug = self._debug()
        if debug is None:
            return
        if debug.is_stopped():
            debug.request_go()
        else:
            debug.request_pause()

    def _stepped(self) -> None:
        debug = self._debug()
        if debug is not None:
            debug.request_step()

    def closeEvent(self, event):  # noqa: N802
        """The window doesn't go away at the user's wish: it's the machine's
        hold on the processor, and closing it while held would strand the
        core -- and a debugger one can lose by accident isn't much of one.
        It closes only when the display says so, at shutdown, when its job
        is to let go of the processor before the applications are killed."""
        if self._closing:
            debug = self._debug()
            if debug is not None:
                debug.detach()          # let a held core go, and stop slicing
            self._timer.stop()
            super().closeEvent(event)
        else:
            event.ignore()

    def force_close(self) -> None:
        """Close the window past its refusal: the display's way, and the
        only way."""
        self._closing = True
        self.close()

    # -- the command line -------------------------------------------------------
    # One command a line, entered as typed: b and cb and their kindred, in
    # the MacsBug letters.  An address is hex, with or without the $; a trap
    # is its name, with or without the _, or the word itself.
    def _command(self) -> None:
        text = self.command.text().strip()
        self.command.clear()
        if not text:
            return
        self._log(f"> {text}")
        debug = self._debug()
        if debug is None:
            self._log("no processor yet: nothing to break on")
            return
        parts = text.split()
        cmd, arg = parts[0].lower(), parts[1] if len(parts) > 1 else ""
        if cmd.startswith("c") and len(cmd) > 1:
            kind, clearing = cmd[1:], True
        else:
            kind, clearing = cmd, False
        try:
            if kind == "b":
                self._bp_address(debug, parse_address(arg), clearing)
            elif kind == "bt":
                self._bp_trap(debug, arg, clearing)
            elif kind in ("bmr", "bmw"):
                self._bp_memory(debug, kind[2], parse_address(arg), clearing)
            else:
                self._log(f"don't know the command {cmd}")
        except ValueError as e:
            self._log(str(e))
        self.refresh_breakpoints()

    def _bp_address(self, debug, addr: int, clearing: bool) -> None:
        if clearing:
            debug.clear_bp_addr(addr)
            self._log(f"cleared breakpoint at ${addr:06X}")
        else:
            debug.add_bp_addr(addr)
            self._log(f"breakpoint at ${addr:06X}")

    def _bp_memory(self, debug, letter: str, addr: int, clearing: bool) -> None:
        add, clear = (debug.add_bp_memr, debug.clear_bp_memr) if letter == "r" \
            else (debug.add_bp_memw, debug.clear_bp_memw)
        what = f"{'read' if letter == 'r' else 'write'} of ${addr:06X}"
        if clearing:
            clear(addr)
            self._log(f"cleared breakpoint on {what}")
        else:
            add(addr)
            self._log(f"breakpoint on {what}")

    def _bp_trap(self, debug, name: str, clearing: bool) -> None:
        keys = sorted(trap_keys(name))
        if not keys:
            self._log(f"no trap called {name}")
            return
        for key in keys:
            if clearing:
                debug.clear_bp_trap(key)
            else:
                debug.add_bp_trap(key)
        shown = f"_{dispatch_name(keys[0])}" if len(keys) == 1 else name
        self._log(f"{'cleared breakpoint on' if clearing else 'breakpoint on'} trap {shown}")

    # -- the log ----------------------------------------------------------------
    def _log(self, text: str) -> None:
        """A line added to what's happened.  The log is kept to what a window
        is tall enough to scroll through; a game that breaks at a trap in its
        own loop would otherwise fill it, and it's the last lines that say
        where things are."""
        self.log.appendPlainText(text)
        if self.log.blockCount() > LOG_LINES:
            self.log.setPlainText("\n".join(self.log.toPlainText().splitlines()[-LOG_LINES:]))
        scrollbar = self.log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # -- drawing --------------------------------------------------------------
    def refresh(self) -> None:
        debug = self._debug()
        if debug is None:
            self.play.setEnabled(False)
            self.step.setEnabled(False)
            self._show_state(NOTHING, None, "")
            return
        if not debug.attached:            # the window opened before there was
            debug.attach()                # a processor: start watching now
        held = debug.is_stopped()
        self.play.setEnabled(True)
        self.step.setEnabled(held)
        # The last snapshot stays up while the application runs on: it's
        # where the core was stopped, and there's nothing newer to show.
        self._show_state(PAUSED if held else RUNNING, debug.get_view(), debug.get_reason())
        self.refresh_breakpoints()

    def refresh_breakpoints(self) -> None:
        """The list of them, rewritten only when it's changed.  It's the
        machine's own sets that say what's broken on, so what's listed is
        what's armed, not what was typed."""
        debug = self._debug()
        lines = "\n".join(debug.bp_list()) if debug is not None else ""
        if self.breakpoints.toPlainText() != lines:
            self.breakpoints.setPlainText(lines)

    def _show_state(self, state: str, view: dict | None, reason: str) -> None:
        """Redraw only when something's changed, so a window watching a busy
        application doesn't repaint itself a dozen times a second.  The view
        is recognised by identity -- a new snapshot is a new dict -- and the
        one shown is kept, so its id can't be reused by a dict that isn't it.

        Every new stop is one the log hasn't said yet: what it was for, and
        where the core is -- the address, and the routine around it when a
        symbol table knows one.  The machine says why; the window has the
        snapshot, so the where is added here."""
        if self._shown is not None and self._shown[0] == state \
                and self._shown[1] is view:
            return
        self._shown = (state, view)
        self.status.setText(state)
        self.play.setText("Resume" if state == PAUSED else "Pause")
        if view is None:
            self._clear()
        else:
            if state == PAUSED and view is not self._logged_view:
                self._logged_view = view
                # A step says nothing: the window moving one instruction on
                # is itself the news, and a line each time would be noise.
                if reason:
                    self._log(f"{reason}{where(view)}")
            self._draw(view)

    def _clear(self) -> None:
        if self.registers.toPlainText():
            self.registers.setPlainText("")
        if self.listing.toPlainText():
            self.listing.setPlainText("")

    def _draw(self, view: dict) -> None:
        text = register_text(view)
        self._fit_registers(text)
        self.registers.setPlainText(text)
        self._draw_listing(view)

    def _fit_registers(self, text: str) -> None:
        """Widen the register panels for a line wider than the sample they
        were measured with -- a routine's name under the PC can be longer
        than any register line.  Only ever wider: a name is never clipped,
        and the panels don't shiver as the names change."""
        need = max(self._registers_metrics.horizontalAdvance(line)
                   for line in text.splitlines()) + self._registers_margin
        current = self.registers.width()
        if need > current:
            # Both panels together, so the window keeps its look.  The
            # listing, which is what gives way, has the stretch.
            self.registers.setFixedWidth(round(need))
            self.breakpoints.setFixedWidth(round(need))

    def _draw_listing(self, view: dict) -> None:
        """The code around the program counter, the arrow marking the line
        it's on.  The lines before it are what's in memory there, not what
        ran to get here."""
        pc = view["pc"]
        lines = [f"{'=>' if row.address == pc else '  '} {row.address:06X}  "
                 f"{row.raw:<{RAW_WIDTH}}  {row.text}" for row in view["listing"]]
        at = next((n for n, row in enumerate(view["listing"]) if row.address == pc), None)
        if view.get("symbol"):
            lines += ["", f"in  {view['symbol']}"]
        self.listing.setPlainText("\n".join(lines))
        self.listing.setExtraSelections([] if at is None else [current_line(self.listing, at)])


def where(view: dict) -> str:
    """Where a stop is, said the way the user asked for it: the address, and
    the routine the PC sits in with its offset from the entry -- when a
    symbol table knows one.  (The snapshot carries the symbol already in
    that shape; see Debug.snapshot.)  A PC with nothing around it to name
    says whether that's because no table is loaded, or the address is simply
    outside any routine one was made for."""
    place = f"${view['pc'] & 0xFFFFFF:06X}"
    if view.get("symbol"):
        return f" at {place}, {view['symbol']}"
    if not view.get("symbols"):
        return f" at {place}  (no symbol table loaded)"
    return f" at {place}  (not in a known routine)"


def register_text(view: dict) -> str:
    """The registers as they're written: hex, the flags by name, the mode
    and interrupt level the status register holds.  Under the PC, the
    routine it sits in, when a symbol table knows one -- the line is left
    blank when it doesn't, so SP stays where it is.  Over the data
    registers, the application the low-memory globals say is current:
    whose code these registers are running."""
    flags = view["flags"]
    lines = [f" PC  {view['pc']:08X}",
             f"     {view['symbol']}" if view.get("symbol") else ""]
    lines += [f" SP  {view['sp']:08X}",
              f" SR  {view['sr']:04X}  {flag_line(flags)}  {mode(flags)}", "",
              "CurApName:", view.get("app_name") or "(no application)", ""]
    for n, v in enumerate(view["d"]):
        lines.append(f" D{n}  {v:08X}")
    lines.append("")
    for n, v in enumerate(view["a"]):
        lines.append(f" A{n}  {v:08X}")
    return "\n".join(lines)


def mode(flags: dict) -> str:
    """The part of the status register that isn't a condition code."""
    level = flags["irq"]
    return ("sup" if flags["supervisor"] else "usr") + \
           (f" irq{level}" if level else "") + (" trace" if flags["trace"] else "")


def register_text_sample() -> str:
    """The longest line register_text can ever write, so the panel can be
    made exactly wide enough for it: a flag is a letter whether it's set or
    not, and the mode line has every part of it."""
    return " SR  FFFF  XNZVC  sup irq7 trace"


def flag_line(flags: dict) -> str:
    """The condition codes as MacsBug writes them: the ones that are set,
    among the ones that aren't."""
    return "".join(c if flags[c] else c.lower() for c in "XNZVC")


def current_line(listing, row: int) -> QTextEdit.ExtraSelection:
    """The selection covering one line of the listing: the instruction the
    PC is on, written in red.  (A wash of colour behind it instead was the
    first attempt, and read as grey mush -- the text carries the arrow
    anyway.  ExtraSelection is only defined on QTextEdit, in Qt's own
    headers, though QPlainTextEdit is what takes it.)"""
    block = listing.document().findBlockByNumber(row)
    selection = QTextEdit.ExtraSelection()
    selection.cursor = QTextCursor(block)
    selection.cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                  QTextCursor.MoveMode.KeepAnchor)
    selection.format.setForeground(current_text_colour(listing))
    return selection


def current_text_colour(widget) -> QColor:
    """Red, but the red that reads: dark ink on a light panel, a bright one
    if the desktop is a dark theme.  The rest of the window takes the
    palette's own text colour, so this follows it rather than assuming;
    either way it stays far enough from the panel behind it to be seen."""
    base = widget.palette().color(QPalette.ColorRole.Base)
    if base.lightness() < 128:
        return QColor(255, 120, 120)
    return QColor(170, 0, 0)


def panel(font: QFont) -> QPlainTextEdit:
    """A read-only panel of fixed-width text, which is what all of this is."""
    field = QPlainTextEdit()
    field.setReadOnly(True)
    field.setFont(font)
    field.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    field.setFrameShape(QFrame.Shape.NoFrame)
    return field


def rule() -> QFrame:
    """The line between the two panels."""
    line = QFrame()
    line.setFrameShape(QFrame.Shape.VLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    return line


def hrule() -> QFrame:
    """The line between the log and the listing."""
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    return line


def parse_address(text: str) -> int:
    """An address as typed: hex, with or without the $ or a 0x.  A number
    in a debugger is hex -- a MacsBug address is -- and the letters in one
    (a $2C00's C) rule out reading it any other way."""
    bare = text.strip().lstrip("$")
    if bare.lower().startswith("0x"):
        bare = bare[2:]
    if not bare:
        raise ValueError("no address given")
    try:
        return int(bare, 16)
    except ValueError:
        raise ValueError(f"{text} is not an address") from None


def trap_keys(name: str) -> set[int]:
    """The trap keys a command's argument names: a routine's name with or
    without its underscore, or a trap word itself -- a $ or 0x always makes
    a word, and a bare hex number is one when it's in the A-line range
    where every trap word is.  Nothing for a name the trap table doesn't
    know, so the caller can say so."""
    text = name.strip()
    bare = text.lstrip("$")
    explicit = text.startswith("$") or bare.lower().startswith("0x")
    try:
        word = int(bare[2:] if bare.lower().startswith("0x") else bare, 16)
    except ValueError:
        word = None
    if word is not None and (explicit or 0xA000 <= word <= 0xAFFF):
        return {dispatch_trap_key(word)}
    return set(_reverse_trap_names().get(text.lstrip("_"), ()))


def dispatch_trap_key(word: int) -> int:
    from ..m68k import dispatch
    return dispatch.trap_key(word)


def dispatch_name(key: int) -> str:
    from ..m68k import dispatch
    return dispatch.trap_name(key)


def mono(point_size: int = POINT_SIZE) -> QFont:
    font = QFont("Menlo")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSize(point_size)
    return font


def open_debugger(display) -> DebuggerWindow:
    """The window, shown.  Kept on the display so it stays alive while it's
    on screen, and raised if it's already there."""
    window = getattr(display, "debugger", None)
    if window is None:
        window = display.debugger = DebuggerWindow(display)
    window.show()
    window.raise_()
    return window
