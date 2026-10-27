"""
macrt.ui.automation - Driving the running apps from a Python script.

`Controller` wraps a Display and synthesizes the same input the
InputRouter posts for real Qt events: it updates the Event Manager's
low-memory record of the mouse and keyboard (Mouse, MBState, KeyMap,
KeyLast) and posts EventRecords to the target process's queue.  The
guest sees it exactly as typed input: MenuKey, MenuSelect trackers and
programs that poll the KeyMap all hear it.

    macrt = Controller(display)
    macrt.wait_window()
    macrt.press("f+cmd")
    macrt.press("return")
    macrt.screenshot("after.png")

Everything that touches widgets or the guest's memory is marshalled onto
the GUI thread with the bridge; `sleep` and `wait` run on the script
thread and leave the GUI event loop running.  Coordinates are Mac
global, as in the test harness (conftest.Harness).
"""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from ..toolbox.constants import (btnState, cmdKey, controlKey, keyDown, keyUp, mouseDown,
                                 mouseUp, optionKey, shiftKey)
from ..toolbox.events import EventRecord
from ..toolbox.types import Point
from . import keymap
from .keymap import PLUS_KEYBOARD, PLUS_ARROWS, SPECIAL_CHARS, SPECIAL_KEYCODES, _KEYCODES

_MODS = {"cmd": cmdKey, "command": cmdKey, "shift": shiftKey,
         "option": optionKey, "alt": optionKey, "ctrl": controlKey, "control": controlKey}

# Named keys, to the Qt key the keymap tables are indexed by.
_NAMES = {
    "return": Qt.Key.Key_Return, "enter": Qt.Key.Key_Enter, "tab": Qt.Key.Key_Tab,
    "esc": Qt.Key.Key_Escape, "escape": Qt.Key.Key_Escape,
    "backspace": Qt.Key.Key_Backspace, "delete": Qt.Key.Key_Delete,
    "space": Qt.Key.Key_Space, "home": Qt.Key.Key_Home, "end": Qt.Key.Key_End,
    "pageup": Qt.Key.Key_PageUp, "pagedown": Qt.Key.Key_PageDown,
    "left": Qt.Key.Key_Left, "right": Qt.Key.Key_Right,
    "up": Qt.Key.Key_Up, "down": Qt.Key.Key_Down,
}


def parse_key(spec: str, keyboard: int = PLUS_KEYBOARD) -> tuple[int, int]:
    """A key spec like "f", "return" or "f+cmd" to its keyDown message
    ((key code << 8) | character) and the Mac modifier bits asked for."""
    mods, name = 0, None
    for part in spec.lower().split("+"):
        part = part.strip()
        if not part:
            continue
        if part in _MODS:
            mods |= _MODS[part]
        elif name is None:
            name = part
        else:
            raise ValueError(f"{spec!r}: more than one key")
    if name is None:
        raise ValueError(f"{spec!r}: no key")
    qt = _NAMES.get(name)
    if qt is not None:
        char = SPECIAL_CHARS[qt]
        code = PLUS_ARROWS.get(qt) if keyboard == PLUS_KEYBOARD else None
        if code is None:
            code = SPECIAL_KEYCODES[qt]
    elif len(name) == 1 and name in _KEYCODES:
        char, code = ord(name), _KEYCODES[name]
    else:
        raise ValueError(f"{spec!r}: no such key")
    return (code << 8) | char, mods


class Controller:
    """Script-facing input and observation for a Display.  Input goes to
    the front process by default; `attach(name)` picks another."""

    def __init__(self, display):
        self.d = display
        self._keyboard = display.system.model.keyboard
        self._target = None
        self._symbols: list[dict] = []
        self._symbols_meta: dict = {}

    # -- time --------------------------------------------------------------
    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def wait(self, cond, timeout: float = 10.0, what: str = "condition") -> None:
        """Poll cond (a function, run on the GUI thread) until it's true."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.d.bridge.call(cond):
                return
            time.sleep(0.02)
        raise AssertionError(f"timed out waiting for {what}")

    # -- processes and windows ---------------------------------------------
    def processes(self) -> list[str]:
        return self.d.bridge.call(lambda: [p.name for p in self.d.processes])

    def front(self) -> str | None:
        return self.d.bridge.call(lambda: getattr(self.d.front_process, "name", None))

    def attach(self, name: str) -> None:
        """Send input to the named app whether or not it's front."""
        def pick():
            for p in self.d.processes:
                if p.name == name:
                    self._target = p
                    return
            raise KeyError(name)
        self.d.bridge.call(pick)

    def windows(self) -> list[tuple[str, str]]:
        """(app, title) for each visible window of the target process."""
        return self.d.bridge.call(self._window_list)

    def wait_window(self, timeout: float = 30.0, title: str | None = None) -> None:
        """Wait for the target process to have a visible window (with this
        title, if given)."""
        self.wait(lambda: any(t == title for _, t in self._window_list())
                  if title is not None else bool(self._window_list()),
                  timeout, f"a window{' titled ' + repr(title) if title else ''}")

    def _window_list(self):
        proc = self._proc()
        return [(proc.name, w.title) for w in proc.windows if w.visible] if proc else []

    # -- keys --------------------------------------------------------------
    def key_down(self, spec: str) -> None:
        msg, mods = parse_key(spec, self._keyboard)
        self.d.bridge.call(self._post_key, msg, mods, True)

    def key_up(self, spec: str) -> None:
        msg, mods = parse_key(spec, self._keyboard)
        self.d.bridge.call(self._post_key, msg, mods, False)

    def press(self, spec: str, hold: float = 0.02) -> None:
        """A whole key press: down, a beat, up."""
        self.key_down(spec)
        time.sleep(hold)
        self.key_up(spec)

    def type_text(self, text: str, hold: float = 0.02) -> None:
        for ch in text:
            self.press({" ": "space", "\n": "return", "\t": "tab"}.get(ch, ch), hold)

    def _post_key(self, msg: int, mods: int, down: bool) -> None:
        d = self.d
        d.input.modifiers = mods | (0 if down else btnState)
        d.system.input.modifiers(d.input.modifiers)
        d.system.input.key(msg, down)
        if d.tracker is not None:
            return
        proc = self._proc()
        if proc is not None:
            proc.events.post(EventRecord(keyDown if down else keyUp, msg, 0,
                                         d.input.mac_pos, d.input.modifiers))

    # -- mouse, in Mac global coordinates ------------------------------------
    def mouse_move(self, h: int, v: int) -> None:
        self.d.bridge.call(self._move, h, v)

    def mouse_down(self, h: int, v: int) -> None:
        def press():
            self._set_input(h, v, True)
            g = self.d.global_from_mac(Point(v, h))
            self.d.mouse_down(QApplication.widgetAt(g))
        self.d.bridge.call(press)

    def mouse_up(self, h: int, v: int) -> None:
        self.d.bridge.call(self._set_input, h, v, False)
        self.d.bridge.call(self._release)

    def click(self, h: int, v: int, hold: float = 0.02) -> None:
        self.mouse_down(h, v)
        time.sleep(hold)
        self.mouse_up(h, v)

    def _move(self, h: int, v: int) -> None:
        d = self.d
        d.input.global_pos = d.global_from_mac(Point(v, h))
        d.input.mac_pos = Point(h, v)
        d.system.input.mouse(d.input.mac_pos, d.input.down)

    def _set_input(self, h: int, v: int, down: bool) -> None:
        d = self.d
        if down:
            d.input.press_time = time.monotonic()
        d.input.down = down
        d.input.modifiers = d.input.modifiers | (0 if down else btnState)
        self._move(h, v)
        d.system.input.modifiers(d.input.modifiers)

    def _release(self) -> None:
        d = self.d
        if d.tracker is not None:
            # Tracking calls eat the mouseUp, as WaitMouseUp does.
            d.tracker.release(d.input.global_pos)
            return
        if d._swallow_release:
            d._swallow_release = False
            return
        proc = self._proc()
        if proc is not None:
            proc.events.post(EventRecord(mouseUp, 0, 0, d.input.mac_pos, d.input.modifiers))

    # -- symbols, mapping, tracing ----------------------------------------
    def load_symbols(self, path: str) -> int:
        """Read a Ghidra symbol table (macrt.symtab's JSON) for the
        target process to map and trace against.  Returns how many
        functions it holds."""
        from .. import symtab
        self._symbols, self._symbols_meta = symtab.load_symbols(path)
        return len(self._symbols)

    def extract_symbols(self, ghidra_url: str = "http://127.0.0.1:8080/mcp",
                        program: str | None = None, path: str | None = None,
                        progress=None) -> int:
        """Ask a running Ghidra for every function's name, arguments and
        return value, and keep them.  The program is picked by matching
        the running app's jump table, unless named.  Saves to `path`."""
        from .. import symtab
        mcp = symtab.GhidraMcp(ghidra_url)
        if program is None:
            program = self._pick_program(mcp)
        table = symtab.extract_symbols(mcp, program, progress)
        self._symbols = table
        from .. import symtab as _st
        self._symbols_meta = {"ghidra": {"program": program, "url": ghidra_url},
                              "jank_a5": _st.jank_layout(self._proc().app.rsrc).jank_a5}
        if path:
            symtab.save_symbols(path, table, self._symbols_meta)
        return len(table)

    def _pick_program(self, mcp) -> str:
        """The open Ghidra program that is the target's application."""
        proc = self._proc()
        if proc is None or proc.app is None:
            raise RuntimeError("extract_symbols needs a 68k application")
        from .. import symtab
        return symtab.pick_program(mcp, proc.app.rsrc)

    def symbols(self) -> list[dict]:
        return list(getattr(self, "_symbols", []))

    def map_address(self, ghidra_addr: int):
        """Where Ghidra's address `ghidra_addr` is in Classetta's memory
        right now, or None if its segment isn't loaded.  Needs
        `load_symbols` (or `extract_symbols`) first -- that is what says
        this application is the one Ghidra looked at."""
        proc = self._proc()
        from .. import symtab
        layout = symtab.jank_layout(proc.app.rsrc)
        return symtab.AppMap(proc, layout).resolve(ghidra_addr)

    def trace_functions(self, path: str | None = None,
                        match: tuple[str, ...] = ()) -> int:
        """Start tracing the target's own functions -- name, arguments,
        return value -- to a file or stderr.  `match` keeps the log to
        the routines whose names contain one of these.  The hooks go on
        as the guest next stops in its event loop; `trace_ready()` says
        when they're all on.  Returns how many functions were queued."""
        from .. import symtab
        if not self._symbols:
            raise RuntimeError("trace_functions needs a symbol table: "
                               "load_symbols() or extract_symbols() first")
        def start():
            proc = self._proc()
            out = open(path, "w") if path else None
            proc._trace_out = out
            proc._tracer = symtab.symbols_for(proc, self._symbols, self._symbols_meta,
                                              match, out)
            return True
        self.d.bridge.call(start)
        return len(self._symbols)

    def trace_ready(self) -> bool:
        """Whether every matched function that lives in memory is hooked."""
        def check():
            proc = self._proc()
            tracer = getattr(proc, "_tracer", None)
            return tracer is not None and not tracer.pending
        return self.d.bridge.call(check)

    def trace_stop(self) -> None:
        def stop():
            proc = self._proc()
            if getattr(proc, "_tracer", None) is not None:
                proc._tracer.uninstall()
                proc.runner.tracer = None
                proc._tracer = None
            out, proc._trace_out = getattr(proc, "_trace_out", None), None
            if out is not None:
                out.close()
        self.d.bridge.call(stop)

    # -- hooks: Python on entry, on return, in place --------------------------
    #
    # A `target` is a Ghidra name from the loaded symbol table -- exact,
    # or a substring that matches one function -- or a jank address.
    # Handlers run on the guest thread with its machine stopped; from
    # them, `hook.regs()`, `hook.call_original(...)` and the `call`
    # below all reach the game directly.

    from .. import inject as _inject
    SKIP = _inject.SKIP

    def _patcher(self):
        cached = getattr(self, "_patcher_obj", None)
        proc = self._proc()
        if cached is not None and cached.process is proc:
            return cached
        runner = proc.runner
        if runner is not None and getattr(runner, "patcher", None) is not None:
            self._patcher_obj = runner.patcher
            return runner.patcher
        # Building it reads the live jump table, so ask the GUI thread
        # (which, in a scripted run, answers right away).
        self._patcher_obj = self.d.bridge.call(proc.patcher)
        return self._patcher_obj

    def find(self, target) -> dict:
        """The symbol table's row for a name or jank address; a bare
        address with no symbol gets a row that knows only its entry.
        Ghidra makes a stub function of each jump table slot under the
        routine's own name; when both exist, the routine wins -- its
        body is real, and hooking it covers every call, table or
        direct."""
        from .. import inject
        if isinstance(target, int):
            for sym in self._symbols:
                if sym["entry"] == target:
                    return sym
            return inject.symbol_at(target)
        name = str(target)
        exact = [s for s in self._symbols if s["name"] == name]
        hits = exact or [s for s in self._symbols if name.lower() in s["name"].lower()]
        if len(hits) > 1:
            layout = self._patcher().app_map.layout
            real = [s for s in hits if not layout.is_jt_slot(s["entry"])]
            if len(real) == 1:
                return real[0]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise KeyError(f"no function {name!r} in the symbol table")
        raise KeyError(f"{name!r} matches {len(hits)} functions: "
                       + ", ".join(sorted(s["name"] for s in hits)[:8]) + "...")

    def hook(self, target, phase: str = "replace"):
        """A decorator hooking one function.

            @mac.hook("math_Abs16", phase="replace")
            def abs16(h):                  # h.args, h.regs()
                return abs(h.args[0])      # becomes the return value

        Phases: "enter" (before the body; return mac.SKIP to skip it),
        "return" (h.value is the return value; assign to change it),
        "replace" (the body never runs).  The decorated function is
        returned unchanged, carrying `.unhook()`.  The hook goes on as
        the guest next stops -- `hooks_ready()` says when."""
        sym = self.find(target)
        from .. import inject

        def decorate(fn):
            fh = self._patcher().hook(sym, phase, fn)
            fn.unhook = fh.uninstall
            fn.hook = fh
            return fn
        return decorate

    def unhook(self, target) -> int:
        """Take the hooks off a function -- by the decorated name or
        the function itself.  Returns how many came off."""
        fn = target
        name = getattr(fn, "__name__", None)
        if isinstance(target, str):
            name = self.find(target)["name"]
        patcher = self._patcher()
        hits = [fh for fh in patcher.hooks
                if fh.handler is fn or (name and fh.name == name)]
        for fh in hits:
            fh.uninstall()
        return len(hits)

    def hooks_ready(self) -> bool:
        """Whether every hook that's been made is on (a hook on a
        segment not loaded yet stays pending)."""
        return self._patcher().ready()

    def hooks_pending(self) -> list[str]:
        return [fh.name for fh in self._patcher().pending]

    # -- memory, by label or Ghidra address -----------------------------------
    def resolve(self, target) -> int:
        """Where a Ghidra name or jank address is in live memory now.
        Raises if its segment isn't loaded."""
        sym = self.find(target) if not isinstance(target, int) else None
        addr = sym["entry"] if sym is not None else target
        live = self._patcher().app_map.resolve(addr)
        if live is None:
            what = sym["name"] if sym is not None else f"{addr:#x}"
            raise LookupError(f"{what} isn't loaded right now")
        return live

    def read(self, target, n: int) -> bytes:
        return self._patcher().mem.read(self.resolve(target), n)

    def write(self, target, data: bytes) -> None:
        self._patcher().mem.write(self.resolve(target), data)

    def peek(self, target, size: int = 4) -> int:
        mem = self._patcher().mem
        at = self.resolve(target)
        return {1: mem.r8, 2: mem.r16, 4: mem.r32}[size](at)

    def poke(self, target, value: int, size: int = 4) -> None:
        mem = self._patcher().mem
        at = self.resolve(target)
        {1: mem.w8, 2: mem.w16, 4: mem.w32}[size](at, value)

    # -- the registers, and calls into the game ---------------------------------
    def regs(self) -> dict:
        """d0-d7, a0-a6, sp, pc, sr.  The game must be stopped to look:
        inside a hook handler it is; from the script thread, only while
        it's waiting.  `call_async` runs on the guest thread, where it's
        always possible."""
        return self._patcher().regs()

    def call(self, target, args=(), result: str | None = None):
        """Call a game function and get its answer back.  `args` are
        Python values, pushed as the Ghidra signature says; `result`
        overrides how the answer comes back (a Ghidra format, a
        register like "d3", "" for raw D0).  Refuses while the game is
        running its own code -- use it inside a hook handler, from
        `call_async`, or while it's waiting."""
        sym = self.find(target)
        live = self._patcher().app_map.resolve(sym["entry"])
        if live is None:
            raise LookupError(f"{sym['name']} isn't loaded right now")
        if result is None:
            result = (sym.get("return") or {}).get("format", "")
        return self._patcher().call(live, sym.get("params", []), tuple(args), result)

    def call_async(self, fn) -> None:
        """Run fn on the game's own thread at its next stop: inside it,
        `regs()` and `call()` always work.  Doesn't wait."""
        self._patcher().async_call(fn)

    def dump_memory(self, path: str) -> int:
        """Write the Mac's whole RAM to a file: what's in memory now,
        the game's loaded code and all.  Returns the byte count."""
        return self.d.bridge.call(self._proc().dump_memory, path)

    # -- looking -------------------------------------------------------------
    def screenshot(self, path: str) -> None:
        """Save what's on the emulated screen to a PNG."""
        def grab():
            if self.d.screen_widget is None:
                raise RuntimeError("screenshot needs host='screen'")
            self.d.screen_widget.grab().save(path)
        self.d.bridge.call(grab)

    def quit(self) -> None:
        self.d.bridge.call(self.d.shutdown)

    # =====================================================================
    def _proc(self):
        if self._target is not None and self._target in self.d.processes:
            return self._target
        return self.d.front_process
