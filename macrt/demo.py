"""
Two small guest apps that drive the chrome through the Toolbox, written
the way a classic Mac program is: set up menus, open a window, then sit in
a WaitNextEvent loop handling FindWindow part codes.  Nothing on screen
reacts to a click unless the guest asks it to.

    python -m macrt                          # host windows, global menu bar
    python -m macrt --menubar window         # menu bar under each title bar
    python -m macrt --host screen            # everything inside one Mac screen

Or run a real 68k application instead (see docs/running-apps.md):

    python -m macrt App.bin                  # MacBinary, BinHex, AppleDouble…
    python -m macrt Disk.dsk --app "Disk:Apps:App"
    python -m macrt One.bin Two.hqx          # several, side by side
    python -m macrt App.hqx --list           # just list its resources
    python -m macrt App.bin --view           # show its resources; don't run its code
    python -m macrt App.bin --trace-traps    # log every trap it calls
    python -m macrt App.bin --system System  # with a real System file
"""

from __future__ import annotations

import argparse
import logging
import math
import os
import re
import signal
import sys
import threading
import time

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from . import ansi, symtab
from .m68k.segload import has_code, why_no_code
from .macfile import is_control_panel, open_application, open_disks
from .resfork import is_fork
from .toolbox import constants as k
from .toolbox.api import Toolbox
from .toolbox.types import Rect
from .ui.display import Display, DisplayConfig
from .viewer import describe, viewer_main

# No "(" in these: AppendMenu reads it as "disable this item", as on a Mac.
WINDOW_KINDS = [
    ("Document", k.zoomDocProc, True),
    ("No-Grow Document", k.zoomNoGrow, True),
    ("Plain Document", k.documentProc, True),
    None,
    ("Modal Dialog — dBoxProc", k.dBoxProc, False),
    ("Plain Box — plainDBox", k.plainDBox, False),
    ("Shadow Box — altDBoxProc", k.altDBoxProc, False),
    ("Movable Modal", k.movableDBoxProc, False),
    None,
    ("Desk Accessory — rDocProc", k.rDocProc, True),
]


def lo_word(x: int) -> int:
    return x & 0xFFFF


def hi_word(x: int) -> int:
    v = (x >> 16) & 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


class Sampler:
    """Opens one of every window kind and reports what it's sent."""

    APPLE, FILE, EDIT, WINDOWS = 128, 129, 130, 131

    def __init__(self, tb: Toolbox):
        self.tb = tb
        self.info: dict = {}      # window -> lines it displays
        self.count = 0
        self.last_key = "(none yet)"
        self.quit = False

    def run(self):
        tb = self.tb
        apple = tb.NewMenu(self.APPLE, k.APPLE_MENU_TITLE)
        tb.AppendMenu(apple, "About Sampler…;(-")
        file = tb.NewMenu(self.FILE, "File")
        tb.AppendMenu(file, "New/N;Close/W;(-;Quit/Q")
        edit = tb.NewMenu(self.EDIT, "Edit")
        tb.AppendMenu(edit, "(Undo/Z;(-;(Cut/X;(Copy/C;(Paste/V;(Clear")
        kinds = tb.NewMenu(self.WINDOWS, "Windows")
        tb.AppendMenu(kinds, ";".join(kind[0] if kind else "(-" for kind in WINDOW_KINDS))
        for m in (apple, file, edit, kinds):
            tb.InsertMenu(m, 0)
        tb.DrawMenuBar()
        self.open_window(0)
        while not self.quit:
            got, ev = tb.WaitNextEvent(k.everyEvent, 30)
            if got:
                self.handle(ev)

    def open_window(self, index: int):
        name, proc_id, go_away = WINDOW_KINDS[index]
        self.count += 1
        off = 22 * (self.count % 8)
        boxed = proc_id in (k.dBoxProc, k.plainDBox, k.altDBoxProc, k.movableDBoxProc)
        w, h = (300, 120) if boxed else (340, 200)
        bounds = Rect.from_xywh(40 + off, 70 + off, w, h)
        title = "" if proc_id in (k.dBoxProc, k.plainDBox, k.altDBoxProc) else (
            f"Untitled {self.count}" if index == 0 else name)
        win = self.tb.NewWindow(bounds, title, True, proc_id, go_away=go_away)
        lines = [f"{name}", f"procID {proc_id}"]
        if not go_away:
            lines.append("Click inside to close.")
        self.info[win] = lines

    def draw(self, win):
        tb = self.tb
        tb.SetPort(win)
        r = win.content
        tb.EraseRect(Rect(0, 0, r.height, r.width))
        v = 22
        for line in self.info.get(win, []) + [f"Last key: {self.last_key}",
                                              f"Size: {r.width} x {r.height}"]:
            tb.MoveTo(12, v)
            tb.DrawString(line)
            v += 16
        tb.DrawGrowIcon(win)

    def handle(self, ev):
        tb = self.tb
        if ev.what == k.mouseDown:
            part, win = tb.FindWindow(ev.where)
            if part == k.inMenuBar:
                self.do_menu(tb.MenuSelect(ev.where))
            elif part == k.inDrag:
                tb.DragWindow(win, ev.where, None)
            elif part == k.inGoAway:
                if tb.TrackGoAway(win, ev.where):
                    self.close(win)
            elif part in (k.inZoomIn, k.inZoomOut):
                if tb.TrackBox(win, ev.where, part):
                    tb.ZoomWindow(win, part, False)
            elif part == k.inGrow:
                size = tb.GrowWindow(win, ev.where, Rect(80, 120, 2000, 2000))
                if size:
                    tb.SizeWindow(win, lo_word(size), hi_word(size), True)
            elif part == k.inContent:
                if win is not tb.FrontWindow():
                    tb.SelectWindow(win)
                elif not win.go_away:
                    self.close(win)
        elif ev.what in (k.keyDown, k.autoKey):
            ch = chr(ev.message & 0xFF)
            if ev.modifiers & k.cmdKey:
                self.do_menu(tb.MenuKey(ch))
            else:
                self.last_key = f"{ch!r} (key code 0x{(ev.message >> 8) & 0xFF:02X})"
                front = tb.FrontWindow()
                if front is not None:
                    self.draw(front)
        elif ev.what == k.updateEvt:
            tb.BeginUpdate(ev.message)
            self.draw(ev.message)
            tb.EndUpdate(ev.message)
        elif ev.what == k.activateEvt:
            tb.SetPort(ev.message)
            tb.DrawGrowIcon(ev.message)

    def close(self, win):
        self.info.pop(win, None)
        self.tb.DisposeWindow(win)

    def do_menu(self, result: int):
        tb = self.tb
        menu, item = hi_word(result), lo_word(result)
        if menu == self.APPLE and item == 1:
            self.about()
        elif menu == self.FILE:
            if item == 1:
                self.open_window(0)
            elif item == 2:
                front = tb.FrontWindow()
                if front is not None:
                    self.close(front)
            elif item == 4:
                self.quit = True
        elif menu == self.WINDOWS:
            self.open_window(item - 1)
        tb.HiliteMenu(0)

    def about(self):
        win = self.tb.NewWindow(Rect.from_xywh(120, 120, 280, 90), "", True, k.dBoxProc,
                                go_away=False)
        self.info[win] = ["Sampler", "A macrt chrome demo.", "Click inside to close."]


class Ticker:
    """A second app, so there is something to switch to."""

    APPLE, FILE, OPTIONS = 128, 129, 130

    def __init__(self, tb: Toolbox):
        self.tb = tb
        self.seconds = True

    def run(self):
        tb = self.tb
        apple = tb.NewMenu(self.APPLE, k.APPLE_MENU_TITLE)
        tb.AppendMenu(apple, "About Ticker…;(-")
        file = tb.NewMenu(self.FILE, "File")
        tb.AppendMenu(file, "Quit/Q")
        self.options = tb.NewMenu(self.OPTIONS, "Options")
        tb.AppendMenu(self.options, "Show Seconds!\x12")
        for m in (apple, file, self.options):
            tb.InsertMenu(m, 0)
        tb.DrawMenuBar()
        sw = tb.ScreenBounds().right
        win = tb.NewWindow(Rect.from_xywh(max(sw - 230, 420), 90, 180, 60), "Ticker", True,
                           k.noGrowDocProc)
        shown = ""
        while True:
            got, ev = tb.WaitNextEvent(k.everyEvent, 20)
            now = time.strftime("%H:%M:%S" if self.seconds else "%H:%M")
            if ev.what == k.updateEvt:
                tb.BeginUpdate(ev.message)
                shown = ""
                tb.EndUpdate(ev.message)
            elif ev.what == k.mouseDown:
                part, w = tb.FindWindow(ev.where)
                if part == k.inMenuBar:
                    if self.do_menu(tb.MenuSelect(ev.where)):
                        return
                elif part == k.inDrag:
                    tb.DragWindow(w, ev.where, None)
                elif part == k.inGoAway and tb.TrackGoAway(w, ev.where):
                    return
                elif part == k.inContent and w is not tb.FrontWindow():
                    tb.SelectWindow(w)
            elif ev.what == k.keyDown and ev.modifiers & k.cmdKey:
                if self.do_menu(tb.MenuKey(chr(ev.message & 0xFF))):
                    return
            if now != shown:
                shown = now
                tb.SetPort(win)
                tb.EraseRect(Rect(0, 0, 60, 180))
                tb.MoveTo(56 if self.seconds else 70, 34)
                tb.DrawString(now)

    def do_menu(self, result: int) -> bool:
        menu, item = hi_word(result), lo_word(result)
        quit_ = menu == self.FILE and item == 1
        if menu == self.OPTIONS and item == 1:
            self.seconds = not self.seconds
            self.tb.CheckItem(self.options, 1, self.seconds)
        self.tb.HiliteMenu(0)
        return quit_


def sampler_main(tb: Toolbox):
    Sampler(tb).run()


def ticker_main(tb: Toolbox):
    Ticker(tb).run()


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="macrt", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", choices=["desktop", "screen"], default="desktop",
                    help="Mac windows as host windows, or inside one emulated screen")
    ap.add_argument("--menubar", choices=["global", "window"], default="global",
                    help="one bar for the front app, or one under each window's title bar")
    ap.add_argument("--size", default=None, help="Mac screen size, e.g. 640x480")
    ap.add_argument("--speed", type=float, default=None, metavar="N",
                    help="run 68k code at about N times a Mac Plus's speed, for games that "
                         "run as fast as the processor goes (default: as fast as it goes)")
    ap.add_argument("--model", choices=["plus", "ii"], default="plus",
                    help="the Mac it says it is: a Mac Plus's 68000, or a Mac II's 68020 and "
                         "68881, for programs that need one (default: plus)")
    ap.add_argument("--depth", type=int, choices=[1, 2, 4, 8, 16, 32], default=None,
                    help="with --model ii, the screen's bits a pixel: 1 for black and white, "
                         "2 to 8 for colours by a colour table, 16 and 32 for direct colour "
                         "(default: 8)")
    ap.add_argument("--row-bytes", type=int, metavar="N", default=None,
                    help="how many bytes apart the screen's rows are at the depth it starts "
                         "at (and at another, as many pixels apart), for a program that writes "
                         "to the screen taking them to be so many rather than asking QuickDraw "
                         "(default: as few as a row needs)")
    ap.add_argument("--no-sound", action="store_true",
                    help="don't play the Mac's sound on the host's sound output")
    ap.add_argument("--record-sound", metavar="FILE.wav",
                    help="write the Mac's sound to a WAV file as it plays")
    ap.add_argument("--classic-menus", action="store_true",
                    help="press-drag-release only (no sticky menus)")
    ap.add_argument("--rainbow", action="store_true", help="System 7 color apple")
    ap.add_argument("--single", action="store_true", help="launch only the Sampler")
    ap.add_argument("file", nargs="*",
                    help="Mac applications to run instead of the demo, side by side: "
                         "MacBinary, BinHex, AppleSingle/Double, emulator side files, or "
                         "disk images (HFS or MFS; raw, DiskCopy 4.2 or MOOF); an image "
                         "with no application to run is a disk of documents, in a drive")
    ap.add_argument("--app", metavar="NAME", action="append", default=[],
                    help="which application on a disk image (its name or Mac path), or "
                         "a document, to launch the application that made it with it; "
                         "repeat it to run several")
    ap.add_argument("--memory", type=int, default=None, metavar="K",
                    help="give the application K kilobytes of memory, in place of what its "
                         "SIZE resource asks for, as the memory size in the Finder's Get "
                         "Info does; a control panel's is for the application it launches "
                         "from its own file")
    ap.add_argument("--list", action="store_true", help="list the file's resources and exit")
    ap.add_argument("--view", action="store_true",
                    help="show the application's menus, windows and dialogs from its "
                         "resources instead of running its code")
    ap.add_argument("--trace-traps", action="store_true",
                    help="log every Toolbox and OS trap the application calls")
    ap.add_argument("--suppress-traps", metavar="NAMES", default="",
                    help="comma-separated trap names --trace-traps shouldn't log "
                         "(e.g. TickCount,Random)")
    ap.add_argument("--system", metavar="FILE",
                    help="a real System file, or a disk image holding one, in place of the "
                         "built-in empty one")
    ap.add_argument("--script", metavar="FILE",
                    help="a Python file run against the running display, to drive the "
                         "applications with synthetic keys and clicks")
    ap.add_argument("--inject", metavar="FILE",
                    help="a Python file run against the running display with `mac` in "
                         "its globals: hook the game's own functions (on entry, on "
                         "return, replaced outright), call them, and read its memory "
                         "and registers.  Needs the symbols: --symbols or Ghidra.")
    ap.add_argument("--quit-when-done", action="store_true",
                    help="with --script, shut down once the script returns")
    ap.add_argument("--ghidra-project", metavar="PATH",
                    help="the Ghidra project the symbols come from, recorded with them; "
                         "the symbols themselves are read from a running Ghidra "
                         "(see --ghidra-mcp) and cached by --symbols")
    ap.add_argument("--ghidra-program", metavar="NAME",
                    help="which open Ghidra program the application is "
                         "(found on its own if not given)")
    ap.add_argument("--ghidra-mcp", metavar="URL", default=symtab.DEFAULT_MCP_URL,
                    help="the running Ghidra's MCP endpoint (default: %(default)s)")
    ap.add_argument("--symbols", metavar="FILE",
                    help="the symbol table file: read it if it's there, otherwise ask "
                         "Ghidra and save it there")
    ap.add_argument("--trace-functions", action="store_true",
                    help="log the application's own function calls -- name, arguments, "
                         "return value -- here; needs --symbols")
    ap.add_argument("--trace-match", metavar="NAMES", default="",
                    help="only trace functions whose name contains one of these "
                         "comma-separated strings")
    ap.add_argument("--log", metavar="FILE",
                    help="write everything -- the log and the traces along with it "
                         "-- to FILE as well as the screen (colour stays on the "
                         "screen; FILE gets plain text)")
    ap.add_argument("--dump-mem", metavar="FILE",
                    help="write the Mac's whole RAM to FILE once the application "
                         "has loaded")
    args = ap.parse_args(argv)
    if args.memory is not None and args.memory <= 0:
        ap.error("--memory is a size in K, more than 0")
    if args.depth not in (None, 1) and args.model != "ii":
        ap.error("a Mac Plus's screen is black and white: --depth needs --model ii")
    if args.row_bytes is not None and (args.row_bytes & 1 or not 0 < args.row_bytes < 0x4000):
        ap.error("--row-bytes is an even number of bytes, less than 16384")
    if args.size is not None:
        args.size = _screen_size(args.size)
        if args.size is None:
            ap.error("--size is a width and height in pixels, e.g. 640x480, each 1 to 32767")
    if args.speed is not None and not 0 < args.speed < math.inf:
        ap.error("--speed is a number of times a Mac Plus's speed, more than 0")
    return args


def _screen_size(text: str) -> tuple[int, int] | None:
    """WxH as a size, or None: QuickDraw's coordinates are INTEGERs."""
    m = re.fullmatch(r"\s*(\d{1,5})\s*[xX]\s*(\d{1,5})\s*", text)
    if m is None:
        return None
    w, h = int(m[1]), int(m[2])
    return (w, h) if 0 < w <= 0x7FFF and 0 < h <= 0x7FFF else None


def open_targets(args):
    """The applications named on the command line, each with whether to
    show it from its resources rather than run its code, and the disk
    images, for the drives; or an error message."""
    try:
        apps, disks = open_disks(args.file, args.app)
    except (OSError, ValueError) as e:
        return None, None, str(e)
    targets = []
    for f in apps:
        print(describe(f, full=args.list))
        for doc in f.documents:
            print(f"Opening {doc.name} with it.")
        if args.list:
            continue
        if not f.rsrc and is_fork(f.data):
            return None, None, (f"{f.name}'s resource fork is in its data fork: it was copied "
                                "by something that didn't keep its two forks apart.")
        if not f.rsrc:
            return None, None, (f"{f.name} has no resource fork. A Mac file has to travel in "
                                "a form that keeps it: MacBinary, BinHex, AppleDouble or a "
                                "disk image.")
        if not is_fork(f.rsrc):
            return None, None, f"{f.name}'s resource fork is damaged"
        view = args.view
        if view:
            print("Showing its menus and windows from its resources, without running its code.")
        elif not has_code(f) and not is_control_panel(f):
            print(f"{f.name} has no 68k code ({why_no_code(f)}), so macrt shows its menus "
                  "and windows from its resources.")
            view = True
        targets.append((f, view))
    return targets, disks, None


def _run_script(display, path: str, quit_when_done: bool = False,
                controller=None) -> None:
    """Run a Python file on its own thread, with `macrt` (the Controller),
    `mac` (the same, for injection scripts) and `display` in its globals.
    The GUI thread stays free to draw and answer traps while the script
    sleeps and waits."""
    import traceback

    from .ui.automation import Controller

    controller = controller or Controller(display)
    display._controller = controller

    def run():
        try:
            with open(path) as f:
                source = f.read()
            exec(compile(source, path, "exec"),
                 {"mac": controller, "macrt": controller, "display": display,
                  "__name__": "__script__"})
        except BaseException:  # noqa: BLE001 - reported, not propagated
            traceback.print_exc()
        finally:
            if quit_when_done:
                display.shutdown()

    t = threading.Thread(target=run, name="script", daemon=True)
    t.start()


def _extract_progress(done: int, total: int) -> None:
    if done % 250 == 0 or done == total:
        print(f"macrt:   {done}/{total} functions\r", end="", flush=True)


def _get_symbols(args, app, progress=None) -> tuple[list[dict], dict] | None:
    """The symbol table: the cache file if it's there, else asked of a
    running Ghidra and saved.  The Ghidra program is the one whose jump
    table matches the application's, unless --ghidra-program says."""
    if args.symbols and os.path.exists(args.symbols):
        return symtab.load_symbols(args.symbols)
    log = logging.getLogger("macrt")
    try:
        mcp = symtab.GhidraMcp(args.ghidra_mcp)
    except Exception as e:                                       # noqa: BLE001
        log.error("%s", e)
        return None
    program = args.ghidra_program or symtab.pick_program(mcp, app.rsrc)
    log.info("reading symbols from Ghidra program %r...", program)
    table = symtab.extract_symbols(mcp, program, progress)
    meta = {"ghidra": {"program": program, "url": args.ghidra_mcp,
                       "project": args.ghidra_project},
            "app": {"name": app.name},
            "jank_a5": symtab.jank_layout(app.rsrc).jank_a5}
    if args.symbols:
        symtab.save_symbols(args.symbols, table, meta)
        log.info("%d functions saved to %s", len(table), args.symbols)
    return table, meta


def _wait_loaded(app, display, timeout: float = 60.0) -> bool:
    """Let the applications boot: poll, keeping the GUI answering traps,
    until one has a visible window (or the timeout)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        for p in display.processes:
            if p.windows and any(w.visible for w in p.windows):
                app.processEvents()
                return True
        time.sleep(0.05)
    return False


def main(argv=None) -> int:
    args = parse_args(argv)
    # The log from the first moment: the screen takes it coloured, and
    # --log's file takes every line plain.  Either trace is DEBUG, which
    # is where trace lines are written.
    ansi.setup(args.log, logging.DEBUG
               if args.trace_traps or args.trace_functions else logging.INFO)
    log = logging.getLogger("macrt")
    targets, disks = [], []
    if args.file:
        targets, disks, error = open_targets(args)
        if error:
            log.error(error)
            return 2
        if args.list:
            return 0
    system_file = None
    if args.system:
        try:
            system_file = open_application(args.system, "System")
        except (OSError, ValueError) as e:
            log.error(e)
            return 2
    app = QApplication.instance() or QApplication(sys.argv[:1])
    from .ui import theme
    theme.RAINBOW_APPLE = args.rainbow
    try:
        display = Display(DisplayConfig(host=args.host, menu_bar=args.menubar,
                                        screen_size=args.size,
                                        sticky_menus=not args.classic_menus,
                                        system_file=system_file, speed=args.speed,
                                        model=args.model, depth=args.depth,
                                        row_bytes=args.row_bytes, disks=disks,
                                        sound=not args.no_sound, record_sound=args.record_sound,
                                        scripted=bool(args.script)))
    except (OSError, ValueError) as e:      # a screen too big, a WAV file that can't be made
        print(f"macrt: {e}", file=sys.stderr)
        return 2
    display.show()
    wanted = bool(args.symbols or args.trace_functions or args.dump_mem
                  or args.inject)
    game = None
    if targets:
        try:
            for f, view in targets:
                p = display.launch(f.name, viewer_main if view else None, app=f,
                                   trace=args.trace_traps,
                                   memory=args.memory * 1024 if args.memory else None,
                                   trace_suppress=tuple(
                                       n.strip() for n in args.suppress_traps.split(",")
                                       if n.strip()))
                if game is None and not view:
                    game = p
        except (MemoryError, ValueError) as e:
            display.shutdown(quit_app=False)
            log.error("%s", e)
            return 2
    else:
        display.launch("Sampler", sampler_main)
        if not args.single:
            display.launch("Ticker", ticker_main)
    if wanted:
        if game is None:
            log.error("symbol tracing needs a 68k application to run")
        elif not _wait_loaded(app, display):
            log.error("the application did not load in time")
        else:
            table = _get_symbols(args, game.app, progress=_extract_progress
                                 if args.symbols and not os.path.exists(args.symbols)
                                 else None)
            if table is None:
                return 2
            functions, meta = table
            if args.dump_mem:
                n = game.dump_memory(args.dump_mem)
                log.info("wrote %d MB of Mac memory to %s", n // 65536, args.dump_mem)
            if args.trace_functions:
                match = tuple(s.strip() for s in args.trace_match.split(",") if s.strip())
                try:
                    display.bridge.call(
                        lambda: symtab.symbols_for(game, functions, meta, match))
                except ValueError as e:
                    log.error(e)
                    return 2
                log.info("tracing %d functions (hooks go on as the game runs)",
                         len(functions))
            if args.inject:
                # Hand the symbols to the controller the script will get,
                # so it can hook and call by Ghidra name without loading
                # them again.  One controller for --script and --inject
                # both, so they see the same hooks and loaded symbols.
                from .ui.automation import Controller
                controller = getattr(display, "_controller", None) or Controller(display)
                controller._symbols, controller._symbols_meta = functions, meta
                display._controller = controller
    for path in (args.script, args.inject):
        if path:
            _run_script(display, path, quit_when_done=args.quit_when_done,
                        controller=getattr(display, "_controller", None))
    signal.signal(signal.SIGINT, lambda *_: display.shutdown())
    heartbeat = QTimer(interval=200)      # lets Python see Ctrl+C
    heartbeat.timeout.connect(lambda: None)
    heartbeat.start()
    status = app.exec()
    display.shutdown(quit_app=False)
    display.join()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
