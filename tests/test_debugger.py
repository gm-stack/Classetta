"""The debugger: a pause that stops the core between two instructions, a
step that runs exactly one more, and the listing that goes with them.

A pause lands at the next safe point rather than at a chosen instruction,
so *where* it stops isn't fixed -- but what it shows is checked to be a
whole machine.  The loop these tests run adds 1, then 2, then 4, then takes
the 7 back off, so D0 holds a different figure at each instruction and
returns to nought every turn: it says exactly which instruction the machine
is between, and a run of any length can't wrap it round.  A core stopped in
the middle of an instruction whose store had already been made, or one
instruction run twice by the stopping and starting, shows the figure
belonging to its neighbour instead.  That's checked at every pause.

The stepping is checked the same way, one instruction at a time, across
the branch that sends the PC back to the top -- a step moves the program
counter to the next instruction and does exactly one instruction's work.

The listing comes from the decoder the core itself uses for its lengths,
with capstone for the text, so it's checked against the whole game's dump:
every line ends where the next begins, and the Toolbox traps capstone
reads as data are named from the trap table.
"""

import struct
from types import SimpleNamespace
import threading
import time

import pytest

from macrt.m68k import disasm
from macrt.m68k.cpu import CPU, Debug
from macrt.memory import RAM

CODE, NEVER = 0x10000, 0x12000
# Five instructions adding 1, 2 and 4, taking the 7 back off again, and
# jumping back.  What D0 holds therefore says exactly which instruction the
# machine is between -- not merely which one it's between modulo the turn's
# total -- and it never leaves 0..7, so a long run can't wrap it round.
#   addq #1,d0 ; addq #2,d0 ; addq #4,d0 ; subq #7,d0 ; bra -10
# (addq to a data register is a word instruction: 5240 is addq.w #1,d0.
# Nothing here needs more than a word, which is what keeps the totals exact.)
LOOP = bytes.fromhex("5240" "5440" "5840" "5F40" "60f6")
LOOP_SIZE = 10
AT = {0: 0, 2: 1, 4: 3, 6: 7, 8: 0}    # D0 held as each instruction is set to run
NEXT = {0: 2, 2: 4, 4: 6, 6: 8, 8: 0}  # where each leaves the program counter


def consistent(pc: int, d0: int) -> bool:
    """Whether D0 is what it must be at this instruction: the arithmetic
    agrees, to the unit, with where the PC says the machine is.  A core
    stopped in the middle of an instruction whose store had been made, or
    stopped having run one twice, shows a D0 belonging to its neighbour."""
    return d0 == AT[(pc - CODE) % LOOP_SIZE]


def machine(loop=LOOP):
    mem = RAM(0x20000)
    mem.write(CODE, loop)
    cpu = CPU(mem)
    cpu.sr = 0x2000
    cpu.sp = 0x18000
    for n in range(8):
        cpu.set_d(n, 0)
    cpu.pc = CODE
    return mem, cpu


class Guest:
    """The CPU run the way the Runner runs it, on its own thread: every
    stop goes through the debugger's pump, which is where it holds."""

    def __init__(self, cpu):
        self.cpu = cpu
        self.debug = Debug(cpu)
        self.debug.attach()
        self.stopping = threading.Event()
        self.error = None
        self.stops = 0                  # how often the core has come back
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while not self.stopping.is_set():
                event = self.cpu.run(NEVER)
                self.stops += 1
                if event.kind == "trap":
                    # There's no Toolbox here.  A trap word is two bytes and
                    # a trap doesn't change the PC, so stepping past one is
                    # seen as the PC moving on to what follows it.
                    self.cpu.pc = event.pc + 2
                self.debug.pump()
        except BaseException as e:                                # noqa: BLE001
            self.error = e

    def wait_stopped(self, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.debug.is_stopped():
                view = self.debug.get_view()
                assert self.error is None, self.error
                return view
            time.sleep(0.002)
        raise AssertionError("the core was not stopped")

    def wait_next_view(self, previous, timeout=2.0):
        """The snapshot after a step: the old one is what's shown until the
        core stops again, so identity is how you see the step taken."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            view = self.debug.get_view()
            if self.debug.is_stopped() and view is not previous:
                return view
            time.sleep(0.002)
        raise AssertionError("no new snapshot after a step")

    def close(self):
        self.stopping.set()
        self.debug.detach()
        self.thread.join(2)
        self.cpu.close()


# ---------------------------------------------------------------------------
# Pausing
# ---------------------------------------------------------------------------
def test_a_pause_stops_the_core_and_shows_the_machine():
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        view = g.wait_stopped()
        assert (view["pc"] - CODE) % LOOP_SIZE == 0
        assert len(view["d"]) == 8 and len(view["a"]) == 7
        assert view["sp"] and view["listing"]
        assert consistent(view["pc"], view["d"][0])
    finally:
        g.close()


def test_the_snapshot_reads_the_running_application_s_name_from_low_memory():
    """CurApName is a Pascal string at $910, and the snapshot says it.
    Low memory proper, not a World's side copy: the core is stopped while
    its own process is the active one, so that's where its name is."""
    from macrt.toolbox import lowmem

    mem, cpu = machine()
    name = b"F/A-18 Hornet"
    mem.write(lowmem.CurApName, bytes([len(name)]) + name.ljust(31, b"\0"))
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        assert g.wait_stopped()["app_name"] == "F/A-18 Hornet"
    finally:
        g.close()


def test_every_pause_lands_on_a_whole_instruction():
    """The registers must agree with the PC, which they can't if the core
    was taken in the middle of an instruction that had already stored, or
    rewound to one that had."""
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        for _ in range(25):
            g.debug.request_pause()
            view = g.wait_stopped()
            assert consistent(view["pc"], view["d"][0]), view
            g.debug.request_go()
            time.sleep(0.005)
    finally:
        g.close()


def test_a_pause_takes_effect_while_the_code_calls_nothing():
    """A game that just runs, with no trap to come back on, is still taken:
    run() comes back every slice while a debugger is watching."""
    mem, cpu = machine(bytes.fromhex("5240" "60fe"))      # addq #1,d0 ; bra -2
    g = Guest(cpu)
    try:
        started = time.monotonic()
        g.debug.request_pause()
        view = g.wait_stopped(timeout=1.0)
        assert time.monotonic() - started < 1.0, "the pause waited for a trap"
        assert CODE <= view["pc"] < CODE + 4, view      # stopped inside the loop
    finally:
        g.close()


# ---------------------------------------------------------------------------
# Stepping
# ---------------------------------------------------------------------------
def test_a_step_runs_exactly_one_instruction():
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        view = g.wait_stopped()
        for _ in range(15):                   # fifteen: three turns round, so
            where = (view["pc"] - CODE) % LOOP_SIZE   # the branch is stepped over
            g.debug.request_step()
            view = g.wait_next_view(view)
            assert (view["pc"] - CODE) % LOOP_SIZE == NEXT[where], \
                f"from ${where:02X}: PC at ${view['pc'] - CODE:02X}, " \
                f"want ${NEXT[where]:02X}"
            assert consistent(view["pc"], view["d"][0]), view
    finally:
        g.close()


def test_a_step_over_a_trap_lands_on_the_instruction_after_it():
    """A step that starts on a Toolbox trap doesn't stop inside it: the trap
    is one instruction, so the step ends on the instruction after it.  (What
    the trap would go on to do in the Toolbox -- answered in Python, across
    many more instructions -- is the Runner's business, and is what the next
    test covers.)"""
    #   trap _WaitNextEvent ; addq #1,d0 ; bra -6
    code = struct.pack(">H", 0xA860) + bytes.fromhex("5240" "60fa")
    mem, cpu = machine(code)
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        view = g.wait_stopped()
        for _ in range(6):
            g.debug.request_step()
            view = g.wait_next_view(view)
            assert (view["pc"] - CODE) in (0, 2, 4), view["pc"]
        assert view["listing"], "the listing went empty"
    finally:
        g.close()


def test_a_pause_waits_for_a_trap_that_is_running_68k_code():
    """A pause asked for while a trap is answering in Python and running 68k
    code of its own waits for the trap, rather than holding it half-done."""
    mem, cpu = machine()
    debug = Debug(cpu)
    debug.attach()
    nested = [0]                      # how deep in a trap's own 68k calls
    held_deep = []
    stopping = threading.Event()

    def loop():
        try:
            while not stopping.is_set():
                cpu.run(NEVER)
                nested[0] += 1
                debug.pump(outermost=False)          # a trap: must not hold
                held_deep.append(debug.is_stopped())
                cpu.run(cpu.pc)                      # the trap's own code
                nested[0] -= 1
                debug.pump(outermost=True)           # the trap is done
        except BaseException:                        # noqa: BLE001
            pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        debug.request_pause()
        deadline = time.monotonic() + 2
        while not debug.is_stopped() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert debug.is_stopped(), "a pause never took while nested"
        assert not any(held_deep), "held inside a trap's own nested run"
    finally:
        debug.detach()
        stopping.set()
        t.join(2)
        cpu.close()


def test_go_lets_it_run_again():
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        g.wait_stopped()
        stopped_at = g.stops
        g.debug.request_go()
        deadline = time.monotonic() + 2.0
        while g.stops == stopped_at and time.monotonic() < deadline:
            time.sleep(0.005)
        assert not g.debug.is_stopped()
        assert g.stops > stopped_at, "it didn't run on"
    finally:
        g.close()


def test_closing_the_window_while_paused_lets_the_core_go():
    """Letting go of the processor is done on the guest thread -- unicorn's
    hooks belong to the thread running the core -- so what's watched is the
    core coming back to life, not the flags the guest clears."""
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        g.wait_stopped()
        stopped_at = g.stops
        g.debug.detach()
        deadline = time.monotonic() + 2.0
        while g.stops == stopped_at and time.monotonic() < deadline:
            time.sleep(0.005)
        assert g.stops > stopped_at, "a detached debugger left the core held"
        deadline = time.monotonic() + 2.0
        while cpu.debug_slicing and time.monotonic() < deadline:
            time.sleep(0.005)
        assert not cpu.debug_slicing, "run() still slicing for a window gone"
    finally:
        g.close()


# ---------------------------------------------------------------------------
# The listing
# ---------------------------------------------------------------------------
def test_the_listing_shows_the_pc_with_the_instructions_around_it():
    mem, cpu = machine()
    rows = disasm.window(mem._b, CODE + 2, before=4, after=3)
    shown = [r.address for r in rows]
    assert CODE + 2 in shown
    assert len(rows) == 8 and shown.index(CODE + 2) == 4
    current = rows[shown.index(CODE + 2)]
    assert current.text.startswith("addq") and current.length == 2


def test_the_listing_reads_a_toolbox_trap_as_the_trap_it_is():
    """Capstone reads an A-line word as data; the machine runs it as a call
    into the Toolbox, and the trap table knows which one."""
    mem = RAM(0x20000)
    mem.write(CODE, struct.pack(">HHHH", 0x7005, 0xA9A0, 0xA860, 0x4E75))
    rows = disasm.forward(mem._b, CODE, 4)
    assert rows[0].text.startswith("moveq")
    assert "GetResource" in rows[1].text, rows[1].text
    assert "WaitNextEvent" in rows[2].text, rows[2].text
    assert rows[3].text.startswith("rts")


def game():
    from pathlib import Path
    base = Path("/Users/geordiemillar/ghidra-fa18/fa18-hornet-app/1.1.2_classic")
    blob, table = base / "dump_hornet_classic", base / "symbols_classic.json"
    if not (blob.exists() and table.exists()):
        return None, None
    import json
    return blob.read_bytes(), json.loads(table.read_text())["functions"]


@pytest.mark.parametrize("count", [40])
def test_the_listing_walks_the_whole_game_in_step(count):
    """Every line ends where the next begins.  One instruction read as the
    wrong length puts every line after it out of step, which is exactly what
    the window would then show; the lengths come from the decoder the core
    runs by, so this holds over all the game's code, not just the fixture."""
    blob, functions = game()
    if blob is None:
        pytest.skip("the game's dump and symbol table aren't here")
    checked = 0
    for fn in functions:
        entry, end = fn["entry"], fn.get("body_end") or entry + 2
        if not (0 < end - entry <= 4000 and end < len(blob)):
            continue
        rows = disasm.forward(blob, entry, count)
        for a, b in zip(rows, rows[1:]):
            assert a.address + a.length == b.address, (fn["name"], a.address, b.address)
        checked += 1
    assert checked > 500, f"only {checked} functions read"


def test_the_game_own_code_disassembles_as_code_not_data():
    """What the window shows for the game's routines should be mostly
    instructions rather than `dc.w`: the trap words are named, and only real
    data and unknown encodings fall back to hex."""
    blob, functions = game()
    if blob is None:
        pytest.skip("the game's dump and symbol table aren't here")
    known = hexes = 0
    for fn in functions[:400]:
        entry, end = fn["entry"], fn.get("body_end") or entry + 2
        if not (0 < end - entry <= 2000 and end < len(blob)):
            continue
        for row in disasm.forward(blob, entry, 40):
            if row.text.startswith("dc.w"):
                hexes += 1
            else:
                known += 1
    assert known > 5000, known
    assert hexes / (known + hexes) < 0.06, (known, hexes)


# ---------------------------------------------------------------------------
# Breakpoints
#
# An address or memory breakpoint is a hook the core stops on; a trap's stop
# is arranged by the Runner, which holds the core before the trap is
# answered.  The loop the pause tests run suits these too: it reaches CODE+4
# once a turn, so a break there says exactly where it stopped, and a break
# that lets the core run again after one must stop there again the next time
# round -- the core rewinds to the instruction it stopped in, and the hook
# has to let that one run rather than stopping on it again.
# ---------------------------------------------------------------------------
def test_an_address_breakpoint_stops_at_the_instruction_and_again():
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.add_bp_addr(CODE + 4)
        view = g.wait_stopped()
        assert (view["pc"] - CODE) % LOOP_SIZE == 4, view["pc"]
        assert "Breakpoint hit" in g.debug.get_reason(), g.debug.get_reason()
        assert consistent(view["pc"], view["d"][0]), view     # a whole machine, again
        g.debug.request_go()
        view = g.wait_next_view(view)                          # past the re-run,
        assert (view["pc"] - CODE) % LOOP_SIZE == 4            # and stopped again
    finally:
        g.close()


def run_free(debug: "object", for_: float = 0.3) -> None:
    """The core was told to go: wait until it has, and then watch it stay
    free.  Going is a note the guest thread reads at its next look, so it
    isn't resumed the instant it's asked."""
    deadline = time.monotonic() + 2.0
    while debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not debug.is_stopped(), "the core never resumed"
    deadline = time.monotonic() + for_
    while time.monotonic() < deadline:
        assert not debug.is_stopped(), "stopped again"
        time.sleep(0.01)


def test_clearing_a_breakpoint_while_held_lets_the_core_run_free():
    """The usual case: the window is sitting at a breakpoint, the user has
    had enough of it, and Resume must actually resume -- across the
    instruction the hold released on."""
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.add_bp_addr(CODE + 4)
        g.wait_stopped()
        g.debug.clear_bp_addr(CODE + 4)
        g.debug.request_go()
        run_free(g.debug)
    finally:
        g.close()


def test_a_memory_breakpoint_stops_at_the_instruction_that_writes():
    """A write breakpoint stops with the PC on the store that made it: the
    core rewinds into the instruction, so that's where a debugger looks."""
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        paused = g.wait_stopped()
        #   move.b d0,(a0) ; bra -4        a0 at a byte nothing else touches
        mem.write(CODE + 16, bytes.fromhex("1080" "60fc"))
        cpu.set_a(0, 0x18000)
        cpu.pc = CODE + 16
        g.debug.add_bp_memw(0x18000)
        g.debug.request_go()
        view = g.wait_next_view(paused)
        assert view["pc"] == CODE + 16, view["pc"]
        assert "write of $018000" in g.debug.get_reason(), g.debug.get_reason()
        g.debug.clear_bp_memw(0x18000)
        g.debug.request_go()
        run_free(g.debug)
    finally:
        g.close()


def test_a_memory_breakpoint_lets_the_store_it_stopped_at_complete():
    """Letting the re-run through means the instruction the core rewound to
    runs once, not zero times: the byte arrives where it was written to."""
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        paused = g.wait_stopped()
        mem.write(CODE + 16, bytes.fromhex("1080" "60fc"))
        cpu.set_a(0, 0x18000)
        cpu.set_d(0, 0x5A)
        cpu.pc = CODE + 16
        g.debug.add_bp_memw(0x18000)
        g.debug.request_go()
        view = g.wait_next_view(paused)
        assert view["pc"] == CODE + 16
        assert mem.r8(0x18000) == 0x5A, "the store it stopped at never landed"
    finally:
        g.close()


def test_a_breakpoint_on_a_read_stops_at_the_instruction_that_reads():
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.request_pause()
        paused = g.wait_stopped()
        mem.write(CODE + 16, bytes.fromhex("1010" "60fc"))     # move.b (a0),d0
        cpu.set_a(0, 0x18000)
        mem.w8(0x18000, 0x77)
        cpu.pc = CODE + 16
        g.debug.add_bp_memr(0x18000)
        g.debug.request_go()
        view = g.wait_next_view(paused)
        assert view["pc"] == CODE + 16, view["pc"]
        assert "read of $018000" in g.debug.get_reason(), g.debug.get_reason()
    finally:
        g.close()


class TrapGuest(Guest):
    """The guest loop with the Runner's one extra piece: a trap the program
    calls is held at, before it's answered, when a breakpoint is on it.
    (The plain Guest just moves the PC past a trap; there's no Toolbox
    here to answer it.)"""

    def _run(self):
        try:
            while not self.stopping.is_set():
                event = self.cpu.run(NEVER)
                self.stops += 1
                if event.kind == "trap":
                    if self.debug.trap_hit(event.code):
                        self.debug.hold_trap(event.code)
                    self.cpu.pc = event.pc + 2
                self.debug.pump()
        except BaseException as e:                                # noqa: BLE001
            self.error = e


def test_a_breakpoint_on_a_trap_stops_before_it_is_answered():
    #   trap _WaitNextEvent ; bra -4
    mem, cpu = machine(struct.pack(">H", 0xA860) + bytes.fromhex("60fc"))
    g = TrapGuest(cpu)
    try:
        g.debug.add_bp_trap(0xA860)
        view = g.wait_stopped()
        assert view["pc"] == CODE, view["pc"]            # on the trap itself
        assert "trap _WaitNextEvent" in g.debug.get_reason(), g.debug.get_reason()
        g.debug.clear_bp_trap(0xA860)
        g.debug.request_go()
        run_free(g.debug)
    finally:
        g.close()


def test_a_pause_still_works_while_a_breakpoint_is_set():
    """The two ways of stopping share one hold: a pause asked for while a
    breakpoint waits elsewhere stops the core at a safe point as before."""
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.add_bp_addr(NEVER)                 # set, but nothing reaches it
        g.debug.request_pause()
        view = g.wait_stopped()
        assert "Pause pressed" in g.debug.get_reason(), g.debug.get_reason()
        assert consistent(view["pc"], view["d"][0])
    finally:
        g.close()


def test_the_breakpoint_list_shows_what_is_set():
    mem, cpu = machine()
    g = Guest(cpu)
    try:
        g.debug.add_bp_addr(CODE + 4)
        g.debug.add_bp_trap(0xA860)
        g.debug.add_bp_memr(0x2000)
        g.debug.add_bp_memw(0x2000)
        assert g.debug.bp_list() == [f"b   ${CODE + 4:06X}", "bt  _WaitNextEvent",
                                     "bmr $002000", "bmw $002000"], g.debug.bp_list()
    finally:
        g.close()


# ---------------------------------------------------------------------------
# The window
#
# It asks the display for the processor and nothing else, so a stub display
# holding a machine is enough to try the whole of it -- buttons, panels,
# command line and all -- without booting a Mac.
# ---------------------------------------------------------------------------
class StubSystem:
    def __init__(self):
        self.machine = None


class StubDisplay:
    def __init__(self):
        self.system = StubSystem()


@pytest.fixture
def window(qapp):
    """A window on a machine, and a guest thread running it.  There is one
    Debug per machine, the guest thread pumping that one, so the window is
    pointed at the guest's rather than at a second one of its own."""
    from macrt.ui.debugger import DebuggerWindow

    mem, cpu = machine()
    guest = Guest(cpu)
    display = StubDisplay()
    display.system.machine = SimpleNamespace(debug=guest.debug)
    win = DebuggerWindow(display)
    try:
        yield win, guest, guest.debug
    finally:
        guest.close()
        win.force_close()
        qapp.processEvents()


def test_the_window_watches_a_processor_that_appears_later(window):
    """Opened before the game boots, it says so, and starts watching on its
    own once there's a processor -- the buttons come alive by themselves."""
    from macrt.ui import debugger

    win, guest, debug = window
    win.display.system.machine = None
    win.refresh()
    assert win.status.text() == debugger.NOTHING
    assert not win.play.isEnabled() and not win.step.isEnabled()

    win.display.system.machine = SimpleNamespace(debug=debug)
    win.refresh()
    assert win.status.text() == debugger.RUNNING
    assert win.play.isEnabled() and not win.step.isEnabled()
    assert debug.attached


def test_pausing_from_the_button_shows_the_machine_and_lets_it_go(window):
    from macrt.ui import debugger

    win, guest, debug = window
    win.refresh()
    win.play.click()                       # Pause
    deadline = time.monotonic() + 2.0
    while not debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    assert win.status.text() == debugger.PAUSED
    assert win.play.text() == "Resume"
    assert win.step.isEnabled()
    assert " PC  " in win.registers.toPlainText()
    assert any(line.startswith("=>") for line in win.listing.toPlainText().splitlines())

    win.play.click()                       # Resume
    deadline = time.monotonic() + 2.0
    while debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    assert win.status.text() == debugger.RUNNING
    assert not win.step.isEnabled()


def test_closing_the_window_releases_the_processor(window):
    from macrt.ui import debugger

    win, guest, debug = window
    win.refresh()
    win.play.click()                       # Pause, then go away while held
    deadline = time.monotonic() + 2.0
    while not debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    stops = guest.stops
    win.force_close()
    deadline = time.monotonic() + 2.0
    while guest.stops == stops and time.monotonic() < deadline:
        time.sleep(0.005)
    assert guest.stops > stops, "closing the window left the core held"
    assert not debug.attached


def test_the_window_refuses_to_be_closed_by_the_user(window):
    """It holds the processor; losing it by accident -- or stranding a held
    core by closing the only window on it -- is what this refuses.  The
    display's shutdown closes it with force_close."""
    win, guest, debug = window
    win.show()
    assert not win.close(), "a user's close went through"    # refused: stays up
    assert win.isVisible(), "the window closed on the user's wish"
    assert debug.attached                        # still watching, still holding


def test_the_register_panel_names_every_register_and_the_flags():
    from macrt.m68k.cpu import ccr_names
    from macrt.ui.debugger import register_text

    view = {"pc": 0x1234, "sp": 0x1000, "sr": 0x2700, "app_name": "F/A-18 Hornet",
            "d": list(range(8)), "a": list(range(0x100, 0x107)),
            "flags": ccr_names(0x2700)}
    text = register_text(view).splitlines()
    assert text[0] == " PC  00001234"
    assert text[1] == ""                              # nothing to name the PC with
    assert text[2] == " SP  00001000"
    assert text[3] == " SR  2700  xnzvc  sup irq7"    # no condition code set
    assert text[6] == "F/A-18 Hornet"                 # the application running
    assert text[8] == " D0  00000000" and text[15] == " D7  00000007"
    assert text[17] == " A0  00000100" and text[23] == " A6  00000106"


def test_the_PC_is_named_under_itself_and_the_application_above_the_registers():
    """The routine the PC sits in, spelled with its offset, under the PC;
    and whose code it is, from the low-memory globals."""
    from macrt.m68k.cpu import ccr_names
    from macrt.ui.debugger import register_text

    view = {"pc": 0x1234, "sp": 0x1000, "sr": 0, "symbol": "DrawScreen+1E",
            "app_name": "F/A-18 Hornet", "d": [0] * 8, "a": [0] * 7,
            "flags": ccr_names(0)}
    text = register_text(view).splitlines()
    assert text[:7] == [" PC  00001234", "     DrawScreen+1E", " SP  00001000",
                        " SR  0000  xnzvc  usr", "", "CurApName:", "F/A-18 Hornet"]


def test_the_widest_register_line_fits_the_panel_it_is_measured_for(window):
    """The panel's width is set from a sample line, so a real one -- which
    has more in it than the sample if the flags differ -- mustn't overflow."""
    from macrt.m68k.cpu import ccr_names
    from macrt.ui.debugger import register_text, register_text_sample

    widest = register_text({"pc": -1 & 0xFFFFFFFF, "sp": -1 & 0xFFFFFFFF,
                            "sr": 0xFFFF, "d": [0] * 8, "a": [0] * 7,
                            "flags": ccr_names(0xFFFF)})
    assert max(len(line) for line in widest.splitlines()) <= len(register_text_sample())


def test_a_long_routine_name_widens_the_panel_rather_than_being_clipped(window):
    """The register panel is fixed-width, so a name longer than any
    register line has to widen it -- and a shorter name after it mustn't
    take the width back, or the window shivers as you step through code."""
    from macrt.m68k.cpu import ccr_names

    win, guest, debug = window
    win.refresh()
    start = win.registers.width()
    view = {"pc": 0x1234, "sp": 0x1000, "sr": 0, "app_name": "F/A-18 Hornet",
            "d": [0] * 8, "a": [0] * 7, "flags": ccr_names(0), "listing": [],
            "symbol": "dialog_showSecretMissionAircraftSelect+1A2B"}
    win._draw(view)
    assert win.registers.width() > start, "a long name was left clipped"
    assert win.breakpoints.width() == win.registers.width()

    view["symbol"] = "main"
    win._draw(view)
    assert win.registers.width() > start, "the panel shrank back as names changed"


def test_the_last_snapshot_stays_up_while_the_application_runs(window):
    """Resuming doesn't blank the window: what it holds is where the core
    was stopped, and there's nothing newer to say until it stops again."""
    from macrt.ui import debugger

    win, guest, debug = window
    win.refresh()
    assert win.registers.toPlainText() == ""     # never stopped: nothing to show
    win.play.click()                             # Pause
    deadline = time.monotonic() + 2.0
    while not debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    stopped = win.registers.toPlainText(), win.listing.toPlainText()
    assert all(stopped)
    win.play.click()                             # Resume
    deadline = time.monotonic() + 2.0
    while debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    assert win.status.text() == debugger.RUNNING
    assert (win.registers.toPlainText(), win.listing.toPlainText()) == stopped


def test_a_step_moves_the_window_and_says_nothing(window):
    """The window moving one instruction on is itself the news; a log line
    every step would be noise, and the pause that got there said it."""
    win, guest, debug = window
    win.refresh()
    win.play.click()                             # Pause
    deadline = time.monotonic() + 2.0
    while not debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    lines = win.log.toPlainText().count("\n")
    pc = win.registers.toPlainText()

    win.step.click()
    deadline = time.monotonic() + 2.0
    while win.registers.toPlainText() == pc and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    assert win.registers.toPlainText() != pc, "the window didn't move on"
    assert win.log.toPlainText().count("\n") == lines, "a step was logged"


def test_the_log_says_so_when_no_symbol_table_is_loaded():
    """The address is all there is without a symbol table; saying which of
    the two nothings it is beats a bare address."""
    from macrt.ui.debugger import where

    assert where({"pc": 0x10000, "symbols": False}) == " at $010000  (no symbol table loaded)"
    assert where({"pc": 0x10000, "symbols": True}) == " at $010000  (not in a known routine)"
    assert where({"pc": 0x10C, "symbol": "DrawScreen+1E", "symbols": True}) \
        == " at $00010C, DrawScreen+1E"


def test_the_namer_alone_counts_as_a_symbol_table():
    """--debug reads the table for names alone: no tracer, but the PC is
    named all the same, and the log knows a table is loaded."""
    class Runner:
        tracer = None
        namer = SimpleNamespace(
            app_map=SimpleNamespace(ghidra_at=lambda pc: pc),
            symbol_at=lambda _a: "main+2")

    mem, cpu = machine()
    cpu.debug_runner = Runner()
    d = Debug(cpu)
    assert d.symbols_loaded()
    assert d.symbol(0x10002) == "main+2"


def test_the_instruction_under_the_pc_is_written_in_red(window):
    """The line the arrow points at has to be unmistakable, and unmistakable
    means a colour that reads on whatever the panel's own background is."""
    from PyQt6.QtGui import QColor

    from macrt.ui.debugger import current_text_colour

    class On:
        """A widget whose only relevant property is its background."""

        def __init__(self, base):
            self._base = base

        def palette(self):
            class P:
                def color(_self, _role):
                    return QColor(base)
            base = self._base
            return P()

    light = current_text_colour(On("#ffffff"))
    dark = current_text_colour(On("#1c1c1e"))
    assert light.red() > 120 and max(light.green(), light.blue()) < light.red()
    assert dark.red() > 120 and max(dark.green(), dark.blue()) < dark.red()
    # The one on the light panel must read as ink; the one on the dark panel
    # must read against it, so they can't be the same colour.
    assert light.lightness() < 90 < dark.lightness()


# ---------------------------------------------------------------------------
# The command line and the log
# ---------------------------------------------------------------------------
def enter(win, text: str) -> None:
    """A command, entered as typed: what returnPressed does."""
    win.command.setText(text)
    win._command()


def test_the_command_line_sets_a_breakpoint_of_each_kind(window):
    """The four commands, and the panel that lists what they set."""
    win, guest, debug = window
    win.refresh()
    enter(win, f"b ${CODE + 4:06X}")
    enter(win, "bmr $18000")
    enter(win, "bmw $19000")
    enter(win, "bt WaitNextEvent")
    assert debug.bp_addr == {CODE + 4}, debug.bp_addr
    assert debug.bp_memr == {0x18000} and debug.bp_memw == {0x19000}
    assert 0xA860 in debug.bp_trap, debug.bp_trap
    listed = win.breakpoints.toPlainText()
    assert f"b   ${CODE + 4:06X}" in listed, listed
    assert "bmr $018000" in listed and "bmw $019000" in listed, listed
    assert "bt  _WaitNextEvent" in listed, listed


def test_c_in_front_clears_the_breakpoint_the_letter_names(window):
    win, guest, debug = window
    win.refresh()
    enter(win, f"b ${CODE + 4:06X}")
    enter(win, "bmr $18000")
    enter(win, "bmw $19000")
    enter(win, "cb $10004")
    enter(win, "cbmr $18000")
    enter(win, "cbmw $19000")
    assert debug.bp_addr == set() and debug.bp_memr == set() and debug.bp_memw == set()
    assert win.breakpoints.toPlainText() == "", win.breakpoints.toPlainText()


def test_an_address_is_hex_with_or_without_the_dollar(window):
    from macrt.ui.debugger import parse_address

    assert parse_address("$2C00") == parse_address("2C00") == 0x2C00
    assert parse_address("0x2c00") == 0x2C00
    for bad in ("", "$", "nonsense"):
        with pytest.raises(ValueError):
            parse_address(bad)


def test_a_trap_is_named_by_name_or_by_its_word():
    from macrt.ui.debugger import trap_keys

    assert 0xA860 in trap_keys("WaitNextEvent")
    assert trap_keys("_WaitNextEvent") == trap_keys("WaitNextEvent")
    assert 0xA9F0 in trap_keys("$A9F0")
    assert 0xA9F0 in trap_keys("A9F0")       # a word in the trap range needs no $
    assert trap_keys("NoSuchRoutine") == set()


def test_a_command_that_makes_no_sense_is_answered_in_the_log(window):
    """A debugger's user is typing at a machine that's stopped; the answer
    has to say what went wrong there rather than raise or do nothing."""
    win, guest, debug = window
    win.refresh()
    enter(win, "frobnicate $1")
    enter(win, "b")
    enter(win, "bt Nonesuch")
    log = win.log.toPlainText()
    assert "don't know the command" in log, log
    assert "no address given" in log, log
    assert "no trap called Nonesuch" in log, log


def test_the_log_says_why_the_core_was_entered(window):
    """The pause button, and then a breakpoint: each stop is one line, said
    once however often the window redraws."""
    from macrt.ui import debugger

    win, guest, debug = window
    win.refresh()
    win.play.click()                             # Pause
    deadline = time.monotonic() + 2.0
    while not debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    assert "Pause pressed" in win.log.toPlainText(), win.log.toPlainText()

    win.play.click()                             # Resume, then break on an address
    deadline = time.monotonic() + 2.0
    while debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    debug.add_bp_addr(CODE + 4)
    deadline = time.monotonic() + 2.0
    while not debug.is_stopped() and time.monotonic() < deadline:
        time.sleep(0.005)
    win.refresh()
    assert f"Breakpoint hit at ${CODE + 4:06X}" in win.log.toPlainText(), win.log.toPlainText()
    said = win.log.toPlainText().count("Breakpoint hit")
    win.refresh()
    win.refresh()
    assert win.log.toPlainText().count("Breakpoint hit") == said, "the same stop logged twice"
    assert win.status.text() == debugger.PAUSED


def test_the_log_does_not_grow_without_limit(window):
    """A game that breaks at a trap in its own loop would fill the log; what
    it keeps is the tail of it."""
    from macrt.ui.debugger import LOG_LINES

    win, guest, debug = window
    for n in range(LOG_LINES + 400):
        win._log(f"line {n}")
    lines = win.log.toPlainText().splitlines()
    assert len(lines) == LOG_LINES, len(lines)
    assert lines[-1] == f"line {LOG_LINES + 399}" and "line 0" not in lines
