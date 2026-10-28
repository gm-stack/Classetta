"""Function hooks on the running fixture: Python on entry, on return,
in place of the routine.

The fixture is test_symtab's -- main, AddTwo (CODE 1) and Twice (CODE 2,
loaded on first call), looping through the jump table with a
WaitNextEvent between rounds.  The hooks are put on while that loop
runs, which is what they're for: a call the loop makes after the hook is
armed is answered by Python, and the loop's own stack comes out intact.

Each test ends by taking its hooks off and watching the fixture return
to its 68k answers (RESULT back to 5, RESULT2 back to 6) -- the same
observation proves both directions.
"""

import pytest

from macrt import inject, symtab

from test_symtab import (EVENT, RESULT, RESULT2, jank_fixture,  # noqa: F401
                         launch_fixture, table)


def by_name(lay, name):
    return next(s for s in table(lay) if s["name"] == name)


def read(mem, a5, off):
    return mem.r16(a5 + off)


# ---------------------------------------------------------------------------
# replace: Python answers, the routine doesn't run
# ---------------------------------------------------------------------------
def test_replace_answers_in_place_of_the_routine(harness, jank_fixture):
    """Twice replaced with Python: every call the fixture's loop makes
    from then on comes back with the Python value -- across the segment
    boundary, and with the caller's stack intact (the loop keeps
    running rounds)."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()
    calls = []

    def twice(hook):
        calls.append(tuple(hook.args))
        return 777

    fh = p.hook(by_name(jank_fixture, "Twice"), "replace", twice)
    h.wait_until(lambda: read(mem, a5, RESULT2) == 777, timeout=5,
                 what="the fixture's next Twice to come back from Python")
    assert calls and all(a == (3,) for a in calls)
    assert read(mem, a5, RESULT) == 5          # AddTwo untouched

    fh.uninstall()
    h.wait_until(lambda: read(mem, a5, RESULT2) == 6, timeout=5,
                 what="Twice back to its 68k self")
    when = mem.r32(a5 + EVENT + 6)
    h.wait_until(lambda: mem.r32(a5 + EVENT + 6) > when, timeout=5,
                 what="the loop still turning")


def test_replace_can_call_the_original(harness, jank_fixture):
    """A replacement that wants the real thing, partway: depth keeps
    the routine's own entry from re-triggering its hook while the
    handler runs, so call_original reaches the 68k code and the
    registers under the stopped hook come back as they were."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()
    seen = []

    def twice(hook):
        inner = hook.call_original(21)          # the real Twice, now
        seen.append(inner)
        return 1000 + inner

    fh = p.hook(by_name(jank_fixture, "Twice"), "replace", twice)
    h.wait_until(lambda: read(mem, a5, RESULT2) == 1042, timeout=5,
                 what="Python's 1000 over the original's 42")
    assert seen and all(v == 42 for v in seen)
    fh.uninstall()
    h.wait_until(lambda: read(mem, a5, RESULT2) == 6, timeout=5,
                 what="the original behaviour back")


def test_replace_handler_can_call_other_routines(harness, jank_fixture):
    """A replacement built out of the app's other routines: the handler
    calls AddTwo while Twice's hook holds the stopped machine, and the
    answer comes back exactly as a JSR would leave it -- D0 per the
    signature, and every register under the hook as it was."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()
    addtwo = p.app_map.resolve(by_name(jank_fixture, "AddTwo")["entry"])
    params = by_name(jank_fixture, "AddTwo")["params"]
    answers = []

    def twice(hook):
        before = hook.regs()
        # Twice(n) replaced by AddTwo(n, n) -- a real JSR, nested in the
        # stopped hook, with the machine saved and restored around it.
        total = p.call(addtwo, params, (hook.args[0], hook.args[0]), "h")
        after = hook.regs()
        answers.append((total, before == after))
        return total * 10

    fh = p.hook(by_name(jank_fixture, "Twice"), "replace", twice)
    h.wait_until(lambda: read(mem, a5, RESULT2) == 60, timeout=5,
                 what="Twice answered through a call to AddTwo")
    assert answers and all(t == 6 and unchanged for t, unchanged in answers)
    fh.uninstall()
    h.wait_until(lambda: read(mem, a5, RESULT2) == 6, timeout=5,
                 what="the original behaviour back")


def test_hooks_fire_inside_a_replacement_callee(harness, jank_fixture):
    """Nesting: with Twice replaced by a handler that JSRs to AddTwo, an
    enter hook on AddTwo sees the call the handler made -- a replacement
    is not a hole in the hooking."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()
    addtwo = p.app_map.resolve(by_name(jank_fixture, "AddTwo")["entry"])
    params = by_name(jank_fixture, "AddTwo")["params"]
    seen = []

    p.hook(by_name(jank_fixture, "AddTwo"), "enter",
           lambda hook: seen.append(tuple(hook.args)))

    def twice(hook):
        return p.call(addtwo, params, (hook.args[0], hook.args[0]), "h")

    fh = p.hook(by_name(jank_fixture, "Twice"), "replace", twice)
    h.wait_until(lambda: any(a == (3, 3) for a in seen), timeout=5,
                 what="the AddTwo hook to fire inside the replacement")
    fh.uninstall()


def test_replace_handler_error_lets_the_routine_run(harness, jank_fixture):
    """A broken hook stops the hook, not the game: the handler raises,
    and the routine simply runs -- RESULT2 keeps its 68k answer."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()

    def bad(hook):
        raise ZeroDivisionError

    fh = p.hook(by_name(jank_fixture, "Twice"), "replace", bad)
    when = mem.r32(a5 + EVENT + 6)
    h.wait_until(lambda: mem.r32(a5 + EVENT + 6) > when, timeout=5,
                 what="the loop still turning past a broken hook")
    assert read(mem, a5, RESULT2) == 6
    fh.uninstall()


# ---------------------------------------------------------------------------
# enter / return: observers
# ---------------------------------------------------------------------------
def test_enter_and_return_see_the_call(harness, jank_fixture):
    """An enter observer reads the arguments off the caller's stack; a
    return observer reads D0 and can change it -- the loop's own
    `move.w d0,RESULT` stores what the handler assigned."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()
    seen = []

    p.hook(by_name(jank_fixture, "AddTwo"), "enter",
           lambda hook: seen.append(("in", tuple(hook.args), hook.retpc != 0)))
    p.hook(by_name(jank_fixture, "AddTwo"), "return",
           lambda hook: seen.append(("out", hook.value)))
    h.wait_until(lambda: ("in", (3, 2), True) in seen and ("out", 5) in seen,
                 timeout=5, what="both sides of an AddTwo")

    def bump(hook):
        hook.value = 42

    fh = p.hook(by_name(jank_fixture, "Twice"), "return", bump)
    h.wait_until(lambda: read(mem, a5, RESULT2) == 42, timeout=5,
                 what="a return handler's value stored by the caller")
    fh.uninstall()
    h.wait_until(lambda: read(mem, a5, RESULT2) == 6, timeout=5,
                 what="Twice's own 6 back")


def test_enter_can_skip(harness, jank_fixture):
    """An enter handler that returns SKIP: the body never runs and the
    caller gets hook.skip_value, its stack cleaned as the RTS would."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()

    def skip(hook):
        hook.skip_value = 99
        return inject.SKIP

    fh = p.hook(by_name(jank_fixture, "AddTwo"), "enter", skip)
    h.wait_until(lambda: read(mem, a5, RESULT) == 99, timeout=5,
                 what="a skipped AddTwo answering 99")
    assert read(mem, a5, RESULT2) == 6         # the rest of the round goes on
    fh.uninstall()
    h.wait_until(lambda: read(mem, a5, RESULT) == 5, timeout=5,
                 what="the real AddTwo back")


# ---------------------------------------------------------------------------
# the engine's bookkeeping
# ---------------------------------------------------------------------------
def test_hook_on_a_segment_never_loaded_stays_pending(harness, jank_fixture):
    """CODE 3 is never loaded: its hook waits, says so, and comes off
    clean without ever firing."""
    h = harness()
    proc = launch_fixture(h)
    p = proc.patcher()
    sym3 = inject.symbol_at(jank_fixture.segments[2].jank_base)
    fh = p.hook(sym3, "enter", lambda hook: None)
    # The guest's loop turns constantly, so the pump has looked for the
    # segment many times by now, and CODE 3 is still nowhere.
    h.wait_until(lambda: p.pending == [fh], timeout=5,
                 what="the pump to have looked for CODE 3 and not found it")
    assert not p.ready()
    fh.uninstall()
    h.wait_until(lambda: p.ready(), timeout=5, what="the pending hook withdrawn")


def test_unhook_while_events_queued(harness, jank_fixture):
    """Uninstalling takes the hooks off even between a stopped call and
    its answer -- the queued answer knows its hook is gone."""
    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    p = proc.patcher()
    fh = p.hook(by_name(jank_fixture, "Twice"), "replace", lambda hook: 777)
    h.wait_until(lambda: read(mem, a5, RESULT2) == 777, timeout=5)
    fh.uninstall()
    h.wait_until(lambda: read(mem, a5, RESULT2) == 6, timeout=5,
                 what="the uninstall, between stops")


# ---------------------------------------------------------------------------
# memory and calls, as a script uses them
# ---------------------------------------------------------------------------
def test_call_and_helpers_through_the_controller(harness, jank_fixture, tmp_path):
    """The Controller path: symbols loaded, then call a routine and get
    its answer (on the guest thread via call_async, where the machine is
    always in hand), resolve a Ghidra label to live memory, and read a
    register set by the game."""
    from macrt.ui.automation import Controller

    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    lay = jank_fixture
    cache = tmp_path / "syms.json"
    symtab.save_symbols(str(cache), table(lay), {"jank_a5": lay.jank_a5})
    ctl = Controller(h.d, symbols_file=str(cache))
    assert len(ctl.symbols()) == 3

    out = []
    ctl.call_async(lambda: out.append(ctl.call("Twice", (21,))))
    h.wait_until(lambda: out == [42], timeout=5,
                 what="a call into the game answered on its own thread")

    live = ctl.resolve("Twice")
    assert live == symtab.AppMap(proc, lay).bases[2]     # Twice, first entry
    with pytest.raises(KeyError):
        ctl.find("NoSuchRoutine")

    ctl.poke(lay.jank_a5 - 4, 0x1234, 2)
    assert ctl.peek(lay.jank_a5 - 4, 2) == 0x1234
    addtwo = ctl.resolve("AddTwo")
    assert ctl.read("AddTwo", 4) == mem.read(addtwo, 4)

    r = ctl.regs()
    assert {"d0", "a7", "sp", "pc", "sr"} <= set(r)


def test_controller_decorator_end_to_end(harness, jank_fixture, tmp_path):
    """The script-facing form: @mac.hook(name, phase="replace") puts a
    Python function over a Ghidra-named routine in the running app, and
    mac.unhook takes it off."""
    from macrt.ui.automation import Controller

    h = harness()
    proc = launch_fixture(h)
    a5, mem = proc.partition.a5, proc.system.mem
    cache = tmp_path / "syms.json"
    symtab.save_symbols(str(cache), table(jank_fixture),
                        {"jank_a5": jank_fixture.jank_a5})
    ctl = Controller(h.d, symbols_file=str(cache))

    @ctl.hook("Twice", phase="replace")
    def twice(hook):
        return abs(hook.args[0]) * 100

    h.wait_until(ctl.hooks_ready, timeout=5, what="the hook to go on")
    h.wait_until(lambda: read(mem, a5, RESULT2) == 300, timeout=5,
                 what="the game's Twice answered by Python")
    assert twice.unhook is not None
    ctl.unhook(twice)
    h.wait_until(lambda: read(mem, a5, RESULT2) == 6, timeout=5,
                 what="the routine back to 68k")


def test_call_refuses_while_the_guest_holds_the_machine(harness, jank_fixture):
    """The deadlock guard: registers are in use while the game runs its
    own code, so a script thread's call says so instead of waiting
    forever for it to stop."""
    from macrt.ui.automation import Controller

    h = harness()
    proc = launch_fixture(h)
    p = proc.patcher()          # built while the guest lets us read its table
    proc.runner.holding = True  # pretend: the guest "is running" right now
    try:
        with pytest.raises(RuntimeError, match="running its own code"):
            p.call(proc.partition.a5 + 32)
    finally:
        proc.runner.holding = False
