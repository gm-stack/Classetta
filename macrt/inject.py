"""
macrt.inject - Function hooks: Python on entry, on return, in place.

A `FunctionPatcher` belongs to one running 68k process, and finds its
way around its memory the way `symtab.FunctionTracer` does -- through
the same `AppMap`, from Ghidra's addresses to live ones.  A
`FunctionHook` attaches to one routine, in one of three phases:

  enter    Python runs just before the routine's first instruction,
           with the arguments as they sit on the caller's stack
           (hook.args) and the registers (hook.regs()).  Returning SKIP
           from the handler skips the call -- hook.skip_value is then
           what it "returned" -- and the handler can call the routine's
           real code with hook.call_original() before deciding.
  return   Python runs at each of the routine's return sites, after
           the body's last word and before the RTS: hook.value is the
           return value, and assigning it changes what comes back.
  replace  the routine's own code doesn't run: the handler's return
           value is the return value.

How the core is held.  A unicorn code hook cannot safely rewrite
registers or the PC while a translated block is in flight -- the block
writes its own state back when it ends, undoing the change (which is
why the CPU's own `_watch`ed traps stop and are handled by `run`, not
mutated in the callback).  So every hook stops the core at its address,
snapshots the call, and defers to `pump` -- which the Runner calls at
each instruction stop, with the core between blocks.  There the handler
has a settled machine: it can read and write registers, and run 68k
code.  Then the call is answered:

  replace / skip   exactly as the routine's RTS would have answered it:
       D0 (A0 for a pointer) from the handler, the return address off
       the stack, and a routine's own RTD cleanup done here instead of
       there -- the caller's stack and registers come out as the
       routine would have left them.  The PC moves to the caller, so
       the entry hook never re-fires for a call already served.
  enter (no skip)  and return leave the PC where it stopped, so the
       instruction that was hooked still has to run; a one-shot flag
       waves that immediate re-fire through, and clears itself, so the
       routine's next real call fires the handler normally again.
       (A hooked routine reached by a VBL or Time Manager task during
       the same stop can be waved through by mistake -- the one cost of
       the wave-through, and rare enough to live with.)

`async_call` runs a Python function on the guest thread at its next
stop -- the machine in hand; `wake` posts a null event so an application
asleep in WaitNextEvent takes a turn.  A script can also *call* 68k code
and wait for the answer -- `call` -- which takes the machine for the
length of the call and refuses while the guest is running its own code,
since its registers are in use.

`sym` rows are the symbol table's shape (name, entry, body_end, params,
return); `symbol_at` makes one for a bare jank address, which knows only
its entry -- enough to hook, and to call with plain long arguments.
"""

from __future__ import annotations

import logging
import struct
import threading
import traceback
from collections import deque
from typing import Any, Callable

from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_MEM_READ, UC_MEM_WRITE)
from unicorn.m68k_const import UC_M68K_REG_PC

from . import symtab
from .memory import ADDRESS_MASK
from .toolbox.events import EventRecord
from .toolbox.types import Point

log = logging.getLogger("macrt.inject")

PHASES = ("enter", "return", "replace")

# Ghidra type formats (symtab.type_info) to (struct char, byte length).
_STACK_FMT = {"b": "b", "B": "B", "h": "h", "H": "H",
              "i": "i", "I": "I", "f": "f", "p": "I", "x": "I"}
_MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}


class _Skip:
    """Return one from an enter handler to skip the call."""

    def __repr__(self) -> str:
        return "SKIP"


SKIP = _Skip()


def _arg_bytes(fmt: str, length: int, value) -> bytes:
    """One argument as it sits on the stack, big-endian.  Signed
    formats wrap down through their sign bit, so -1 for a short is
    $FFFF like the game's own MOVE.W would leave it."""
    if fmt == "f":
        return struct.pack(">f", float(value))
    v = int(value) & _MASK[length]
    if fmt in ("b", "h") and v & (1 << (8 * length - 1)):
        v -= 1 << (8 * length)
    return struct.pack(">" + _STACK_FMT[fmt], v)


def _decode(mem, at: int, fmt: str, length: int):
    try:
        if fmt in ("p", "x"):
            return mem.r32(at)
        return struct.unpack_from(">" + _STACK_FMT[fmt], mem._b, mem.physical(at))[0]
    except Exception:                                       # noqa: BLE001
        return None


def _encode_result(fmt: str, value) -> int:
    """A handler's return value as the bits for D0 (or A0)."""
    if value is None:
        return 0
    if fmt == "f":
        return struct.unpack(">I", struct.pack(">f", float(value)))[0]
    return int(value) & 0xFFFFFFFF


def _decode_result(fmt: str, bits: int):
    if fmt == "f":
        return struct.unpack(">f", struct.pack(">I", bits & 0xFFFFFFFF))[0]
    if fmt in ("b", "h"):
        n = 8 if fmt == "b" else 16
        v = bits & ((1 << n) - 1)
        return v - (1 << n) if v & (1 << (n - 1)) else v
    if fmt in ("B", "H"):
        return bits & (0xFF if fmt == "B" else 0xFFFF)
    return bits & 0xFFFFFFFF


def symbol_at(addr: int) -> dict:
    """A symbol row for a bare jank address: enough to hook it, and to
    call it with plain long arguments."""
    return {"name": f"{addr:#x}", "entry": addr, "body_end": 0, "signature": "",
            "return": {"type": "unknown", "format": "x", "length": 4},
            "params": []}


class Hook:
    """The call, as the handler sees it.

    `args` are the stack arguments decoded per the Ghidra signature;
    `sp` and `retpc` the raw state at the hook; `value` the return
    value -- the handler's in the replace phase, D0 in the return
    phase (assign it to change what comes back).  `skip_value` is what
    a skipped call returns.
    """

    __slots__ = ("name", "phase", "args", "sp", "retpc", "skipped",
                 "skip_value", "_fh", "_fmt", "_value", "_value_set")

    def __init__(self, fh: "FunctionHook", args, sp: int, retpc: int,
                 value=None, value_set: bool = False):
        self._fh = fh
        self._fmt = fh.ret_format
        self.name = fh.sym["name"]
        self.phase = fh.phase
        self.args = args
        self.sp = sp
        self.retpc = retpc
        self.skipped = False
        self.skip_value = 0
        self._value = value
        self._value_set = value_set

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v) -> None:
        self._value = v
        self._value_set = True

    def regs(self) -> dict:
        """The registers, right now: d0-d7, a0-a6, sp, pc, sr.  The
        core is stopped, so they're the routine's own."""
        return self._fh.patcher._regs_now()

    def call_original(self, *args):
        """The routine's own code, with these arguments (or, with none,
        with the caller's stack as it stands).  Enter and replace
        handlers only -- they run before the body, with the core
        stopped, so there's a machine to run it on."""
        return self._fh.call_original(args)

    def uninstall(self) -> None:
        self._fh.uninstall()


class FunctionHook:
    """One routine, one phase, one handler."""

    def __init__(self, patcher: "FunctionPatcher", sym: dict, phase: str,
                 handler: Callable):
        if phase not in PHASES:
            raise ValueError(f"phase is one of {PHASES}, not {phase!r}")
        if not callable(handler):
            raise TypeError("a hook's handler must be callable")
        self.patcher = patcher
        self.sym = dict(sym)
        self.phase = phase
        self.handler = handler
        self.name = sym["name"]
        self.jank_entry = sym["entry"]
        self.ret_format = (sym.get("return") or {}).get("format", "x")
        self.entry: int | None = None           # live address, once installed
        self.rtd = 0                            # its RTD cleanup, if any
        self.handles: list[int] = []
        self.installed = False
        self.depth = 0                          # inside its own handler
        self._resume: int | None = None         # the one stop to wave through

    def uninstall(self) -> None:
        self.patcher._schedule_remove(self)

    def call_original(self, args) -> Any:
        if self.phase == "return":
            raise RuntimeError(
                f"{self.name}: call_original is for enter and replace hooks; "
                "at a return the body is already behind you")
        if self.entry is None:
            raise RuntimeError(f"{self.name} isn't in memory yet")
        params = self.sym.get("params", [])
        args = tuple(args)
        if args and len(args) != len(params):
            raise TypeError(f"{self.name} takes {len(params)} arguments, "
                            f"got {len(args)}")
        return self.patcher._invoke(self.entry, params, args, self.ret_format)

    def __repr__(self) -> str:
        where = f" at {self.entry:#x}" if self.entry is not None else " (pending)"
        return f"<FunctionHook {self.phase} {self.name}{where}>"


class Watchpoint:
    """A memory access to one address, recorded as it happens.

    The address is a Ghidra address; the live one is found as the
    segment loads, the same way a function hook's is, and the unicorn
    memory hook goes on then.  A 68k `MOVE.L` that writes the whole
    slot containing the watched byte fires once, with the access's base
    address and size, so the value is the word or long it wrote.

    Observe-only: the handler, if any, runs inside unicorn's memory
    hook, mid-instruction, on the guest thread.  It may read registers
    and memory, but must not stop the core, write memory, or call 68k
    code -- the instruction is still in flight.  `events` holds the
    accesses as (kind, addr, size, value, pc, ghidra_pc), newest last,
    capped at `max_events`; `pc` is the live PC and `ghidra_pc` the
    address Ghidra would name it, None outside the application.
    """

    __slots__ = ("patcher", "jank_addr", "size", "mode", "handler",
                 "live_addr", "handles", "installed", "events", "max_events",
                 "_to_remove")

    def __init__(self, patcher: "FunctionPatcher", jank_addr: int, size: int,
                 mode: str, handler: Callable | None, max_events: int):
        if mode not in ("read", "write", "both"):
            raise ValueError(f"mode is one of read, write, both, not {mode!r}")
        if size not in (1, 2, 4):
            raise ValueError(f"size is 1, 2 or 4, not {size!r}")
        self.patcher = patcher
        self.jank_addr = jank_addr
        self.size = size
        self.mode = mode
        self.handler = handler
        self.live_addr: int | None = None
        self.handles: list[int] = []
        self.installed = False
        self.events: list[tuple] = []
        self.max_events = max_events
        self._to_remove = False

    def uninstall(self) -> None:
        self.patcher._schedule_unwatch(self)

    def clear(self) -> None:
        self.events.clear()

    def __repr__(self) -> str:
        where = f" at {self.live_addr:#x}" if self.live_addr is not None else " (pending)"
        return f"<Watchpoint {self.mode} {self.jank_addr:#x}{where}>"


class FunctionPatcher:
    """The hook engine for one running process.  `hook` registers a
    hook; `pump`, which the Runner calls at every instruction stop,
    arms them and answers the calls they stopped; `call` runs 68k code
    for a script that's waiting for an answer."""

    def __init__(self, process, app_map: "symtab.AppMap"):
        if process.runner is None:
            raise ValueError(f"{process.name} has no 68k code to hook")
        self.process = process
        self.app_map = app_map
        self.runner = process.runner
        self.cpu = process.runner.cpu
        self.mem = process.system.mem
        self.hooks: list[FunctionHook] = []
        self.watchpoints: list[Watchpoint] = []
        self._answers: deque = deque()        # stopped calls awaiting pump
        self._async: deque = deque()
        self._to_remove: list[FunctionHook] = []
        self._to_unwatch: list[Watchpoint] = []
        self._qlock = threading.Lock()

    # -- registering ---------------------------------------------------------
    def hook(self, sym: dict, phase: str, handler: Callable) -> FunctionHook:
        """Queue a hook on one routine.  It goes on as the guest next
        stops, and stays queued until its segment is loaded."""
        fh = FunctionHook(self, sym, phase, handler)
        with self._qlock:
            self.hooks.append(fh)
        self.wake()
        return fh

    def _schedule_remove(self, fh: FunctionHook) -> None:
        with self._qlock:
            if fh not in self._to_remove:
                self._to_remove.append(fh)
        self.wake()

    def watch(self, jank_addr: int, size: int = 1, mode: str = "write",
              handler: Callable | None = None, max_events: int = 1024) -> Watchpoint:
        """Record the accesses to one address as the guest makes them.
        `jank_addr` is a Ghidra address; the live one is found as the
        segment loads, and the hook goes on then.  `mode` is read, write
        or both; `size` the access's width, 1, 2 or 4 -- a wider access
        that reaches the address fires once, with its own base and size.
        Observe-only: see `Watchpoint`."""
        wp = Watchpoint(self, jank_addr, size, mode, handler, max_events)
        with self._qlock:
            self.watchpoints.append(wp)
        self.wake()
        return wp

    def _schedule_unwatch(self, wp: Watchpoint) -> None:
        with self._qlock:
            if wp not in self._to_unwatch:
                self._to_unwatch.append(wp)
        self.wake()

    @property
    def pending(self) -> list[FunctionHook]:
        """Hooks not yet on: their segment isn't loaded yet."""
        with self._qlock:
            return [fh for fh in self.hooks if not fh.installed
                    and fh not in self._to_remove]

    def ready(self) -> bool:
        with self._qlock:
            return not any(not fh.installed for fh in self.hooks)

    # -- the guest thread's turn ---------------------------------------------
    def pump(self) -> None:
        """Add and remove hooks, and answer the calls they stopped.
        Called by the Runner after every instruction stop; a handler's
        own nested call runs this too, which is how hooks fire inside a
        replacement's callees."""
        cpu = self.cpu
        with self._qlock:
            todo_remove, self._to_remove = self._to_remove, []
            todo_install = [fh for fh in self.hooks
                            if not fh.installed and fh not in todo_remove]
            todo_unwatch, self._to_unwatch = self._to_unwatch, []
            todo_watch = [wp for wp in self.watchpoints
                          if not wp.installed and wp not in todo_unwatch]
            answers, self._answers = list(self._answers), deque()
            todo_async, self._async = self._async, deque()
        changed = False
        for fh in todo_remove:
            self._unhook(fh)
            with self._qlock:
                if fh in self.hooks:
                    self.hooks.remove(fh)
            changed = True
        if todo_install or todo_watch:
            self.app_map.refresh()      # segments loaded since last look
        for fh in todo_install:
            if self._install(fh):
                changed = True
        for wp in todo_unwatch:
            self._unwatch(wp)
            with self._qlock:
                if wp in self.watchpoints:
                    self.watchpoints.remove(wp)
        for wp in todo_watch:
            self._install_watch(wp)
        if changed:
            cpu.uc.ctl_flush_tb()       # blocks translated before wouldn't hook
        for stop in answers:
            self._answer(*stop)
        for fn in todo_async:
            try:
                fn()
            except Exception:                                   # noqa: BLE001
                traceback.print_exc()

    def _install(self, fh: FunctionHook) -> bool:
        at = self.app_map.resolve(fh.jank_entry)
        if at is None:                        # its segment isn't loaded yet
            return False
        fh.entry = at
        fh.rtd = symtab.stack_adjust(self.app_map, fh.sym, at)
        uc = self.cpu.uc
        if fh.phase in ("enter", "replace"):
            fh.handles.append(uc.hook_add(UC_HOOK_CODE, self._at_entry, fh, at, at))
        if fh.phase == "return":
            for site in symtab.return_sites(self.app_map, fh.sym, at):
                fh.handles.append(
                    uc.hook_add(UC_HOOK_CODE, self._at_return, fh, site, site))
        fh.installed = True
        return True

    def _unhook(self, fh: FunctionHook) -> None:
        for h in fh.handles:
            self.cpu.uc.hook_del(h)
        fh.handles.clear()
        fh.installed = False
        fh._resume = None

    # -- memory watchpoints ---------------------------------------------------
    def _install_watch(self, wp: Watchpoint) -> bool:
        at = self.app_map.resolve(wp.jank_addr)
        if at is None:                        # its segment isn't loaded yet
            return False
        wp.live_addr = at
        uc = self.cpu.uc
        begin = at                            # the watched bytes, exactly
        end = begin + wp.size
        if wp.mode in ("write", "both"):
            wp.handles.append(uc.hook_add(UC_HOOK_MEM_WRITE, self._mem, wp, begin, end))
        if wp.mode in ("read", "both"):
            wp.handles.append(uc.hook_add(UC_HOOK_MEM_READ, self._mem, wp, begin, end))
        wp.installed = True
        return True

    def _unwatch(self, wp: Watchpoint) -> None:
        for h in wp.handles:
            self.cpu.uc.hook_del(h)
        wp.handles.clear()
        wp.installed = False
        wp.live_addr = None

    def _mem(self, uc, access: int, address: int, size: int, value: int,
             wp: Watchpoint) -> None:
        """A 68k access that reached the watched address: record it.  Runs
        inside unicorn, mid-instruction, on the guest thread -- read the
        PC and, if set, run the handler, but don't stop the core."""
        pc = uc.reg_read(UC_M68K_REG_PC) & ADDRESS_MASK
        kind = "write" if access == UC_MEM_WRITE else "read"
        ghidra_pc = self.app_map.ghidra_at(pc)
        with self._qlock:
            wp.events.append((kind, address, size, value, pc, ghidra_pc))
            if len(wp.events) > wp.max_events:
                del wp.events[:len(wp.events) - wp.max_events]
        if wp.handler is not None:
            try:
                wp.handler(kind, address, size, value, pc, ghidra_pc)
            except Exception:                                   # noqa: BLE001
                traceback.print_exc()

    def shutdown(self) -> None:
        """Take every hook off, as the application ends.  The hooks are
        on a shared core, so they go off with the machine held: if this
        application lost it while dying (killed inside a trap that was
        waiting), it takes the machine back for the moment -- the same
        way a process switch does -- and gives it back after."""
        with self._qlock:
            all_hooks, self.hooks = self.hooks, []
            all_wps, self.watchpoints = self.watchpoints, []
            self._answers.clear()
            self._async.clear()
            self._to_remove.clear()
            self._to_unwatch.clear()
        if not all_hooks and not all_wps:
            return
        runner = self.runner
        took = not runner.holding
        if took:
            runner.machine.acquire(runner)
        try:
            for fh in all_hooks:
                self._unhook(fh)
            for wp in all_wps:
                self._unwatch(wp)
            self.cpu.uc.ctl_flush_tb()
        finally:
            if took:
                runner.machine.release()

    # -- the core's turn -------------------------------------------------------
    def _at_entry(self, uc, addr, _size, fh: FunctionHook) -> None:
        """Before the routine's first instruction: snapshot the call and
        stop.  A stop the same call makes a second time -- the handler's
        own call_original, or the immediate re-fire the wave-through
        allows -- passes through quietly."""
        if fh.depth or fh._resume == addr:
            fh._resume = None
            return
        sp = self.cpu.sp
        try:
            retpc = self.mem.r32(sp)
        except Exception:                                       # noqa: BLE001
            return
        args = self._read_args(sp, fh.sym.get("params", []))
        with self._qlock:
            self._answers.append((fh, addr, "call", (sp, retpc, args)))
        uc.emu_stop()

    def _at_return(self, uc, addr, _size, fh: FunctionHook) -> None:
        """At a return site, before the RTS runs: D0 as the routine left
        it (the tracer's own read at this spot), snapshotted and stopped
        so the handler's write, if any, lands where nothing overwrites
        it.  The wave-through lets the RTS itself run once the handler
        is done."""
        if fh.depth or fh._resume == addr:
            fh._resume = None
            return
        fmt = fh.ret_format
        bits = self.cpu.a(0) if fmt == "p" else self.cpu.d(0)
        sp = self.cpu.sp            # the RTS hasn't run: it still points at
        try:                        #   the return address, the arguments
            retpc = self.mem.r32(sp)          #   above it -- the same stack
            args = self._read_args(sp, fh.sym.get("params", []))   # as entry
        except Exception:                               # noqa: BLE001
            retpc, args = 0, None
        with self._qlock:
            self._answers.append((fh, addr, "return", (sp, retpc, args, bits)))
        uc.emu_stop()

    def _read_args(self, sp: int, params: list) -> list:
        out, off = [], 4                      # past the return address
        for p in params:
            out.append(_decode(self.mem, sp + off, p["format"], p["length"]))
            off += (p["length"] + 1) & ~1
        return out

    # -- answering a stopped call -------------------------------------------------
    def _answer(self, fh: FunctionHook, addr: int, kind: str, snap) -> None:
        """The core is stopped and between blocks.  Run the handler, then
        put the machine where the routine would have: a replaced or
        skipped call answered as its RTS would have (D0, the return
        address popped, the RTD cleanup), a value assigned at a return
        written back to D0, and any call the handler let run waved into
        its hooked instruction."""
        with self._qlock:
            if fh not in self.hooks:          # uninstalled before this ran
                return
        fh.depth += 1
        try:
            if kind == "call":
                sp, retpc, args = snap
                hook = Hook(fh, args, sp, retpc)
                if fh.phase == "replace":
                    try:
                        value = fh.handler(hook)
                    except Exception:                           # noqa: BLE001
                        traceback.print_exc()
                        fh._resume = addr       # broken hook: let the routine run
                        return
                    self._ret(fh, hook, sp, retpc, value)   # PC to caller
                else:
                    try:
                        skip = fh.handler(hook) is SKIP
                    except Exception:                           # noqa: BLE001
                        traceback.print_exc()
                        skip = False
                    if skip:
                        self._ret(fh, hook, sp, retpc, hook.skip_value)
                    else:
                        fh._resume = addr       # and the routine goes on
            else:
                sp, retpc, args, bits = snap
                fmt = fh.ret_format
                hook = Hook(fh, args, sp, retpc,
                            value=_decode_result(fmt, bits), value_set=False)
                try:
                    fh.handler(hook)
                except Exception:                               # noqa: BLE001
                    traceback.print_exc()
                if hook._value_set:
                    setter = self.cpu.set_a if fmt == "p" else self.cpu.set_d
                    setter(0, _encode_result(fmt, hook.value))
                fh._resume = addr               # the RTS runs next
        finally:
            fh.depth -= 1

    def _ret(self, fh: FunctionHook, hook: Hook, sp: int, retpc: int, value) -> None:
        """Answer the call the way its RTS would have: the value in D0
        (A0 for a pointer), the return address off the stack, and the
        routine's own RTD cleanup done here instead of there.  The
        condition codes are not emulated; the caller sees whatever the
        handler left."""
        fmt = fh.ret_format
        if fmt:
            setter = self.cpu.set_a if fmt == "p" else self.cpu.set_d
            setter(0, _encode_result(fmt, value))
        self.cpu.sp = sp + 4 + fh.rtd
        self.cpu.pc = retpc & ADDRESS_MASK
        hook.skipped = True

    # -- calling 68k code back ------------------------------------------------------
    def _guest_thread(self) -> bool:
        return threading.current_thread() is self.process.thread

    def _guard(self) -> None:
        if self._guest_thread():
            return                      # pump's turn: everything is ours
        if self.runner.holding:
            raise RuntimeError(
                f"{self.process.name} is running its own code right now; "
                "call from a hook handler or async_call, or from a thread "
                "while it's waiting")

    def call(self, addr: int, params=(), args=(), result: str | None = "") -> Any:
        """Run a routine and return its answer: `args` pushed on the
        stack per `params`, and what comes back decoded per `result` --
        a Ghidra format, a register name like "d3", or "" for raw D0.
        Takes the machine for the length of the call; refuses if the
        guest is running its own code."""
        self._guard()
        if self._guest_thread():
            return self._invoke(addr, list(params), tuple(args), result)
        machine = self.runner.machine
        machine.acquire(self.runner)
        try:
            return self._invoke(addr, list(params), tuple(args), result)
        finally:
            machine.release()

    def call_regs(self, addr: int, out=("d0",), **regs: int):
        """Call it with its arguments in registers, and take back the
        registers named in `out`."""
        self._guard()
        if self._guest_thread():
            return self.runner.call_for(addr, tuple(out), **regs)
        machine = self.runner.machine
        machine.acquire(self.runner)
        try:
            return self.runner.call_for(addr, tuple(out), **regs)
        finally:
            machine.release()

    def _invoke(self, addr: int, params: list, args: tuple, result) -> Any:
        """The call itself, on the thread holding the machine: Pascal
        arguments as the signature says -- pushed right to left, so the
        first sits nearest the return address -- and the answer from
        where the routine leaves it.  The registers all come back as
        they were, so this runs transparently under a stopped hook."""
        cpu = self.cpu
        ctx = cpu.context()
        try:
            for p, value in zip(reversed(params), reversed(args)):
                raw = _arg_bytes(p["format"], p["length"], value)
                pad = (p["length"] + 1) & ~1
                sp = cpu.sp - pad
                cpu.sp = sp
                self.mem.write(sp, raw)
                if pad > len(raw):
                    self.mem.write(sp + len(raw), bytes(pad - len(raw)))
            self.runner._jsr(addr)
            if result and len(result) == 2 and result[0] in "da":
                reg = int(result[1])
                return (cpu.a if result[0] == "a" else cpu.d)(reg)
            fmt = result or "x"
            bits = cpu.a(0) if fmt == "p" else cpu.d(0)
            return _decode_result(fmt, bits)
        finally:
            cpu.restore(ctx)

    def async_call(self, fn: Callable) -> None:
        """Run fn on the guest thread at its next stop; wakes the
        application if it was waiting."""
        with self._qlock:
            self._async.append(fn)
        self.wake()

    def wake(self) -> None:
        """Nudge the process: an application asleep in WaitNextEvent
        takes the null event and its loop turns -- which is where hooks
        go on and queued calls run."""
        try:
            self.process.events.post(EventRecord(0, 0, 0, Point(0, 0), 0))
        except Exception:                                       # noqa: BLE001
            pass

    # -- the machine's state ----------------------------------------------------------
    def _regs_now(self) -> dict:
        """The registers, read wherever the caller is: at a hook stop or
        pump, the core is between blocks and they're the routine's own."""
        cpu = self.cpu
        out = {f"d{n}": cpu.d(n) for n in range(8)}
        out.update({f"a{n}": cpu.a(n) for n in range(7)})
        out["a7"] = out["sp"] = cpu.sp
        out["pc"] = cpu.pc
        out["sr"] = cpu.sr
        return out

    def regs(self) -> dict:
        """d0-d7, a0-a6, sp (a7), pc and sr, right now.  The guest has
        to be stopped to look: see `call`."""
        self._guard()
        if self._guest_thread():
            return self._regs_now()
        machine = self.runner.machine
        machine.acquire(self.runner)
        try:
            return self._regs_now()
        finally:
            machine.release()
