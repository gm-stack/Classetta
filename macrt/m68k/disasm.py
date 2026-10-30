"""
Disassembly of the guest's own memory, for the debugger.

Capstone gives the text; the instruction *lengths* come from cpu._step,
the decoder the core's own bookkeeping already trusts.  That pairing is
what keeps a listing in step: given the wrong length, a disassembler will
happily begin in the middle of an instruction, and one wrong length among
data or code it doesn't know throws every line after it out of step.
_step knows where each instruction the 68k would run ends, so the listing
walks by its lengths and capstone only ever sees a whole instruction.

What neither knows is a Mac Toolbox trap.  Capstone reads an A-line word
as `dc.w $A9F0`; the core stops at it and answers it in Python, and
dispatch knows which routine that word is.  So those lines read
`trap _GetResource`, which is what the machine is really doing there.
Words neither knows -- data, or code of the 68881's -- come out as
`dc.w $xxxx`, which is honest.

Reading backwards is the one thing the 68k doesn't allow: an instruction's
length is told only from its own start, so there's no way back from an
address to the instruction before it.  A window of instructions ending at
the PC is found by starting a little way back and walking forward until
one lands exactly on it; a start that overshoots was in the middle of an
instruction, and the next one further back is tried.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

from . import dispatch
from .cpu import _step

LONGEST = 6             # bytes, of what _step knows; the window to search back over
NO_ENGINE = "dc.w      (no disassembler)"


class Instruction(NamedTuple):
    address: int
    length: int
    raw: str            # its bytes, as text
    text: str           # how it reads

    @property
    def end(self) -> int:
        return self.address + self.length


_md = ...               # None once tried and capstone isn't there; a Cs when it is


def _engine():
    """Capstone, brought in on first need: only reading code wants it, and
    its absence should leave the listing as hex, not stop the runtime."""
    global _md
    if _md is ...:
        try:
            from capstone import CS_ARCH_M68K, CS_MODE_M68K_020, Cs
            _md = Cs(CS_ARCH_M68K, CS_MODE_M68K_020)
        except Exception:                                       # noqa: BLE001
            _md = None
    return _md


def is_trap(word: int) -> bool:
    """An A-line instruction: a Toolbox or OS trap, which the core answers
    in Python instead of running."""
    return 0xA000 <= word <= 0xAFFF


def instruction(mem, at: int) -> tuple[int, str]:
    """How long the instruction at `at` is and how to write it.  `mem` are
    the guest's bytes, indexed as they lie."""
    if at + 2 > len(mem):
        return 2, NO_ENGINE
    word = struct.unpack_from(">H", mem, at)[0]
    if is_trap(word):
        return 2, f"trap      _{dispatch.trap_name(word)}"
    step = _step(mem, at)
    length = step[0] if step else _scan_length(mem, at)
    return length, _text(mem, at, length)


def _scan_length(mem, at: int) -> int:
    """How long capstone thinks what begins at `at] runs to, for a word
    _step doesn't recognise: the 68881's instructions, and data."""
    for ins in _disassemble(mem, at, at + 16, whole=False):
        return len(ins.bytes) or 2
    return 2


def _text(mem, at: int, length: int) -> str:
    for ins in _disassemble(mem, at, at + length):
        if not ins.mnemonic.startswith("dc.") and ins.mnemonic != "bad":
            return f"{ins.mnemonic:<9} {ins.op_str}".rstrip()
    return f"dc.w      ${struct.unpack_from('>H', mem, at)[0]:04X}"


def _disassemble(mem, at: int, end: int, whole: bool = True):
    md = _engine()
    if md is None:
        return ()
    try:
        return list(md.disasm(bytes(mem[at:end]), at))
    except Exception:                                           # noqa: BLE001
        return ()


def row(mem, at: int) -> Instruction:
    length, text = instruction(mem, at)
    raw = " ".join(f"{b:02X}" for b in mem[at:at + length])
    return Instruction(at, length, raw, text)


def forward(mem, at: int, count: int) -> list[Instruction]:
    """`count` instructions from `at`, `at` among them."""
    out = []
    for _ in range(count):
        if not 0 <= at < len(mem):
            break
        out.append(row(mem, at))
        at += out[-1].length
    return out


def window(mem, at: int, before: int = 10, after: int = 5, shift: int = 0) -> list[Instruction]:
    """The instructions around `at`: the `before` that lie before it, the one
    at it, and the `after` following.  Those before are what's there rather
    than what ran -- after a jump they lead nowhere -- which is what a
    listing of the memory around the PC shows.

    `at` indexes the bytes as they lie (`mem`); `shift`, when given, is
    added to the address each line shows.  They differ only where an address
    is another way to memory under it -- a Mac Plus's, which repeats through
    its 4 MB -- where the PC is the address the program used and `at` the
    bytes it points at; the listing shows what the program calls it."""
    back = _backwards(mem, at, before)
    here = row(mem, at)
    rows = back + [here] + forward(mem, here.end, after)
    if shift:
        rows = [r._replace(address=r.address + shift) for r in rows]
    return rows


def _backwards(mem, at: int, want: int) -> list[Instruction]:
    """The `want` instructions lying just before `at`, oldest first.  The
    nearest instruction boundary at or before `at` is looked for by starting
    where they must begin and walking forward; a start that lands on `at` was
    on a boundary, one that walks past it began in the middle of an
    instruction.  From the nearest boundary that reaches `at` with at least
    `want` instructions, the last `want` are the window.  If `at` is on no
    boundary -- a PC caught off a byte, say -- nothing reaches it exactly,
    and the longest honest run before it is what there is to show."""
    exact: list[Instruction] = []
    best: list[Instruction] = []
    for start in range(at - 2, max(-2, at - LONGEST * (want + 1)), -2):
        run, end = [], start
        while end < at and 0 <= end < len(mem):
            run.append(row(mem, end))
            end += run[-1].length
        if end == at:                       # started on a boundary, landed on at
            if len(run) >= want:
                return run[-want:] if want else []
            if len(run) > len(exact):
                exact = run                 # a boundary, but fewer than asked
        elif end > at and len(run) > len(best):
            best = [r for r in run if r.address < at]
    run = exact or best
    return run[-want:] if want else []
