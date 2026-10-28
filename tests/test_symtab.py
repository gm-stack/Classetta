"""Ghidra's symbol table, mapped onto a running application.

The application here is assembled by hand -- every word checked against
capstone, and against the checked-in test apps' own bytes -- because the
host has no m68k assembler.  It is deliberately built the way the jank
loader sees real applications: several CODE segments, loaded through the
jump table as the guest runs, so the map has to find segment 2 wherever
the Segment Loader happened to put it, and say plainly that CODE 3,
which nothing ever calls, resolves nowhere.

The fixture's jump table (CODE 0):

    entry 0   main      (CODE 1)    where execution starts
    entry 1   AddTwo    (CODE 1)
    entry 2   Twice     (CODE 2)    loaded when main first calls it

main pushes 3 and 2 and calls AddTwo through entry 1 -- 5 comes back --
then Twice through entry 2 -- 6 -- and loops: AddTwo again, Twice again,
and WaitNextEvent, so a tracer installed after start-up still has calls
to catch.  It calls no routine through entry 0 after the start, so the
tracer, which arms while the loop runs, logs AddTwo and Twice but not
main's own entry.
"""

import logging
import re
import struct

import pytest

from macrt import symtab
from macrt.macfile import MacFile
from macrt.resfork import Resource, build_fork

from apps.build import LOCKED_PRELOAD
from conftest import Recorder

RESULT, RESULT2, EVENT = -8, -10, -226
GLOBALS = 236

# Every encoding checked against capstone; the WaitNextEvent sequence is
# hello.s's own.  The branches' displacements are asserted against
# MAIN's length below.
MAIN = bytes.fromhex(
    "3F3C0002"               # 00 move.w #2,-(a7)      param_2
    "3F3C0003"               # 04 move.w #3,-(a7)      param_1
    "4EAD002A"               # 08 jsr 42(a5)           AddTwo's entry
    "588F"                   # 0c addq.l #4,a7
    "3B40FFF8"               # 0e move.w d0,RESULT(a5)
    "3F3C0003"               # 12 move.w #3,-(a7)
    "4EAD0032"               # 16 jsr 50(a5)           Twice's entry
    "588F"                   # 1a addq.l #4,a7
    "3B40FFF6"               # 1c move.w d0,RESULT2(a5)
    "3F3C0002"               # 20 loop: move.w #2,-(a7)
    "3F3C0003"               # 24 move.w #3,-(a7)
    "4EAD002A"               # 28 jsr 42(a5)           AddTwo again
    "588F"                   # 2c addq.l #4,a7
    "3B40FFF8"               # 2e move.w d0,RESULT(a5)
    "3F3C0003"               # 32 move.w #3,-(a7)
    "4EAD0032"               # 36 jsr 50(a5)           Twice again
    "588F"                   # 3a addq.l #4,a7
    "3B40FFF6"               # 3c move.w d0,RESULT2(a5)
    "3F3CFFFF"               # 40 move.w #$ffff,-(a7)  everyEvent
    "486DFF1E"               # 44 pea EVENT(a5)
    "2F3C0000001E"           # 48 move.l #30,-(a7)     sleep
    "42A7"                   # 4e clr.l -(a7)          mouseRgn
    "A860"                   # 50 _WaitNextEvent
    "101F"                   # 52 move.b (a7)+,d0
    "67CA"                   # 54 beq.s loop           (0x20 - 0x56)
    "302DFF1E"               # 56 move.w EVENT(a5),d0
    "0C400006"               # 5a cmpi.w #6,d0         updateEvt
    "66C0"                   # 5e bne.s loop           (0x20 - 0x60)
    "4E75")                  # 60 rts
ADDTWO = bytes.fromhex("302F0004"      # move.w 4(a7),d0    param_1
                       "D06F0006"      # add.w 6(a7),d0     param_2
                       "4E75")
TWICE = bytes.fromhex("302F0004"       # move.w 4(a7),d0
                      "D040"           # add.w d0,d0
                      "4E75")


def jt_entry(offset, seg):
    """One jump table entry as CODE 0 leaves it: the routine's offset in
    its segment, then MOVE.W #seg,-(SP) and _LoadSeg."""
    return struct.pack(">4H", offset, 0x3F3C, seg, 0xA9F0)


JT = jt_entry(0, 1) + jt_entry(len(MAIN), 1) + jt_entry(0, 2)


CODE3 = b"\x4E\x75" * 4     # a segment nothing ever loads, but the dump laid out


def fixture_app():
    """CODE 0 describes the A5 world; CODE 1..3 are the segments, each
    starting with its first entry and entry count (a byte offset into
    the jump table), then its code.  CODE 3 nothing ever loads."""
    code0 = struct.pack(">IIII", 32 + len(JT), GLOBALS, len(JT), 32) + JT
    code1 = struct.pack(">HH", 0, 2) + MAIN + ADDTWO
    code2 = struct.pack(">HH", len(jt_entry(0, 1)) + len(jt_entry(len(MAIN), 1)), 1) + TWICE
    code3 = struct.pack(">HH", 24, 0) + CODE3
    rsrc = build_fork([
        Resource(b"CODE", 0, code0, b"", 0x20 | LOCKED_PRELOAD),
        Resource(b"CODE", 1, code1, b"Main"),
        Resource(b"CODE", 2, code2, b"Far"),
        Resource(b"CODE", 3, code3, b"NotLoaded"),
        Resource(b"SIZE", -1, struct.pack(">HII", 0, 64 * 1024, 64 * 1024)),
    ])
    return MacFile(name="SymFix", type=b"APPL", creator=b"SYMF", rsrc=rsrc)


def sym(name, entry, body_end, params=()):
    """One symbol as extract_symbols saves it: short args and return,
    the way Ghidra found them for the fixture's routines."""
    return {"name": name, "entry": entry, "body_end": body_end, "signature": "",
            "return": {"type": "short", "format": "h", "length": 2},
            "params": [{"name": n, "type": "short", "format": "h", "length": 2}
                       for n in params]}


def table(lay):
    """Ghidra's view of the fixture, in jank addresses.  body_end runs
    past each routine's RTS into its neighbour -- the way a Ghidra body
    can overrun -- to prove the tracer's scan stops at the segment."""
    seg1, seg2 = lay.segments[0], lay.segments[1]
    return [sym("main", seg1.jank_base, seg1.jank_base + len(MAIN)),
            sym("AddTwo", seg1.jank_base + len(MAIN),
                seg1.jank_base + len(MAIN) + len(ADDTWO) + 2,
                ("param_1", "param_2")),
            sym("Twice", seg2.jank_base, seg2.jank_base + len(TWICE), ("param_1",))]


def _traced(caplog) -> str:
    """Everything the trace loggers have said, as one text."""
    return "\n".join(r.message for r in caplog.records)


def launch_fixture(h):
    """The fixture running, with a Python app alongside so the display
    stays up whatever it does."""
    h.launch(Recorder("Other"))
    proc = h.d.launch("SymFix", None, app=fixture_app())
    a5 = proc.partition.a5
    h.wait_until(lambda: proc.system.mem.r16(a5 + RESULT) == 5, timeout=10,
                 what="the fixture's first AddTwo")
    h.wait_until(lambda: proc.system.mem.r16(a5 + RESULT2) == 6,
                 what="the fixture's Twice")
    return proc


@pytest.fixture
def jank_fixture():
    return symtab.jank_layout(fixture_app().rsrc)


def test_jank_layout_of_the_fixture(jank_fixture):
    """What `jank_layout` computes is what the jank loader laid out:
    the segments back to back in id order -- CODE 0 taking no room --
    the A5 at the end of them, and the image's jump table CODE 0's,
    rewritten as segnum | JMP | address."""
    lay = jank_fixture
    assert lay.below_a5 == GLOBALS
    assert lay.jank_a5 == 0x10000 + GLOBALS + len(MAIN) + len(ADDTWO) + len(TWICE) \
        + len(CODE3)            # the dump lays out every segment it sees
    assert [(s.id, s.first_entry, s.entry_count) for s in lay.segments] == \
        [(1, 0, 2), (2, 16, 1), (3, 24, 0)]   # first_entry: bytes into the jump table
    seg1, seg2, seg3 = lay.segments
    assert seg1.jank_base == 0x10000 and seg1.size == len(MAIN) + len(ADDTWO)
    assert seg2.jank_base == seg1.jank_base + seg1.size
    assert seg3.jank_base == seg2.jank_base + seg2.size
    image = lay.image()
    assert len(image) == lay.jank_a5 + 32 + len(JT)
    assert image[seg1.jank_base:seg1.jank_base + 4] == MAIN[:4]
    assert image[seg1.jank_base + len(MAIN):][:4] == ADDTWO[:4]
    assert image[seg2.jank_base:seg2.jank_base + 4] == TWICE[:4]
    e0 = struct.unpack_from(">II", image, lay.jank_a5 + 32)
    assert e0[0] == (1 << 16) | 0x4EF9 and e0[1] == seg1.jank_base


def test_symbols_for_refuses_another_version(jank_fixture):
    """A table extracted for another application -- its jank A5, which
    every resource the dump was built from adds up to, is different --
    is refused rather than let mislabel the log."""
    class Holder:
        app = fixture_app()

    with pytest.raises(ValueError, match="another application"):
        symtab.symbols_for(Holder(), [], {"jank_a5": 0x1234})


def test_jump_table_slots_are_not_traced(jank_fixture):
    """Ghidra makes a function of each jump table slot, under the
    routine's own name; hooking it too would log every call through the
    table twice.  `install` leaves the slots out -- and knows a slot when
    it sees one, the table's callable word being two bytes into each
    eight-byte entry."""
    lay = jank_fixture
    assert lay.is_jt_slot(lay.jank_a5 + 32 + 2)      # entry 0's callable word
    assert lay.is_jt_slot(lay.jank_a5 + 32 + 10)     # entry 1's
    assert not lay.is_jt_slot(lay.jank_a5 + 32)      # the offset word
    assert not lay.is_jt_slot(lay.jank_a5 + 32 + 1)  # the MOVE.W's first word
    assert not lay.is_jt_slot(lay.segments[0].jank_base)   # real code

    tracer = symtab.FunctionTracer(None, _MapOnly(lay), [
        sym("main", lay.segments[0].jank_base, 0),
        sym("AddTwoSlot", lay.jank_a5 + 32 + 8 + 2, 0),         # entry 1's slot
    ])
    assert tracer.install() == 1                      # only main queued
    assert [s["name"] for s in tracer.pending] == ["main"]


class _MapOnly:
    def __init__(self, layout):
        self.layout = layout


def test_char_pointer_arguments_show_their_strings():
    """A `char *` argument prints its address and -- when the bytes
    really are a NUL-terminated string -- the text after it.  A pointer
    that isn't one (unterminated, or binary) shows its address alone."""
    import struct as _struct

    class Mem:
        def __init__(self, blob, base):
            self.blob, self.base = blob, base

        def r8(self, a):
            i = a - self.base
            if not 0 <= i < len(self.blob):
                raise RuntimeError("bus")
            return self.blob[i]

        def read(self, a, n):
            return bytes(self.r8(a + i) for i in range(n))

    base = 0x500000
    blob = bytearray(b"hello\x00" + b"\xff\xfe" * 4 + b"\x00" * 4)
    slots = len(blob)
    blob += _struct.pack(">I", base) + _struct.pack(">I", base + 6) + b"\x00" * 4
    mem = Mem(blob, base)
    fmt = symtab.FunctionTracer._fmt
    p = {"format": "p", "length": 4, "type": "char *"}
    sp = base
    assert fmt(None, mem, sp, p, slots) == f'0x{base:08X} "hello"'
    # Not a string: binary bytes, no termination to be found in text.
    assert fmt(None, mem, sp, p, slots + 4) == f"0x{base + 6:08X}"
    # NULL shows as NULL, with no string of course.
    assert fmt(None, mem, sp, p, slots + 8) == "NULL"
    # Any other pointer type: the address, string or not.
    assert fmt(None, mem, sp, {"format": "p", "length": 4, "type": "int *"},
               slots) == f"0x{base:08X}"


def _stub_headless(tmp_path, body: str) -> str:
    """A fake Ghidra install: a `support/analyzeHeadless` shell script
    running `body` (it sees the real argument list, so it can check the
    flags and write the output JSON wherever asked)."""
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    script = home / "support" / "analyzeHeadless"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)
    return str(home)


def test_headless_extraction_reads_the_project(tmp_path, jank_fixture):
    """`extract_symbols_headless` runs Ghidra's analyzeHeadless over the
    project read-only and with analysis off, hands the post-script its
    output path and this application's jank A5, and returns the JSON the
    script wrote; `finalize_rows` then parses the signatures."""
    home = _stub_headless(tmp_path, """
echo "$@" > "$STUB_ARGS"
# the post-script's output path is its first argument, after its own name
out=""
seen=0
for a in "$@"; do
    if [ "$seen" = 1 ]; then out="$a"; break; fi
    case "$a" in *ExtractSymbols.java) seen=1;; esac
done
printf '{"program": "the_dump", "a5": %d, "functions": [
  {"name": "main", "entry": "00010000", "body_end": "00010060",
   "signature": "short main(void)"},
  {"name": "AddTwo", "entry": "0x10062", "body_end": null, "signature": null}]}' \\
    %d > "$out"
""" % (jank_fixture.jank_a5, jank_fixture.jank_a5))
    (tmp_path / "stub.args").touch()
    rows, meta = symtab.extract_symbols_headless(
        str(tmp_path / "proj.gpr"), "the_dump", ghidra_home=home,
        jank_a5=jank_fixture.jank_a5,
        env={"STUB_ARGS": str(tmp_path / "stub.args")})
    args = (tmp_path / "stub.args").read_text()
    assert "-noanalysis" in args and "-readOnly" in args
    assert "ExtractSymbols.java" in args
    assert f"{jank_fixture.jank_a5:X}" in args
    assert meta["program"] == "the_dump"
    table = symtab.finalize_rows(rows)
    assert [t["name"] for t in table] == ["main", "AddTwo"]
    assert table[0]["entry"] == 0x10000 and table[0]["body_end"] == 0x10060
    assert table[0]["return"]["format"] == "h"
    assert table[1]["body_end"] == table[1]["entry"] + 1     # no body given
    assert table[1]["params"] == []


def test_headless_extraction_refuses_another_version(tmp_path):
    """A project whose program's dump A5 is not this application's: the
    script prints EXTRACT-MISMATCH and writes nothing, and the reader
    says so -- the same refusal the live path made."""
    home = _stub_headless(tmp_path, """
echo "EXTRACT-MISMATCH a5=dead want=BEEF"
exit 0
""")
    with pytest.raises(ValueError, match="matches this application"):
        symtab.extract_symbols_headless(str(tmp_path / "proj.gpr"), "other",
                                        ghidra_home=home, jank_a5=0xBEEF)


def test_headless_extraction_reports_a_failed_read(tmp_path):
    home = _stub_headless(tmp_path, """
echo "ERROR: something Ghidra said" >&2
exit 1
""")
    with pytest.raises(RuntimeError, match="symbol read failed"):
        symtab.extract_symbols_headless(str(tmp_path / "proj.gpr"), "gone",
                                        ghidra_home=home)


def test_find_ghidra_needs_an_install(tmp_path):
    with pytest.raises(FileNotFoundError, match="analyzeHeadless"):
        symtab.find_ghidra(str(tmp_path / "not_ghidra"))


def test_signature_parsing():
    """What `extract_symbols` reads off a Ghidra signature: the stack
    slots each argument takes, and the return."""
    parsed = symtab._parse_signature(
        "int __stdcall menu_SetItemEnabled(int param_1, char * param_2);")
    assert [p["format"] for p in parsed["params"]] == ["i", "p"]
    assert parsed["return"]["format"] == "i"
    assert symtab._parse_signature("void no_args(void)")["params"] == []
    assert symtab.type_info("Handle") == ("x", 4)      # unknown shape: four hex bytes


def test_map_finds_every_segment_while_it_runs(harness, jank_fixture):
    """The live jump table -- patched by the loader as the guest runs --
    tells the map where every loaded piece of the application is.  The
    image and live memory agree word for word over both loaded
    segments; below A5 and the table itself map by the A5 delta; low
    memory is the same place; CODE 3, never loaded, resolves nowhere."""
    h = harness()
    proc = launch_fixture(h)
    lay = jank_fixture
    amap = symtab.AppMap(proc, lay)
    assert amap.refresh() >= 2
    # The loader puts each segment where the heap finds room, not side by
    # side; every one of them is found through the table, wherever it is.
    image = lay.image()
    for seg in (lay.segments[0], lay.segments[1]):
        for off in range(0, seg.size - 3, 2):
            assert amap.live_bytes(seg.jank_base + off, 4) == \
                image[seg.jank_base + off:seg.jank_base + off + 4], \
                f"segment {seg.id} at {off:#x}"
    assert amap.resolve(lay.jank_a5 + 32) == proc.partition.a5 + 32
    assert amap.resolve(lay.jank_a5 - 10) == proc.partition.a5 - 10
    assert amap.resolve(0x120) == 0x120
    assert amap.resolve(lay.segments[2].jank_base) is None


def test_tracer_logs_arguments_and_returns(harness, jank_fixture, caplog):
    """The tracer arms while the fixture's loop runs and logs every
    call it resolves: the name, the arguments as they sit on the stack,
    and what came back -- across the segment boundary, from CODE 2's
    routine too.  main itself entered before the hooks went on, so the
    log holds no line for it; that's what arming late means."""
    h = harness()
    proc = launch_fixture(h)
    lay = jank_fixture
    with caplog.at_level(logging.DEBUG, logger="macrt.func"):
        tr = symtab.symbols_for(proc, table(lay), {"jank_a5": lay.jank_a5})
        h.wait_until(lambda: "func Twice(param_1=3)" in _traced(caplog),
                     timeout=5, what="Twice traced")
    text = _traced(caplog)
    assert re.search(r"SymFix: func AddTwo\(param_1=3, param_2=2\) -> 5 "
                     r"\(called from \$[0-9A-F]{6} / ram:[0-9A-F]{8} @ main\+2C\)", text)
    assert re.search(r"SymFix: func Twice\(param_1=3\) -> 6 "
                     r"\(called from \$[0-9A-F]{6} / ram:[0-9A-F]{8} @ main\+3A\)", text)
    assert "main" not in text.replace("@ main", "")
    tr.uninstall()
    h.wait_until(lambda: not tr.pending and not tr._handles, timeout=5,
                 what="the hooks to come off")
    # The guest goes on living: WaitNextEvent keeps stamping its record.
    when = proc.system.mem.r32(proc.partition.a5 + EVENT + 6)
    h.wait_until(lambda: proc.system.mem.r32(proc.partition.a5 + EVENT + 6) > when,
                 timeout=5, what="the guest still running after uninstall")
    assert "AddTwo" in _traced(caplog)             # and the log keeps what it saw


def test_dump_memory_matches_live_ram(harness, tmp_path):
    h = harness()
    proc = launch_fixture(h)
    path = tmp_path / "ram.bin"
    assert proc.dump_memory(str(path)) == len(proc.system.mem._b)
    data = path.read_bytes()
    mem = proc.system.mem
    for at, n in ((0x120, 4), (proc.partition.a5 + 32, 16),
                  (proc.partition.a5 + RESULT, 2), (proc.partition.a5 - 4, 2)):
        assert data[at:at + n] == mem.read(at, n)


def test_controller_flow(harness, jank_fixture, tmp_path, caplog):
    """The automation path end to end: save a table in the extractor's
    format, load it, map a Ghidra address, trace with a name filter."""
    from macrt.ui.automation import Controller

    h = harness()
    proc = launch_fixture(h)
    lay = jank_fixture
    ctl = Controller(h.d)
    assert ctl.symbols() == []
    with pytest.raises(RuntimeError, match="symbol table"):
        ctl.trace_functions()

    cache = tmp_path / "syms.json"
    symtab.save_symbols(str(cache), table(lay), {"jank_a5": lay.jank_a5})
    assert ctl.load_symbols(str(cache)) == 3
    functions, meta = symtab.load_symbols(str(cache))
    assert meta["jank_a5"] == lay.jank_a5
    assert [f["name"] for f in functions] == ["main", "AddTwo", "Twice"]

    assert ctl.map_address(lay.segments[1].jank_base) == \
        symtab.AppMap(proc, lay).bases[2]
    assert ctl.map_address(lay.segments[2].jank_base) is None

    with caplog.at_level(logging.DEBUG, logger="macrt.func"):
        ctl.trace_functions(("AddTwo",))
        ctl.wait(ctl.trace_ready, timeout=5)
        ctl.wait(lambda: re.search(
            r"func AddTwo\(param_1=3, param_2=2\) -> 5 "
            r"\(called from \$[0-9A-F]{6} / ram:[0-9A-F]{8} @ main\+[0-9A-F]+\)",
            _traced(caplog)), timeout=5)
        assert "Twice" not in _traced(caplog)      # the filter held
        ctl.trace_stop()


def test_trap_trace_shaped_like_the_function_trace(harness, jank_fixture, caplog):
    """--trace-traps logs `Name(args) -> value (called from $live /
    ram:jank)`: the WaitNextEvent at MAIN's $50 answers with its
    event mask, and the call site names both worlds -- the live
    address the guest ran at, and the same byte in Ghidra's dump."""
    import logging
    import re

    h = harness()
    proc = launch_fixture(h)
    lay = jank_fixture
    with caplog.at_level(logging.DEBUG, logger="macrt.m68k"):
        proc.runner.trace = True
        h.wait_until(
            lambda: any("trap WaitNextEvent(" in r.message
                        for r in caplog.records), timeout=5,
            what="the trap traced")
    proc.runner.trace = False
    line = next(r.message for r in caplog.records
                if "trap WaitNextEvent(" in r.message)
    m = re.search(r"SymFix: trap WaitNextEvent\(-1, \$[0-9A-F]+, 30, \$0\) "
                  r"-> ([01]) \(called from \$([0-9A-F]{6}) / ram:([0-9A-F]{8})\)", line)
    assert m, line
    jank = int(m.group(3), 16)
    assert jank == lay.segments[0].jank_base + 0x50      # MAIN's own TRAP word
