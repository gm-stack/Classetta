"""
Ghidra's symbol table, and where its functions live while the
application runs here.

The Ghidra project was loaded from a "jank loader" image: the
application's CODE resources laid out by hand -- low memory, then the
STRS resource, then every CODE segment back to back (Think C's CREL
relocations applied as though A5 sat just above them), then the
globals from DATA and ZERO, then the A5 world with its jump table.
Every address in Ghidra is an address in that image.

This application, run by Classetta, gets a partition wherever the
Memory Manager can find one, and its own start-up code loads its
segments and patches its jump table the way the Segment Loader does.
So a Ghidra address finds its way back to live memory through the
jump table itself: entry i of the live table, and entry i of the
table in the image, are entries of the same routine, and the offset
word each carries says how far into its segment the routine is.
`AppMap.resolve` does that translation.

`GhidraMcp` asks a running Ghidra (the ghidrassist MCP server) for
each function's name, arguments and return value, and `load_symbols`
caches what it found in a JSON file, so a later run needs no Ghidra.
`FunctionTracer` hooks every routine the map resolves and logs its
name, its arguments as they pass on the stack, and what it returns.
"""

from __future__ import annotations

import json
import re
import struct
import sys
import threading
import urllib.request
from dataclasses import dataclass, field
from typing import IO, Callable, Iterator

from unicorn import UC_HOOK_CODE

from .memory import ADDRESS_MASK
from .resfork import open_fork

SYSTEM_RAM_SIZE = 0x10000
JT_OFFSET = 0x20                    # the jump table's offset from A5, in both worlds
DUMMY_ADDR = 0xFFFFFFFF

DEFAULT_MCP_URL = "http://127.0.0.1:8080/mcp"


# ---------------------------------------------------------------------------
# The jank loader's image, rebuilt from the application's resources
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class JankSegment:
    id: int
    jank_base: int              # where the segment's code (past its 4-byte header) sits
    size: int                   # bytes of code
    first_entry: int            # its first entry in the jump table
    entry_count: int
    relocated: bool             # Think C: a CREL resource to apply


@dataclass(frozen=True)
class JankLayout:
    """Every address the jank dump uses, recomputed from the resources it
    was made from.  `image()` rebuilds the dump itself, byte for byte."""
    above_a5: int
    below_a5: int
    jt_size: int
    jump_table: bytes           # CODE 0's jump table, as loaded
    segments: tuple[JankSegment, ...]
    jank_a5: int
    strs_base: int | None       # where STRS 0 sits, if the app has one
    strs: bytes
    below_data: bytes           # DATA/ZERO merged, DREL applied, padded below_a5 long
    low_ram: bytes              # the dump's first 0x10000 bytes
    segment_images: tuple[bytes, ...] = ()    # the segments, CREL-applied, in id order

    def segment_at(self, addr: int) -> JankSegment | None:
        for s in self.segments:
            if s.jank_base <= addr < s.jank_base + s.size:
                return s
        return None

    def is_jt_slot(self, addr: int) -> bool:
        """Is this address a jump table entry's callable word?  Ghidra
        disassembles the table and makes a function of each slot, under
        the routine's own name: the same call would log twice, once at
        the slot and once in the routine, and the slot's 'body' is
        nonsense -- two words and the next entry's JMP.  Tracing works
        from the routines, not their entries."""
        off = addr - (self.jank_a5 + JT_OFFSET)
        return 0 <= off < len(self.jump_table) and (off - 2) % 8 == 0

    def image(self) -> bytes:
        a5_world = bytearray(b"\0" * JT_OFFSET)
        for i in range(0, len(self.jump_table) - 7, 8):
            entry = self.jump_table[i:i + 8]
            if entry[2:4] == b"\x3f\x3c":             # MOVE.W #seg,-(SP); _LoadSeg
                seg = self._by_id(struct.unpack_from(">H", entry, 4)[0])
                addr = (seg.jank_base + struct.unpack_from(">H", entry)[0]
                        if seg else DUMMY_ADDR)
                num = seg.id if seg else 0
            elif entry[2:4] == b"\x4e\xed":           # JMP OFFSET(a5): pre-loaded
                num = 0
                addr = JT_OFFSET + i + struct.unpack_from(">H", entry, 4)[0]
            else:
                num = 0
                addr = DUMMY_ADDR
            a5_world += struct.pack(">H", num) + b"\x4e\xf9" + struct.pack(">I", addr)
        return (self.low_ram + self.strs + b"".join(self.segment_images)
                + self.below_data + bytes(a5_world))

    def _by_id(self, seg_id: int) -> JankSegment | None:
        return next((s for s in self.segments if s.id == seg_id), None)


def jank_layout(rsrc: bytes) -> JankLayout:
    """Rebuild what dump.py made, from an application's resource fork.
    Segments go in resource-id order and CODE 0 doesn't take room.  The
    result's image() matches the dump Ghidra was loaded from exactly."""
    fm = open_fork(rsrc)
    resources: dict[bytes, dict[int, bytes]] = {}
    for e in fm.entries:
        resources.setdefault(e.type, {})[e.id] = fm.raw(e)
    codes = resources.get(b"CODE")
    if not codes or 0 not in codes:
        raise ValueError("no CODE 0 resource to lay out")
    jumptable = codes[0]
    above, below, jt_size, jt_offset = struct.unpack_from(">IIII", jumptable)
    if jt_size < 8 or len(jumptable) < 16 + jt_size:
        raise ValueError("CODE 0's jump table doesn't add up")
    if jt_offset != JT_OFFSET:
        raise ValueError(f"jump table at ${jt_offset:04X}, not ${JT_OFFSET:02X} "
                         "as the jank loader puts it")
    table = jumptable[16:16 + jt_size].ljust(jt_size, b"\0")

    strs = resources.get(b"STRS", {}).get(0, b"")
    ids = sorted(i for i in codes if i != 0)
    jank_a5 = below + SYSTEM_RAM_SIZE + len(strs)
    jank_a5 += sum(len(codes[i]) - 4 for i in ids)

    strs_base = SYSTEM_RAM_SIZE if strs else None
    crels = resources.get(b"CREL", {})
    segments: list[JankSegment] = []
    seg_bytes: list[bytes] = []
    base = SYSTEM_RAM_SIZE + len(strs)
    for i in ids:
        data = bytearray(codes[i][4:])
        first, count = struct.unpack_from(">HH", codes[i])
        relocated = bool(first & 0x8000)
        count &= 0x7FFF
        first &= 0x7FFF
        if relocated and count and i in crels:        # Think C relocations
            crel = crels[i]
            for j in range(0, len(crel) - 1, 2):
                addr = struct.unpack_from(">H", crel, j)[0] - 4
                patch_base = strs_base if addr & 1 else jank_a5
                addr &= 0xFFFE
                value = (struct.unpack_from(">I", data, addr)[0] + patch_base) & 0xFFFFFFFF
                struct.pack_into(">I", data, addr, value)
        segments.append(JankSegment(i, base, len(data), first, count, relocated))
        seg_bytes.append(bytes(data))
        base += len(data)

    below_data = bytes(below)
    if b"DATA" in resources and b"ZERO" in resources:
        data_rsrc = bytes(resources[b"DATA"][0])
        zero_rsrc = bytes(resources[b"ZERO"][0])
        merged = bytearray()
        zi = 0
        for i in range(0, len(data_rsrc), 2):
            merged += data_rsrc[i:i + 2]
            if struct.unpack_from(">H", data_rsrc, i)[0] == 0:
                merged += bytes(struct.unpack_from(">H", zero_rsrc, zi)[0])
                zi += 2
        if len(merged) <= below and b"DREL" in resources:
            drel = bytes(resources[b"DREL"][0])
            i = 0
            while i < len(drel) - 1:
                addr = struct.unpack_from(">h", drel, i)[0]
                if addr >= 0:
                    i += 2
                    addr = -struct.unpack_from(">H", drel, i)[0]
                patch_base = strs_base if addr & 1 else jank_a5
                if addr & 1:
                    addr -= 1
                addr += below                     # DREL counts from A5
                value = (struct.unpack_from(">I", merged, addr)[0] + patch_base) & 0xFFFFFFFF
                struct.pack_into(">I", merged, addr, value)
                i += 2
        elif len(merged) > below:
            merged = bytearray()
        if merged:
            below_data = bytes(merged) + bytes(below - len(merged))

    low = bytearray(SYSTEM_RAM_SIZE)
    header = (b"J\xffA\xffN\xffK\xff" + b"\x2a\x7c"
              + struct.pack(">I", jank_a5 & 0xFFFFFFFF) + b"\x4e\x75")
    low[:len(header)] = header
    low[0x904:0x908] = struct.pack(">I", jank_a5 & 0xFFFFFFFF)
    return JankLayout(above, below, jt_size, table, tuple(segments), jank_a5,
                      strs_base, strs, below_data, bytes(low), tuple(seg_bytes))


# ---------------------------------------------------------------------------
# The symbols, from a running Ghidra
# ---------------------------------------------------------------------------
class GhidraMcp:
    """The ghidrassist MCP server, over its streamable-HTTP transport:
    a session id from initialize, then tools/call, whose answers come
    back as SSE `data:` lines."""

    def __init__(self, url: str = DEFAULT_MCP_URL):
        self.url = url
        self._session: str | None = None

    def _post(self, payload: dict) -> dict | None:
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=120) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            body = resp.read().decode()
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return None

    def _connect(self) -> None:
        if self._session is None:
            self._post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "classetta", "version": "1"}}})
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool: str, **arguments) -> str:
        """One tool's text answer."""
        self._connect()
        reply = self._post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                            "params": {"name": tool, "arguments": arguments}})
        result = (reply or {}).get("result") or {}
        if result.get("isError"):
            raise RuntimeError(f"{tool}: {result}")
        return "\n".join(c.get("text", "") for c in result.get("content", [])
                         if c.get("type") == "text")


# FunctionSignature types, as Ghidra names them, to (struct char, bytes).
# 'p' is a pointer (shown in hex, taken from A0); 'x' is anything of an
# unknown shape, shown as hex.
_TYPE_SIZES: dict[str, tuple[str, int]] = {
    "char": ("b", 1), "schar": ("b", 1), "uchar": ("B", 1), "byte": ("B", 1),
    "undefined1": ("B", 1), "undefined": ("B", 1), "bool": ("B", 1),
    "short": ("h", 2), "ushort": ("H", 2), "word": ("H", 2),
    "undefined2": ("H", 2), "wchar_t": ("H", 2),
    "int": ("i", 4), "uint": ("I", 4), "long": ("i", 4), "ulong": ("I", 4),
    "dword": ("I", 4), "undefined4": ("I", 4), "size_t": ("I", 4),
    "float": ("f", 4),
    "void": ("", 0),
}


def type_info(t: str) -> tuple[str, int]:
    """(struct format, bytes) for a Ghidra type name: pointers first, then
    the primitives; a struct or unknown by value reads as four hex bytes."""
    t = t.strip()
    while t.endswith("*"):
        t = t[:-1].strip()
        return ("p", 4)
    t = t.split("[")[0].strip()
    if t in _TYPE_SIZES:
        return _TYPE_SIZES[t]
    return ("x", 4)


_SIG_RE = re.compile(r"^(?P<ret>.*?)\s+(?:(?P<conv>__\w+)\s+)?"
                     r"(?P<name>[\w:]+)\s*\((?P<params>.*)\)\s*;?\s*$")
_FUNC_RE = re.compile(r"^- (.+?) @ ([0-9a-fA-F]+) \((\d+) params\)", re.MULTILINE)
_BODY_RE = re.compile(r"Body: \[\[([0-9a-fA-F]+),\s*([0-9a-fA-F]+)\]\]")


def _parse_signature(sig: str) -> dict:
    m = _SIG_RE.match(sig)
    if not m:
        return {}
    ret = m.group("ret").strip()
    params = []
    text = m.group("params").strip()
    if text and text != "void":
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            # "int * param_1" or "int param_1": the name is the last word.
            words = part.rsplit(None, 1)
            if len(words) == 2 and "*" not in words[1]:
                ptype, pname = words
            else:
                ptype, pname = part, ""
            ptype = ptype.strip() + " " * ("*" in part and ptype == part)
            fmt, length = type_info(ptype)
            params.append({"name": pname, "type": ptype, "format": fmt, "length": length})
    rfmt, rlen = type_info(ret)
    return {"signature": sig, "return": {"type": ret, "format": rfmt, "length": rlen},
            "params": params}


def extract_symbols(mcp: GhidraMcp, program: str, progress: Callable[[int, int], None]
                    | None = None) -> list[dict]:
    """Every function in a program: name, entry, body, and what it takes
    and returns, as Ghidra has it.  A function whose signature Ghidra
    can't show still gets its name and address, with no parameters."""
    listing, total = [], 0
    offset = 0
    while True:
        text = mcp.call("get_functions", program_name=program, offset=offset, limit=200)
        page = _FUNC_RE.findall(text)
        if not page:
            break
        for name, addr, _n in page:
            listing.append({"name": name, "entry": int(addr, 16)})
        offset += len(page)
        m = re.search(r"Showing \d+ of (\d+)", text)
        total = int(m.group(1)) if m else total
        if offset >= total or len(page) < 200:
            break
    out = []
    for i, item in enumerate(listing):
        try:
            info = mcp.call("analyze_function", function_name=item["name"],
                            program_name=program)
        except Exception:                                   # noqa: BLE001
            info = ""
        sig_line = next((l.split("Signature: ", 1)[1].strip()
                         for l in info.splitlines() if l.startswith("Signature:")), "")
        body = _BODY_RE.search(info)
        row = {"name": item["name"], "entry": item["entry"],
               "body_end": int(body.group(2), 16) if body else item["entry"] + 1,
               "signature": sig_line}
        row.update(_parse_signature(sig_line) if sig_line else
                   {"return": {"type": "unknown", "format": "x", "length": 4}, "params": []})
        out.append(row)
        if progress:
            progress(i + 1, len(listing))
    return out


def pick_program(mcp: GhidraMcp, rsrc: bytes) -> str:
    """Which open Ghidra program the application is: the dumps record
    their A5 at $904, and the one equal to this application's jank A5
    was made from these same resources."""
    import re as _re
    layout = jank_layout(rsrc)
    names = _re.findall(r"Project Path: (\S+)", mcp.call("list_binaries"))
    for name in names:
        try:
            data = mcp.call("get_data_at", address="0x904", len=4, program_name=name)
            hexdump = _re.search(r"^[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{2} ){4})", data,
                                 _re.MULTILINE)
        except Exception:                                        # noqa: BLE001
            continue
        if hexdump and int(hexdump.group(1).replace(" ", ""), 16) == layout.jank_a5:
            return name
    raise ValueError(f"no open Ghidra program matches this application "
                     f"(jank A5 {layout.jank_a5:#x})")


def save_symbols(path: str, table: list[dict], meta: dict) -> None:
    with open(path, "w") as f:
        json.dump({"version": 1, "meta": meta, "functions": table}, f)


def load_symbols(path: str) -> tuple[list[dict], dict]:
    with open(path) as f:
        data = json.load(f)
    if data.get("version") != 1:
        raise ValueError(f"{path}: not a Classetta symbol table")
    return data["functions"], data.get("meta", {})


def symbols_for(process, table: list[dict], meta: dict | None = None,
                match: tuple[str, ...] = (), out=None) -> "FunctionTracer":
    """Trace the process's own functions -- name, arguments, return
    value -- against a symbol table extracted from Ghidra.  A table
    extracted here records the application it came from (its jank A5,
    which every resource the dump was built from adds up to); a table
    for another version is refused rather than let mislabel the log.
    The hooks go on as the guest next stops in its event loop."""
    layout = jank_layout(process.app.rsrc)
    if meta and meta.get("jank_a5") is not None and meta["jank_a5"] != layout.jank_a5:
        raise ValueError(
            f"the symbol table is for another application "
            f"(its dump's A5 {meta['jank_a5']:#x}, this app's {layout.jank_a5:#x})")
    return process.trace_functions(table, match, out)


# ---------------------------------------------------------------------------
# Where the image's addresses are while the application runs
# ---------------------------------------------------------------------------
class AppMap:
    """Ghidra's addresses to live ones, for one running application.

    The live jump table, which the application's own start-up code
    patches as its segments load, says where each loaded segment is:
    a loaded entry is `segnum, JMP, target`, and the same entry in
    CODE 0's table carries the routine's offset in the segment.  So
    `target - offset` is the segment's start, for every segment, and
    an address inside one maps by that.  Below A5 and in the jump
    table itself there's one constant: the difference between the two
    A5s."""

    def __init__(self, process, layout: JankLayout):
        self.process = process
        self.system = process.system
        self.mem = process.system.mem
        self.layout = layout
        self.live_a5 = process.partition.a5
        self.table = self.live_a5 + JT_OFFSET
        self.bases: dict[int, int] = {}        # segment id -> where its code is
        self.strs_live: int | None = None
        self.refresh()

    def refresh(self) -> int:
        """Notice segments loaded since last time; returns how many are known."""
        mem = self.mem
        for i in range(0, len(self.layout.jump_table) - 7, 8):
            e = self.table + i
            if mem.r16(e + 2) != 0x4EF9:
                continue
            jank = self.layout.jump_table[i:i + 8]
            if jank[2:4] not in (b"\x3f\x3c", b"\x4e\xed"):
                continue
            seg = struct.unpack_from(">H", jank, 4)[0] if jank[2:4] == b"\x3f\x3c" else -1
            if jank[2:4] == b"\x4e\xed":
                continue                        # JMP OFFSET(a5): below A5, no segment
            offset = struct.unpack_from(">H", jank)[0]
            self.bases[seg] = (mem.r32(e + 4) & ADDRESS_MASK) - offset
        if self.strs_live is None and self.layout.strs:
            h = self._strs_handle()
            if h:
                heap = self.system.heap_of(h)
                self.strs_live = heap.deref(h)
        return len(self.bases)

    def _strs_handle(self) -> int:
        for m in self.process.resources.maps():
            e = m.find(b"STRS", 0)
            if e is not None and e.handle:
                return e.handle
        return 0

    def resolve(self, addr: int) -> int | None:
        """Where the byte Ghidra calls `addr` is now, or None: not loaded
        yet, or not part of the application."""
        layout = self.layout
        if addr < SYSTEM_RAM_SIZE:
            return addr                                     # low memory: the same
        seg = layout.segment_at(addr)
        if seg is not None:
            base = self.bases.get(seg.id)
            return None if base is None else base + (addr - seg.jank_base)
        if layout.strs_base is not None and \
                layout.strs_base <= addr < layout.strs_base + len(layout.strs):
            return None if self.strs_live is None else \
                self.strs_live + (addr - layout.strs_base)
        below_lo = layout.jank_a5 - layout.below_a5
        if below_lo <= addr < layout.jank_a5:               # the globals below A5
            return self.live_a5 - layout.below_a5 + (addr - below_lo)
        if layout.jank_a5 <= addr < layout.jank_a5 + JT_OFFSET + layout.jt_size:
            return self.live_a5 + (addr - layout.jank_a5)   # the jump table
        return None

    def live_bytes(self, addr: int, n: int) -> bytes | None:
        at = self.resolve(addr)
        return None if at is None else self.mem.read(at, n)


# ---------------------------------------------------------------------------
# Tracing
# ---------------------------------------------------------------------------
class FunctionTracer:
    """Hooks every routine the map resolves, and writes what it sees:
    each call's name and arguments as they sit on the stack, and what
    came back when it returned.  `match` (a substring, or a list of
    them) keeps the log to the routines you asked about.

    Unicorn only takes hooks added on the thread running the CPU, so
    this queues them and installs them on the guest thread -- through
    `pump`, which the Runner calls each time an instruction stops it.
    An application stopped in its event loop is stopping constantly:
    the queue drains in a heartbeat.  The Controller can wait for it
    (`wait(lambda: not tracer.pending)`)."""

    def __init__(self, process, app_map: AppMap, table: list[dict],
                 out: IO[str] | None = None, match: tuple[str, ...] = ()):
        self.process = process
        self.app_map = app_map
        self.table = table
        self.out = out or sys.stderr
        self.match = tuple(match)
        self.depth = 0
        self.pending: list[dict] = []             # symbols waiting to be hooked
        self._handles: list = []
        self._installed: set[int] = set()         # jank entries hooked
        self._drop = False                        # uninstall queued
        self._qlock = threading.Lock()            # the queue: any thread, pump's thread

    def _wanted(self, sym: dict) -> bool:
        if not self.match:
            return True
        return any(p.lower() in sym["name"].lower() for p in self.match)

    def install(self) -> int:
        """Queue every wanted function not yet hooked; returns how many.
        Call again as more segments load -- unresolved ones stay in the
        table, and `refresh` re-queues what's still missing.  Ghidra's
        jump-table slot stubs are left out: they carry the routine's
        own name, and the routine's entry is hooked directly, so the
        slot would only log the same call a second time."""
        todo = [s for s in self.table
                if self._wanted(s) and s["entry"] not in self._installed
                and not self.app_map.layout.is_jt_slot(s["entry"])]
        with self._qlock:
            self.pending.extend(todo)
        return len(todo)

    def refresh(self) -> int:
        """Re-queue what never resolved, for segments loaded since."""
        return self.install()

    def pump(self) -> None:
        """The guest thread's turn: add and remove hooks.  The Runner
        calls this after every instruction stop."""
        cpu = self.process.runner.cpu
        with self._qlock:
            todo, self.pending = self.pending, []
            drop = self._drop
            if drop:
                self._drop = False
                for h in self._handles:
                    cpu.uc.hook_del(h)
                self._handles.clear()
                self._installed.clear()
            if not todo and not drop:
                return
            self.app_map.refresh()
            added = False
            for sym in todo:
                if sym["entry"] in self._installed:
                    continue
                at = self.app_map.resolve(sym["entry"])
                if at is None:                    # its segment isn't loaded yet
                    self.pending.append(sym)
                    continue
                self._installed.add(sym["entry"])
                self._handles.append(
                    cpu.uc.hook_add(UC_HOOK_CODE, self._enter, sym, at, at))
                for end in self._return_sites(sym, at):
                    self._handles.append(
                        cpu.uc.hook_add(UC_HOOK_CODE, self._exit, sym, end, end))
                added = True
            if added or drop:
                cpu.uc.ctl_flush_tb()      # blocks translated before wouldn't hook

    def uninstall(self) -> None:
        with self.process.system.lock:
            self.pending.clear()
            self._drop = True

    @staticmethod
    def _is_return(op: int) -> bool:
        """RTR, RTE, RTS, RTD #n, JMP (An), JMP (An)+: the ways out."""
        return op in (0x4E73, 0x4E75, 0x4E77, 0x4ED0, 0x4EE9) or 0x4E78 <= op <= 0x4E7F

    def _return_sites(self, sym: dict, entry: int) -> list[int]:
        """Where the routine can leave: every return-shaped instruction
        in its body.  Ghidra's body doesn't necessarily end at the RTS
        -- a routine returns early, or ends in a trap -- so each one is
        hooked.  The scan stops at the routine's own segment: past it
        lives its neighbours, whose RTS would log as this one's.  A
        return-shaped word that's really data inside the body logs an
        out-of-place line; that's the cost, and a small one."""
        mem = self.app_map.mem
        layout = self.app_map.layout
        body_end = sym.get("body_end", 0) or 0
        seg = layout.segment_at(sym["entry"])
        if seg is not None:                       # keep the body in its segment
            body_end = min(body_end or seg.jank_base + seg.size - 1,
                           seg.jank_base + seg.size - 1)
        end = self.app_map.resolve(body_end)
        if end is None or end <= entry:
            return []
        try:
            words = mem.read(entry, min(end - entry + 1, 0x10000))
        except Exception:                                # noqa: BLE001
            return []
        return [entry + i for i in range(0, len(words) - 1, 2)
                if self._is_return(struct.unpack_from(">H", words, i)[0])]

    def _fmt(self, mem, sp: int, p: dict, off: int) -> str:
        at = sp + off
        fmt, length = p["format"], p["length"]
        try:
            if fmt in ("b", "B", "h", "H", "i", "I", "f"):
                size = struct.calcsize(">" + fmt)
                value = struct.unpack_from(">" + fmt, mem._b, mem.physical(at))[0]
                if fmt in ("b", "B", "h", "H"):
                    return str(value)
                if fmt == "f":
                    return f"{value:g}"
                return f"{value:#x}" if fmt == "I" else str(value)
            raw = mem.read(at, length)
            return "0x" + raw.hex().upper()
        except Exception:                                # noqa: BLE001
            return "?"

    def _enter(self, uc, addr, _size, sym) -> None:
        mem = self.app_map.mem
        try:
            sp = self.process.runner.cpu.sp
        except Exception:                                # noqa: BLE001
            sp = 0
        args = []
        off = 4                                          # the return address is at SP
        for p in sym.get("params", []):
            args.append(f"{p['name']}={self._fmt(mem, sp, p, off)}" if p["name"]
                        else self._fmt(mem, sp, p, off))
            off += (p["length"] + 1) & ~1
        pad = "  " * min(self.depth, 24)
        self.out.write(f"{pad}{sym['name']}({', '.join(args)})\n")
        self.depth += 1

    def _exit(self, uc, addr, _size, sym) -> None:
        cpu = self.process.runner.cpu
        ret = sym.get("return", {})
        fmt = ret.get("format", "x")
        try:
            reg = cpu.a(0) if fmt == "p" else cpu.d(0)
            value = (f"{reg:#x}" if fmt in ("p", "I", "x")
                     else str(struct.unpack(">f", struct.pack(">I", reg & 0xFFFFFFFF))[0]
                              if fmt == "f" else reg & 0xFFFFFFFF))
        except Exception:                                # noqa: BLE001
            value = "?"
        self.depth = max(0, self.depth - 1)
        pad = "  " * min(self.depth, 24)
        self.out.write(f"{pad}-> {sym['name']}: {value}\n")
        if self.depth == 0 and hasattr(self.out, "flush"):
            self.out.flush()
