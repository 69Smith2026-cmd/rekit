from __future__ import annotations

import struct
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
SCN_MEM_WRITE = 0x80000000
SCN_MEM_EXECUTE = 0x20000000


@register
class PEAnalyzer(Analyzer):
    name = "pe"
    description = "PE header and section walk with packing heuristics"
    tags = ("pe", "packing")

    def applies_to(self, path: Path, data: bytes) -> bool:
        return len(data) > 0x40 and data[:2] == b"MZ"

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        out: list[Finding] = []
        if len(data) < 0x40 or data[:2] != b"MZ":
            return out
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error:
            return out

        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            out.append(Finding(
                self.name, "MZ without valid PE signature", Severity.LOW,
                "DOS stub present but no PE header at e_lfanew.",
                {"e_lfanew": e_lfanew}, [0x3C], ["pe", "malformed"],
            ))
            return out

        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        n_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        chars = struct.unpack_from("<H", data, e_lfanew + 22)[0]

        out.append(Finding(
            self.name, "PE header", Severity.INFO, "",
            {
                "machine": MACHINES.get(machine, hex(machine)),
                "sections": n_sections,
                "compile_time": timestamp,
                "is_dll": bool(chars & 0x2000),
            },
            [e_lfanew], ["pe"],
        ))

        sec_off = e_lfanew + 24 + opt_size
        for i in range(min(n_sections, 96)):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            sname = data[base:base + 8].rstrip(b"\0").decode("latin-1", "replace")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, base + 8)
            flags = struct.unpack_from("<I", data, base + 36)[0]

            if flags & SCN_MEM_WRITE and flags & SCN_MEM_EXECUTE:
                out.append(Finding(
                    self.name, f"RWX section {sname!r}", Severity.HIGH,
                    "Writable and executable - self-modifying or packed.",
                    {"vaddr": hex(vaddr), "raw_size": rsize}, [base], ["pe", "packing"],
                ))
            if rsize == 0 and vsize > 0:
                out.append(Finding(
                    self.name, f"Unbacked section {sname!r}", Severity.MEDIUM,
                    "Virtual size with no file bytes - unpacking space.",
                    {"vaddr": hex(vaddr), "vsize": vsize}, [base], ["pe", "packing"],
                ))
            if rsize and roff + rsize > len(data):
                out.append(Finding(
                    self.name, f"Section {sname!r} overruns EOF", Severity.MEDIUM,
                    "Raw data extends past end of file - truncated or crafted.",
                    {"raw_offset": hex(roff), "raw_size": rsize}, [roff], ["pe", "malformed"],
                ))
        return out
