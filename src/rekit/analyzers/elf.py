from __future__ import annotations

import struct
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

SHT_NOBITS = 8
SHF_WRITE = 0x1
SHF_EXEC = 0x4


@register
class ELFAnalyzer(Analyzer):
    name = "elf"
    description = "ELF header and section walk with permission heuristics"
    tags = ("elf", "packing")

    def applies_to(self, path: Path, data: bytes) -> bool:
        return data[:4] == b"\x7fELF"

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        out: list[Finding] = []
        if len(data) < 52 or data[:4] != b"\x7fELF":
            return out
        is64 = data[4] == 2
        end = "<" if data[5] == 1 else ">"

        e_type = struct.unpack_from(end + "H", data, 16)[0]
        e_machine = struct.unpack_from(end + "H", data, 18)[0]
        out.append(Finding(
            self.name, "ELF header", Severity.INFO, "",
            {
                "class": "64-bit" if is64 else "32-bit",
                "endian": "little" if end == "<" else "big",
                "type": hex(e_type),
                "machine": hex(e_machine),
            },
            [0], ["elf"],
        ))

        if is64:
            shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
            shentsize, shnum = struct.unpack_from(end + "HH", data, 0x3A)
        else:
            shoff = struct.unpack_from(end + "I", data, 0x20)[0]
            shentsize, shnum = struct.unpack_from(end + "HH", data, 0x2E)

        if shoff == 0 or shentsize < 16:
            return out

        for i in range(min(shnum, 96)):
            base = shoff + i * shentsize
            if base + shentsize > len(data):
                break
            stype = struct.unpack_from(end + "I", data, base + 4)[0]
            flags = struct.unpack_from(end + ("Q" if is64 else "I"), data, base + 8)[0]

            if flags & SHF_WRITE and flags & SHF_EXEC:
                out.append(Finding(
                    self.name, f"W+X section #{i}", Severity.HIGH,
                    "Writable and executable - self-modifying code.",
                    {"section_index": i}, [base], ["elf", "packing"],
                ))
            if stype == SHT_NOBITS:
                out.append(Finding(
                    self.name, f"NOBITS section #{i}", Severity.MEDIUM,
                    "Occupies memory but no file bytes - unpacking space.",
                    {"section_index": i}, [base], ["elf", "packing"],
                ))
        return out
