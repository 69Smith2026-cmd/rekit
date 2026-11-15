from __future__ import annotations

import struct
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

MH_MAGIC_64 = b"\xcf\xfa\xed\xfe"
MH_MAGIC_32 = b"\xce\xfa\xed\xfe"
FAT_MAGIC = b"\xca\xfe\xba\xbe"
FAT_CIGAM = b"\xbe\xba\xfe\xca"

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18

VM_PROT_WRITE = 0x2
VM_PROT_EXEC = 0x4

FILETYPES = {1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB", 8: "MH_BUNDLE"}
CPUS = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}
SYSTEM_PREFIXES = ("/usr/lib/", "/System/")


@register
class MachOAnalyzer(Analyzer):
    name = "macho"
    description = "Mach-O load command walk: W+X segments, code signature, dylib paths"
    tags = ("macho", "packing")

    def applies_to(self, path: Path, data: bytes) -> bool:
        return data[:4] in (MH_MAGIC_64, MH_MAGIC_32, FAT_MAGIC, FAT_CIGAM)

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        out: list[Finding] = []
        if not self.applies_to(path, data):
            return out

        if data[:4] in (FAT_MAGIC, FAT_CIGAM):
            endian = ">" if data[:4] == FAT_MAGIC else "<"
            if len(data) < 8:
                return out
            n = struct.unpack_from(endian + "I", data, 4)[0]
            out.append(Finding(
                self.name, "Fat binary", Severity.INFO,
                "Multi-architecture container - each slice is analysed separately.",
                {"arch_count": n}, [0], ["macho"],
            ))
            for i in range(min(n, 32)):
                entry = 8 + i * 20
                if entry + 20 > len(data):
                    break
                cputype = struct.unpack_from(endian + "I", data, entry)[0]
                off, size = struct.unpack_from(endian + "II", data, entry + 8)
                label = CPUS.get(cputype, hex(cputype))
                if off + size > len(data) or size == 0:
                    out.append(Finding(
                        self.name, f"Slice {label} overruns EOF", Severity.MEDIUM,
                        "Fat arch entry points outside the file.",
                        {"offset": off, "size": size}, [entry], ["macho", "malformed"],
                    ))
                    continue
                self._slice(data[off:off + size], off, out, label)
            return out

        self._slice(data, 0, out, None)
        return out

    def _slice(self, data: bytes, base: int, out: list[Finding], label: str | None) -> None:
        tag = f"[{label}] " if label else ""

        if data[:4] not in (MH_MAGIC_64, MH_MAGIC_32):
            return
        is64 = data[:4] == MH_MAGIC_64
        hdr_size = 32 if is64 else 28
        if len(data) < hdr_size:
            return

        cputype = struct.unpack_from("<I", data, 4)[0]
        filetype = struct.unpack_from("<I", data, 12)[0]
        ncmds = struct.unpack_from("<I", data, 16)[0]
        sizeofcmds = struct.unpack_from("<I", data, 20)[0]

        out.append(Finding(
            self.name, f"{tag}Mach-O header", Severity.INFO, "",
            {
                "cpu": CPUS.get(cputype, hex(cputype)),
                "filetype": FILETYPES.get(filetype, hex(filetype)),
                "load_commands": ncmds,
            },
            [base], ["macho"],
        ))

        off = hdr_size
        end = min(hdr_size + sizeofcmds, len(data))
        has_sig = False
        dylibs: list[str] = []
        segnames: list[str] = []

        for _ in range(min(ncmds, 512)):
            if off + 8 > end:
                break
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmdsize < 8 or off + cmdsize > len(data):
                out.append(Finding(
                    self.name, f"{tag}Malformed load command", Severity.MEDIUM,
                    "cmdsize out of range - truncated or crafted header.",
                    {"cmd": hex(cmd), "cmdsize": cmdsize}, [base + off],
                    ["macho", "malformed"],
                ))
                break

            if cmd == LC_SEGMENT_64 and is64 and cmdsize >= 72:
                seg = data[off + 8:off + 24].rstrip(b"\0").decode("latin-1", "replace")
                vmsize = struct.unpack_from("<Q", data, off + 32)[0]
                fileoff = struct.unpack_from("<Q", data, off + 40)[0]
                filesize = struct.unpack_from("<Q", data, off + 48)[0]
                initprot = struct.unpack_from("<I", data, off + 60)[0]
                segnames.append(seg)

                if initprot & VM_PROT_WRITE and initprot & VM_PROT_EXEC:
                    out.append(Finding(
                        self.name, f"{tag}W+X segment {seg!r}", Severity.HIGH,
                        "Writable and executable segment - self-modifying or packed.",
                        {"vmsize": vmsize, "filesize": filesize, "initprot": initprot},
                        [base + off], ["macho", "packing"],
                    ))
                if filesize == 0 and vmsize > 0 and seg != "__PAGEZERO":
                    out.append(Finding(
                        self.name, f"{tag}Unbacked segment {seg!r}", Severity.MEDIUM,
                        "Virtual size with no file bytes - runtime-populated.",
                        {"vmsize": vmsize}, [base + off], ["macho", "packing"],
                    ))
                if filesize and fileoff + filesize > len(data):
                    out.append(Finding(
                        self.name, f"{tag}Segment {seg!r} overruns EOF", Severity.MEDIUM,
                        "Segment extends past end of file - truncated or crafted.",
                        {"fileoff": fileoff, "filesize": filesize}, [base + off],
                        ["macho", "malformed"],
                    ))

            elif cmd == LC_CODE_SIGNATURE:
                has_sig = True

            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB) and cmdsize >= 24:
                name_off = struct.unpack_from("<I", data, off + 8)[0]
                if 24 <= name_off < cmdsize:
                    raw = data[off + name_off:off + cmdsize].split(b"\0", 1)[0]
                    dylibs.append(raw.decode("latin-1", "replace"))

            off += cmdsize

        if filetype in (2, 6, 8) and not has_sig:
            out.append(Finding(
                self.name, f"{tag}No code signature", Severity.MEDIUM,
                "LC_CODE_SIGNATURE absent - unsigned or stripped signature.",
                {"filetype": FILETYPES.get(filetype, hex(filetype))}, [base],
                ["macho", "signing"],
            ))

        outside = [d for d in dylibs if not d.startswith(SYSTEM_PREFIXES) and not d.startswith("@")]
        if outside:
            out.append(Finding(
                self.name, f"{tag}{len(outside)} dylib(s) from non-system paths", Severity.MEDIUM,
                "Hijack surface - resolves outside /usr/lib and /System.",
                {"dylibs": outside[:40]}, [], ["macho", "hijack"],
            ))

        if "__PAGEZERO" not in segnames and filetype == 2:
            out.append(Finding(
                self.name, f"{tag}Missing __PAGEZERO", Severity.LOW,
                "Executables normally map a null guard page.",
                {"segments": segnames}, [base], ["macho"],
            ))
