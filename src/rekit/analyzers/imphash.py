from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

SUSPICIOUS_DLLS = {
    "ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "crypt32.dll",
    "netapi32.dll", "psapi.dll", "dbghelp.dll",
}
MAX_DESC = 128
MAX_THUNK = 512


@register
class ImphashAnalyzer(Analyzer):
    name = "imphash"
    description = "PE import table parse, imphash, suspicious DLL detection"
    tags = ("pe", "imports")

    def applies_to(self, path: Path, data: bytes) -> bool:
        return len(data) > 0x40 and data[:2] == b"MZ"

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        out: list[Finding] = []
        if len(data) < 0x40:
            return out
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error:
            return out
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return out

        opt = e_lfanew + 24
        if opt + 96 > len(data):
            return out
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        dir_base = opt + (112 if is64 else 96)
        if dir_base + 16 > len(data):
            return out

        n_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_off = opt + opt_size

        sections: list[tuple[int, int, int, int]] = []
        for i in range(min(n_sections, 96)):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, base + 8)
            sections.append((vaddr, vsize, rsize, roff))

        imp_rva, imp_size = struct.unpack_from("<II", data, dir_base + 8)
        if imp_rva == 0:
            out.append(Finding(
                self.name, "No import directory", Severity.MEDIUM,
                "Empty import table - typical of packed or shellcode stubs.",
                {}, [dir_base + 8], ["pe", "packing"],
            ))
            return out

        desc_off = self._rva_to_off(sections, imp_rva)
        if desc_off is None:
            out.append(Finding(
                self.name, "Import directory RVA unmapped", Severity.MEDIUM,
                "Directory points outside any section - crafted header.",
                {"rva": hex(imp_rva)}, [dir_base + 8], ["pe", "malformed"],
            ))
            return out

        entries: list[str] = []
        dlls: list[str] = []
        ordinals: list[str] = []
        consumed = 0

        for i in range(MAX_DESC):
            d = desc_off + i * 20
            if d + 20 > len(data):
                break
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, d)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            consumed += 1

            name_off = self._rva_to_off(sections, name_rva)
            if name_off is None:
                continue
            raw = data[name_off:name_off + 256].split(b"\0", 1)[0]
            dll = raw.decode("latin-1", "replace").lower()
            if not dll:
                continue
            dlls.append(dll)

            t_off = self._rva_to_off(sections, oft or ft)
            if t_off is None:
                continue
            step = 8 if is64 else 4
            for j in range(MAX_THUNK):
                t = t_off + j * step
                if t + step > len(data):
                    break
                val = struct.unpack_from("<Q" if is64 else "<I", data, t)[0]
                if val == 0:
                    break
                if val & (1 << (63 if is64 else 31)):
                    entries.append(f"{dll}#ord{val & 0xFFFF}")
                    ordinals.append(f"{dll}#{val & 0xFFFF}")
                    continue
                h_off = self._rva_to_off(sections, val & 0x7FFFFFFF)
                if h_off is None or h_off + 2 > len(data):
                    continue
                fname = data[h_off + 2:h_off + 128].split(b"\0", 1)[0]
                if fname:
                    entries.append(f"{dll}.{fname.decode('latin-1', 'replace').lower()}")

        if not entries:
            return out

        imphash = hashlib.md5(",".join(entries).encode()).hexdigest()
        out.append(Finding(
            self.name, f"imphash {imphash}", Severity.INFO,
            "Import-table fingerprint for sample clustering.",
            {"imphash": imphash, "dlls": sorted(set(dlls))[:40],
             "import_count": len(entries), "descriptors": consumed},
            [desc_off], ["pe", "imports"],
        ))

        if len(entries) < 10:
            out.append(Finding(
                self.name, f"Only {len(entries)} imports", Severity.MEDIUM,
                "Sparse import table - common in packers and small stagers.",
                {"count": len(entries)}, [desc_off], ["pe", "packing"],
            ))

        odd = sorted({d for d in dlls if d in SUSPICIOUS_DLLS})
        if odd:
            out.append(Finding(
                self.name, f"Suspicious DLLs: {', '.join(odd)}", Severity.LOW,
                "Networking, crypto or anti-debug library present.",
                {"dlls": odd}, [], ["pe", "behavior"],
            ))

        if ordinals:
            out.append(Finding(
                self.name, f"{len(ordinals)} ordinal import(s)", Severity.LOW,
                "Ordinal-only imports hide the function name from casual review.",
                {"ordinals": ordinals[:40]}, [], ["pe", "imports"],
            ))
        return out

    @staticmethod
    def _rva_to_off(sections, rva: int) -> int | None:
        for vaddr, vsize, rsize, roff in sections:
            span = max(vsize, rsize)
            if vaddr <= rva < vaddr + span:
                delta = rva - vaddr
                if delta < rsize:
                    return roff + delta
        return None
