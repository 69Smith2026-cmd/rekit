from __future__ import annotations

import pytest

import struct
from pathlib import Path

from rekit.analyzers.entropy import EntropyAnalyzer
from rekit.analyzers.hashes import HashesAnalyzer
from rekit.analyzers.pe import PEAnalyzer
from rekit.analyzers.elf import ELFAnalyzer
from rekit.analyzers.strings import StringsAnalyzer
from rekit.analyzers.macho import MachOAnalyzer
from rekit.analyzers.imphash import ImphashAnalyzer
from rekit.analyzers.yara import YaraAnalyzer
from rekit.models import Severity
from rekit.scanner import scan


def build_pe(sections):
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    hdr = bytearray(24)
    hdr[0:4] = b"PE\0\0"
    hdr[4:6] = struct.pack("<H", 0x8664)
    hdr[6:8] = struct.pack("<H", len(sections))
    hdr[20:22] = struct.pack("<H", 0)
    hdr[22:24] = struct.pack("<H", 0x22)
    body = bytearray()
    for name, vsize, rsize, roff, flags in sections:
        e = bytearray(40)
        e[0:len(name)] = name
        struct.pack_into("<IIII", e, 8, vsize, 0x1000, rsize, roff)
        struct.pack_into("<I", e, 36, flags)
        body += e
    return bytes(dos + hdr + body)


def test_hashes(tmp_path: Path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello world")
    ev = HashesAnalyzer().analyze(f, b"")[0].evidence
    assert ev["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert ev["size"] == 11


def test_entropy_high(tmp_path: Path):
    f = tmp_path / "x.bin"
    f.write_bytes(bytes(range(256)) * 40)
    assert EntropyAnalyzer().analyze(f, bytes(range(256)) * 40)[0].severity == Severity.MEDIUM


def test_entropy_low(tmp_path: Path):
    f = tmp_path / "x.bin"
    assert EntropyAnalyzer().analyze(f, b"A" * 1000)[0].severity == Severity.INFO


def test_strings_offsets(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"padding text http://evil.example.com cmd.exe"
    findings = StringsAnalyzer().analyze(f, data)
    assert any(x.title == "Indicators inside strings" for x in findings)
    offs = findings[0].offsets
    assert offs and data[offs[0]:offs[0] + 4] == b"padd"


def test_pe_rwx(tmp_path: Path):
    f = tmp_path / "x.exe"
    data = build_pe([(b".text", 0x1000, 0x200, 0x200, 0xE0000020)])
    findings = PEAnalyzer().analyze(f, data)
    assert any("RWX" in x.title for x in findings)


def test_pe_unbacked(tmp_path: Path):
    f = tmp_path / "x.exe"
    data = build_pe([(b".data", 0x2000, 0, 0, 0xC0000040)])
    findings = PEAnalyzer().analyze(f, data)
    assert any("Unbacked" in x.title for x in findings)


def test_pe_overrun(tmp_path: Path):
    f = tmp_path / "x.exe"
    data = build_pe([(b".text", 0x1000, 0x9999, 0x200, 0x60000020)])
    findings = PEAnalyzer().analyze(f, data)
    assert any("overruns" in x.title for x in findings)


def test_pe_not_pe(tmp_path: Path):
    f = tmp_path / "x.bin"
    assert PEAnalyzer().analyze(f, b"not a pe file") == []


def build_elf(sh_type, sh_flags):
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 0x28, 64)
    struct.pack_into("<HH", data, 0x3A, 64, 1)
    sh = bytearray(64)
    struct.pack_into("<I", sh, 4, sh_type)
    struct.pack_into("<Q", sh, 8, sh_flags)
    return bytes(data + sh)


def test_elf_wx(tmp_path: Path):
    f = tmp_path / "x.elf"
    findings = ELFAnalyzer().analyze(f, build_elf(1, 0x5))
    assert any("W+X" in x.title for x in findings)


def test_elf_nobits(tmp_path: Path):
    f = tmp_path / "x.elf"
    findings = ELFAnalyzer().analyze(f, build_elf(8, 0x2))
    assert any("NOBITS" in x.title for x in findings)


def test_elf_not_elf(tmp_path: Path):
    f = tmp_path / "x.bin"
    assert ELFAnalyzer().analyze(f, b"MZ something") == []


def test_applies_to_gates(tmp_path: Path):
    f = tmp_path / "x.bin"
    assert not PEAnalyzer().applies_to(f, b"\xcf\xfa\xed\xfe" + b"\0" * 60)
    assert not ELFAnalyzer().applies_to(f, b"\xcf\xfa\xed\xfe" + b"\0" * 60)
    assert ELFAnalyzer().applies_to(f, b"\x7fELF" + b"\0" * 60)


def test_macho_gets_no_pe_or_elf(tmp_path: Path):
    f = tmp_path / "x.macho"
    f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 4096)
    result = scan([f])
    names = {x.analyzer for x in result.files[0].findings}
    assert "pe" not in names
    assert "elf" not in names


def build_macho(segments, filetype=2, code_sig=False, dylibs=()):
    hdr = bytearray(32)
    hdr[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", hdr, 4, 0x0100000C)
    struct.pack_into("<I", hdr, 12, filetype)

    cmds = bytearray()
    for name, initprot, vmsize, filesize, fileoff in segments:
        c = bytearray(72)
        struct.pack_into("<II", c, 0, 0x19, 72)
        c[8:8 + len(name)] = name
        struct.pack_into("<QQ", c, 32, vmsize, 0)
        struct.pack_into("<QQ", c, 40, fileoff, filesize)
        struct.pack_into("<II", c, 56, 7, initprot)
        cmds += c
    if code_sig:
        c = bytearray(16)
        struct.pack_into("<IIII", c, 0, 0x1D, 16, 0, 0)
        cmds += c
    for path in dylibs:
        name = path.encode() + b"\0"
        size = 24 + len(name)
        c = bytearray(size)
        struct.pack_into("<IIIIII", c, 0, 0x0C, size, 24, 0, 0, 0)
        c[24:24 + len(name)] = name
        cmds += c

    struct.pack_into("<II", hdr, 16, len(segments) + int(code_sig) + len(dylibs), len(cmds))
    return bytes(hdr + cmds + bytearray(4096))


def test_macho_wx(tmp_path: Path):
    f = tmp_path / "x"
    data = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0),
                        (b"__TEXT", 5, 0x1000, 0x1000, 0),
                        (b"__EVIL", 7, 0x1000, 0x1000, 0)])
    assert any("W+X" in x.title for x in MachOAnalyzer().analyze(f, data))


def test_macho_unsigned(tmp_path: Path):
    f = tmp_path / "x"
    data = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0)], filetype=2)
    assert any("No code signature" in x.title for x in MachOAnalyzer().analyze(f, data))


def test_macho_signed_not_flagged(tmp_path: Path):
    f = tmp_path / "x"
    data = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0)], code_sig=True)
    assert not any("No code signature" in x.title for x in MachOAnalyzer().analyze(f, data))


def test_macho_bad_dylib(tmp_path: Path):
    f = tmp_path / "x"
    data = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0)],
                       code_sig=True, dylibs=["/tmp/evil.dylib"])
    assert any("non-system" in x.title for x in MachOAnalyzer().analyze(f, data))


def test_macho_system_dylib_ok(tmp_path: Path):
    f = tmp_path / "x"
    data = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0)],
                       code_sig=True, dylibs=["/usr/lib/libSystem.B.dylib"])
    assert not any("non-system" in x.title for x in MachOAnalyzer().analyze(f, data))


def test_macho_rejects_pe(tmp_path: Path):
    f = tmp_path / "x"
    assert not MachOAnalyzer().applies_to(f, b"MZ" + b"\0" * 60)


def build_fat(slices):
    hdr = bytearray(8)
    hdr[0:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">I", hdr, 4, len(slices))
    entries = bytearray()
    body = bytearray()
    cursor = 8 + 20 * len(slices)
    for cputype, blob in slices:
        e = bytearray(20)
        struct.pack_into(">IIIII", e, 0, cputype, 0, cursor, len(blob), 12)
        entries += e
        body += blob
        cursor += len(blob)
    return bytes(hdr + entries + body)


def test_macho_fat_walks_slices(tmp_path: Path):
    f = tmp_path / "x"
    inner = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0),
                         (b"__EVIL", 7, 0x1000, 0x1000, 0)])
    data = build_fat([(0x0100000C, inner), (0x01000007, inner)])
    findings = MachOAnalyzer().analyze(f, data)
    assert sum(1 for x in findings if "W+X" in x.title) == 2
    assert any("[arm64]" in x.title for x in findings)


def test_macho_fat_slice_overrun(tmp_path: Path):
    f = tmp_path / "x"
    hdr = bytearray(8)
    hdr[0:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">I", hdr, 4, 1)
    e = bytearray(20)
    struct.pack_into(">IIIII", e, 0, 0x0100000C, 0, 999, 4096, 12)
    findings = MachOAnalyzer().analyze(f, bytes(hdr + e))
    assert any("overruns" in x.title for x in findings)


def test_macho_fat_offsets_absolute(tmp_path:



Path):
    f = tmp_path / "x"
    inner = build_macho([(b"__PAGEZERO", 0, 0x1000, 0, 0),
                         (b"__EVIL", 7, 0x1000, 0x1000, 0)])
    data = build_fat([(0x0100000C, inner)])
    findings = MachOAnalyzer().analyze(f, data)
    wx = next(x for x in findings if "W+X" in x.title)
    assert wx.offsets[0] > 28


def test_strings_filters_code_noise(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"AWAVAUATSH" + b"\0" + b"http://real.example.com/path" + b"\0"
    findings = StringsAnalyzer().analyze(f, data)
    sample = findings[0].evidence["sample"]
    assert "http://real.example.com/path" in sample
    assert "AWAVAUATSH" not in sample


def test_strings_indicators_use_raw(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"\x00HKEY_LOCAL_MACHINE\\Software\\Run\x00"
    findings = StringsAnalyzer().analyze(f, data)
    assert any("registry" in x.evidence for x in findings)


def test_strings_filters_code_noise(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"AWAVAUATSH" + b"\0" + b"http://real.example.com/path" + b"\0"
    findings = StringsAnalyzer().analyze(f, data)
    sample = findings[0].evidence["sample"]
    assert "http://real.example.com/path" in sample
    assert "AWAVAUATSH" not in sample


def test_strings_indicators_use_raw(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"\x00HKEY_LOCAL_MACHINE\\Software\\Run\x00"
    findings = StringsAnalyzer().analyze(f, data)
    assert any("registry" in x.evidence for x in findings)


def test_strings_rejects_code_brackets(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"[A\\A]A^A_]" + b"\x00" + b"__PAGEZERO" + b"\x00" + b"/usr/lib/dyld" + b"\x00"
    sample = StringsAnalyzer().analyze(f, data)[0].evidence["sample"]
    assert "[A\\A]A^A_]" not in sample
    assert "__PAGEZERO" in sample
    assert "/usr/lib/dyld" in sample


def test_strings_dedupes(tmp_path: Path):
    f = tmp_path / "x.bin"
    data = b"http://a.example/x\x00" * 5 + b"http://b.example/y\x00"
    f0 = StringsAnalyzer().analyze(f, data)[0]
    assert f0.evidence["sample"] == ["http://a.example/x", "http://b.example/y"]
    assert len(f0.offsets) == 2


def build_pe_imports(dll="KERNEL32.dll", funcs=("CreateFileA", "ReadFile"), ordinal=False):
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    fh = bytearray(24)
    fh[0:4] = b"PE\0\0"
    struct.pack_into("<H", fh, 4, 0x14C)
    struct.pack_into("<H", fh, 6, 1)
    struct.pack_into("<H", fh, 20, 224)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)
    sec = bytearray(40)
    sec[0:6] = b".rdata"
    struct.pack_into("<IIII", sec, 8, 0x1000, 0x1000, 0x1000, 0x160)
    struct.pack_into("<I", sec, 36, 0x40000040)
    body = bytearray(0x1000)
    struct.pack_into("<II", opt, 96 + 8, 0x1000, 40)
    struct.pack_into("<III", body, 0, 0x1050, 0, 0)
    struct.pack_into("<II", body, 12, 0x1030, 0x1080)
    body[0x30:0x30 + len(dll) + 1] = dll.encode() + b"\0"
    at = 0x200
    thunks = []
    for fn in funcs:
        body[at:at + 2] = b"\0\0"
        body[at + 2:at + 2 + len(fn) + 1] = fn.encode() + b"\0"
        thunks.append(0x1000 + at)
        at += 2 + len(fn) + 1
    if ordinal:
        thunks.append(0x80000000 | 0x1A4)
    for i, t in enumerate(thunks):
        struct.pack_into("<I", body, 0x50 + i * 4, t)
    return bytes(dos + fh + opt + sec + body)


def test_imphash_stable(tmp_path: Path):
    f = tmp_path / "x.exe"
    data = build_pe_imports()
    a = [x for x in ImphashAnalyzer().analyze(f, data) if "imphash" in x.title]
    b = [x for x in ImphashAnalyzer().analyze(f, data) if "imphash" in x.title]
    assert a and a[0].evidence["imphash"] == b[0].evidence["imphash"]
    assert len(a[0].evidence["imphash"]) == 32


def test_imphash_differs(tmp_path: Path):
    f = tmp_path / "x.exe"
    a = [x for x in ImphashAnalyzer().analyze(f, build_pe_imports()) if "imphash" in x.title]
    b = [x for x in ImphashAnalyzer().analyze(f, build_pe_imports(funcs=("Sleep",))) if "imphash" in x.title]
    assert a[0].evidence["imphash"] != b[0].evidence["imphash"]


def test_imphash_ordinal(tmp_path: Path):
    f = tmp_path / "x.exe"
    assert any("ordinal" in x.title for x in ImphashAnalyzer().analyze(f, build_pe_imports(ordinal=True)))


def test_yara_matches(tmp_path: Path, monkeypatch):
    pytest.importorskip("yara")
    rules = tmp_path / "r"
    rules.mkdir()
    (rules / "t.yar").write_text(
        'rule Has_MZ { strings: $a = "MZ" condition: $a }'
    )
    monkeypatch.setenv("REKIT_RULES", str(rules))
    YaraAnalyzer._cache = None
    findings = YaraAnalyzer().analyze(tmp_path / "x", b"MZ hello")
    assert any("Has_MZ" in x.title for x in findings)


def test_yara_no_rules(tmp_path: Path, monkeypatch):
    pytest.importorskip("yara")
    monkeypatch.setenv("REKIT_RULES", str(tmp_path / "nope"))
    monkeypatch.setattr(YaraAnalyzer, "_cache", None, raising=False)
    findings = YaraAnalyzer().analyze(tmp_path / "x", b"MZ")
    assert len(findings) == 1
    assert "No YARA rules loaded" in findings[0].title
    assert findings[0].severity is Severity.LOW
    assert "nope" in findings[0].evidence["dir"]


def _yara_rules(monkeypatch):
    pytest.importorskip("yara")
    monkeypatch.delenv("REKIT_RULES", raising=False)
    monkeypatch.setattr(YaraAnalyzer, "_cache", None, raising=False)


def test_yara_embedded_pe_fires_on_carrier(tmp_path, monkeypatch):
    _yara_rules(monkeypatch)
    data = b"MZ" + b"\x90" * 1022 + b"MZ" + b"\x90" * 60 + b"PE\x00\x00" + b"\x00" * 2048
    assert any("Embedded_PE" in f.title for f in YaraAnalyzer().analyze(tmp_path / "x", data))


def test_yara_embedded_pe_quiet_on_plain_pe(tmp_path, monkeypatch):
    _yara_rules(monkeypatch)
    data = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 2048
    assert not any("Embedded_PE" in f.title for f in YaraAnalyzer().analyze(tmp_path / "x", data))


def test_yara_broken_rule_reports(tmp_path, monkeypatch):
    pytest.importorskip("yara")
    rules = tmp_path / "r"
    rules.mkdir()
    (rules / "bad.yar").write_text("rule Broken { condition: and }")
    monkeypatch.setenv("REKIT_RULES", str(rules))
    monkeypatch.setattr(YaraAnalyzer, "_cache", None, raising=False)
    findings = YaraAnalyzer().analyze(tmp_path / "x", b"MZ")
    assert any("failed to compile" in f.title for f in findings)


def test_yara_broken_rule_reports(tmp_path, monkeypatch):
    pytest.importorskip("yara")
    rules = tmp_path / "r"
    rules.mkdir()
    (rules / "bad.yar").write_text("rule Broken { condition: and }")
    monkeypatch.setenv("REKIT_RULES", str(rules))
    monkeypatch.setattr(YaraAnalyzer, "_cache", None, raising=False)
    findings = YaraAnalyzer().analyze(tmp_path / "x", b"MZ")
    assert any("failed to compile" in f.title for f in findings)
