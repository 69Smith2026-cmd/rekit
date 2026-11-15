from __future__ import annotations

import re
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

MIN_LEN = 6
ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)

INTERESTING = {
    "urls": re.compile(r"https?://[\w./?=&%\-]+"),
    "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "registry": re.compile(r"HKEY_[A-Z_]+"),
    "crypto": re.compile(r"\b(?:AES|RC4|ChaCha20|RSA|Base64|SHA256)\b"),
    "mutex": re.compile(r"(?:Global|Local)\\[\w{}\-\.]+"),
}

SUSPICIOUS_API = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "GetProcAddress", "IsDebuggerPresent", "NtQueryInformationProcess",
    "RegSetValueEx", "WinExec", "ShellExecute", "CryptEncrypt", "InternetOpen",
]


def looks_like_text(s: str) -> bool:
    """Reject machine-code bytes that happen to be printable."""
    if len(s) < MIN_LEN:
        return False
    if " " in s:
        return True
    if s.startswith("__") and s.replace("_", "").isalnum():
        return True
    if not any(c.islower() for c in s):
        return False
    odd = sum(1 for c in s if not (c.isalnum() or c in "._-/\\:"))
    return odd / len(s) <= 0.3


@register
class StringsAnalyzer(Analyzer):
    name = "strings"
    description = "ASCII + UTF-16LE extraction with text filtering"
    tags = ("strings",)

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        raw = [(m.start(), m.group().decode("latin-1")) for m in ASCII_RE.finditer(data)]
        wide = [(m.start(), m.group().decode("utf-16-le", "ignore")) for m in WIDE_RE.finditer(data)]
        if not raw and not wide:
            return []

        texty = [(o, s) for o, s in raw if looks_like_text(s)]
        seen: set[str] = set()
        uniq: list[tuple[int, str]] = []
        for o, s in texty:
            if s in seen:
                continue
            seen.add(s)
            uniq.append((o, s))

        out: list[Finding] = [Finding(
            self.name, f"{len(uniq)} unique text strings / {len(raw)} printable runs",
            Severity.INFO,
            "Filtered and deduplicated. Offsets point at first occurrence.",
            {"sample": [s for _, s in uniq[:60]], "wide_sample": [s for _, s in wide[:20]]},
            [o for o, _ in uniq[:60]], ["strings"],
        )]

        blob = "\n".join(s for _, s in raw + wide)
        buckets = {k: sorted(set(rx.findall(blob)))[:40] for k, rx in INTERESTING.items()}
        buckets = {k: v for k, v in buckets.items() if v}
        if buckets:
            out.append(Finding(
                self.name, "Indicators inside strings", Severity.MEDIUM,
                "URLs, addresses, mutexes or crypto references in string data.",
                buckets, [], ["ioc"],
            ))

        apis = sorted({a for a in SUSPICIOUS_API if a in blob})
        if apis:
            out.append(Finding(
                self.name, f"{len(apis)} notable API reference(s)", Severity.MEDIUM,
                "API combinations hint at injection, persistence or evasion.",
                {"apis": apis}, [], ["behavior"],
            ))
        return out
