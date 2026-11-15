from __future__ import annotations

import logging

import os
from pathlib import Path

import yara

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity
logger = logging.getLogger(__name__)

SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


def _rules_root() -> Path:
    return Path(os.getenv("REKIT_RULES") or (Path(__file__).resolve().parents[1] / "rules"))


@register
class YaraAnalyzer(Analyzer):
    name = "yara"
    description = "Match files against bundled YARA rules or $REKIT_RULES"
    tags = ("yara",)
    requires = ("yara",)

    _cache: tuple[tuple[str, ...], object] | None = None

    def _sources(self) -> list[Path]:
        root = _rules_root()
        if not root.is_dir():
            return []
        return sorted(list(root.glob("*.yar")) + list(root.glob("*.yara")))

    def _compiled(self):
        files = self._sources()
        if not files:
            return None
        key = tuple(str(p.resolve()) for p in files)
        if self._cache and self._cache[0] == key:
            return self._cache[1]
    
        try:

            compiled = yara.compile(filepaths={p.stem: str(p) for p in files})

        except yara.SyntaxError as e:

            logger.warning("YARA compile failed in %s: %s", _rules_root(), e)

            return None
        self._cache = (key, compiled)
        return compiled

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        rules = self._compiled()
        if rules is None:
            empty = not self._sources()
            return [Finding(
                self.name,
                "No YARA rules loaded" if empty else "YARA rules failed to compile",
                Severity.LOW,
                "YARA contributed nothing - rule set missing or malformed.",
                {"dir": str(_rules_root())}, [], ["yara"],
            )]
        try:
            matches = rules.match(data=data, timeout=30)
        except Exception:
            return []

        out: list[Finding] = []
        for m in matches:
            meta = m.meta or {}
            out.append(Finding(
                self.name, f"YARA: {m.rule}",
                SEV.get(str(meta.get("severity", "medium")).lower(), Severity.MEDIUM),
                str(meta.get("description", "")),
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": {k: str(v) for k, v in meta.items()},
                    "strings": [
                        (s.identifier, hex(s.instances[0].offset) if s.instances else None)
                        for s in m.strings[:20]
                    ],
                },
                [s.instances[0].offset for s in m.strings if s.instances][:20],
                ["yara"] + list(m.tags),
            ))
        return out
