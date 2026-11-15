from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {s: i for i, s in enumerate(Severity)}


@dataclass(frozen=True)
class Finding:
    analyzer: str
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    offsets: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "offsets": self.offsets,
            "tags": self.tags,
        }


@dataclass
class FileResult:
    path: Path
    size: int
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "size": self.size,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    targets: list[Path]
    tool_version: str = TOOL_VERSION
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished: datetime | None = None
    files: list[FileResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def worst(self) -> Severity:
        top = Severity.INFO
        for fr in self.files:
            for f in fr.findings:
                if f.severity.rank > top.rank:
                    top = f.severity
        return top

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "started": self.started.isoformat(),
            "finished": self.finished.isoformat() if self.finished else None,
            "duration_s": (
                (self.finished - self.started).total_seconds()
                if self.finished else None
            ),
            "targets": [str(t) for t in self.targets],
            "worst_severity": self.worst.value,
            "files": [f.to_dict() for f in self.files],
            "errors": self.errors,
            "summary": {
                "files_scanned": len(self.files),
                "total_findings": sum(len(f.findings) for f in self.files),
                "by_severity": self._count_by_severity(),
            },
        }

    def _count_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for fr in self.files:
            for finding in fr.findings:
                counts[finding.severity.value] += 1
        return counts
