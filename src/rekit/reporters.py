from __future__ import annotations

import json
from pathlib import Path

from rekit.models import ScanResult, Severity


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = [
        "# rekit scan report\n",
        f"- Tool version: {result.tool_version}",
        f"- Started: {result.started.isoformat()}",
    ]
    if result.finished:
        lines.append(f"- Duration: {(result.finished - result.started).total_seconds():.2f}s")
    lines += [
        f"- Worst severity: {result.worst.value}",
        f"- Files scanned: {len(result.files)}",
        f"- Total findings: {sum(len(f.findings) for f in result.files)}\n",
    ]
    counts = result._count_by_severity()
    lines.append("## By severity\n")
    for sev in Severity:
        lines.append(f"- {sev.value}: {counts[sev.value]}")
    lines.append("")
    if result.errors:
        lines.append("## Errors\n")
        lines += [f"- {e}" for e in result.errors]
        lines.append("")
    for fr in result.files:
        lines.append(f"### `{fr.path}`")
        lines.append(f"- Size: {fr.size} bytes")
        if fr.error:
            lines.append(f"- Note: {fr.error}\n")
        if not fr.findings:
            lines.append("- No findings\n")
            continue
        for f in sorted(fr.findings, key=lambda x: x.severity.rank, reverse=True):
            lines.append(f"#### [{f.severity.value.upper()}] {f.title}")
            lines.append(f"- Analyzer: `{f.analyzer}`")
            if f.description:
                lines.append(f"- {f.description}")
            if f.offsets:
                lines.append(f"- Offsets: {', '.join(hex(o) for o in f.offsets)}")
            for k, v in f.evidence.items():
                lines.append(f"  - `{k}`: `{v}`")
            lines.append("")
    return "\n".join(lines)


def write_report(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(to_json(result), encoding="utf-8")
    else:
        path.write_text(to_markdown(result), encoding="utf-8")
