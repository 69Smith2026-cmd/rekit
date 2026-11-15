from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

WINDOW = 4096
HIGH = 7.4
WHOLE_HIGH = 7.0


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@register
class EntropyAnalyzer(Analyzer):
    name = "entropy"
    description = "Whole-file and windowed entropy; flags packing"
    tags = ("packing",)

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        if not data:
            return []
        out: list[Finding] = []
        overall = shannon(data)
        out.append(Finding(
            self.name, f"Overall entropy {overall:.3f}",
            Severity.MEDIUM if overall >= WHOLE_HIGH else Severity.INFO,
            ("High global entropy suggests compression, encryption or packing."
             if overall >= WHOLE_HIGH else "Entropy within normal range for this size."),
            {"entropy": round(overall, 4), "size": len(data)}, [], ["packing"],
        ))
        hot = [
            (off, round(e, 3))
            for off in range(0, max(0, len(data) - WINDOW), WINDOW)
            if (e := shannon(data[off:off + WINDOW])) >= HIGH
        ]
        if hot:
            out.append(Finding(
                self.name, f"{len(hot)} high-entropy window(s)",
                Severity.HIGH if len(hot) > 1 else Severity.MEDIUM,
                "Contiguous high-entropy regions are typical of embedded or encrypted payloads.",
                {"windows": hot[:25], "window_size": WINDOW},
                [o for o, _ in hot[:25]], ["packing", "payload"],
            ))
        return out
