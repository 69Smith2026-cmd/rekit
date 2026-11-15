from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from rekit.analyzers.base import Analyzer, discover_analyzers
from rekit.models import FileResult, ScanResult

logger = logging.getLogger(__name__)


def _iter_files(targets: Iterable[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for target in targets:
        target = target.expanduser().resolve()
        if not target.exists():
            logger.warning("Target does not exist: %s", target)
            continue
        pool = [target] if target.is_file() else sorted(target.rglob("*"))
        for p in pool:
            if not p.is_file():
                continue
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            yield rp


def scan(
    targets: list[Path],
    analyzers: list[Analyzer] | None = None,
    max_size: int = 50 * 1024 * 1024,
) -> ScanResult:
    if analyzers is None:
        analyzers = [cls() for cls in discover_analyzers().values()]

    result = ScanResult(targets=targets)

    for path in _iter_files(targets):
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            result.files.append(FileResult(path=path, size=0, error=str(exc)))
            continue

        file_result = FileResult(path=path, size=size)

        data: bytes | None = None
        if size <= max_size:
            try:
                data = path.read_bytes()
            except OSError as exc:
                file_result.error = str(exc)
        else:
            file_result.error = f"Buffer analyzers skipped: {size} bytes > {max_size}"

        for analyzer in analyzers:
            if analyzer.streams:
                payload = b""
            elif data is None:
                continue
            else:
                payload = data
            try:
                if not analyzer.applies_to(path, payload):
                    continue
                file_result.findings.extend(analyzer.analyze(path, payload))
            except Exception as exc:
                logger.exception("Analyzer %s failed on %s", analyzer.name, path)
                result.errors.append(f"{analyzer.name} @ {path}: {exc}")

        result.files.append(file_result)

    result.finished = datetime.now(timezone.utc)
    return result
